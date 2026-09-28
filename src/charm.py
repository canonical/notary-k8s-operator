#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application."""

import json
import logging
import random
import socket
import string
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import cached_property
from typing import Iterator

import ops
import yaml
from charmlibs.interfaces.certificate_transfer import CertificateTransferProvides
from charmlibs.interfaces.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    ProviderCertificate,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer, charm_tracing_config
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer

from notary import ClusterMember, Notary
from s3 import S3Parameters
from utils import is_valid_hostname

logger = logging.getLogger(__name__)

CERTIFICATE_PROVIDER_RELATION_NAME = "certificates"

LOGGING_RELATION_NAME = "logging"
METRICS_RELATION_NAME = "metrics"
GRAFANA_RELATION_NAME = "grafana-dashboard"
TLS_ACCESS_RELATION_NAME = "access-certificates"
PEER_RELATION_NAME = "notary-peers"
S3_RELATION_NAME = "s3-parameters"

DB_MOUNT = "database"
CONFIG_MOUNT = "config"
WORKLOAD_CONFIG_PATH = "/etc/notary"
WORKLOAD_DB_PATH = "/var/lib"

CERTIFICATE_COMMON_NAME = "Notary Self Signed Certificate"
SELF_SIGNED_CA_COMMON_NAME = "Notary Self Signed Root CA"
NOTARY_LOGIN_SECRET_LABEL = "Notary Login Details"
SEND_ACCESS_CA_CERT_RELATION_NAME = "send-access-ca-certificate"
CLUSTER_JOIN_SECRET_LABEL = "Notary Cluster Join Tokens"
SELF_SIGNED_CA_SECRET_LABEL = "Notary Self Signed CA"
CLUSTER_DATA_VERSION_KEY = "cluster_data_version"
DQLITE_PORT = 9000

# How long the leader waits for a unit to join before re-minting its one-time
# join token. Tokens expire upstream after 3 hours and are spent by failed join
# attempts, so a unit that hasn't joined within this interval gets a fresh one.
JOIN_TOKEN_REMINT_INTERVAL = timedelta(minutes=15)
CLUSTER_MEMBER_REMOVAL_ATTEMPTS = 3
CLUSTER_MEMBER_REMOVAL_RETRY_DELAY = 2


@dataclass
class LoginSecret:
    """The format of the secret for the login details that are required to login to Notary."""

    email: str
    password: str
    token: str | None

    def to_dict(self) -> dict[str, str]:
        """Return a dict version of the secret."""
        return {
            "email": self.email,
            "password": self.password,
            "token": self.token if self.token else "",
        }


@dataclass(frozen=True)
class JoinTokenRecord:
    """A cluster join token minted for a unit, with the time it was minted."""

    token: str
    minted_at: datetime


@trace_charm(
    tracing_endpoint="_tracing_endpoint",
    server_cert="_tracing_server_cert",
    extra_types=(TLSCertificatesProvidesV4,),
)
class NotaryCharm(ops.CharmBase):
    """Charmed Notary."""

    _stored = ops.StoredState()

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._stored.set_default(restart_required=False)
        self._pebble_unavailable = False
        self.port = 2111
        self.access_csr = CertificateRequestAttributes(
            common_name="Notary",
            sans_dns=self._generate_csr_sans_dns(),
        )

        # Only the API port is exposed through the Juju-managed k8s Service. The
        # dqlite port is served pod-to-pod: cluster traffic uses the peer bind
        # addresses directly, and dqlite mTLS is the only authorization boundary
        # on that port, so it must not be exposed to clients.
        self.unit.set_ports(self.port)
        self.container = self.unit.get_container("notary")
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME)
        self.tls = TLSCertificatesProvidesV4(
            self, relationship_name=CERTIFICATE_PROVIDER_RELATION_NAME
        )

        # Observability
        self.tracing = TracingEndpointRequirer(self, protocols=["otlp_http"])
        self._tracing_endpoint, self._tracing_server_cert = charm_tracing_config(
            self.tracing, cert_path=None
        )
        self.dashboard = GrafanaDashboardProvider(self, relation_name=GRAFANA_RELATION_NAME)
        self.logs = LogForwarder(charm=self, relation_name=LOGGING_RELATION_NAME)
        self.ingress = IngressPerAppRequirer(
            charm=self,
            port=self.port,
            strip_prefix=True,
            scheme=lambda: "https",
        )
        self.metrics = MetricsEndpointProvider(
            charm=self,
            relation_name=METRICS_RELATION_NAME,
            jobs=[
                {
                    "scheme": "https",
                    "tls_config": {"insecure_skip_verify": True},
                    "metrics_path": "/metrics",
                    "static_configs": [{"targets": [f"*:{self.port}"]}],
                }
            ],
        )
        self.tls_access = TLSCertificatesRequiresV4(
            charm=self,
            mode=Mode.UNIT,
            relationship_name=TLS_ACCESS_RELATION_NAME,
            certificate_requests=[self.access_csr],
        )
        self.certificate_transfer = CertificateTransferProvides(
            self, SEND_ACCESS_CA_CERT_RELATION_NAME
        )
        [
            framework.observe(event, self.configure)
            for event in [
                self.on["notary"].pebble_ready,
                self.on["notary"].pebble_custom_notice,
                self.on["certificates"].relation_changed,
                self.on["certificates"].relation_departed,
                self.on["certificates"].relation_broken,
                self.on["access-certificates"].relation_changed,
                self.on["access-certificates"].relation_departed,
                self.on["access-certificates"].relation_broken,
                self.on[SEND_ACCESS_CA_CERT_RELATION_NAME].relation_joined,
                self.on.config_storage_attached,
                self.on.database_storage_attached,
                self.on.config_changed,
                self.on.update_status,
                self.on.start,
                self.on.leader_elected,
                self.on.secret_changed,
                self.on[PEER_RELATION_NAME].relation_joined,
                self.on[PEER_RELATION_NAME].relation_changed,
                self.on[PEER_RELATION_NAME].relation_departed,
            ]
        ]
        framework.observe(self.on.collect_app_status, self._on_collect_status)
        framework.observe(self.on.collect_unit_status, self._on_collect_status)
        framework.observe(self.on.remove, self._on_remove)

    def _on_remove(self, event: ops.RemoveEvent):
        """Remove this member while it can still participate in quorum."""
        if not self.container.can_connect():
            raise RuntimeError("Cannot safely remove unit: Pebble is unavailable")
        if self._cluster_has_state():
            relation = self.model.get_relation(PEER_RELATION_NAME)
            clients = self._cluster_clients(relation) if relation else iter([self.client])
            members = None
            for client in clients:
                token = self._get_valid_admin_token(client)
                if token:
                    members = client.list_cluster_members(token)
                    if members is not None:
                        break
            if members is None:
                raise RuntimeError("Cannot determine cluster membership before removal")
            peers = sorted(
                (
                    member
                    for member in members
                    if member.name != self._cluster_member_name and member.address
                ),
                key=lambda member: member.name,
            )
            if any(member.name == self._cluster_member_name for member in members) and peers:
                if not self._remove_cluster_member_via_peers(peers):
                    raise RuntimeError("Cannot remove this member from the cluster")
        with suppress(ops.ModelError):
            self.container.stop("notary")

    def _remove_cluster_member_via_peers(self, peers: list[ClusterMember]) -> bool:
        """Remove this unit through a survivor, retrying transient leadership changes."""
        clients = []
        for member in peers:
            # The advertised API address may be a shared ingress hostname. Use
            # the persisted dqlite host to reach this specific surviving unit.
            host = member.address.rsplit(":", 1)[0]
            address = f"https://{host}:{self.port}"
            clients.append(Notary(address, self._ca_certificate_path))
        for attempt in range(CLUSTER_MEMBER_REMOVAL_ATTEMPTS):
            for client in clients:
                token = self._get_valid_admin_token(client)
                if not token:
                    continue
                if client.delete_cluster_member(self._cluster_member_name, token):
                    return True
                # Eviction may succeed even when cleanup or the HTTP response
                # fails. Confirm absence through a survivor before retrying.
                members = client.list_cluster_members(token)
                if members and all(
                    member.name and member.name != self._cluster_member_name for member in members
                ):
                    return True
            if attempt < CLUSTER_MEMBER_REMOVAL_ATTEMPTS - 1:
                time.sleep(CLUSTER_MEMBER_REMOVAL_RETRY_DELAY)
        return False

    def configure(self, event: ops.EventBase):
        """Handle configuration events."""
        try:
            self._configure()
        except (TimeoutError, ops.pebble.ConnectionError) as error:
            logger.warning("Workload container temporarily unavailable: %s", error)
            self._pebble_unavailable = True

    def _configure(self):
        """Reconcile workload configuration."""
        if not self.container.can_connect() or not self._storages_attached():
            return
        self._sync_peer_relation_data()
        self._coordinate_bootstrap()
        self._configure_access_certificates()
        if not self._cluster_prerequisites_met():
            if self._certificates_available():
                self._reconcile_cluster_membership()
            if not self._cluster_prerequisites_met():
                return
        self._configure_notary_config_file()
        if not self._certificates_available():
            return
        service_was_running = False
        with suppress(ops.ModelError):
            service_was_running = self.container.get_service("notary").is_running()
        self._configure_pebble_plan()
        if service_was_running and self._stored.restart_required:
            logger.info("Configuration or certificates changed. Restarting service.")
            with suppress(ops.pebble.ChangeError):
                self.container.restart("notary")
                self._stored.restart_required = False
        elif not service_was_running:
            self._stored.restart_required = False
        if not self.unit.is_leader():
            return
        self._configure_charm_authorization()
        self._reconcile_cluster_membership()
        self._configure_certificate_requirers()
        self._send_ca_cert()
        self._configure_juju_workload_version()

    def _on_collect_status(self, event: ops.CollectStatusEvent):
        if self._pebble_unavailable:
            event.add_status(ops.WaitingStatus("waiting for workload container"))
            return
        try:
            self._collect_status(event)
        except (TimeoutError, ops.pebble.ConnectionError) as error:
            logger.warning("Workload container temporarily unavailable: %s", error)
            event.add_status(ops.WaitingStatus("waiting for workload container"))

    def _collect_status(self, event: ops.CollectStatusEvent):
        if not self.container.can_connect():
            event.add_status(ops.WaitingStatus("container not yet connectable"))
            return
        if not self._storages_attached():
            event.add_status(ops.WaitingStatus("storages not yet available"))
            return
        if not self._cluster_prerequisites_met():
            event.add_status(ops.WaitingStatus("waiting for cluster join token"))
            return
        if not self._certificates_available():
            event.add_status(ops.WaitingStatus("certificates not yet pushed to workload"))
            return
        if not self.client.is_api_available():
            event.add_status(ops.WaitingStatus("server not yet available"))
            return
        if not self.client.is_initialized():
            event.add_status(ops.BlockedStatus("please initialize Notary"))
            return
        if self.model.get_relation(S3_RELATION_NAME):
            try:
                S3Parameters.from_relation(self.s3_requirer.get_s3_connection_info())
            except ValueError as error:
                event.add_status(ops.BlockedStatus(str(error)))
                return
        event.add_status(ops.ActiveStatus())

    ## Configure Dependencies ##
    def _configure_pebble_plan(self):
        """Add the Pebble layer and replan."""
        layer = ops.pebble.Layer(self._pebble_layer)
        if self.container.get_plan().services.get("notary") != layer.services["notary"]:
            self.container.add_layer("notary", layer, combine=True)
        with suppress(ops.pebble.ChangeError):
            self.container.replan()

    def _configure_notary_config_file(self) -> None:
        """Push changed config and record whether the workload needs a restart."""
        desired_config = yaml.dump(
            data={
                "key_path": f"{WORKLOAD_CONFIG_PATH}/config/private_key.pem",
                "cert_path": f"{WORKLOAD_CONFIG_PATH}/config/certificate.pem",
                "db_path": f"{WORKLOAD_DB_PATH}/notary/database/dqlite",
                "external_hostname": self._get_external_hostname_config() or socket.getfqdn(),
                "port": self.port,
                "pebble_notifications": True,
                "cluster": self._cluster_config,
                "logging": {
                    "system": {
                        "level": "debug",
                        "output": "stderr",
                    },
                    "audit": {
                        "level": "debug",
                        "output": "stderr",
                    },
                },
                "encryption_backend": {
                    "type": "none",
                },
            }
        )
        restart_required = True
        try:
            existing_config = self.container.pull(
                f"{WORKLOAD_CONFIG_PATH}/config/config.yaml"
            ).read()
            if existing_config == desired_config:
                logger.info("Config file already up to date.")
                return
            existing_data = yaml.safe_load(existing_config)
            desired_data = yaml.safe_load(desired_config)
            if isinstance(existing_data, dict) and isinstance(existing_data.get("cluster"), dict):
                if "join_token" not in desired_data["cluster"]:
                    existing_data["cluster"].pop("join_token", None)
                    restart_required = existing_data != desired_data
        except ops.pebble.PathError:
            pass
        except yaml.YAMLError:
            pass
        self.container.make_dir(path=f"{WORKLOAD_CONFIG_PATH}/config", make_parents=True)
        # Retain the restart across hooks if Pebble becomes unavailable after writing.
        if restart_required:
            self._stored.restart_required = True
        self.container.push(
            path=f"{WORKLOAD_CONFIG_PATH}/config/config.yaml",
            source=desired_config,
        )
        logger.info("Config file updated.")

    @property
    def _cluster_config(self) -> dict[str, str]:
        """Return the dqlite cluster configuration block for this unit.

        Pending joins retain admission tokens. Established nodes resume from disk.
        """
        config = {
            "name": self._cluster_member_name,
            "address": f"{self._cluster_bind_address}:{DQLITE_PORT}",
        }
        if not self._cluster_has_state() or self._cluster_join_pending():
            if join_token := self._get_join_token():
                config["join_token"] = join_token
        return config

    @property
    def _cluster_member_name(self) -> str:
        """Return the dqlite member name for this unit (LXD-style, no slashes)."""
        return self.unit.name.replace("/", "-")

    @property
    def _cluster_bind_address(self) -> str:
        """Return a stable address for this unit's persisted dqlite identity."""
        return socket.getfqdn()

    def _cluster_has_state(self) -> bool:
        """Return whether this unit's dqlite data directory already holds cluster state."""
        try:
            self.container.pull(f"{WORKLOAD_DB_PATH}/notary/database/dqlite/info.yaml")
            return True
        except ops.pebble.PathError:
            return False

    def _configure_access_certificates(self) -> None:
        """Write access certificates when they change."""
        if not self._tls_access_relation_active():
            ca = self._get_or_create_self_signed_ca()
            if ca is None:
                logger.info(
                    "Self-signed CA not available yet, skipping certificate configuration."
                )
                return
            ca_certificate, ca_private_key = ca
            if not self._self_signed_certificates_generated(ca_certificate):
                self._generate_self_signed_certificates(ca_certificate, ca_private_key)
        else:
            self._store_certificate_from_access_relation_if_available()

    def _cluster_join_pending(self) -> bool:
        """Return whether dqlite still marks its first admission as incomplete."""
        try:
            self.container.pull(f"{WORKLOAD_DB_PATH}/notary/database/dqlite/join")
            return True
        except ops.pebble.PathError:
            return False

    def _configure_charm_authorization(self):
        """Create an admin user to manage Notary if needed, and acquire a token by logging in if needed."""
        self._get_valid_admin_token()

    def _get_valid_admin_token(self, client: Notary | None = None) -> str | None:
        """Return a valid admin token, logging in with the stored credentials if needed.

        Only the leader persists a refreshed token back to the app secret; other
        units use the refreshed token transiently (e.g. to remove themselves
        from the cluster when departing).
        """
        client = client if client is not None else self.client
        login_details = self._get_or_create_admin_account(client)
        if not login_details:
            return None
        if login_details.token and client.token_is_valid(login_details.token):
            return login_details.token
        login_response = client.login(login_details.email, login_details.password)
        if not login_response or not login_response.token:
            logger.warning(
                "failed to login with the existing admin credentials."
                " If you've manually modified the admin account credentials,"
                " please update the charm's credentials secret accordingly."
            )
            return None
        if self.unit.is_leader():
            login_details.token = login_response.token
            login_details_secret = self.model.get_secret(label=NOTARY_LOGIN_SECRET_LABEL)
            login_details_secret.set_content(login_details.to_dict())
        return login_response.token

    def _configure_certificate_requirers(self):
        """Get all CSR's and certs from databags and Notary, compare differences and update requirers if needed."""
        login_details = self._get_or_create_admin_account()
        if not login_details or not login_details.token:
            logger.warning("couldn't distribute certificates: not logged in")
            return
        databag_csrs = self.tls.get_certificate_requests()
        notary_certificate_requests = self.client.list_certificate_requests(login_details.token)
        for request in databag_csrs:
            notary_certificate_requests_with_matching_csr = [
                notary_certificate_request
                for notary_certificate_request in notary_certificate_requests
                if notary_certificate_request.csr == str(request.certificate_signing_request)
            ]
            if len(notary_certificate_requests_with_matching_csr) < 1:
                self.client.create_certificate_request(
                    str(request.certificate_signing_request), login_details.token
                )
                continue
            assert len(notary_certificate_requests_with_matching_csr) < 2
            request_notary_entry = notary_certificate_requests_with_matching_csr[0]
            certificates_provided_for_csr = [
                csr
                for csr in self.tls.get_issued_certificates(request.relation_id)
                if str(csr.certificate_signing_request) == request_notary_entry.csr
            ]
            if (
                request_notary_entry.status == "Rejected"
                or request_notary_entry.status == "Revoked"
                or request_notary_entry.status == "Outstanding"
            ):
                if len(certificates_provided_for_csr) > 0:
                    last_provided_certificate = certificates_provided_for_csr[0]
                    self.tls.set_relation_certificate(
                        ProviderCertificate(
                            relation_id=request.relation_id,
                            certificate_signing_request=request.certificate_signing_request,
                            certificate=last_provided_certificate.certificate,
                            ca=last_provided_certificate.ca,
                            chain=last_provided_certificate.chain,
                            revoked=True,
                        )
                    )
                continue
            certificate_chain = [
                Certificate.from_string(cert) for cert in request_notary_entry.certificate_chain
            ]
            certificate_not_provided_yet = (
                len(certificate_chain) > 0 and len(certificates_provided_for_csr) == 0
            )
            certificate_provided_is_stale = (
                len(certificate_chain) > 0
                and len(certificates_provided_for_csr) == 1
                and certificate_chain[0] != certificates_provided_for_csr[0].certificate
            )
            if certificate_not_provided_yet or certificate_provided_is_stale:
                self.tls.set_relation_certificate(
                    ProviderCertificate(
                        relation_id=request.relation_id,
                        certificate_signing_request=request.certificate_signing_request,
                        certificate=certificate_chain[0],
                        ca=certificate_chain[-1],
                        chain=certificate_chain,
                    )
                )

    def _send_ca_cert(self):
        """Send the CA certificate in the workload to all requirers of the certificate-transfer interface."""
        with self.container.pull(
            f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/ca.pem",
        ) as ca_cert_file:
            if ca_cert := ca_cert_file.read().strip():
                for relation in self.model.relations.get(SEND_ACCESS_CA_CERT_RELATION_NAME, []):
                    self.certificate_transfer.add_certificates(
                        certificates={ca_cert}, relation_id=relation.id
                    )
                    logger.info("Sent CA certificate to relation %s", relation.id)

    def _configure_juju_workload_version(self):
        """Set the Juju workload version to the Notary version."""
        if not self.unit.is_leader():
            return
        if not self.client.is_api_available():
            return
        if version := self.client.get_version():
            self.unit.set_workload_version(version)

    ## Properties ##
    @cached_property
    def _ca_certificate_path(self) -> str:
        """Copy the workload CA locally for HTTPS clients once per hook.

        Juju's storage paths differ between versions, and storage metadata may
        be unavailable during startup or removal. The workload mount is stable.
        """
        with self.container.pull(f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/ca.pem") as source:
            ca = source.read()
        path = self.charm_dir / "notary-ca.pem"
        path.write_text(ca)
        return str(path)

    @cached_property
    def client(self) -> Notary:
        """Create the local client when needed, after storage is attached."""
        return Notary(f"https://{socket.getfqdn()}:{self.port}", self._ca_certificate_path)

    @property
    def _pebble_layer(self) -> ops.pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "notary layer",
            "description": "pebble config layer for notary",
            "services": {
                "notary": {
                    "override": "replace",
                    "summary": "notary",
                    "command": f"notary start -c {WORKLOAD_CONFIG_PATH}/config/config.yaml",
                    "startup": "enabled",
                }
            },
        }

    ## Status Checks ##
    def _storages_attached(self) -> bool:
        """Return if the storages are attached."""
        return bool(self.model.storages.get("config")) and bool(
            self.model.storages.get("database")
        )

    ## Cluster Coordination ##
    def _sync_peer_relation_data(self) -> None:
        """Publish this unit's dqlite address and cluster state to the peer relation."""
        relation = self.model.get_relation(PEER_RELATION_NAME)
        if not relation:
            return
        relation.data[self.unit]["cluster_address"] = f"{self._cluster_bind_address}:{DQLITE_PORT}"
        relation.data[self.unit]["api_address"] = f"https://{socket.getfqdn()}:{self.port}"
        relation.data[self.unit]["has_cluster_state"] = (
            "true" if self._cluster_has_state() else "false"
        )

    def _cluster_exists_among_peers(self) -> bool:
        """Return whether any other unit reports existing dqlite cluster state."""
        relation = self.model.get_relation(PEER_RELATION_NAME)
        if not relation:
            return False
        return any(
            relation.data[unit].get("has_cluster_state") == "true" for unit in relation.units
        )

    def _cluster_prerequisites_met(self) -> bool:
        """Resume existing state, join with a token, or honor the bootstrap decision."""
        if self._cluster_join_pending():
            return self._get_join_token() is not None
        if self._cluster_has_state():
            return True
        if self._get_join_token() is not None:
            return True
        relation = self.model.get_relation(PEER_RELATION_NAME)
        if not relation:
            return False
        return (
            relation.data[self.app].get("bootstrap_unit") == self.unit.name
            and relation.data[self.app].get("cluster_established") != "true"
            and not self._cluster_exists_among_peers()
        )

    def _coordinate_bootstrap(self) -> None:
        """Persist bootstrap authorization once; never infer recovery from absent peers."""
        relation = self.model.get_relation(PEER_RELATION_NAME)
        if not self.unit.is_leader() or not relation:
            return
        data = relation.data[self.app]
        if self._cluster_has_state() or self._cluster_exists_among_peers():
            data["cluster_established"] = "true"
            return
        if data.get("bootstrap_unit") or data.get("cluster_established") == "true":
            return
        try:
            self.model.get_secret(label=NOTARY_LOGIN_SECRET_LABEL)
        except ops.SecretNotFoundError:
            data["bootstrap_unit"] = self.unit.name
        else:
            data["cluster_established"] = "true"

    def _get_join_token(self) -> str | None:
        """Return this unit's one-time cluster join token from the peer app secret."""
        record = self._read_join_tokens().get(self._cluster_member_name)
        return record.token if record else None

    def _reconcile_cluster_membership(self) -> None:
        """Mint join tokens for units that need one (leader only)."""
        if not self.unit.is_leader():
            return
        relation = self.model.get_relation(PEER_RELATION_NAME)
        if not relation:
            return
        for client in self._cluster_clients(relation):
            token = self._get_valid_admin_token(client)
            if not token:
                continue
            members = client.list_cluster_members(token)
            if not members:
                continue
            relation.data[self.app]["cluster_established"] = "true"
            self._reconcile_join_tokens(relation, members, token, client)
            return
        logger.warning("No reachable cluster member available for admission.")

    def _cluster_clients(self, relation: ops.Relation) -> Iterator[Notary]:
        """Use direct unit APIs, never ingress or the dqlite leader's identity."""
        if self._cluster_has_state():
            yield self.client
        for unit in sorted(relation.units, key=lambda unit: unit.name):
            if address := relation.data[unit].get("api_address"):
                yield Notary(address, self._ca_certificate_path)

    def _reconcile_join_tokens(
        self, relation: ops.Relation, members: list[ClusterMember], token: str, client: Notary
    ) -> None:
        """Mint or re-mint one-time join tokens for units that have not joined yet.

        A token is (re-)minted for every unit that is not in the cluster member
        list and whose token is missing or older than JOIN_TOKEN_REMINT_INTERVAL
        (tokens expire upstream and are spent by failed join attempts). Tokens
        of members that joined or units that left are pruned from the secret.
        """
        expected_names = {unit.name.replace("/", "-") for unit in relation.units}
        expected_names.add(self._cluster_member_name)
        members_by_name = {member.name: member for member in members if member.name}
        tokens = self._read_join_tokens()
        changed = False
        now = datetime.now(timezone.utc)
        for name in sorted(expected_names):
            if name in members_by_name:
                continue
            if (
                name == self._cluster_member_name
                and self._cluster_has_state()
                and not self._cluster_join_pending()
            ):
                continue
            existing = tokens.get(name)
            if existing and now - existing.minted_at < JOIN_TOKEN_REMINT_INTERVAL:
                continue
            response = client.create_cluster_join_token(name, token)
            if response and response.join_token:
                tokens[name] = JoinTokenRecord(token=response.join_token, minted_at=now)
                changed = True
                logger.info("Minted cluster join token for %s", name)
        for name in list(tokens):
            if name in members_by_name or name not in expected_names:
                tokens.pop(name)
                changed = True
        if changed:
            self._write_join_tokens(tokens)

    def _read_join_tokens(self) -> dict[str, JoinTokenRecord]:
        """Return the map of member name to join token record from the peer app secret."""
        try:
            secret = self.model.get_secret(label=CLUSTER_JOIN_SECRET_LABEL)
            raw = secret.get_content(refresh=True).get("tokens", "")
        except ops.SecretNotFoundError:
            return {}
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Cluster join token secret is malformed; ignoring its content.")
            return {}
        tokens = {}
        for name, entry in data.items():
            try:
                tokens[name] = JoinTokenRecord(
                    token=entry["token"],
                    minted_at=datetime.fromisoformat(entry["minted_at"]),
                )
            except (KeyError, TypeError, ValueError):
                logger.warning("Dropping malformed join token entry for %s", name)
        return tokens

    def _write_join_tokens(self, tokens: dict[str, JoinTokenRecord]) -> None:
        """Persist the join token map to the peer app secret and notify peer units."""
        content = json.dumps(
            {
                name: {"token": record.token, "minted_at": record.minted_at.isoformat()}
                for name, record in sorted(tokens.items())
            }
        )
        try:
            secret = self.model.get_secret(label=CLUSTER_JOIN_SECRET_LABEL)
            secret.set_content({"tokens": content})
        except ops.SecretNotFoundError:
            self.app.add_secret(
                label=CLUSTER_JOIN_SECRET_LABEL,
                content={"tokens": content},
            )
        self._bump_peer_data_version()

    def _bump_peer_data_version(self) -> None:
        """Bump a version key in the peer app databag.

        Writes to a peer relation's application databag trigger a
        relation-changed event on the other units, so units
        waiting for a join token or the self-signed CA re-run configure promptly
        instead of waiting for the next update-status.
        """
        if not self.unit.is_leader():
            return
        relation = self.model.get_relation(PEER_RELATION_NAME)
        if not relation:
            return
        relation.data[self.app][CLUSTER_DATA_VERSION_KEY] = str(
            datetime.now(timezone.utc).timestamp()
        )

    ## Helpers ##
    def _store_certificate_from_access_relation_if_available(self) -> None:
        """Write the assigned access certificate when it changes."""
        try:
            cert, pk = self.tls_access.get_assigned_certificate(
                certificate_request=self.access_csr
            )
        except (KeyError, TypeError, ValueError) as error:
            logger.info("Access certificate relation is not ready: %s", error)
            return
        if not cert or not pk or not cert.ca:
            logger.info("Access certificate relation is not fully available yet.")
            return
        try:
            saved_cert = self.container.pull(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem",
            ).read()
        except ops.pebble.PathError:
            saved_cert = None
        if str(cert.certificate) == saved_cert:
            return
        self._push_files_to_workload(cert.ca, cert.certificate, pk)

    def _get_or_create_self_signed_ca(self) -> tuple[Certificate, PrivateKey] | None:
        """Return the shared self-signed CA from the app secret, creating it on the leader if needed.

        Every unit signs its workload certificate with the same CA so that
        clients can trust any member of the cluster with a single CA
        certificate.
        """
        try:
            secret = self.model.get_secret(label=SELF_SIGNED_CA_SECRET_LABEL)
            content = secret.get_content(refresh=True)
            return (
                Certificate.from_string(content["ca-certificate"]),
                PrivateKey.from_string(content["ca-private-key"]),
            )
        except ops.SecretNotFoundError:
            if not self.unit.is_leader():
                logger.info("Waiting for the leader to generate the self-signed CA.")
                return None
            ca_private_key = generate_private_key()
            ca_certificate = generate_ca(
                private_key=ca_private_key,
                common_name=SELF_SIGNED_CA_COMMON_NAME,
                validity=timedelta(days=365),
            )
            self.app.add_secret(
                label=SELF_SIGNED_CA_SECRET_LABEL,
                content={
                    "ca-certificate": str(ca_certificate),
                    "ca-private-key": str(ca_private_key),
                },
            )
            logger.info("Generated self-signed CA and saved it to secrets.")
            self._bump_peer_data_version()
            return ca_certificate, ca_private_key

    def _generate_self_signed_certificates(
        self, ca_certificate: Certificate, ca_private_key: PrivateKey
    ) -> None:
        """Generate this unit's self signed certificate signed by the shared CA and push it to the workload."""
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name=CERTIFICATE_COMMON_NAME,
            sans_dns=self._generate_csr_sans_dns(),
        )
        certificate = generate_certificate(
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            csr=csr,
            validity=timedelta(days=365),
        )
        self._push_files_to_workload(ca_certificate, certificate, private_key)
        logger.info("Created self signed certificates.")

    def _self_signed_certificates_generated(self, ca_certificate: Certificate) -> bool:
        """Check if the workload certificate exists, matches the shared CA, and matches the current hostname."""
        try:
            existing_ca = self.container.pull(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/ca.pem"
            ).read()
            existing_cert = self.container.pull(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem"
            )
        except ops.pebble.PathError:
            return False
        if existing_ca.strip() != str(ca_certificate).strip():
            return False
        cert = Certificate.from_string(existing_cert.read())
        if cert.common_name != CERTIFICATE_COMMON_NAME:
            return False
        current_hostname = self._get_external_hostname_config()
        if current_hostname is None:
            return True
        return cert.sans_dns is not None and current_hostname in cert.sans_dns

    def _tls_access_relation_active(self) -> bool:
        """Check if the tls-access relation is created and active."""
        relation = self.model.get_relation(TLS_ACCESS_RELATION_NAME)
        if not relation:
            return False
        if not relation.active:
            return False
        return True

    def _certificates_available(self) -> bool:
        """Check if the workload certificate is available."""
        try:
            self.container.pull(f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem")
        except ops.pebble.PathError:
            return False
        return True

    def _get_or_create_admin_account(self, client: Notary | None = None) -> LoginSecret | None:
        """Get the first admin user for the charm to use from secrets. Create one if it doesn't exist.

        Only the leader may create the secret or the first user in Notary; other
        units get None while the credentials don't exist yet, and must never try
        to create the app secret themselves.

        Returns:
            Login details secret if they exist. None if the related account couldn't be created in Notary.
        """
        client = client if client is not None else self.client
        try:
            secret = self.model.get_secret(label=NOTARY_LOGIN_SECRET_LABEL)
            secret_content = secret.get_content(refresh=True)
            email = secret_content.get("email", "")
            password = secret_content.get("password", "")
            token = secret_content.get("token")
            account = LoginSecret(email, password, token)
        except ops.SecretNotFoundError:
            if not self.unit.is_leader():
                return None
            email = _generate_email()
            password = _generate_password()
            account = LoginSecret(email, password, None)
            self.app.add_secret(
                label=NOTARY_LOGIN_SECRET_LABEL,
                content=account.to_dict(),
            )
            logger.info("admin account details saved to secrets.")
        if not client.is_api_available() or client.is_initialized():
            return account
        if not self.unit.is_leader():
            return None
        response = client.create_first_user(email, password)
        if not response:
            return None
        return account

    def _push_files_to_workload(
        self,
        ca_certificate: Certificate | None,
        certificate: Certificate | None,
        private_key: PrivateKey | None,
    ) -> None:
        """Push all given files to workload."""
        if ca_certificate or certificate or private_key:
            self._stored.restart_required = True
        if ca_certificate:
            self.container.push(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/ca.pem",
                str(ca_certificate),
                make_dirs=True,
            )
        if certificate:
            self.container.push(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem",
                str(certificate),
                make_dirs=True,
            )
        if private_key:
            self.container.push(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/private_key.pem",
                str(private_key),
                make_dirs=True,
            )

    def _get_external_hostname_config(self) -> str | None:
        """Return the external hostname configuration, or socket fqdn if it was not set."""
        hostname = str(self.config.get("external-hostname", ""))
        if not is_valid_hostname(hostname):
            logger.warning(
                "The provided external hostname '%s' is not valid. Ignoring.",
                hostname,
            )
            return None
        return str(hostname)

    def _generate_csr_sans_dns(self) -> frozenset[str]:
        dns: list[str] = []
        if external_hostname := self._get_external_hostname_config():
            dns.append(external_hostname)
        if fqdn := socket.getfqdn():
            dns.append(fqdn)
        return frozenset(dns)


def _generate_password() -> str:
    """Generate a password for the Notary Account."""
    pw = []
    pw.append(random.choice(string.ascii_lowercase))
    pw.append(random.choice(string.ascii_uppercase))
    pw.append(random.choice(string.digits))
    pw.append(random.choice(["!", "@", "#", "$", "%", "^", "&", "*"]))
    for i in range(8):
        pw.append(random.choice(string.ascii_letters + string.digits + string.punctuation))
    random.shuffle(pw)
    return "".join(pw)


def _generate_email() -> str:
    """Generate a email for the Notary Account."""
    suffix = [random.choice(string.ascii_lowercase) for i in range(4)]
    return f"{'charm-' + ''.join(suffix)}@notary.com"


if __name__ == "__main__":  # pragma: nocover
    ops.main(NotaryCharm)  # type: ignore
