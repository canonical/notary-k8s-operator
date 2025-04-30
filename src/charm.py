#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
import random
import socket
import string
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta

import ops
import yaml
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer, charm_tracing_config
from charms.tls_certificates_interface.v4.tls_certificates import (
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
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer

from notary import Notary

logger = logging.getLogger(__name__)

CERTIFICATE_PROVIDER_RELATION_NAME = "certificates"

LOGGING_RELATION_NAME = "logging"
METRICS_RELATION_NAME = "metrics"
GRAFANA_RELATION_NAME = "grafana-dashboard"
TLS_ACCESS_RELATION_NAME = "access-certificates"

DB_MOUNT = "database"
CONFIG_MOUNT = "config"
CHARM_PATH = "/var/lib/juju/storage"
WORKLOAD_CONFIG_PATH = "/etc/notary"
WORKLOAD_DB_PATH = "/var/lib"

CERTIFICATE_COMMON_NAME = "Notary Self Signed Certificate"
SELF_SIGNED_CA_COMMON_NAME = "Notary Self Signed Root CA"
NOTARY_LOGIN_SECRET_LABEL = "Notary Login Details"
SEND_CA_CERT_RELATION_NAME = "send-ca-cert"


@dataclass
class LoginSecret:
    """The format of the secret for the login details that are required to login to Notary."""

    username: str
    password: str
    token: str | None

    def to_dict(self) -> dict[str, str]:
        """Return a dict version of the secret."""
        return {
            "username": self.username,
            "password": self.password,
            "token": self.token if self.token else "",
        }


@trace_charm(
    tracing_endpoint="_tracing_endpoint",
    server_cert="_tracing_server_cert",
    extra_types=(TLSCertificatesProvidesV4,),
)
class NotaryCharm(ops.CharmBase):
    """Charmed Notary."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self.port = 2111
        self.access_csr = CertificateRequestAttributes(
            common_name="Notary",
            sans_dns=frozenset([socket.getfqdn()]),
        )

        self.unit.set_ports(self.port)
        self.container = self.unit.get_container("notary")
        self.tls = TLSCertificatesProvidesV4(
            self, relationship_name=CERTIFICATE_PROVIDER_RELATION_NAME
        )
        self.tracing = TracingEndpointRequirer(self, protocols=["otlp_http"])
        self._tracing_endpoint, self._tracing_server_cert = charm_tracing_config(
            self.tracing, cert_path=None
        )
        self.certificate_transfer = CertificateTransferProvides(self, SEND_CA_CERT_RELATION_NAME)
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
            mode=Mode.APP,
            relationship_name=TLS_ACCESS_RELATION_NAME,
            certificate_requests=[self.access_csr],
        )

        self.client = Notary(
            f"https://{socket.getfqdn()}:{self.port}",
            f"{CHARM_PATH}/{CONFIG_MOUNT}/0/ca.pem",
        )
        [
            framework.observe(event, self.configure)
            for event in [
                self.on["notary"].pebble_ready,
                self.on["notary"].pebble_custom_notice,
                self.on["certificates"].relation_changed,
                self.on["certificates"].relation_departed,
                self.on["access-certificates"].relation_changed,
                self.on["access-certificates"].relation_departed,
                self.on[SEND_CA_CERT_RELATION_NAME].relation_joined,
                self.on.config_storage_attached,
                self.on.database_storage_attached,
                self.on.config_changed,
                self.on.update_status,
                self.on.start,
            ]
        ]
        framework.observe(self.on.collect_app_status, self._on_collect_status)
        framework.observe(self.on.collect_unit_status, self._on_collect_status)

    def configure(self, event: ops.EventBase):
        """Handle configuration events."""
        if not self.unit.is_leader():
            return
        if not self.container.can_connect():
            return
        self._configure_notary_config_file()
        self._configure_access_certificates()
        self._configure_charm_authorization()
        self._configure_certificate_requirers()
        self._send_ca_cert()
        self._configure_juju_workload_version()

    def _on_collect_status(self, event: ops.CollectStatusEvent):
        if not self.unit.is_leader():
            event.add_status(ops.WaitingStatus("multiple units not supported"))
            return
        if not self.container.can_connect():
            event.add_status(ops.WaitingStatus("container not yet connectable"))
            return
        if not self._storages_attached():
            event.add_status(ops.WaitingStatus("storages not yet available"))
            return
        if not self._certificates_available():
            event.add_status(ops.WaitingStatus("certificates not yet pushed to workload"))
            return
        if not self.client.is_api_available():
            event.add_status(ops.WaitingStatus("Notary server not yet available"))
            return
        if not self.client.is_initialized():
            event.add_status(ops.BlockedStatus("Please initialize Notary"))
            return
        event.add_status(ops.ActiveStatus())

    ## Configure Dependencies ##
    def _configure_notary_config_file(self):
        """Push the config file."""
        try:
            self.container.pull(f"{WORKLOAD_CONFIG_PATH}/config/config.yaml")
            logger.info("Config file already created.")
        except ops.pebble.PathError:
            self.container.make_dir(path=f"{WORKLOAD_CONFIG_PATH}/config", make_parents=True)
            self.container.push(
                path=f"{WORKLOAD_CONFIG_PATH}/config/config.yaml",
                source=yaml.dump(
                    data={
                        "key_path": f"{WORKLOAD_CONFIG_PATH}/config/private_key.pem",
                        "cert_path": f"{WORKLOAD_CONFIG_PATH}/config/certificate.pem",
                        "db_path": f"{WORKLOAD_DB_PATH}/notary/database/certs.db",
                        "port": self.port,
                        "pebble_notifications": True,
                        "logging": {
                            "system": {
                                "level": "debug",
                                "output": "stderr",
                            },
                        },
                    }
                ),
            )
            logger.info("Config file created.")

    def _configure_access_certificates(self):
        """Update the config files for notary and replan if required."""
        certificates_changed = False
        if not self.tls_access._tls_relation_created():
            if not self._self_signed_certificates_generated():
                certificates_changed = True
                self._generate_self_signed_certificates()
        else:
            certificates_changed = self._store_certificate_from_access_relation_if_available()
        if certificates_changed:
            logger.info("Certificates changed. Restarting service.")
            self.container.restart("notary")
        self.container.add_layer("notary", self._pebble_layer, combine=True)
        with suppress(ops.pebble.ChangeError):
            self.container.replan()

    def _configure_charm_authorization(self):
        """Create an admin user to manage Notary if needed, and acquire a token by logging in if needed."""
        login_details = self._get_or_create_admin_account()
        if not login_details:
            return
        if not login_details.token or not self.client.token_is_valid(login_details.token):
            login_response = self.client.login(login_details.username, login_details.password)
            if not login_response or not login_response.token:
                logger.warning(
                    "failed to login with the existing admin credentials."
                    " If you've manually modified the admin account credentials,"
                    " please update the charm's credentials secret accordingly."
                )
                return
            login_details.token = login_response.token
            login_details_secret = self.model.get_secret(label=NOTARY_LOGIN_SECRET_LABEL)
            login_details_secret.set_content(login_details.to_dict())

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
                for relation in self.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
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
                    "command": f"notary -config {WORKLOAD_CONFIG_PATH}/config/config.yaml",
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

    ## Helpers ##
    def _store_certificate_from_access_relation_if_available(self) -> bool:
        """Check if the requirer object has a certificate assigned. Save it to the workload if so.

        Returns:
            bool: True if a new certificate was saved.
        """
        cert, pk = self.tls_access.get_assigned_certificate(certificate_request=self.access_csr)
        if not cert or not pk:
            return False
        saved_cert = self.container.pull(
            f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem",
        ).read()
        if str(cert.certificate) == saved_cert:
            return False
        self._push_files_to_workload(cert.ca, cert.certificate, pk)
        return True

    def _generate_self_signed_certificates(self) -> None:
        """Generate self signed certificates and saves them to secrets and the charm."""
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=SELF_SIGNED_CA_COMMON_NAME,
            validity=timedelta(days=365),
        )
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name=CERTIFICATE_COMMON_NAME,
            sans_dns=frozenset([socket.getfqdn()]),
        )
        certificate = generate_certificate(
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            csr=csr,
            validity=timedelta(days=365),
        )
        self._push_files_to_workload(ca_certificate, certificate, private_key)
        logger.info("Created self signed certificates.")

    def _self_signed_certificates_generated(self) -> bool:
        """Check if the workload certificate was generated and was self signed."""
        try:
            existing_cert = self.container.pull(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem"
            )
        except ops.pebble.PathError:
            return False
        cert = Certificate.from_string(existing_cert.read())
        return cert.common_name == CERTIFICATE_COMMON_NAME

    def _certificates_available(self) -> bool:
        """Check if the workload certificate is available."""
        try:
            self.container.pull(f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem")
        except ops.pebble.PathError:
            return False
        return True

    def _get_or_create_admin_account(self) -> LoginSecret | None:
        """Get the first admin user for the charm to use from secrets. Create one if it doesn't exist.

        Returns:
            Login details secret if they exist. None if the related account couldn't be created in Notary.
        """
        try:
            secret = self.model.get_secret(label=NOTARY_LOGIN_SECRET_LABEL)
            secret_content = secret.get_content(refresh=True)
            username = secret_content.get("username", "")
            password = secret_content.get("password", "")
            token = secret_content.get("token")
            account = LoginSecret(username, password, token)
        except ops.SecretNotFoundError:
            username = _generate_username()
            password = _generate_password()
            account = LoginSecret(username, password, None)
            self.app.add_secret(
                label=NOTARY_LOGIN_SECRET_LABEL,
                content=account.to_dict(),
            )
            logger.info("admin account details saved to secrets.")
        if self.client.is_api_available() and not self.client.is_initialized():
            response = self.client.create_first_user(username, password)
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


def _generate_username() -> str:
    """Generate a username for the Notary Account."""
    suffix = [random.choice(string.ascii_lowercase) for i in range(4)]
    return "charm-" + "".join(suffix)


if __name__ == "__main__":  # pragma: nocover
    ops.main(NotaryCharm)  # type: ignore
