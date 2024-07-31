#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
from dataclasses import dataclass
from typing import Tuple

import ops
import requests
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV3,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
    x509,
)

logger = logging.getLogger(__name__)

DB_MOUNT = "database"
CONFIG_MOUNT = "config"
CHARM_PATH = "/var/lib/juju/storage"
WORKLOAD_PATH = "/etc"

SELF_SIGNED_CA_COMMON_NAME = "GoCert Self Signed Root CA"
SELF_SIGNED_CA_SECRET_LABEL = "Self Signed Root CA"


@dataclass
class CertificateSecret:
    """The format of the secret for the certificate that will be used for https connections to GoCert."""

    certificate: str
    private_key: str

    def to_dict(self) -> dict[str, str]:
        """Return a dict version of the secret."""
        return {"certificate": self.certificate, "private-key": self.private_key}


class GocertCharm(ops.CharmBase):
    """Charmed Gocert."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        self.container = self.unit.get_container("gocert")
        self.tls = TLSCertificatesProvidesV3(self, relationship_name="certificates")

        self.port = 2111

        framework.observe(self.on["gocert"].pebble_custom_notice, self._on_gocert_notify)
        framework.observe(self.tls.on.certificate_creation_request, self._on_new_certificate)

        framework.observe(self.on.collect_unit_status, self._on_collect_status)

        [
            framework.observe(event, self.configure)
            for event in [
                self.on["gocert"].pebble_ready,
                self.on.config_storage_attached,
                self.on.database_storage_attached,
                self.on.update_status,
                self.on.start,
            ]
        ]

    def configure(self, event: ops.EventBase):
        """Handle configuration events."""
        self._configure_gocert_config_file()
        self._configure_access_certificates()
        self.container.add_layer("gocert", self._pebble_layer, combine=True)
        try:
            self.container.replan()
        except ops.pebble.ChangeError:
            pass

    def _on_collect_status(self, event: ops.CollectStatusEvent):
        if not self.container.can_connect():
            event.add_status(ops.BlockedStatus("container not yet connectable"))
        if not self._storages_attached():
            event.add_status(ops.BlockedStatus("storages not yet available"))
        if not self._self_signed_certificates_generated():
            event.add_status(ops.BlockedStatus("access certificates not yet created"))
        if not self._gocert_available():
            event.add_status(ops.BlockedStatus("GoCert server not yet available"))
        if not self._gocert_initialized():
            event.add_status(ops.WaitingStatus("GoCert initialization required"))
        event.add_status(ops.ActiveStatus())

    def _on_new_certificate(self, event: CertificateCreationRequestEvent):
        csr = event.certificate_signing_request
        requests.post(
            url=f"https://{self._application_bind_address}:{self.port}/api/v1/certificate_requests",
            data=csr,
            headers={"Content-Type": "text/plain"},
            verify=f"{CHARM_PATH}/{CONFIG_MOUNT}/0/ca.pem",
        )

    def _on_gocert_notify(self, event: ops.PebbleCustomNoticeEvent):
        r = requests.get(
            url=f"https://{self._application_bind_address}:{self.port}/api/v1/certificate_requests",
            verify=f"{CHARM_PATH}/{CONFIG_MOUNT}/0/ca.pem",
        )
        response_data = r.json()
        for relation in self.model.relations["certificates"]:
            unfulfilled_csrs = self.tls.get_outstanding_certificate_requests(
                relation_id=relation.id
            )
            for row in response_data:
                csr = row.get("CSR")
                cert = row.get("Certificate")
                for relation_csr in unfulfilled_csrs:
                    if csr == relation_csr.csr:
                        self.tls.set_relation_certificate(
                            certificate_signing_request=csr,
                            certificate=cert,
                            ca="",
                            chain=[cert],
                            relation_id=relation.id,
                        )

    ## Configure Dependencies ##
    def _configure_gocert_config_file(self):
        """Push the config file."""
        logger.info("[GoCert] Configuring the config file.")
        try:
            self.container.pull("/etc/config/config.yaml")
            logger.info("[GoCert] Config file already created.")
        except ops.pebble.PathError:
            config_file = open("src/config/config.yaml").read()
            self.container.make_dir(path="/etc/config", make_parents=True)
            self.container.push(path="/etc/config/config.yaml", source=config_file)
            logger.info("[GoCert] Config file created.")

    def _configure_access_certificates(self):
        """Update the config files for gocert and replan if required."""
        logger.info("[GoCert] Configuring certificates.")
        if not self._self_signed_certificates_generated():
            self._generate_self_signed_certificates()
        logger.info("[GoCert] Certificates configured.")

    ## Properties ##
    @property
    def _pebble_layer(self) -> ops.pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "gocert layer",
            "description": "pebble config layer for gocert",
            "services": {
                "gocert": {
                    "override": "replace",
                    "summary": "gocert",
                    "command": "gocert -config /etc/config/config.yaml",
                    "startup": "enabled",
                }
            },
        }

    @property
    def _application_bind_address(self) -> str | None:
        binding = self.model.get_binding("juju-info")
        if not binding:
            return None
        if not binding.network:
            return None
        if not binding.network.bind_address:
            return None
        return str(binding.network.bind_address)

    ## Status Checks ##
    def _storages_attached(self) -> bool:
        """Return if the storages are attached."""
        return self.container.exists("/etc/config") and self.container.exists("/etc/database")

    def _gocert_available(self) -> bool:
        """Return if the gocert server is reachable."""
        try:
            req = requests.get(
                f"https://{self._application_bind_address}:{self.port}/status",
                verify=f"{CHARM_PATH}/{CONFIG_MOUNT}/0/ca.pem",
            )
        except (requests.RequestException, OSError) as e:
            logger.warning(e)
            return False
        if req.status_code != 200:
            return False
        return True

    def _gocert_initialized(self) -> bool:
        """Return if gocert is initialized."""
        try:
            req = requests.get(
                f"https://{self._application_bind_address}:{self.port}/status",
                verify=f"{CHARM_PATH}/{CONFIG_MOUNT}/0/ca.pem",
            )
        except (requests.RequestException, OSError) as e:
            logger.warning(e)
            return False
        if req.status_code != 200:
            return False
        body = req.json()
        return body["initialized"]

    ## Helpers ##
    def _generate_self_signed_certificates(self) -> None:
        """Generate self signed certificates and saves them to secrets and the charm."""
        logger.info("[GoCert] Creating self signed certificates.")
        if not self._application_bind_address:
            logger.warning("[GoCert] unit IP not found.")
            return
        ca, ca_pk = self._get_ca_certificate()
        pk = generate_private_key()
        csr = generate_csr(
            private_key=pk,
            subject="GoCert Self Signed Certificate",
            sans_ip=[self._application_bind_address],
        )
        cert = generate_certificate(csr=csr, ca=ca, ca_key=ca_pk)

        self.container.push(f"{WORKLOAD_PATH}/{CONFIG_MOUNT}/ca.pem", ca, make_dirs=True)
        self.container.push(f"{WORKLOAD_PATH}/{CONFIG_MOUNT}/certificate.pem", cert, make_dirs=True)
        self.container.push(f"{WORKLOAD_PATH}/{CONFIG_MOUNT}/private_key.pem", pk, make_dirs=True)

        logger.info("[GoCert] Created self signed certificates.")

    def _self_signed_certificates_generated(self) -> bool:
        """Check if the workload certificate was generated and was self signed."""
        try:
            existing_cert = self.container.pull(f"{WORKLOAD_PATH}/{CONFIG_MOUNT}/certificate.pem")
        except ops.pebble.PathError:
            return False
        try:
            certificate = x509.load_pem_x509_certificate(existing_cert.read().encode())
            common_name = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        except (ValueError, TypeError):
            return False
        if common_name.value != SELF_SIGNED_CA_COMMON_NAME:
            logger.warning(common_name.value)
            logger.warning(SELF_SIGNED_CA_COMMON_NAME)
            return False
        return True

    def _get_ca_certificate(self) -> Tuple[bytes, bytes]:
        """Get the CA certificate from secrets. Create one if it doesn't exist."""
        try:
            secret = self.model.get_secret(label=SELF_SIGNED_CA_SECRET_LABEL)
            secret_content = secret.get_content(refresh=True)
            ca_cert = secret_content.get("certificate", "")
            ca_pk = secret_content.get("private-key", "")
            content = CertificateSecret(
                certificate=ca_cert,
                private_key=ca_pk,
            )
        except ops.SecretNotFoundError:
            pk = generate_private_key()
            ca = generate_ca(private_key=pk, subject=SELF_SIGNED_CA_COMMON_NAME)
            content = CertificateSecret(certificate=ca.decode(), private_key=pk.decode())
            self.app.add_secret(label=SELF_SIGNED_CA_SECRET_LABEL, content=content.to_dict())
        return content.certificate.encode(), content.private_key.encode()


if __name__ == "__main__":  # pragma: nocover
    ops.main(GocertCharm)  # type: ignore
