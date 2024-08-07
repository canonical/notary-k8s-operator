#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
import random
import string
from contextlib import suppress
from dataclasses import dataclass
from typing import Tuple

import ops
from charms.tls_certificates_interface.v3.tls_certificates import (
    TLSCertificatesProvidesV3,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
    x509,
)
from gocert import GoCert

logger = logging.getLogger(__name__)

DB_MOUNT = "database"
CONFIG_MOUNT = "config"
CHARM_PATH = "/var/lib/juju/storage"
WORKLOAD_CONFIG_PATH = "/etc/gocert"

SELF_SIGNED_CA_COMMON_NAME = "GoCert Self Signed Root CA"
SELF_SIGNED_CA_SECRET_LABEL = "Self Signed Root CA"
GOCERT_LOGIN_SECRET_LABEL = "GoCert Login Details"


@dataclass
class CertificateSecret:
    """The format of the secret for the certificate that will be used for https connections to GoCert."""

    certificate: str
    private_key: str

    def to_dict(self) -> dict[str, str]:
        """Return a dict version of the secret."""
        return {"certificate": self.certificate, "private-key": self.private_key}


@dataclass
class LoginSecret:
    """The format of the secret for the login details that are required to login to GoCert."""

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


class GocertCharm(ops.CharmBase):
    """Charmed Gocert."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        self.port = 2111

        self.container = self.unit.get_container("gocert")
        self.tls = TLSCertificatesProvidesV3(self, relationship_name="certificates")
        self.client = GoCert(
            f"https://{self._application_bind_address}:{self.port}",
            f"{CHARM_PATH}/{CONFIG_MOUNT}/0/ca.pem",
        )

        [
            framework.observe(event, self.configure)
            for event in [
                self.on["gocert"].pebble_ready,
                self.on["gocert"].pebble_custom_notice,
                self.tls.on.certificate_creation_request,
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
        self._configure_gocert_config_file()
        self._configure_access_certificates()
        self._configure_charm_authorization()

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
        if not self._self_signed_certificates_generated():
            event.add_status(ops.WaitingStatus("certificates not yet created"))
            return
        if not self.client.is_api_available():
            event.add_status(ops.WaitingStatus("GoCert server not yet available"))
            return
        if not self.client.is_initialized():
            event.add_status(ops.BlockedStatus("Please initialize GoCert"))
            return
        event.add_status(ops.ActiveStatus())

    ## Configure Dependencies ##
    def _configure_gocert_config_file(self):
        """Push the config file."""
        try:
            self.container.pull(f"{WORKLOAD_CONFIG_PATH}/config/config.yaml")
            logger.info("Config file already created.")
        except ops.pebble.PathError:
            config_file = open("src/config/config.yaml").read()
            self.container.make_dir(path=f"{WORKLOAD_CONFIG_PATH}/config", make_parents=True)
            self.container.push(
                path=f"{WORKLOAD_CONFIG_PATH}/config/config.yaml", source=config_file
            )
            logger.info("Config file created.")

    def _configure_access_certificates(self):
        """Update the config files for gocert and replan if required."""
        certificates_changed = False
        if not self._self_signed_certificates_generated():
            certificates_changed = True
            self._generate_self_signed_certificates()
        logger.info("Certificates configured.")
        if certificates_changed:
            self.container.add_layer("gocert", self._pebble_layer, combine=True)
            with suppress(ops.pebble.ChangeError):
                self.container.replan()

    def _configure_charm_authorization(self):
        """Create an admin user to manage GoCert if needed, and acquire a token by logging in if needed."""
        login_details = self._get_or_create_admin_account()
        if not login_details:
            return
        if not login_details.token or not self.client.token_is_valid(login_details.token):
            login_details.token = self.client.login(login_details.username, login_details.password)
            login_details_secret = self.model.get_secret(label=GOCERT_LOGIN_SECRET_LABEL)
            login_details_secret.set_content(login_details.to_dict())

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
                    "command": f"gocert -config {WORKLOAD_CONFIG_PATH}/config/config.yaml",
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
        return bool(self.model.storages.get("config")) and bool(
            self.model.storages.get("database")
        )

    ## Helpers ##
    def _generate_self_signed_certificates(self) -> None:
        """Generate self signed certificates and saves them to secrets and the charm."""
        if not self._application_bind_address:
            logger.warning("unit IP not found.")
            return
        ca, ca_pk = self._get_or_create_ca_certificate()
        pk = generate_private_key()
        csr = generate_csr(
            private_key=pk,
            subject="GoCert Self Signed Certificate",
            sans_ip=[self._application_bind_address],
        )
        cert = generate_certificate(csr=csr, ca=ca, ca_key=ca_pk)

        self.container.push(f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/ca.pem", ca, make_dirs=True)
        self.container.push(
            f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem", cert, make_dirs=True
        )
        self.container.push(
            f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/private_key.pem", pk, make_dirs=True
        )
        logger.info("Created self signed certificates.")

    def _self_signed_certificates_generated(self) -> bool:
        """Check if the workload certificate was generated and was self signed."""
        try:
            existing_cert = self.container.pull(
                f"{WORKLOAD_CONFIG_PATH}/{CONFIG_MOUNT}/certificate.pem"
            )
        except ops.pebble.PathError:
            return False
        try:
            certificate = x509.load_pem_x509_certificate(existing_cert.read().encode())
            common_name = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        except (ValueError, TypeError):
            return False
        if common_name.value != SELF_SIGNED_CA_COMMON_NAME:
            return False
        return True

    def _get_or_create_ca_certificate(self) -> Tuple[bytes, bytes]:
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

    def _get_or_create_admin_account(self) -> LoginSecret | None:
        """Get the first admin user for the charm to use from secrets. Create one if it doesn't exist.

        Returns:
            Login details secret if they exist. None if the related account couldn't be created in GoCert.
        """
        try:
            secret = self.model.get_secret(label=GOCERT_LOGIN_SECRET_LABEL)
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
                label=GOCERT_LOGIN_SECRET_LABEL,
                content=account.to_dict(),
            )
            logger.info("admin account details saved to secrets.")
        if self.client.is_api_available() and not self.client.is_initialized():
            response = self.client.create_first_user(username, password)
            if not response:
                return None
        return account


def _generate_password() -> str:
    """Generate a password for the GoCert Account."""
    pw = []
    pw.append(random.choice(string.ascii_lowercase))
    pw.append(random.choice(string.ascii_uppercase))
    pw.append(random.choice(string.digits))
    pw.append(random.choice(string.punctuation))
    for i in range(8):
        pw.append(random.choice(string.ascii_letters + string.digits + string.punctuation))
    random.shuffle(pw)
    return "".join(pw)


def _generate_username() -> str:
    """Generate a username for the GoCert Account."""
    suffix = [random.choice(string.ascii_uppercase) for i in range(4)]
    return "charm-admin-" + "".join(suffix)


if __name__ == "__main__":  # pragma: nocover
    ops.main(GocertCharm)  # type: ignore
