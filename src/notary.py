# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for interacting with the Notary application."""

import logging
from dataclasses import dataclass
from typing import Literal

import requests

logger = logging.getLogger(__name__)


class NotaryClientError(Exception):
    """Base class for exceptions raised by the Notary client."""


@dataclass(frozen=True)
class CertificateRequest:
    """The certificate request that's stored in Notary."""

    id: int
    csr: str
    certificate_chain: list[str] | Literal["", "rejected"]


@dataclass
class CertificateRequests:
    """The table of certificate requests in Notary."""

    rows: list[CertificateRequest]


class Notary:
    """Class to interact with Notary."""

    API_VERSION = "v1"

    def __init__(self, url: str, ca_path: str | bool = False) -> None:
        """Initialize a client for interacting with Notary.

        Args:
            url: the endpoint that notary is listening on e.g https://notary.com:8000
            ca_path: the file path that contains the ca cert that notary uses for https communication
        """
        self.url = url
        self.ca_path = ca_path

    def login(self, username: str, password: str) -> str | None:
        """Login to notary by sending the username and password and return a Token."""
        try:
            req = requests.post(
                f"{self.url}/login",
                verify=self.ca_path,
                json={"username": username, "password": password},
            )
        except (requests.RequestException, OSError):
            return
        try:
            req.raise_for_status()
        except requests.HTTPError:
            logger.error("couldn't log in: code %s, %s", req.status_code, req.text)
            return
        logger.info("logged in to Notary successfully")
        return req.text

    def token_is_valid(self, token: str) -> bool:
        """Return if the token is still valid by attempting to connect to an endpoint."""
        try:
            req = requests.get(
                f"{self.url}/api/{self.API_VERSION}/accounts/me",
                verify=self.ca_path,
                headers={"Authorization": f"Bearer {token}"},
            )
            req.raise_for_status()
        except (requests.RequestException, OSError):
            return False
        return True

    def is_api_available(self) -> bool:
        """Return if the Notary server is reachable."""
        try:
            req = requests.get(
                f"{self.url}/status",
                verify=self.ca_path,
            )
            req.raise_for_status()
        except (requests.RequestException, OSError):
            return False
        return True

    def is_initialized(self) -> bool:
        """Return if the Notary server is initialized."""
        try:
            req = requests.get(
                f"{self.url}/status",
                verify=self.ca_path,
            )
            req.raise_for_status()
        except (requests.RequestException, OSError):
            return False
        body = req.json()
        return body.get("initialized", False)

    def create_first_user(self, username: str, password: str) -> int | None:
        """Create the first admin user.

        Args:
            username: username of the first user
            password: password for the first user. It must be longer than 7 characters, have at least one lowercase,
                one uppercase and one number or special character.

        Returns:
            int | None: the id of the created user, or None if the request failed

        """
        try:
            req = requests.post(
                f"{self.url}/api/{self.API_VERSION}/accounts",
                verify=self.ca_path,
                json={"username": username, "password": password},
            )
        except (requests.RequestException, OSError):
            return None
        try:
            req.raise_for_status()
        except requests.HTTPError:
            logger.error("couldn't create first user: code %s, %s", req.status_code, req.text)
            return None
        logger.info("created the first user in Notary.")
        id = req.json().get("id")
        return int(id) if id else None

    def get_certificate_requests_table(self, token: str) -> CertificateRequests | None:
        """Get all certificate requests table from Notary.

        Returns:
            None if the request fails to go through. The table itself, otherwise.
        """
        try:
            res = requests.get(
                f"{self.url}/api/{self.API_VERSION}/certificate_requests",
                verify=self.ca_path,
                headers={"Authorization": f"Bearer {token}"},
            )
            res.raise_for_status()
        except requests.RequestException as e:
            logger.error(
                "couldn't retrieve certificate requests table: code %s, %s",
                e.response.status_code if e.response else "unknown",
                e.response.text if e.response else "unknown",
            )
            return None
        except OSError:
            logger.error("error occurred during HTTP request: TLS file invalid")
            return None
        table = res.json()
        return CertificateRequests(
            rows=[
                CertificateRequest(
                    row.get("id"),
                    row.get("csr"),
                    serialize(row.get("certificate")),
                )
                for row in table
            ]
            if table
            else []
        )

    def post_csr(self, csr: str, token: str) -> None:
        """Post a new CSR to Notary."""
        try:
            res = requests.post(
                f"{self.url}/api/{self.API_VERSION}/certificate_requests",
                verify=self.ca_path,
                headers={"Authorization": f"Bearer {token}"},
                data=csr,
            )
            res.raise_for_status()
        except requests.RequestException as e:
            logger.error(
                "couldn't post new certificate requests: code %s, %s",
                e.response.status_code if e.response else "unknown",
                e.response.text if e.response else "unknown",
            )
        except OSError:
            logger.error("error occurred during HTTP request: TLS file invalid")

    def post_certificate(self, csr: str, cert_chain: list[str], token: str) -> None:
        """Post a certificate chain to an associated csr to Notary."""
        try:
            table = self.get_certificate_requests_table(token)
            if not table:
                return
            csr_ids = list(filter(lambda x: x.csr == csr, table.rows))
            if len(csr_ids) != 1:
                logger.error("given CSR not found in Notary")
                return
            res = requests.post(
                f"{self.url}/api/{self.API_VERSION}/certificate_requests/{csr_ids[0].id}/certificate",
                verify=self.ca_path,
                headers={"Authorization": f"Bearer {token}"},
                data="\n".join(cert_chain),
            )
            res.raise_for_status()
        except requests.RequestException as e:
            logger.error(
                "couldn't post new certificate: code %s, %s",
                e.response.status_code if e.response else "unknown",
                e.response.text if e.response else "unknown",
            )
        except OSError:
            logger.error("error occurred during HTTP request: TLS file invalid")


def serialize(pem_string: str) -> list[str] | Literal["", "rejected"]:
    """Process the certificate entry coming from Notary.

    Returns:
        a list of pem strings, an empty string or a rejected string.
    """
    if pem_string != "" and pem_string != "rejected":
        return [
            cert.strip() + "-----END CERTIFICATE-----"
            for cert in pem_string.split("-----END CERTIFICATE-----")
            if cert.strip()
        ]
    return pem_string
