# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for interacting with the Notary application."""

import json
import logging
from dataclasses import asdict, dataclass
from typing import List, Literal, Optional

import requests

logger = logging.getLogger(__name__)


class NotaryClientError(Exception):
    """Base class for exceptions raised by the Notary client."""


@dataclass
class Response:
    """Response from Notary."""

    result: any  # type: ignore[reportGeneralTypeIssues]
    error: str


@dataclass
class StatusResponse:
    """Response from Notary when checking the status."""

    initialized: bool
    version: str


@dataclass
class LoginParams:
    """Parameters to login to Notary."""

    username: str
    password: str


@dataclass
class LoginResponse:
    """Response from Notary when logging in."""

    token: str


@dataclass
class CreateUserParams:
    """Parameters to create a user in Notary."""

    username: str
    password: str


@dataclass
class CreateUserResponse:
    """Response from Notary when creating a user."""

    id: int


@dataclass
class CreateCertificateRequestParams:
    """Parameters to create a certificate request in Notary."""

    csr: str


@dataclass
class CreateCertificateRequestResponse:
    """Response from Notary when creating a certificate request."""

    id: int


@dataclass
class DeleteCertificateRequestResponse:
    """Response from Notary when deleting a certificate request."""

    id: int


@dataclass
class CreateCertificateParams:
    """Parameters to create a certificate in Notary."""

    certificate: str


@dataclass
class CreateCertificateResponse:
    """Response from Notary when creating a certificate."""

    id: int


@dataclass(frozen=True)
class CertificateRequest:
    """The certificate request that's stored in Notary."""

    id: int
    csr: str
    certificate_chain: list[str] | Literal["", "rejected"]


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

    def _make_request(
        self,
        method: str,
        endpoint: str,
        token: Optional[str] = None,
        data: any = None,  # type: ignore[reportGeneralTypeIssues]
    ) -> Response | None:
        """Make an HTTP request and handle common error patterns."""
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        url = f"{self.url}{endpoint}"
        try:
            req = requests.request(
                method=method,
                url=url,
                verify=self.ca_path,
                headers=headers,
                json=data,
            )
        except requests.RequestException as e:
            logger.error("HTTP request failed: %s", e)
            return None
        except OSError as e:
            logger.error("couldn't complete HTTP request: %s", e)
            return None

        response = self._get_result(req)
        try:
            req.raise_for_status()
        except requests.HTTPError:
            logger.error(
                "Request failed: code %s, %s",
                req.status_code,
                response.error if response else "unknown",
            )
            return None
        return response

    def _get_result(self, req: requests.Response) -> Response | None:
        """Return the response from a request."""
        try:
            response = req.json()
        except json.JSONDecodeError:
            return None
        return Response(
            result=response.get("result"),
            error=response.get("error"),
        )

    def is_initialized(self) -> bool:
        """Return if the Notary server is initialized."""
        status = self.get_status()
        return status.initialized if status else False

    def is_api_available(self) -> bool:
        """Return if the Notary server is reachable."""
        status = self.get_status()
        return status is not None

    def login(self, username: str, password: str) -> LoginResponse | None:
        """Login to notary by sending the username and password and return a Token."""
        login_params = LoginParams(username=username, password=password)
        response = self._make_request("POST", "/login", data=asdict(login_params))
        if response and response.result:
            return LoginResponse(
                token=response.result.get("token"),
            )
        return None

    def token_is_valid(self, token: str) -> bool:
        """Return if the token is still valid by attempting to connect to an endpoint."""
        response = self._make_request("GET", f"/api/{self.API_VERSION}/accounts/me", token=token)
        return response is not None

    def get_status(self) -> StatusResponse | None:
        """Return if the Notary server is initialized."""
        response = self._make_request("GET", "/status")
        if response and response.result:
            return StatusResponse(
                initialized=response.result.get("initialized"),
                version=response.result.get("version"),
            )
        return None

    def create_first_user(self, username: str, password: str) -> CreateUserResponse | None:
        """Create the first admin user."""
        create_user_params = CreateUserParams(username=username, password=password)
        response = self._make_request(
            "POST", f"/api/{self.API_VERSION}/accounts", data=asdict(create_user_params)
        )
        if response and response.result:
            return CreateUserResponse(
                id=response.result.get("id"),
            )
        return None

    def list_certificate_requests(self, token: str) -> List[CertificateRequest]:
        """Get all certificate requests from Notary."""
        response = self._make_request(
            "GET", f"/api/{self.API_VERSION}/certificate_requests", token=token
        )
        if response and response.result:
            return [
                CertificateRequest(
                    id=cert.get("id"),
                    csr=cert.get("csr"),
                    certificate_chain=serialize(cert.get("certificate")),
                )
                for cert in response.result
            ]
        return []

    def create_certificate_request(
        self, csr: str, token: str
    ) -> CreateCertificateRequestResponse | None:
        """Create a new certificate request in Notary."""
        create_certificate_request_params = CreateCertificateRequestParams(csr=csr)
        response = self._make_request(
            "POST",
            f"/api/{self.API_VERSION}/certificate_requests",
            token=token,
            data=asdict(create_certificate_request_params),
        )
        if response and response.result:
            return CreateCertificateRequestResponse(
                id=response.result.get("id"),
            )
        return None

    def create_certificate_from_csr(
        self, csr: str, cert_chain: list[str], token: str
    ) -> CreateCertificateResponse | None:
        """Create a certificate from a CSR in Notary."""
        certificate_requests = self.list_certificate_requests(token=token)
        if not certificate_requests:
            logger.error("couldn't list certificate requests")
            return None
        csr_ids = [cert for cert in certificate_requests if cert.csr == csr]
        if len(csr_ids) != 1:
            logger.error("given CSR not found in Notary")
            return None
        create_certificate_params = CreateCertificateParams(certificate="\n".join(cert_chain))
        response = self._make_request(
            "POST",
            f"/api/{self.API_VERSION}/certificate_requests/{csr_ids[0].id}/certificate",
            token=token,
            data=asdict(create_certificate_params),
        )
        if response and response.result:
            return CreateCertificateResponse(
                id=response.result.get("id"),
            )
        return None


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
