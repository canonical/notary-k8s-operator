# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for interacting with the GoCert application."""

import logging

import requests

logger = logging.getLogger(__name__)


class GoCertClientError(Exception):
    """Base class for exceptions raised by the GoCert client."""


class GoCert:
    """Class to interact with GoCert."""

    API_VERSION = "v1"

    def __init__(self, url: str, ca_path: str) -> None:
        """Initialize a client for interacting with GoCert.

        Args:
            url: the endpoint that gocert is listening on e.g https://gocert.com:8000
            ca_path: the file path that contains the ca cert that gocert uses for https communication
        """
        self.url = url
        self.ca_path = ca_path

    def login(self, username: str, password: str) -> str | None:
        """Login to gocert by sending the username and password and return a Token."""
        try:
            req = requests.post(
                f"{self.url}/login",
                verify=self.ca_path if self.ca_path else None,
                json={"username": username, "password": password},
            )
        except (requests.RequestException, OSError):
            return
        if req.status_code != 200:
            logger.error("couldn't log in: code %s, %s", req.status_code, req.text)
            return
        body = req.text
        if body != "":
            logger.info("logged in to GoCert successfully")
            return body
        return None

    def token_is_valid(self, token: str) -> bool:
        """Return if the token is still valid by attempting to connect to an endpoint."""
        try:
            req = requests.get(
                f"{self.url}/accounts",
                verify=self.ca_path if self.ca_path else None,
                headers={"Authorization": f"Bearer {token}"},
            )
        except (requests.RequestException, OSError):
            return False
        if req.status_code == 401:
            return False
        return True

    def is_api_available(self) -> bool:
        """Return if the GoCert server is reachable."""
        try:
            req = requests.get(
                f"{self.url}/status",
                verify=self.ca_path if self.ca_path else None,
            )
        except (requests.RequestException, OSError):
            return False
        if req.status_code != 200:
            return False
        return True

    def is_initialized(self) -> bool:
        """Return if the GoCert server is initialized."""
        try:
            req = requests.get(
                f"{self.url}/status",
                verify=self.ca_path if self.ca_path else None,
            )
        except (requests.RequestException, OSError):
            return False
        if req.status_code != 200:
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
                verify=self.ca_path if self.ca_path else None,
                json={"username": username, "password": password},
            )
        except (requests.RequestException, OSError):
            return None
        if req.status_code != 201:
            logger.warning("couldn't create first user: code %s, %s", req.status_code, req.text)
            return None
        logger.info("created the first user in GoCert.")
        id = req.json().get("id")
        return int(id) if id else None
