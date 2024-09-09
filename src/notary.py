# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for interacting with the Notary application."""

import logging

import requests

logger = logging.getLogger(__name__)


class NotaryClientError(Exception):
    """Base class for exceptions raised by the Notary client."""


class Notary:
    """Class to interact with Notary."""

    API_VERSION = "v1"

    def __init__(self, url: str, ca_path: str) -> None:
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
                verify=self.ca_path if self.ca_path else None,
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
                f"{self.url}/accounts",
                verify=self.ca_path if self.ca_path else None,
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
                verify=self.ca_path if self.ca_path else None,
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
                verify=self.ca_path if self.ca_path else None,
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
                verify=self.ca_path if self.ca_path else None,
                json={"username": username, "password": password},
            )
        except (requests.RequestException, OSError):
            return None
        try:
            req.raise_for_status()
        except requests.HTTPError:
            logger.warning("couldn't create first user: code %s, %s", req.status_code, req.text)
            return None
        logger.info("created the first user in Notary.")
        id = req.json().get("id")
        return int(id) if id else None
