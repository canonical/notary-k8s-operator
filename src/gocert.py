# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for interacting with the GoCert application."""

import requests


class GoCertClientError(Exception):
    """Base class for exceptions raised by the GoCert client."""


class GoCert:
    """Class to interact with GoCert."""

    def __init__(self, url: str, ca_path: str) -> None:
        self.url = url
        self.ca_path = ca_path

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
