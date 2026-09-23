# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""S3 connection handling, following the Vault charm's S3 integration."""

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import urlsplit

from boto3.session import Session
from botocore.config import Config


@dataclass(frozen=True)
class S3Parameters:
    """Validated relation parameters; credentials are excluded from representations."""

    bucket: str
    endpoint: str
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    region: str = "us-east-1"
    path: str = ""
    ca_chain: tuple[str, ...] = ()

    @classmethod
    def from_relation(cls, data: Mapping[str, Any]) -> "S3Parameters":
        """Validate required fields and normalize the optional object prefix."""
        required = ("bucket", "endpoint", "access-key", "secret-key")
        missing = [
            key for key in required if not isinstance(data.get(key), str) or not data[key].strip()
        ]
        if missing:
            raise ValueError(f"S3 parameters missing ({', '.join(missing)})")
        endpoint = data["endpoint"].strip()
        parsed = urlsplit(endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("S3 endpoint must be an HTTP or HTTPS URL")
        path = data.get("path", "")
        region = data.get("region", "us-east-1")
        if not isinstance(path, str) or not isinstance(region, str):
            raise ValueError("S3 path and region must be strings")
        path = path.strip().strip("/")
        chain = data.get("tls-ca-chain", [])
        if not isinstance(chain, list) or any(
            not isinstance(cert, str) or not cert.strip() for cert in chain
        ):
            raise ValueError("S3 tls-ca-chain must be a list of PEM certificates")
        return cls(
            bucket=data["bucket"].strip(),
            endpoint=endpoint,
            access_key=data["access-key"].strip(),
            secret_key=data["secret-key"].strip(),
            region=region.strip() or "us-east-1",
            path=f"{path}/" if path else "",
            ca_chain=tuple(chain),
        )


@contextmanager
def s3_client(parameters: S3Parameters) -> Iterator[Any]:
    """Open an S3 client with bounded retries and a temporary custom CA bundle."""
    proxies = {
        scheme: value
        for scheme in ("http", "https")
        if (value := os.environ.get(f"JUJU_CHARM_{scheme.upper()}_PROXY"))
    }
    with NamedTemporaryFile(mode="w", suffix=".pem") as ca_file:
        verify: str | bool = True
        if parameters.ca_chain:
            ca_file.write("\n".join(parameters.ca_chain))
            ca_file.flush()
            verify = ca_file.name
        session = Session(
            aws_access_key_id=parameters.access_key,
            aws_secret_access_key=parameters.secret_key,
            region_name=parameters.region,
        )
        client = session.client(
            "s3",
            endpoint_url=parameters.endpoint,
            verify=verify,
            config=Config(
                connect_timeout=10,
                read_timeout=60,
                retries={"max_attempts": 2, "mode": "standard"},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                proxies=proxies or None,
            ),
        )
        try:
            yield client
        finally:
            client.close()
