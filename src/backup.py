# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cold Notary backups stored in S3, with explicit unit identity metadata."""

import hashlib
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import PurePosixPath
from tempfile import TemporaryFile
from typing import Any, BinaryIO
from uuid import uuid4

import ops
from botocore.exceptions import ClientError

from s3 import S3Parameters, s3_client

DATABASE_PATH = "/var/lib/notary/database/dqlite"
STAGING_ROOT = "/var/lib/notary/database"
BACKUP_PREFIX = "notary-backup-"


class BackupError(Exception):
    """A backup operation could not be completed safely."""


class BackupManager:
    """Manage the workload lifecycle and transfer physical database archives."""

    def __init__(
        self, container: ops.Container, parameters: S3Parameters, identity: dict[str, str]
    ):
        self.container = container
        self.parameters = parameters
        self.identity = identity

    @contextmanager
    def _staging_directory(self) -> Iterator[str]:
        """Allocate private temporary workload storage outside the database."""
        path = f"{STAGING_ROOT}/.backup-{uuid4().hex}"
        self.container.make_dir(path, permissions=0o700, make_parents=True)
        try:
            yield path
        finally:
            self.container.remove_path(path, recursive=True)

    @contextmanager
    def _stopped_service(self) -> Iterator[None]:
        """Stop Notary and restore its previous running state even after failure."""
        was_running = self.container.get_service("notary").is_running()
        if was_running:
            self.container.stop("notary")
        try:
            yield
        finally:
            if was_running:
                self.container.start("notary")

    def _ensure_bucket(self, client: Any) -> None:
        """Create a missing bucket without treating access or network errors as absence."""
        try:
            client.head_bucket(Bucket=self.parameters.bucket)
            return
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in (
                "404",
                "NoSuchBucket",
                "NotFound",
            ):
                raise
        configuration = {}
        if self.parameters.region != "us-east-1":
            configuration["CreateBucketConfiguration"] = {
                "LocationConstraint": self.parameters.region
            }
        try:
            client.create_bucket(Bucket=self.parameters.bucket, **configuration)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "BucketAlreadyOwnedByYou":
                raise
        client.get_waiter("bucket_exists").wait(
            Bucket=self.parameters.bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 15}
        )

    def create_backup(self) -> str:
        """Create a cold archive and upload it after bringing Notary back online."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        key = f"{self.parameters.path}{BACKUP_PREFIX}{timestamp}-{uuid4().hex}.tar.gz"
        with s3_client(self.parameters) as client:
            # Fail before interrupting service if the bucket is inaccessible.
            self._ensure_bucket(client)
            with self._staging_directory() as directory:
                with self._stopped_service():
                    self.container.exec(
                        ["notary", "backup", "--db-path", DATABASE_PATH, "--file", directory],
                        timeout=600,
                    ).wait_output()
                archives = [
                    info.path
                    for info in self.container.list_files(directory)
                    if info.type == "file"
                    and info.name.endswith(".tar.gz")
                    and str(PurePosixPath(info.path).parent) == directory
                ]
                if len(archives) != 1:
                    raise BackupError("Notary did not produce exactly one backup archive")
                with (
                    self.container.pull(archives[0], encoding=None) as source,
                    TemporaryFile() as archive,
                ):
                    shutil.copyfileobj(source, archive)
                    digest = _digest(archive)
                    client.upload_fileobj(
                        archive,
                        self.parameters.bucket,
                        key,
                        ExtraArgs={
                            "ContentType": "application/gzip",
                            "Metadata": {**self.identity, "format": "1", "sha256": digest},
                        },
                    )
        return key


def _digest(stream: BinaryIO) -> str:
    """Hash an archive without loading it into memory; rewind for transfer."""
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()
