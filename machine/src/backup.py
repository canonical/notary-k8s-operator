# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cold Notary backups stored in S3, with explicit unit identity metadata."""

import hashlib
import shutil
import tarfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import PurePosixPath
from tempfile import TemporaryFile
from typing import Any, BinaryIO
from uuid import uuid4

import yaml
from botocore.exceptions import ClientError

from machine import NotarySnap
from s3 import S3Parameters, s3_client

DATABASE_PATH = "/var/snap/notary/common/notary/database/dqlite"
STAGING_ROOT = "/var/snap/notary/common/notary/database"
BACKUP_PREFIX = "notary-backup-"


class BackupError(Exception):
    """A backup operation could not be completed safely."""


class BackupManager:
    """Manage the workload lifecycle and transfer physical database archives."""

    def __init__(self, workload: NotarySnap, parameters: S3Parameters, identity: dict[str, str]):
        self.workload = workload
        self.parameters = parameters
        self.identity = identity

    @contextmanager
    def _staging_directory(self) -> Iterator[str]:
        """Allocate private temporary workload storage outside the database."""
        path = f"{STAGING_ROOT}/.backup-{uuid4().hex}"
        self.workload.create_directory(path)
        try:
            yield path
        finally:
            self.workload.remove(path)

    @contextmanager
    def _stopped_service(self) -> Iterator[None]:
        """Stop Notary and restore its previous running state even after failure."""
        was_running = self.workload.is_running()
        if was_running:
            self.workload.stop()
        try:
            yield
        finally:
            if was_running:
                self.workload.start()

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

    def list_backups(self) -> list[str]:
        """List complete archive keys in the configured path across every S3 page."""
        prefix = f"{self.parameters.path}{BACKUP_PREFIX}"
        with s3_client(self.parameters) as client:
            pages = client.get_paginator("list_objects_v2").paginate(
                Bucket=self.parameters.bucket, Prefix=prefix
            )
            return sorted(
                entry["Key"]
                for page in pages
                for entry in page.get("Contents", [])
                if entry["Key"].startswith(prefix) and entry["Key"].endswith(".tar.gz")
            )

    def restore_backup(self, key: str, is_ready: Callable[[], bool]) -> None:
        """Validate a same-unit archive before replacing the offline database."""
        object_key = self._restore_key(key)
        with s3_client(self.parameters) as client, TemporaryFile() as archive:
            response = client.get_object(Bucket=self.parameters.bucket, Key=object_key)
            body = response["Body"]
            try:
                metadata = response.get("Metadata", {})
                if metadata.get("format") != "1" or any(
                    metadata.get(name) != value for name, value in self.identity.items()
                ):
                    raise BackupError(
                        "Backup belongs to a different unit or has unsupported metadata"
                    )
                shutil.copyfileobj(body, archive)
            finally:
                body.close()
            if _digest(archive) != metadata.get("sha256"):
                raise BackupError("Backup checksum verification failed")
            self._validate_archive(archive)
            with self._staging_directory() as directory:
                path = f"{directory}/restore.tar.gz"
                self.workload.copy_from_stream(path, archive)
                self._replace_database(path, is_ready)

    def _restore_key(self, key: str) -> str:
        """Resolve a full key or short ID within the configured S3 path."""
        path = self.parameters.path
        name = key[len(path) :] if path and key.startswith(path) else key
        if "/" in name or not name.startswith(BACKUP_PREFIX) or not name.endswith(".tar.gz"):
            raise BackupError(
                "backup-id must be a Notary backup ID or a full key in the configured S3 path"
            )
        return f"{path}{name}"

    def _validate_archive(self, archive: BinaryIO) -> None:
        """Reject unsafe entries and verify single-member dqlite identity."""
        identity_files = {}
        seen = set()
        try:
            with tarfile.open(fileobj=archive, mode="r:gz") as contents:
                for member in contents:
                    path = PurePosixPath(member.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or str(path) in seen
                        or not (member.isfile() or member.isdir())
                    ):
                        raise BackupError("Backup contains unsafe or duplicate archive entries")
                    seen.add(str(path))
                    if member.name in ("info.yaml", "cluster.yaml"):
                        if not member.isfile() or member.size > 65536:
                            raise BackupError("Backup contains invalid cluster identity files")
                        source = contents.extractfile(member)
                        if source is None:
                            raise BackupError("Backup is missing cluster identity data")
                        with source:
                            identity_files[member.name] = yaml.safe_load(source.read())
        except (tarfile.TarError, EOFError, yaml.YAMLError) as error:
            raise BackupError("Backup is not a valid Notary archive") from error
        finally:
            archive.seek(0)
        info = identity_files.get("info.yaml")
        members = identity_files.get("cluster.yaml")
        if (
            not isinstance(info, dict)
            or info.get("Address") != self.identity["address"]
            or not isinstance(members, list)
            or len(members) != 1
            or not isinstance(members[0], dict)
            or members[0].get("Address") != info.get("Address")
            or members[0].get("ID") != info.get("ID")
            or not info.get("ID")
        ):
            raise BackupError("Backup must contain this unit's single-member cluster identity")

    def _replace_database(self, path: str, is_ready: Callable[[], bool]) -> None:
        """Keep the previous database until the restored API can read initialized state."""
        was_running = self.workload.is_running()
        rollback = f"{STAGING_ROOT}/.pre-restore-{uuid4().hex}"
        moved = False
        if was_running:
            self.workload.stop()
        try:
            if self.workload.path_exists(DATABASE_PATH):
                self.workload.move(DATABASE_PATH, rollback)
                moved = True
            self.workload.run(["restore", "--db-path", DATABASE_PATH, "--file", path], timeout=600)
            self.workload.start()
            self._wait_until_ready(is_ready)
            if not was_running:
                self.workload.stop()
        except Exception:
            self.workload.stop()
            if moved:
                self.workload.remove(DATABASE_PATH)
                self.workload.move(rollback, DATABASE_PATH)
            if was_running:
                self.workload.start()
            raise
        if moved:
            self.workload.remove(rollback)

    def _wait_until_ready(self, is_ready: Callable[[], bool]) -> None:
        """Require three consecutive database-backed checks, two seconds apart."""
        consecutive = 0
        for attempt in range(30):
            running = self.workload.is_running()
            consecutive = consecutive + 1 if running and is_ready() else 0
            if consecutive == 3:
                return
            if attempt < 29:
                time.sleep(2)
        raise BackupError("Restored database did not become healthy; restoring original database")

    def create_backup(self) -> str:
        """Create a cold archive and upload it after bringing Notary back online."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        key = f"{self.parameters.path}{BACKUP_PREFIX}{timestamp}-{uuid4().hex}.tar.gz"
        with s3_client(self.parameters) as client:
            # Fail before interrupting service if the bucket is inaccessible.
            self._ensure_bucket(client)
            with self._staging_directory() as directory:
                with self._stopped_service():
                    self.workload.run(
                        ["backup", "--db-path", DATABASE_PATH, "--file", directory], timeout=600
                    )
                archives = [
                    str(path)
                    for path in self.workload.files(directory)
                    if path.is_file()
                    and path.name.endswith(".tar.gz")
                    and str(PurePosixPath(path).parent) == directory
                ]
                if len(archives) != 1:
                    raise BackupError("Notary did not produce exactly one backup archive")
                with TemporaryFile() as archive:
                    self.workload.copy_to_stream(archives[0], archive)
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
