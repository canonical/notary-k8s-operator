# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import hashlib
from io import BytesIO
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from backup import DATABASE_PATH, BackupError, BackupManager
from s3 import S3Parameters


@pytest.fixture
def manager():
    container = MagicMock()
    container.get_service.return_value.is_running.return_value = True
    container.list_files.side_effect = lambda directory: [
        SimpleNamespace(type="file", name="backup.tar.gz", path=f"{directory}/backup.tar.gz")
    ]
    container.pull.return_value = BytesIO(b"archive")
    return BackupManager(
        container,
        S3Parameters("bucket", "https://s3.example", "access", "secret", path="prefix/"),
        {
            "model": "model",
            "application": "notary",
            "unit": "notary-0",
            "address": "notary-0:9000",
        },
    )


def test_create_backup_restarts_before_upload_and_cleans_up(manager: Any):
    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value

        def upload(archive: Any, bucket: Any, key: Any, **kwargs: Any):
            manager.container.start.assert_called_once_with("notary")
            assert archive.read() == b"archive"
            assert bucket == "bucket"
            assert key.startswith("prefix/notary-backup-")
            assert (
                kwargs["ExtraArgs"]["Metadata"]["sha256"] == hashlib.sha256(b"archive").hexdigest()
            )
            assert kwargs["ExtraArgs"]["Metadata"]["unit"] == "notary-0"

        client.upload_fileobj.side_effect = upload
        key = manager.create_backup()
        assert key.endswith(".tar.gz")
        command = manager.container.exec.call_args.args[0]
        assert command[:4] == ["notary", "backup", "--db-path", DATABASE_PATH]
        manager.container.stop.assert_called_once_with("notary")
        manager.container.remove_path.assert_called_once()


@pytest.mark.parametrize("failure", ["command", "upload", "missing", "multiple"])
def test_backup_failure_restores_service_and_removes_staging(manager: Any, failure: Any):
    with patch("backup.s3_client") as connection:
        if failure == "command":
            manager.container.exec.return_value.wait_output.side_effect = RuntimeError("failed")
        elif failure == "upload":
            connection.return_value.__enter__.return_value.upload_fileobj.side_effect = (
                RuntimeError("failed")
            )
        else:
            manager.container.list_files.side_effect = None
            manager.container.list_files.return_value = (
                []
                if failure == "missing"
                else [
                    SimpleNamespace(type="file", name="one.tar.gz", path="/unexpected/one.tar.gz"),
                    SimpleNamespace(type="file", name="two.tar.gz", path="/unexpected/two.tar.gz"),
                ]
            )
        with pytest.raises((RuntimeError, BackupError)):
            manager.create_backup()
        manager.container.start.assert_called_once_with("notary")
        manager.container.remove_path.assert_called_once()


def test_inaccessible_bucket_does_not_stop_workload(manager: Any):
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.head_bucket.side_effect = RuntimeError(
            "denied"
        )
        with pytest.raises(RuntimeError):
            manager.create_backup()
    manager.container.stop.assert_not_called()
    manager.container.make_dir.assert_not_called()


def test_originally_stopped_service_remains_stopped(manager: Any):
    manager.container.get_service.return_value.is_running.return_value = False
    with patch("backup.s3_client"):
        manager.create_backup()
    manager.container.start.assert_not_called()
    manager.container.stop.assert_not_called()


@pytest.mark.parametrize("region", ["us-east-1", "eu-west-1"])
def test_backup_creates_missing_bucket_before_stopping(manager: Any, region: str):
    from dataclasses import replace

    from botocore.exceptions import ClientError

    manager.parameters = replace(manager.parameters, region=region)
    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.head_bucket.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadBucket")
        client.create_bucket.side_effect = lambda **kwargs: (
            manager.container.stop.assert_not_called()
        )
        manager.create_backup()
        expected: dict[str, Any] = {"Bucket": "bucket"}
        if region != "us-east-1":
            expected["CreateBucketConfiguration"] = {"LocationConstraint": region}
        client.create_bucket.assert_called_once_with(**expected)
        client.get_waiter.return_value.wait.assert_called_once_with(
            Bucket="bucket", WaiterConfig={"Delay": 2, "MaxAttempts": 15}
        )


@pytest.mark.parametrize("code", ["403", "AccessDenied", "500", "PermanentRedirect"])
def test_bucket_errors_do_not_attempt_creation(manager: Any, code: str):
    from botocore.exceptions import ClientError

    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.head_bucket.side_effect = ClientError({"Error": {"Code": code}}, "HeadBucket")
        with pytest.raises(ClientError):
            manager.create_backup()
        client.create_bucket.assert_not_called()
    manager.container.stop.assert_not_called()


@pytest.mark.parametrize(
    "code", ["BucketAlreadyOwnedByYou", "BucketAlreadyExists", "AccessDenied"]
)
def test_bucket_creation_race_and_failure(manager: Any, code: str):
    from botocore.exceptions import ClientError

    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.head_bucket.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadBucket")
        client.create_bucket.side_effect = ClientError({"Error": {"Code": code}}, "CreateBucket")
        if code == "BucketAlreadyOwnedByYou":
            manager.create_backup()
        else:
            with pytest.raises(ClientError):
                manager.create_backup()
            manager.container.stop.assert_not_called()
