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


@pytest.fixture(autouse=True)
def no_readiness_delay():
    with patch("backup.time.sleep"):
        yield


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


def test_list_backups_paginates_and_filters(manager: Any):
    with patch("backup.s3_client") as connection:
        paginator = connection.return_value.__enter__.return_value.get_paginator.return_value
        paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "prefix/notary-backup-b.tar.gz"},
                    {"Key": "prefix/other.tar.gz"},
                ]
            },
            {},
            {
                "Contents": [
                    {"Key": "prefix/notary-backup-a.tar.gz"},
                    {"Key": "prefix/notary-backup-a.tmp"},
                ]
            },
        ]
        assert manager.list_backups() == [
            "prefix/notary-backup-a.tar.gz",
            "prefix/notary-backup-b.tar.gz",
        ]
        paginator.paginate.assert_called_once_with(Bucket="bucket", Prefix="prefix/notary-backup-")
    manager.container.stop.assert_not_called()


def test_empty_bucket_returns_empty_list(manager: Any):
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_paginator.return_value.paginate.return_value = [
            {}
        ]
        assert manager.list_backups() == []


def archive_bytes(
    address: str = "notary-0:9000", extra_name: str | None = None, identity_only: bool = False
) -> bytes:
    import tarfile

    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as contents:
        files = {
            "info.yaml": f"ID: 1\nAddress: {address}\nRole: 0\n".encode(),
            "cluster.yaml": f"- ID: 1\n  Address: {address}\n  Role: 0\n".encode(),
            "metadata1": b"database content",
        }
        if identity_only:
            del files["metadata1"]
        if extra_name:
            files[extra_name] = b"unexpected"
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            contents.addfile(member, BytesIO(content))
    return archive.getvalue()


def restore_response(manager: Any, data: bytes) -> dict[str, Any]:
    return {
        "Body": BytesIO(data),
        "Metadata": {
            **manager.identity,
            "format": "1",
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    }


def test_restore_valid_archive(manager: Any):
    response = restore_response(manager, archive_bytes())
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.return_value = response
        manager.restore_backup("prefix/notary-backup-test.tar.gz", lambda: True)
    assert response["Body"].closed
    commands = [call.args[0] for call in manager.container.exec.call_args_list]
    assert commands[0][:2] == ["mv", DATABASE_PATH]
    assert commands[1][:4] == ["notary", "restore", "--db-path", DATABASE_PATH]
    manager.container.stop.assert_called_once_with("notary")
    manager.container.start.assert_called_once_with("notary")
    assert manager.container.remove_path.call_count == 2  # Old database and staging.


@pytest.mark.parametrize(
    "failure",
    ["identity", "format", "checksum", "bad-tar", "wrong-address", "traversal", "absolute"],
)
def test_restore_rejects_before_stopping_workload(manager: Any, failure: str):
    data = archive_bytes()
    if failure == "bad-tar":
        data = b"not an archive"
    elif failure == "wrong-address":
        data = archive_bytes("other-unit:9000")
    elif failure == "traversal":
        data = archive_bytes(extra_name="../config.yaml")
    elif failure == "absolute":
        data = archive_bytes(extra_name="/etc/config.yaml")
    response = restore_response(manager, data)
    if failure == "identity":
        response["Metadata"]["unit"] = "other-unit"
    elif failure == "format":
        response["Metadata"]["format"] = "2"
    elif failure == "checksum":
        response["Metadata"]["sha256"] = "bad"
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.return_value = response
        with pytest.raises(BackupError):
            manager.restore_backup("prefix/notary-backup-test.tar.gz", lambda: True)
    assert response["Body"].closed
    manager.container.stop.assert_not_called()
    manager.container.push.assert_not_called()


@pytest.mark.parametrize(
    "key",
    [
        "other/notary-backup-test.tar.gz",
        "prefix/notary-backup-test.txt",
        "",
        "../notary-backup-test.tar.gz",
    ],
)
def test_restore_rejects_keys_outside_scope(manager: Any, key: str):
    with patch("backup.s3_client") as connection, pytest.raises(BackupError):
        manager.restore_backup(key, lambda: True)
    connection.assert_not_called()


@pytest.mark.parametrize("failure", ["restore", "start"])
def test_restore_failure_rolls_back_database(manager: Any, failure: str):
    import ops

    error = ops.pebble.Error("failed")
    if failure == "restore":
        process = MagicMock()
        process.wait_output.side_effect = error
        manager.container.exec.side_effect = [MagicMock(), process, MagicMock()]
    else:
        manager.container.start.side_effect = [error, None]
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.return_value = restore_response(
            manager, archive_bytes()
        )
        with pytest.raises(ops.pebble.Error):
            manager.restore_backup("prefix/notary-backup-test.tar.gz", lambda: True)
    commands = [call.args[0] for call in manager.container.exec.call_args_list]
    assert commands[-1] == ["mv", commands[0][2], DATABASE_PATH]
    assert manager.container.start.call_count == (2 if failure == "start" else 1)
    manager.container.remove_path.assert_any_call(DATABASE_PATH, recursive=True)


def test_restore_download_error_does_not_stop_workload(manager: Any):
    from botocore.exceptions import ClientError

    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}}, "GetObject"
        )
        with pytest.raises(ClientError):
            manager.restore_backup("prefix/notary-backup-test.tar.gz", lambda: True)
    manager.container.stop.assert_not_called()


def test_failed_rollback_retains_original_database(manager: Any):
    import ops

    failed = MagicMock()
    failed.wait_output.side_effect = ops.pebble.Error("failed")
    manager.container.exec.side_effect = [MagicMock(), failed, failed]
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.return_value = restore_response(
            manager, archive_bytes()
        )
        with pytest.raises(ops.pebble.Error):
            manager.restore_backup("prefix/notary-backup-test.tar.gz", lambda: True)
    rollback = manager.container.exec.call_args_list[0].args[0][2]
    assert all(call.args[0] != rollback for call in manager.container.remove_path.call_args_list)
    manager.container.start.assert_not_called()


@pytest.mark.parametrize("key", ["notary-backup-test.tar.gz", "prefix/notary-backup-test.tar.gz"])
def test_restore_resolves_id_in_configured_path(manager: Any, key: str):
    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.get_object.return_value = restore_response(manager, archive_bytes())
        manager.restore_backup(key, lambda: True)
        client.get_object.assert_called_once_with(
            Bucket="bucket", Key="prefix/notary-backup-test.tar.gz"
        )


@pytest.mark.parametrize("code", ["AccessDenied", "NoSuchBucket", "InternalError"])
def test_restore_propagates_s3_errors(manager: Any, code: str):
    from botocore.exceptions import ClientError

    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.get_object.side_effect = ClientError({"Error": {"Code": code}}, "GetObject")
        with pytest.raises(ClientError):
            manager.restore_backup("notary-backup-test.tar.gz", lambda: True)
        assert client.get_object.call_count == 1
    manager.container.stop.assert_not_called()


def test_missing_backup_does_not_search_bucket_root(manager: Any):
    from botocore.exceptions import ClientError

    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        with pytest.raises(ClientError):
            manager.restore_backup("notary-backup-test.tar.gz", lambda: True)
        client.get_object.assert_called_once_with(
            Bucket="bucket", Key="prefix/notary-backup-test.tar.gz"
        )
    manager.container.stop.assert_not_called()


def test_restore_rejects_corrupt_backup_before_stopping_workload(manager: Any):
    response = restore_response(manager, archive_bytes())
    response["Metadata"]["sha256"] = "invalid"
    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.get_object.return_value = response
        with pytest.raises(BackupError, match="checksum"):
            manager.restore_backup("notary-backup-test.tar.gz", lambda: True)
        assert client.get_object.call_count == 1
    manager.container.stop.assert_not_called()


def test_restore_without_configured_path_fetches_once(manager: Any):
    from dataclasses import replace

    manager.parameters = replace(manager.parameters, path="")
    with patch("backup.s3_client") as connection:
        client = connection.return_value.__enter__.return_value
        client.get_object.return_value = restore_response(manager, archive_bytes())
        manager.restore_backup("notary-backup-test.tar.gz", lambda: True)
        client.get_object.assert_called_once_with(Bucket="bucket", Key="notary-backup-test.tar.gz")


@pytest.mark.parametrize("was_running", [True, False])
@pytest.mark.parametrize("healthy", [True, False])
def test_restore_checks_database_before_discarding_original(
    manager: Any, was_running: bool, healthy: bool
):
    manager.container.get_service.return_value.is_running.side_effect = [was_running] + [True] * 30

    def readiness():
        # The original database must still be available during every check.
        assert not manager.container.remove_path.called
        return healthy

    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.return_value = restore_response(
            manager, archive_bytes()
        )
        if healthy:
            manager.restore_backup("notary-backup-test.tar.gz", readiness)
        else:
            with pytest.raises(BackupError, match="did not become healthy"):
                manager.restore_backup("notary-backup-test.tar.gz", readiness)
    commands = [call.args[0] for call in manager.container.exec.call_args_list]
    rollback = commands[0][2]
    if healthy:
        manager.container.remove_path.assert_any_call(rollback, recursive=True)
    else:
        assert commands[-1] == ["mv", rollback, DATABASE_PATH]
        assert all(
            call.args[0] != rollback for call in manager.container.remove_path.call_args_list
        )
    assert manager.container.start.call_count == (2 if was_running and not healthy else 1)
    assert manager.container.stop.call_count == (
        int(was_running) + int(not healthy or not was_running)
    )


def test_readiness_requires_consecutive_successes(manager: Any):
    check = MagicMock(side_effect=[True, True, False, True, True, True])
    manager._wait_until_ready(check)
    assert check.call_count == 6


def test_readiness_exception_rolls_back(manager: Any):
    with pytest.raises(ValueError, match="invalid response"):
        manager._replace_database(
            "/archive", MagicMock(side_effect=ValueError("invalid response"))
        )
    commands = [call.args[0] for call in manager.container.exec.call_args_list]
    assert commands[-1] == ["mv", commands[0][2], DATABASE_PATH]
    assert all(
        call.args[0] != commands[0][2] for call in manager.container.remove_path.call_args_list
    )


def test_identity_only_archive_cannot_discard_original_database(manager: Any):
    # Extraction can succeed while startup creates a fresh, uninitialized database.
    with patch("backup.s3_client") as connection:
        connection.return_value.__enter__.return_value.get_object.return_value = restore_response(
            manager, archive_bytes(identity_only=True)
        )
        with pytest.raises(BackupError, match="did not become healthy"):
            manager.restore_backup("notary-backup-test.tar.gz", lambda: False)
    commands = [call.args[0] for call in manager.container.exec.call_args_list]
    assert commands[-1] == ["mv", commands[0][2], DATABASE_PATH]
    assert all(
        call.args[0] != commands[0][2] for call in manager.container.remove_path.call_args_list
    )
