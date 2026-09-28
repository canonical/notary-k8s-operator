# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from dataclasses import replace
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from scenario import ActionFailed, Container, Context, PeerRelation, Relation, State, Storage

from charm import NotaryCharm
from notary import ClusterMember


@pytest.fixture
def context():
    with (
        patch.object(NotaryCharm, "_on_collect_status", autospec=True),
        patch.object(
            NotaryCharm,
            "_ca_certificate_path",
            new_callable=PropertyMock,
            return_value="/unused-test-ca.pem",
        ),
    ):
        yield Context(NotaryCharm)


@pytest.fixture
def state():
    return State(
        leader=True,
        planned_units=1,
        containers={Container("notary", can_connect=True)},
        storages={Storage("config"), Storage("database")},
        relations={
            Relation(
                "s3-parameters",
                remote_app_data={
                    "bucket": "backups",
                    "endpoint": "https://s3.example",
                    "access-key": "access",
                    "secret-key": "secret",
                },
            )
        },
    )


@pytest.mark.parametrize(
    "change", ["follower", "no-s3", "no-container", "no-storage", "multiple-units", "peers"]
)
def test_create_preconditions(context: Any, state: Any, change: Any):
    if change == "follower":
        state = replace(state, leader=False)
    elif change == "no-s3":
        state = replace(state, relations=set())
    elif change == "no-container":
        state = replace(state, containers={Container("notary")})
    elif change == "no-storage":
        state = replace(state, storages=set())
    elif change == "multiple-units":
        state = replace(state, planned_units=3)
    else:
        state = replace(
            state,
            relations=set(state.relations) | {PeerRelation("notary-peers", peers_data={1: {}})},
        )
    with patch("charm.BackupManager.create_backup") as create, pytest.raises(ActionFailed):
        context.run(context.on.action("create-backup"), state)
    create.assert_not_called()


def test_create_returns_backup_id(context: Any, state: Any):
    member = ClusterMember("notary-k8s-0", 1, "unit:9000", "https://unit:2111", "voter", True)
    with (
        patch.object(NotaryCharm, "_get_valid_admin_token", return_value="token"),
        patch("charm.Notary.list_cluster_members", return_value=[member]),
        patch("charm.BackupManager.create_backup", return_value="prefix/backup.tar.gz"),
    ):
        context.run(context.on.action("create-backup"), state)
    assert context.action_results == {"backup-id": "prefix/backup.tar.gz"}


@pytest.mark.parametrize("members", [None, [], [MagicMock(), MagicMock()]])
def test_unknown_or_clustered_membership_fails(context: Any, state: Any, members: Any):
    with (
        patch.object(NotaryCharm, "_get_valid_admin_token", return_value="token"),
        patch("charm.Notary.list_cluster_members", return_value=members),
        patch("charm.BackupManager.create_backup") as create,
        pytest.raises(ActionFailed),
    ):
        context.run(context.on.action("create-backup"), state)
    create.assert_not_called()


def test_list_without_workload(context: Any, state: Any):
    state = replace(state, containers={Container("notary")}, storages=set())
    with patch("charm.BackupManager.list_backups", return_value=["prefix/backup.tar.gz"]):
        context.run(context.on.action("list-backups"), state)
    assert context.action_results == {"backup-ids": '["prefix/backup.tar.gz"]'}


def test_list_storage_failure(context: Any, state: Any):
    from botocore.exceptions import EndpointConnectionError

    with (
        patch(
            "charm.BackupManager.list_backups",
            side_effect=EndpointConnectionError(endpoint_url="https://s3.example"),
        ),
        pytest.raises(ActionFailed),
    ):
        context.run(context.on.action("list-backups"), state)
    assert not context.action_results
