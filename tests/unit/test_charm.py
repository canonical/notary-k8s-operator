# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Dict, List, Literal
from unittest.mock import Mock, patch

import ops
import ops.testing
import pytest
import requests
from charm import GocertCharm
from scenario import Container, Context, Event, Network, State, Storage

# https://res.cloudinary.com/canonical/image/fetch/f_auto,q_auto/https://discourse-charmhub-io.s3.eu-west-2.amazonaws.com/original/2X/4/4ac42dc8a238a003c7d56fe282246ca102dd594f.png


class TestCharmParametrized:
    @pytest.fixture(scope="function")
    def context(self):
        yield Context(GocertCharm)

    @pytest.mark.parametrize(
        "storages_state,storage_ready",
        [
            pytest.param([Storage(name="config")], False, id="config_storage"),
            pytest.param([Storage(name="database")], False, id="database_storage"),
            pytest.param(
                [Storage(name="config"), Storage(name="database")], True, id="both_storages"
            ),
        ],
    )
    @pytest.mark.parametrize(
        "containers_state,container_ready",
        [
            pytest.param(
                [Container(name="gocert", can_connect=False)], False, id="container_cant_connect"
            ),
            pytest.param(
                [Container(name="gocert", can_connect=True)], True, id="container_can_connect"
            ),
        ],
    )
    @pytest.mark.parametrize(
        "networks_state,network_ready",
        [
            pytest.param({"juju-info": Network([], [], [])}, False, id="network_not_available"),
            pytest.param({"juju-info": Network.default()}, True, id="network_available"),
        ],
    )
    @pytest.mark.parametrize(
        "gocert_state,gocert_status",
        [
            pytest.param(
                Mock(side_effect=requests.ConnectionError), "not-running", id="gocert_not_running"
            ),
            pytest.param(
                Mock(
                    **{"json.return_value": {"initialized": False}, "status_code": 200},
                ),
                "running",
                id="gocert_running",
            ),
            pytest.param(
                Mock(
                    **{"json.return_value": {"initialized": True}, "status_code": 200},
                ),
                "initialized",
                id="gocert_initialized",
            ),
        ],
    )
    def test_configure_handler(
        self,
        storages_state: List[Storage],
        storage_ready: bool,
        containers_state: List[Container],
        container_ready: bool,
        networks_state: Dict[str, Network],
        network_ready: bool,
        gocert_state: Mock,
        gocert_status: Literal["not-running", "running", "initialized"],
        context: Context,
    ):
        state = State(
            storage=storages_state,
            containers=containers_state,
            networks=networks_state,
            leader=True,
        )

        with patch("requests.get", return_value=gocert_state):
            out = context.run(Event("config-changed"), state)

        if not storage_ready and not container_ready:
            assert out.unit_status == ops.WaitingStatus("container not yet connectable")
        if storage_ready and not container_ready:
            assert out.unit_status == ops.WaitingStatus("container not yet connectable")
        if not storage_ready and container_ready:
            assert out.unit_status == ops.WaitingStatus("storages not yet available")
        if storage_ready and container_ready and not network_ready:
            assert len(out.secrets) == 0
            root = out.containers[0].get_filesystem(context)
            assert (root / "var/lib/gocert/config/config.yaml").open("r")
            assert not (root / "var/lib/gocert/config/certificate.pem").exists()
            assert not ((root / "var/lib/gocert/config/private_key.pem").exists())
            assert out.unit_status == ops.WaitingStatus("certificates not yet created")
        if storage_ready and container_ready and network_ready and gocert_status == "not-running":
            assert out.secrets[0].contents.get(0).get("certificate")
            assert out.secrets[0].contents.get(0).get("private-key")
            root = out.containers[0].get_filesystem(context)
            assert (root / "var/lib/gocert/config/config.yaml").open("r")
            assert (
                (root / "var/lib/gocert/config/certificate.pem")
                .open("r")
                .read()
                .startswith("-----BEGIN CERTIFICATE-----")
            )
            assert (
                (root / "var/lib/gocert/config/private_key.pem")
                .open("r")
                .read()
                .startswith("-----BEGIN RSA PRIVATE KEY-----")
            )
            assert out.unit_status == ops.WaitingStatus("GoCert server not yet available")
        if storage_ready and container_ready and network_ready and gocert_status == "running":
            assert out.unit_status == ops.BlockedStatus("Please initialize GoCert")
        if storage_ready and container_ready and network_ready and gocert_status == "initialized":
            assert out.unit_status == ops.ActiveStatus()


"""
equivalent to:
    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_not_running_when_configure_
    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_not_running_when_configure_
    def test_given_storages_available_container_cant_connect_network_not_available_gocert_not_running_when_configure_
    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_not_running_when_configure_
    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_not_running_when_configure_
    def test_given_storages_available_container_can_connect_network_not_available_gocert_not_running_when_configure_
    def test_given_only_config_storage_container_cant_connect_network_available_gocert_not_running_when_configure_
    def test_given_only_database_storage_container_cant_connect_network_available_gocert_not_running_when_configure_
    def test_given_storages_available_container_cant_connect_network_available_gocert_not_running_when_configure_
    def test_given_only_config_storage_container_can_connect_network_available_gocert_not_running_when_configure_
    def test_given_only_database_storage_container_can_connect_network_available_gocert_not_running_when_configure_
    def test_given_storages_available_container_can_connect_network_available_gocert_not_running_when_configure_
    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_running_when_configure_
    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_running_when_configure_
    def test_given_storages_available_container_cant_connect_network_not_available_gocert_running_when_configure_
    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_running_when_configure_
    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_running_when_configure_
    def test_given_storages_available_container_can_connect_network_not_available_gocert_running_when_configure_
    def test_given_only_config_storage_container_cant_connect_network_available_gocert_running_when_configure_
    def test_given_only_database_storage_container_cant_connect_network_available_gocert_running_when_configure_
    def test_given_storages_available_container_cant_connect_network_available_gocert_running_when_configure_
    def test_given_only_config_storage_container_can_connect_network_available_gocert_running_when_configure_
    def test_given_only_database_storage_container_can_connect_network_available_gocert_running_when_configure_
    def test_given_storages_available_container_can_connect_network_available_gocert_running_when_configure_
    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_initialized_when_configure_
    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_initialized_when_configure_
    def test_given_storages_available_container_cant_connect_network_not_available_gocert_initialized_when_configure_
    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_initialized_when_configure_
    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_initialized_when_configure_
    def test_given_storages_available_container_can_connect_network_not_available_gocert_initialized_when_configure_
    def test_given_only_config_storage_container_cant_connect_network_available_gocert_initialized_when_configure_
    def test_given_only_database_storage_container_cant_connect_network_available_gocert_initialized_when_configure_
    def test_given_storages_available_container_cant_connect_network_available_gocert_initialized_when_configure_
    def test_given_only_config_storage_container_can_connect_network_available_gocert_initialized_when_configure_
    def test_given_only_database_storage_container_can_connect_network_available_gocert_initialized_when_configure_
    def test_given_storages_available_container_can_connect_network_available_gocert_initialized_when_configure_
"""
