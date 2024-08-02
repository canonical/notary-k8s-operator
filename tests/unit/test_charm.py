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


class TestCharm:
    @pytest.fixture(scope="function")
    def context(self):
        yield Context(GocertCharm)

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_gocert_not_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert len(out.secrets) == 0
        root = out.containers[0].get_filesystem(context)
        assert (root / "var/lib/gocert/config/config.yaml").open("r")
        assert not (root / "var/lib/gocert/config/certificate.pem").exists()
        assert not ((root / "var/lib/gocert/config/private_key.pem").exists())
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_gocert_not_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_gocert_not_running_when_configure_then_config_and_certificates_generated(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch("requests.get", return_value=Mock(side_effect=requests.ConnectionError)):
            out = context.run(Event("config-changed"), state)
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

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_gocert_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert len(out.secrets) == 0
        root = out.containers[0].get_filesystem(context)
        assert (root / "var/lib/gocert/config/config.yaml").open("r")
        assert not (root / "var/lib/gocert/config/certificate.pem").exists()
        assert not ((root / "var/lib/gocert/config/private_key.pem").exists())
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_gocert_running_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_gocert_running_when_configure_then_status_is_blocked(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": False}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.BlockedStatus("Please initialize GoCert")

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_gocert_initialized_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert len(out.secrets) == 0
        root = out.containers[0].get_filesystem(context)
        assert (root / "var/lib/gocert/config/config.yaml").open("r")
        assert not (root / "var/lib/gocert/config/certificate.pem").exists()
        assert not ((root / "var/lib/gocert/config/private_key.pem").exists())
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_gocert_initialized_when_configure_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_gocert_initialized_when_configure_then_status_is_active(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "requests.get",
            return_value=Mock(
                **{"json.return_value": {"initialized": True}, "status_code": 200},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.unit_status == ops.ActiveStatus()
