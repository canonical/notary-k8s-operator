# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import Mock, patch

import ops
import ops.testing
import pytest
import requests
from charm import GocertCharm
from scenario import Container, Context, Event, Network, State, Storage


class TestCharm:
    @pytest.fixture(scope="function")
    def context(self):
        yield Context(GocertCharm)

    # Configure tests
    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_can_connect_network_not_available_gocert_not_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert len(out.secrets) == 0
        root = out.containers[0].get_filesystem(context)
        assert (root / "etc/gocert/config/config.yaml").open("r")
        assert not (root / "etc/gocert/config/certificate.pem").exists()
        assert not ((root / "etc/gocert/config/private_key.pem").exists())

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_cant_connect_network_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_can_connect_network_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_can_connect_network_available_gocert_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_can_connect_network_available_gocert_not_running_when_configure_then_config_and_certificates_generated(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert out.secrets[0].contents.get(0).get("certificate")
        assert out.secrets[0].contents.get(0).get("private-key")
        root = out.containers[0].get_filesystem(context)
        assert (root / "etc/gocert/config/config.yaml").open("r")
        assert (
            (root / "etc/gocert/config/certificate.pem")
            .open("r")
            .read()
            .startswith("-----BEGIN CERTIFICATE-----")
        )
        assert (
            (root / "etc/gocert/config/private_key.pem")
            .open("r")
            .read()
            .startswith("-----BEGIN RSA PRIVATE KEY-----")
        )

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

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
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert len(out.secrets) == 0
        root = out.containers[0].get_filesystem(context)
        assert (root / "etc/gocert/config/config.yaml").open("r")
        assert not (root / "etc/gocert/config/certificate.pem").exists()
        assert not ((root / "etc/gocert/config/private_key.pem").exists())

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_cant_connect_network_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_can_connect_network_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_can_connect_network_available_gocert_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

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
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

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
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("config-changed"), state)
        assert len(out.secrets) == 0
        root = out.containers[0].get_filesystem(context)
        assert (root / "etc/gocert/config/config.yaml").open("r")
        assert not (root / "etc/gocert/config/certificate.pem").exists()
        assert not ((root / "etc/gocert/config/private_key.pem").exists())

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_storages_available_container_cant_connect_network_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_config_storage_container_can_connect_network_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    def test_given_only_database_storage_container_can_connect_network_available_gocert_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

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
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(Event("config-changed"), state)

    # Unit Status Tests
    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_gocert_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_gocert_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_not_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network([], [], [])},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=False)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_gocert_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storage=[Storage(name="config"), Storage(name="database")],
            containers=[Container(name="gocert", can_connect=True)],
            networks={"juju-info": Network.default()},
            leader=True,
        )

        with patch(
            "gocert.GoCert",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(Event("collect-unit-status"), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")
