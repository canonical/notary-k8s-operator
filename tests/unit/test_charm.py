# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from unittest.mock import Mock, patch

import ops
import pytest
from scenario import Container, Context, Mount, Network, State, Storage

from charm import NotaryCharm
from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    PrivateKey,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)

CERTIFICATE_COMMON_NAME = "Notary Self Signed Certificate"
SELF_SIGNED_CA_COMMON_NAME = "Notary Self Signed Root CA"


class TestCharm:
    @pytest.fixture(scope="function")
    def context(self):
        yield Context(NotaryCharm)

    def example_cert_and_key(self) -> tuple[Certificate, PrivateKey]:
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name=CERTIFICATE_COMMON_NAME,
        )
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=SELF_SIGNED_CA_COMMON_NAME,
            validity=365,
        )
        certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=365,
        )
        return certificate, private_key

    # Configure tests
    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_not_available_notary_not_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.config_changed(), state)
        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert not (root / "etc/notary/config/certificate.pem").exists()
        assert not ((root / "etc/notary/config/private_key.pem").exists())
        assert len(out.secrets) == 1
        assert out.get_secret(label="Notary Login Details")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_available_notary_not_running_when_configure_then_config_and_certificates_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.config_changed(), state)
        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert (
            (root / "etc/notary/config/certificate.pem")
            .open("r")
            .read()
            .startswith("-----BEGIN CERTIFICATE-----")
        )
        assert (
            (root / "etc/notary/config/private_key.pem")
            .open("r")
            .read()
            .startswith("-----BEGIN RSA PRIVATE KEY-----")
        )

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_not_available_notary_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.config_changed(), state)
        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert not (root / "etc/notary/config/certificate.pem").exists()
        assert not ((root / "etc/notary/config/private_key.pem").exists())
        assert len(out.secrets) == 1
        assert out.get_secret(label="Notary Login Details")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_available_notary_running_when_configure_then_status_is_blocked(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_not_available_notary_initialized_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.config_changed(), state)

        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert not (root / "etc/notary/config/certificate.pem").exists()
        assert not ((root / "etc/notary/config/private_key.pem").exists())
        assert len(out.secrets) == 1
        assert out.get_secret(label="Notary Login Details")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_available_notary_initialized_when_configure_then_status_is_active(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            context.run(context.on.config_changed(), state)

    # Unit Status Tests
    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info", [], ingress_addresses=[], egress_subnets=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=False)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={Container(name="notary", can_connect=True)},
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet created")

    def test_given_notary_available_and_initialized_when_collect_status_then_status_is_active(
        self, context
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            config_mount = Mount(location="/etc/notary/config", source=tempdir)
            state = State(
                storages={Storage(name="config"), Storage(name="database")},
                containers=[
                    Container(name="notary", can_connect=True, mounts={"config": config_mount})
                ],
                networks={Network("juju-info")},
                leader=True,
            )

            certificate, _ = self.example_cert_and_key()
            with open(tempdir + "/certificate.pem", "w") as f:
                f.write(str(certificate))

            with patch(
                "notary.Notary.__new__",
                return_value=Mock(
                    **{"is_api_available.return_value": True, "is_initialized.return_value": True},
                ),
            ):
                out = context.run(context.on.collect_unit_status(), state)
            assert out.unit_status == ops.ActiveStatus()

    def test_given_notary_available_and_not_initialized_when_configure_then_admin_user_created(
        self, context
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            config_mount = Mount(location="/etc/notary/config", source=tempdir)
            state = State(
                storages={Storage(name="config"), Storage(name="database")},
                containers=[
                    Container(name="notary", can_connect=True, mounts={"config": config_mount})
                ],
                networks={Network("juju-info")},
                leader=True,
            )

            with patch(
                "notary.Notary.__new__",
                return_value=Mock(
                    **{
                        "is_api_available.return_value": True,
                        "is_initialized.return_value": False,
                        "login.return_value": "example-token",
                        "token_is_valid.return_value": False,
                    },
                ),
            ):
                out = context.run(context.on.update_status(), state)
            assert len(out.secrets) == 1
            secret = out.get_secret(label="Notary Login Details")
            assert secret.latest_content.get("token") == "example-token"
