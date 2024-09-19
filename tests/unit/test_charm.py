# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from unittest.mock import Mock, patch

import ops
import pytest
from ops.pebble import Layer
from scenario import Container, Context, Mount, Network, Relation, Secret, State, Storage

from charm import (
    CERTIFICATE_PROVIDER_RELATION_NAME,
    NOTARY_LOGIN_SECRET_LABEL,
    TLS_ACCESS_RELATION_NAME,
    NotaryCharm,
)
from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    PrivateKey,
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from notary import CertificateRequest as CertificateRequestRow
from notary import CertificateRequests

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"

CERTIFICATE_COMMON_NAME = "Notary Self Signed Certificate"
SELF_SIGNED_CA_COMMON_NAME = "Notary Self Signed Root CA"

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"


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
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_not_available_notary_not_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.config_changed(), state)
        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert len(list(out.secrets)) == 1
        assert out.get_secret(label="Notary Login Details")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_available_notary_not_running_when_configure_then_config_and_certificates_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
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
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_not_available_notary_running_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.config_changed(), state)
        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert len(list(out.secrets)) == 1
        assert out.get_secret(label="Notary Login Details")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_available_notary_running_when_configure_then_status_is_blocked(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_not_available_notary_initialized_when_configure_then_config_file_generated(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.config_changed(), state)

        root = out.get_container("notary").get_filesystem(context)
        assert (root / "etc/notary/config/config.yaml").open("r")
        assert len(list(out.secrets)) == 1
        assert out.get_secret(label="Notary Login Details")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_config_storage_container_can_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_only_database_storage_container_can_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    def test_given_storages_available_container_can_connect_network_available_notary_initialized_when_configure_then_status_is_active(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            context.run(context.on.config_changed(), state)

    # Unit Status Tests
    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)

        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_notary_not_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": False, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_notary_running_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": False},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_not_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info", bind_addresses=[])},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_database_storage_container_cant_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_storages_available_container_cant_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=False,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("container not yet connectable")

    def test_given_only_config_storage_container_can_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_only_database_storage_container_can_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("storages not yet available")

    def test_given_storages_available_container_can_connect_network_available_notary_initialized_when_collect_status_then_status_is_waiting(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers={
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            },
            networks={Network("juju-info")},
            leader=True,
        )

        with patch(
            "notary.Notary",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_notary_available_and_initialized_when_collect_status_then_status_is_active(
        self, context, tmpdir
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmpdir)
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(name="notary", can_connect=True, mounts={"config": config_mount})
            ],
            leader=True,
        )

        certificate, _ = self.example_cert_and_key()
        with open(tmpdir + "/certificate.pem", "w") as f:
            f.write(str(certificate))

        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.ActiveStatus()

    def test_given_notary_available_and_not_initialized_when_configure_then_admin_user_created(
        self, context, tmpdir
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmpdir)
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    mounts={"config": config_mount},
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
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
        assert len(list(out.secrets)) == 1
        secret = out.get_secret(label="Notary Login Details")
        assert secret.latest_content
        assert secret.latest_content.get("token") == "example-token"

    def test_given_tls_requirer_available_when_notary_unreachable_then_no_error_raised(
        self, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            networks={Network("juju-info")},
            leader=True,
            relations=[Relation(id=1, endpoint=CERTIFICATE_PROVIDER_RELATION_NAME)],
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
            context.run(context.on.update_status(), state)

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirer_available_when_configure_then_csrs_posted_to_notary(
        self, mock_get_certificate_requests, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            networks={Network("juju-info")},
            leader=True,
            relations=[Relation(id=1, endpoint=CERTIFICATE_PROVIDER_RELATION_NAME)],
            secrets={
                Secret(
                    {"username": "hello", "password": "world", "token": "test-token"},
                    id="1",
                    label=NOTARY_LOGIN_SECRET_LABEL,
                    owner="app",
                )
            },
        )
        csr = generate_csr(private_key=generate_private_key(), common_name="me")
        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                certificate_signing_request=csr,
            )
        ]
        post_call = Mock()
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "token_is_valid.return_value": True,
                    "get_certificate_requests_table.return_value": CertificateRequests(rows=[]),
                    "post_csr": post_call,
                },
            ),
        ):
            context.run(context.on.update_status(), state)

        post_call.assert_called_once_with(str(csr), "test-token")

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirers_available_when_csrs_already_posted_then_duplicate_csr_not_posted(
        self, mock_get_certificate_requests, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            networks={Network("juju-info")},
            leader=True,
            relations=[Relation(id=1, endpoint=CERTIFICATE_PROVIDER_RELATION_NAME)],
            secrets={
                Secret(
                    {"username": "hello", "password": "world", "token": "test-token"},
                    id="1",
                    label=NOTARY_LOGIN_SECRET_LABEL,
                    owner="app",
                )
            },
        )
        csr = generate_csr(private_key=generate_private_key(), common_name="me")
        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                certificate_signing_request=csr,
            )
        ]
        post_call = Mock()
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "token_is_valid.return_value": True,
                    "get_certificate_requests_table.return_value": CertificateRequests(
                        rows=[CertificateRequestRow(id=1, csr=str(csr), certificate_chain="")]
                    ),
                    "post_csr": post_call,
                },
            ),
        ):
            context.run(context.on.update_status(), state)

        post_call.assert_not_called()

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirers_available_when_certificate_available_then_certs_provided_to_requirer(
        self, mock_get_certificate_requests, mock_set_relation_certificate, context
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            networks={Network("juju-info")},
            leader=True,
            relations=[Relation(id=1, endpoint=CERTIFICATE_PROVIDER_RELATION_NAME)],
            secrets={
                Secret(
                    {"username": "hello", "password": "world", "token": "test-token"},
                    id="1",
                    label=NOTARY_LOGIN_SECRET_LABEL,
                    owner="app",
                )
            },
        )
        ca_pk = generate_private_key()
        ca = generate_ca(ca_pk, 365, "me")
        csr = generate_csr(private_key=generate_private_key(), common_name="notary.com")
        cert = generate_certificate(csr, ca, ca_pk, 365)
        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                certificate_signing_request=csr,
            )
        ]
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "token_is_valid.return_value": True,
                    "get_certificate_requests_table.return_value": CertificateRequests(
                        rows=[
                            CertificateRequestRow(
                                id=1, csr=str(csr), certificate_chain=[str(cert), str(ca)]
                            )
                        ]
                    ),
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        mock_set_relation_certificate.assert_called_once()

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_issued_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirers_when_invalid_certificate_available_when_configure_then_new_cert_provided(
        self,
        mock_get_certificate_requests,
        mock_set_relation_certificate,
        mock_get_issued_certificates,
        context,
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            networks={Network("juju-info")},
            leader=True,
            relations=[Relation(id=1, endpoint=CERTIFICATE_PROVIDER_RELATION_NAME)],
            secrets={
                Secret(
                    {"username": "hello", "password": "world", "token": "test-token"},
                    id="1",
                    label=NOTARY_LOGIN_SECRET_LABEL,
                    owner="app",
                )
            },
        )
        ca_pk = generate_private_key()
        ca = generate_ca(ca_pk, 365, "me")
        csr = generate_csr(private_key=generate_private_key(), common_name="notary.com")
        old_cert = generate_certificate(csr, ca, ca_pk, 365)
        new_cert = generate_certificate(csr, ca, ca_pk, 366)
        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                certificate_signing_request=csr,
            )
        ]
        mock_get_issued_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr,
                certificate=old_cert,
                ca=ca,
                chain=[old_cert, ca],
            )
        ]
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "token_is_valid.return_value": True,
                    "get_certificate_requests_table.return_value": CertificateRequests(
                        rows=[
                            CertificateRequestRow(
                                id=1, csr=str(csr), certificate_chain=[str(new_cert), str(ca)]
                            )
                        ]
                    ),
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        mock_set_relation_certificate.assert_called_once()

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_issued_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_certificate_rejected_in_notary_when_configure_then_certificate_revoked(
        self,
        mock_get_certificate_requests,
        mock_set_relation_certificate,
        mock_get_issued_certificates,
        context,
    ):
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            networks={Network("juju-info")},
            leader=True,
            relations=[Relation(id=1, endpoint=CERTIFICATE_PROVIDER_RELATION_NAME)],
            secrets=[
                Secret(
                    {"username": "hello", "password": "world", "token": "test-token"},
                    id="1",
                    label=NOTARY_LOGIN_SECRET_LABEL,
                    owner="app",
                )
            ],
        )
        ca_pk = generate_private_key()
        ca = generate_ca(ca_pk, 365, "me")
        csr = generate_csr(private_key=generate_private_key(), common_name="notary.com")
        old_cert = generate_certificate(csr, ca, ca_pk, 365)
        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                certificate_signing_request=csr,
            )
        ]
        mock_get_issued_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr,
                certificate=old_cert,
                ca=ca,
                chain=[old_cert, ca],
            )
        ]
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "token_is_valid.return_value": True,
                    "get_certificate_requests_table.return_value": CertificateRequests(
                        rows=[
                            CertificateRequestRow(id=1, csr=str(csr), certificate_chain="rejected")
                        ]
                    ),
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        mock_set_relation_certificate.assert_called_once()

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate")
    def test_given_access_relation_created_when_configure_then_certificate_not_replaced(
        self, mock_assigned_certificates, context, tmpdir
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmpdir)
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    mounts={"config": config_mount},
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            relations=[Relation(id=1, endpoint=TLS_ACCESS_RELATION_NAME)],
            leader=True,
        )
        certificate, _ = self.example_cert_and_key()
        with open(tmpdir + "/certificate.pem", "w") as f:
            f.write(str(certificate))
        mock_assigned_certificates.return_value = (None, None)
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": "example-token",
                    "token_is_valid.return_value": True,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        Path(tmpdir + "etc/notary/config").mkdir(parents=True, exist_ok=True)
        with open(tmpdir + "/certificate.pem") as f:
            saved_cert = f.read()
            assert saved_cert == str(certificate)

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate")
    def test_given_new_certificate_available_when_configure_then_certificate_replaced(
        self, mock_assigned_certificates, context, tmpdir
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmpdir)
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    mounts={"config": config_mount},
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            relations=[Relation(id=1, endpoint=TLS_ACCESS_RELATION_NAME)],
            leader=True,
        )
        existing_certificate, _ = self.example_cert_and_key()
        certificate, pk = self.example_cert_and_key()
        provider_certificate_mock = Mock()
        provider_certificate_mock.certificate = certificate.raw
        with open(tmpdir + "/certificate.pem", "w") as f:
            f.write(str(existing_certificate))
        mock_assigned_certificates.return_value = (provider_certificate_mock, pk)
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": "example-token",
                    "token_is_valid.return_value": True,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        with open(tmpdir + "/certificate.pem") as f:
            saved_cert = f.read()
            assert saved_cert == str(certificate)

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate")
    def test_given_new_certificate_available_and_new_cert_already_saved_when_configure_then_certificate_not_replaced(
        self, mock_assigned_certificates, context, tmpdir
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmpdir)
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    mounts={"config": config_mount},
                    layers={
                        "notary": Layer(
                            {
                                "summary": "notary layer",
                                "description": "pebble config layer for notary",
                                "services": {
                                    "notary": {
                                        "override": "replace",
                                        "summary": "notary",
                                        "command": "notary -config /etc/notary/config/config.yaml",
                                        "startup": "enabled",
                                    }
                                },
                            }
                        )
                    },
                )
            ],
            relations=[Relation(id=1, endpoint=TLS_ACCESS_RELATION_NAME)],
            leader=True,
        )
        certificate, pk = self.example_cert_and_key()
        provider_certificate_mock = Mock()
        provider_certificate_mock.certificate = certificate.raw
        with open(tmpdir + "/certificate.pem", "w") as f:
            f.write(str(certificate))
        mock_assigned_certificates.return_value = (provider_certificate_mock, pk)
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": "example-token",
                    "token_is_valid.return_value": True,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        with open(tmpdir + "/certificate.pem") as f:
            saved_cert = f.read()
            assert saved_cert == str(certificate)
