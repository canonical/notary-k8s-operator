# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import importlib.util
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from types import ModuleType
from unittest.mock import MagicMock, Mock, patch

import ops
import pytest
import requests
import yaml
from charmlibs.interfaces.tls_certificates import (
    Certificate,
    PrivateKey,
    ProviderCertificate,
    RequirerCertificateRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops.pebble import Layer
from scenario import (
    Container,
    Context,
    Mount,
    Network,
    PeerRelation,
    Relation,
    Secret,
    State,
    Storage,
)

from charm import (
    CERTIFICATE_PROVIDER_RELATION_NAME,
    CLUSTER_DATA_VERSION_KEY,
    CLUSTER_JOIN_SECRET_LABEL,
    NOTARY_LOGIN_SECRET_LABEL,
    PEER_RELATION_NAME,
    SELF_SIGNED_CA_SECRET_LABEL,
    SEND_ACCESS_CA_CERT_RELATION_NAME,
    TLS_ACCESS_RELATION_NAME,
    NotaryCharm,
)
from notary import CertificateRequest as CertificateRequestEntry
from notary import (
    ClusterMember,
    CreateClusterMemberResponse,
    LoginResponse,
    Notary,
)

TLS_LIB_PATH = "charmlibs.interfaces.tls_certificates"
CERT_TRANSFER_LIB_PATH = "charmlibs.interfaces.certificate_transfer"

CERTIFICATE_COMMON_NAME = "Notary Self Signed Certificate"
SELF_SIGNED_CA_COMMON_NAME = "Notary Self Signed Root CA"


class TestCharm:
    @pytest.fixture(scope="function")
    def context(self):
        """Exercise application behavior independently of cluster admission."""
        with patch.object(NotaryCharm, "_cluster_prerequisites_met", return_value=True):
            yield Context(NotaryCharm)

    def example_certs_and_key(
        self, hostname: str | None = None
    ) -> tuple[Certificate, Certificate, PrivateKey, PrivateKey]:
        private_key = generate_private_key()
        csr_kwargs: dict = {
            "private_key": private_key,
            "common_name": CERTIFICATE_COMMON_NAME,
        }
        if hostname:
            csr_kwargs["sans_dns"] = frozenset([hostname])
        csr = generate_csr(**csr_kwargs)
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=SELF_SIGNED_CA_COMMON_NAME,
            validity=timedelta(days=365),
        )
        certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
        )
        return certificate, ca_certificate, ca_private_key, private_key

    # Configure tests
    def test_given_only_config_storage_container_cant_connect_network_not_available_notary_not_running_when_configure_then_no_error_raised(
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        assert len(list(out.secrets)) == 2
        assert out.get_secret(label="Notary Login Details")
        assert out.get_secret(label="Notary Self Signed CA")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_not_running_when_configure_then_no_error_raised(
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        assert len(list(out.secrets)) == 2
        assert out.get_secret(label="Notary Login Details")
        assert out.get_secret(label="Notary Self Signed CA")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_running_when_configure_then_no_error_raised(
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        assert len(list(out.secrets)) == 2
        assert out.get_secret(label="Notary Login Details")
        assert out.get_secret(label="Notary Self Signed CA")

    def test_given_only_config_storage_container_cant_connect_network_available_notary_initialized_when_configure_then_no_error_raised(
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm]
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
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
        state = State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(name="notary", can_connect=True, mounts={"config": config_mount})
            ],
            leader=True,
        )

        certificate, _, _, _ = self.example_certs_and_key()
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(certificate))

        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{"is_api_available.return_value": True, "is_initialized.return_value": True},  # type: ignore
            ),
        ):
            out = context.run(context.on.collect_unit_status(), state)
        assert out.unit_status == ops.ActiveStatus()

    def test_given_notary_available_when_configure_then_workload_version_is_set(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
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
                    "login.return_value": None,
                    "get_version.return_value": "1.2.3",
                },
            ),
        ):
            out = context.run(context.on.update_status(), state)
        assert out.workload_version == "1.2.3"

    def test_given_notary_available_and_not_initialized_when_configure_then_admin_user_created(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
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
                    "login.return_value": LoginResponse(token="example-token"),
                    "token_is_valid.return_value": False,
                    "get_version.return_value": None,
                },
            ),
        ):
            out = context.run(context.on.update_status(), state)
        assert len(list(out.secrets)) == 2
        secret = out.get_secret(label="Notary Login Details")
        assert secret.latest_content
        assert secret.latest_content.get("token") == "example-token"
        ca_secret = out.get_secret(label="Notary Self Signed CA")
        assert ca_secret.latest_content
        assert ca_secret.latest_content.get("ca-certificate")

    def test_given_tls_requirer_available_when_notary_unreachable_then_no_error_raised(
        self, context: Context[NotaryCharm]
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
                    "login.return_value": LoginResponse(token="example-token"),
                    "token_is_valid.return_value": False,
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirer_available_when_configure_then_csrs_posted_to_notary(
        self, mock_get_certificate_requests: MagicMock, context: Context[NotaryCharm]
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
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr,
                is_ca=False,
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
                    "list_certificate_requests.return_value": [],
                    "create_certificate_request": post_call,
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)

        post_call.assert_called_once_with(str(csr), "test-token")

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirers_available_when_csrs_already_posted_then_duplicate_csr_not_posted(
        self, mock_get_certificate_requests: MagicMock, context: Context[NotaryCharm]
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
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr,
                is_ca=False,
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
                    "list_certificate_requests.return_value": [
                        CertificateRequestEntry(
                            id=1, csr=str(csr), certificate_chain=[], status="Outstanding"
                        )
                    ],
                    "post_csr": post_call,
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)

        post_call.assert_not_called()

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_tls_requirers_available_when_certificate_available_then_certs_provided_to_requirer(
        self,
        mock_get_certificate_requests: MagicMock,
        mock_set_relation_certificate: MagicMock,
        context: Context[NotaryCharm],
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
        ca = generate_ca(ca_pk, timedelta(days=365), "me")
        csr = generate_csr(private_key=generate_private_key(), common_name="notary.com")
        cert = generate_certificate(csr, ca, ca_pk, timedelta(days=365))
        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr,
                is_ca=False,
            )
        ]
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "token_is_valid.return_value": True,
                    "list_certificate_requests.return_value": [
                        CertificateRequestEntry(
                            id=1,
                            csr=str(csr),
                            certificate_chain=[str(cert), str(ca)],
                            status="Active",
                        )
                    ],
                    "get_version.return_value": None,
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
        mock_get_certificate_requests: MagicMock,
        mock_set_relation_certificate: MagicMock,
        mock_get_issued_certificates: MagicMock,
        context: Context[NotaryCharm],
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
        ca = generate_ca(ca_pk, timedelta(days=365), "me")
        csr = generate_csr(private_key=generate_private_key(), common_name="notary.com")
        old_cert = generate_certificate(csr, ca, ca_pk, timedelta(days=365))
        new_cert = generate_certificate(csr, ca, ca_pk, timedelta(days=366))
        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr,
                is_ca=False,
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
                    "list_certificate_requests.return_value": [
                        CertificateRequestEntry(
                            id=1,
                            csr=str(csr),
                            certificate_chain=[str(new_cert), str(ca)],
                            status="Active",
                        )
                    ],
                    "get_version.return_value": None,
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
        mock_get_certificate_requests: MagicMock,
        mock_set_relation_certificate: MagicMock,
        mock_get_issued_certificates: MagicMock,
        context: Context[NotaryCharm],
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
        ca = generate_ca(ca_pk, timedelta(days=365), "me")
        csr = generate_csr(private_key=generate_private_key(), common_name="notary.com")
        old_cert = generate_certificate(csr, ca, ca_pk, timedelta(days=365))
        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr,
                is_ca=False,
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
                    "list_certificate_requests.return_value": [
                        CertificateRequestEntry(
                            id=1, csr=str(csr), certificate_chain=[], status="Rejected"
                        )
                    ],
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        mock_set_relation_certificate.assert_called_once()

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate")
    def test_given_access_relation_created_when_configure_then_certificate_not_replaced(
        self, mock_assigned_certificates: MagicMock, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
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
        certificate, ca, _, _ = self.example_certs_and_key()
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(certificate))
        with open(tmp_path / "ca.pem", "w") as f:
            f.write(str(ca))
        mock_assigned_certificates.return_value = (None, None)
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": LoginResponse(token="example-token"),
                    "token_is_valid.return_value": True,
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        (tmp_path / "etc/notary/config").mkdir(parents=True, exist_ok=True)
        with open(tmp_path / "certificate.pem") as f:
            saved_cert = f.read()
            assert saved_cert == str(certificate)

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate")
    def test_given_new_certificate_available_when_configure_then_certificate_replaced(
        self, mock_assigned_certificates: MagicMock, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
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
        existing_certificate, _, _, _ = self.example_certs_and_key()
        certificate, _, _, pk = self.example_certs_and_key()
        provider_certificate_mock = Mock()
        provider_certificate_mock.certificate = certificate.raw
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(existing_certificate))
        mock_assigned_certificates.return_value = (provider_certificate_mock, pk)
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": LoginResponse(token="example-token"),
                    "token_is_valid.return_value": True,
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        with open(tmp_path / "certificate.pem") as f:
            saved_cert = f.read()
            assert saved_cert == str(certificate)

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate")
    def test_given_new_certificate_available_and_new_cert_already_saved_when_configure_then_certificate_not_replaced(
        self, mock_assigned_certificates: MagicMock, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
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
        certificate, ca, _, pk = self.example_certs_and_key()
        provider_certificate_mock = Mock()
        provider_certificate_mock.certificate = certificate.raw
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(certificate))
        with open(tmp_path / "ca.pem", "w") as f:
            f.write(str(ca))
        mock_assigned_certificates.return_value = (provider_certificate_mock, pk)
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": LoginResponse(token="example-token"),
                    "token_is_valid.return_value": True,
                    "get_version.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        with open(tmp_path / "certificate.pem") as f:
            saved_cert = f.read()
            assert saved_cert == str(certificate)

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    def test_given_send_ca_requirer_when_configure_then_ca_cert_sent(
        self,
        mock_add_certificates: MagicMock,
        context: Context[NotaryCharm],
        tmp_path: Path,
    ):
        hostname = "notary.example.com"
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
        certificate, ca, ca_private_key, pk = self.example_certs_and_key(hostname=hostname)
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
            relations=[
                Relation(id=1, endpoint=SEND_ACCESS_CA_CERT_RELATION_NAME),
            ],
            config={"external-hostname": hostname},
            secrets={
                Secret(
                    {"ca-certificate": str(ca), "ca-private-key": str(ca_private_key)},
                    label=SELF_SIGNED_CA_SECRET_LABEL,
                    owner="app",
                )
            },
            leader=True,
        )
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(certificate))
        with open(tmp_path / "ca.pem", "w") as f:
            f.write(str(ca))
        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "login.return_value": LoginResponse(token="example-token"),
                    "token_is_valid.return_value": True,
                    "get_version.return_value": "1.2.3",
                },
            ),
        ):
            context.run(context.on.update_status(), state)
        mock_add_certificates.assert_called_once_with(certificates={str(ca)}, relation_id=1)

    def test_given_self_signed_certs_exist_when_hostname_changes_then_certificates_regenerated(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
        # Generate self-signed certs with OLD hostname SAN
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=SELF_SIGNED_CA_COMMON_NAME,
            validity=timedelta(days=365),
        )
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name=CERTIFICATE_COMMON_NAME,
            sans_dns=frozenset(["old-hostname.example.com"]),
        )
        old_certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
        )
        # Write old cert files to the mount
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(old_certificate))
        with open(tmp_path / "ca.pem", "w") as f:
            f.write(str(ca_certificate))
        with open(tmp_path / "private_key.pem", "w") as f:
            f.write(str(private_key))

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
            config={"external-hostname": "new-hostname.example.com"},
            secrets={
                Secret(
                    {"ca-certificate": str(ca_certificate), "ca-private-key": str(ca_private_key)},
                    label=SELF_SIGNED_CA_SECRET_LABEL,
                    owner="app",
                )
            },
            leader=True,
        )

        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": False,
                    "is_initialized.return_value": False,
                    "login.return_value": None,
                },
            ),
        ):
            context.run(context.on.config_changed(), state)

        with open(tmp_path / "certificate.pem") as f:
            new_cert_pem = f.read()
        new_cert = Certificate.from_string(new_cert_pem)
        assert new_cert.common_name == CERTIFICATE_COMMON_NAME
        assert new_cert.sans_dns is not None
        assert "new-hostname.example.com" in new_cert.sans_dns
        assert str(old_certificate) != new_cert_pem

    def test_given_self_signed_certs_exist_when_hostname_unchanged_then_certificates_not_regenerated(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
        hostname = "my-hostname.example.com"
        # Generate self-signed certs with CURRENT hostname SAN
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=SELF_SIGNED_CA_COMMON_NAME,
            validity=timedelta(days=365),
        )
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name=CERTIFICATE_COMMON_NAME,
            sans_dns=frozenset([hostname]),
        )
        existing_certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
        )
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(existing_certificate))
        with open(tmp_path / "ca.pem", "w") as f:
            f.write(str(ca_certificate))
        with open(tmp_path / "private_key.pem", "w") as f:
            f.write(str(private_key))

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
            config={"external-hostname": hostname},
            secrets={
                Secret(
                    {"ca-certificate": str(ca_certificate), "ca-private-key": str(ca_private_key)},
                    label=SELF_SIGNED_CA_SECRET_LABEL,
                    owner="app",
                )
            },
            leader=True,
        )

        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": False,
                    "is_initialized.return_value": False,
                    "login.return_value": None,
                },
            ),
        ):
            context.run(context.on.config_changed(), state)

        with open(tmp_path / "certificate.pem") as f:
            saved_cert = f.read()
        assert saved_cert == str(existing_certificate)

    def test_given_self_signed_certs_exist_when_no_external_hostname_then_certificates_not_regenerated(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        config_mount = Mount(location="/etc/notary/config", source=tmp_path)
        # Generate self-signed certs without a hostname SAN (matches the no-external-hostname case)
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            common_name=SELF_SIGNED_CA_COMMON_NAME,
            validity=timedelta(days=365),
        )
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name=CERTIFICATE_COMMON_NAME,
        )
        existing_certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
        )
        with open(tmp_path / "certificate.pem", "w") as f:
            f.write(str(existing_certificate))
        with open(tmp_path / "ca.pem", "w") as f:
            f.write(str(ca_certificate))
        with open(tmp_path / "private_key.pem", "w") as f:
            f.write(str(private_key))

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
            secrets={
                Secret(
                    {"ca-certificate": str(ca_certificate), "ca-private-key": str(ca_private_key)},
                    label=SELF_SIGNED_CA_SECRET_LABEL,
                    owner="app",
                )
            },
            leader=True,
        )

        with patch(
            "notary.Notary.__new__",
            return_value=Mock(
                **{
                    "is_api_available.return_value": False,
                    "is_initialized.return_value": False,
                    "login.return_value": None,
                },
            ),
        ):
            context.run(context.on.update_status(), state)

        with open(tmp_path / "certificate.pem") as f:
            saved_cert = f.read()
        assert saved_cert == str(existing_certificate)


SELF_MEMBER_NAME = "notary-k8s-0"
PEER_MEMBER_NAME = "notary-k8s-1"


def _member(name: str, address: str, api_address: str = "") -> ClusterMember:
    return ClusterMember(
        name=name,
        id=1,
        address=address,
        api_address=api_address,
        role="voter",
        leader=False,
    )


class TestCharmCluster:
    """Tests for dqlite cluster coordination over the peer relation."""

    def test_follower_publishes_its_own_access_certificate_request(self, tmp_path: Path):
        context = Context(NotaryCharm, unit_id=1)
        relation = Relation(endpoint=TLS_ACCESS_RELATION_NAME, interface="tls-certificates")
        state = self._base_state(tmp_path, leader=False)
        state = replace(state, relations={relation})
        with patch("notary.Notary.__new__", return_value=self._cluster_mock()):
            out = context.run(context.on.relation_created(relation), state)
        relation_out = out.get_relation(relation.id)
        assert json.loads(relation_out.local_unit_data["certificate_signing_requests"])
        assert "certificate_signing_requests" not in relation_out.local_app_data

    @pytest.mark.parametrize("leader", [False, True])
    def test_first_access_certificate_is_installed(
        self, context: Context[NotaryCharm], tmp_path: Path, leader: bool
    ):
        relation = Relation(endpoint=TLS_ACCESS_RELATION_NAME, interface="tls-certificates")
        state = self._base_state(tmp_path, leader=leader, with_db_state=True)
        state = replace(state, relations={relation})
        certificate, ca, _, private_key = TestCharm().example_certs_and_key()
        assigned = Mock(certificate=certificate, ca=ca)
        with (
            patch("notary.Notary.__new__", return_value=self._cluster_mock()),
            patch(
                f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate",
                return_value=(assigned, private_key),
            ),
        ):
            context.run(context.on.relation_changed(relation), state)
        assert (tmp_path / "config/certificate.pem").read_text() == str(certificate)
        assert (tmp_path / "config/private_key.pem").read_text() == str(private_key)
        assert (tmp_path / "config/ca.pem").read_text() == str(ca)

    def test_incomplete_access_certificate_does_not_fail_relation_hook(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        relation = Relation(endpoint=TLS_ACCESS_RELATION_NAME, interface="tls-certificates")
        state = replace(
            self._base_state(tmp_path, leader=True, with_db_state=True), relations={relation}
        )
        with (
            patch("notary.Notary.__new__", return_value=self._cluster_mock()),
            patch(
                f"{TLS_LIB_PATH}.TLSCertificatesRequiresV4.get_assigned_certificate",
                side_effect=KeyError("certificate"),
            ),
        ):
            context.run(context.on.relation_changed(relation), state)

    @pytest.fixture(scope="function")
    def context(self):
        yield Context(NotaryCharm)

    @staticmethod
    def _login_secret() -> Secret:
        return Secret(
            {"email": "admin@example.com", "password": "password", "token": "test-token"},
            label=NOTARY_LOGIN_SECRET_LABEL,
            owner="app",
        )

    @staticmethod
    def _tokens_secret(tokens: dict[str, str], minted_at: datetime | None = None) -> Secret:
        minted_at = minted_at or datetime.now(timezone.utc)
        content = json.dumps(
            {
                name: {"token": token, "minted_at": minted_at.isoformat()}
                for name, token in tokens.items()
            }
        )
        return Secret({"tokens": content}, label=CLUSTER_JOIN_SECRET_LABEL, owner="app")

    @staticmethod
    def _cluster_mock(**overrides: object) -> Mock:
        spec: dict = {
            "is_api_available.return_value": True,
            "is_initialized.return_value": True,
            "token_is_valid.return_value": True,
            "login.return_value": LoginResponse(token="refreshed-token"),
            "get_version.return_value": "1.0.0",
            "list_cluster_members.return_value": [_member(SELF_MEMBER_NAME, "10.0.0.1:9000")],
            "create_cluster_join_token.return_value": CreateClusterMemberResponse(
                server_name=PEER_MEMBER_NAME, join_token="join-token-1"
            ),
            "delete_cluster_member.return_value": True,
        }
        spec.update(overrides)
        return Mock(**spec)  # type: ignore

    def _base_state(
        self,
        tmp_path: Path,
        *,
        leader: bool,
        peer_relation: PeerRelation | None = None,
        secrets: set[Secret] | None = None,
        with_db_state: bool = False,
    ) -> State:
        config_mount = Mount(location="/etc/notary/config", source=tmp_path / "config")
        db_mount = Mount(location="/var/lib/notary/database", source=tmp_path / "db")
        (tmp_path / "config").mkdir(parents=True, exist_ok=True)
        (tmp_path / "db").mkdir(parents=True, exist_ok=True)
        if with_db_state:
            (tmp_path / "db" / "dqlite").mkdir(parents=True, exist_ok=True)
            (tmp_path / "db" / "dqlite" / "info.yaml").write_text("ID: 1\n")
        return State(
            storages={Storage(name="config"), Storage(name="database")},
            containers=[
                Container(
                    name="notary",
                    can_connect=True,
                    mounts={"config": config_mount, "database": db_mount},
                )
            ],
            relations={peer_relation} if peer_relation else set(),
            secrets=secrets or set(),
            leader=leader,
        )

    def test_given_non_leader_without_join_token_when_configure_then_service_not_started(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(endpoint=PEER_RELATION_NAME, interface="notary_peers")
        state = self._base_state(tmp_path, leader=False, peer_relation=peer)

        with patch(
            "notary.Notary.__new__",
            return_value=self._cluster_mock(),
        ):
            out = context.run(context.on.update_status(), state)

        root = out.get_container("notary").get_filesystem(context)
        assert not (root / "etc/notary/config/config.yaml").exists()
        assert "notary" not in out.get_container("notary").plan.services
        assert out.unit_status == ops.WaitingStatus("waiting for cluster join token")

    @pytest.mark.parametrize(
        "app_data",
        [
            {"bootstrap_unit": "notary-k8s/1"},
            {"bootstrap_unit": "notary-k8s/0", "cluster_established": "true"},
        ],
    )
    def test_leadership_does_not_reset_bootstrap_authorization(
        self, context: Context[NotaryCharm], tmp_path: Path, app_data: dict[str, str]
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME, interface="notary_peers", local_app_data=app_data
        )
        state = self._base_state(tmp_path, leader=True, peer_relation=peer)
        with patch("notary.Notary.__new__", return_value=self._cluster_mock()):
            out = context.run(context.on.leader_elected(), state)
        assert "notary" not in out.get_container("notary").plan.services
        assert app_data.items() <= out.get_relation(peer.id).local_app_data.items()

    def test_bootstrap_decision_precedes_service_start(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(endpoint=PEER_RELATION_NAME, interface="notary_peers")
        state = self._base_state(tmp_path, leader=True, peer_relation=peer)
        with (
            patch("notary.Notary.__new__", return_value=self._cluster_mock()),
            patch.object(NotaryCharm, "_configure_pebble_plan") as start,
        ):
            with context(context.on.start(), state) as manager:
                start.side_effect = lambda: self._assert_bootstrap_owner(manager.charm)
                manager.run()
        start.assert_called_once()

    def test_fresh_leader_gets_admission_from_peer(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer_url = "https://notary-k8s-1.notary-k8s-endpoints.model.svc:2111"
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            local_app_data={"bootstrap_unit": "notary-k8s/1", "cluster_established": "true"},
            peers_data={1: {"api_address": peer_url, "has_cluster_state": "true"}},
        )
        state = self._base_state(
            tmp_path, leader=True, peer_relation=peer, secrets={self._login_secret()}
        )
        local = self._cluster_mock(**{"is_api_available.return_value": False})
        remote = self._cluster_mock(
            **{"list_cluster_members.return_value": [_member(PEER_MEMBER_NAME, "peer:9000")]}
        )
        with patch("charm.Notary", side_effect=[local, remote, remote]) as clients:
            out = context.run(context.on.leader_elected(), state)
        remote.create_cluster_join_token.assert_called_with(SELF_MEMBER_NAME, "test-token")
        local.create_cluster_join_token.assert_not_called()
        assert clients.call_args_list[1].args == (
            peer_url,
            "/var/lib/juju/storage/config/0/ca.pem",
        )
        config = yaml.safe_load((tmp_path / "config/config.yaml").read_text())
        assert config["cluster"]["join_token"] == "join-token-1"
        assert "notary" in out.get_container("notary").plan.services

    def test_unreachable_peer_does_not_authorize_bootstrap(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            local_app_data={"bootstrap_unit": "notary-k8s/1"},
            peers_data={1: {"api_address": "https://peer:2111"}},
        )
        state = self._base_state(
            tmp_path, leader=True, peer_relation=peer, secrets={self._login_secret()}
        )
        unavailable = self._cluster_mock(**{"list_cluster_members.return_value": None})
        with patch("charm.Notary", return_value=unavailable):
            out = context.run(context.on.leader_elected(), state)
        unavailable.create_cluster_join_token.assert_not_called()
        assert "notary" not in out.get_container("notary").plan.services
        assert out.get_relation(peer.id).local_app_data["bootstrap_unit"] == "notary-k8s/1"

    @staticmethod
    def _assert_bootstrap_owner(charm: NotaryCharm):
        relation = charm.model.get_relation(PEER_RELATION_NAME)
        assert relation is not None
        assert relation.data[charm.app]["bootstrap_unit"] == charm.unit.name

    def test_given_non_leader_with_join_token_when_configure_then_join_token_in_config(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(endpoint=PEER_RELATION_NAME, interface="notary_peers")
        state = self._base_state(
            tmp_path,
            leader=False,
            peer_relation=peer,
            secrets={self._tokens_secret({SELF_MEMBER_NAME: "join-token-0"})},
        )

        with (
            patch(
                "notary.Notary.__new__",
                return_value=self._cluster_mock(),
            ),
            patch("charm.socket.getfqdn", return_value="notary-0.notary-endpoints.model.svc"),
        ):
            out = context.run(context.on.update_status(), state)

        root = out.get_container("notary").get_filesystem(context)
        config = yaml.safe_load((root / "etc/notary/config/config.yaml").open())
        assert config["cluster"]["name"] == SELF_MEMBER_NAME
        assert config["cluster"]["address"] == "notary-0.notary-endpoints.model.svc:9000"
        assert config["cluster"]["join_token"] == "join-token-0"
        assert "notary" not in out.get_container("notary").plan.services
        assert out.unit_status == ops.WaitingStatus("certificates not yet pushed to workload")

    def test_given_cluster_state_exists_when_configure_then_no_join_token_in_config(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(endpoint=PEER_RELATION_NAME, interface="notary_peers")
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={
                self._login_secret(),
                self._tokens_secret({SELF_MEMBER_NAME: "stale-join-token"}),
            },
        )

        with patch(
            "notary.Notary.__new__",
            return_value=self._cluster_mock(),
        ):
            out = context.run(context.on.update_status(), state)

        root = out.get_container("notary").get_filesystem(context)
        config = yaml.safe_load((root / "etc/notary/config/config.yaml").open())
        assert config["cluster"]["name"] == SELF_MEMBER_NAME
        assert "join_token" not in config["cluster"]

    def test_given_new_peer_unit_when_configure_then_join_token_minted(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "false"}},
        )
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        mock = self._cluster_mock()

        with patch("notary.Notary.__new__", return_value=mock):
            out = context.run(context.on.update_status(), state)

        mock.create_cluster_join_token.assert_called_once_with(PEER_MEMBER_NAME, "test-token")
        secret = out.get_secret(label=CLUSTER_JOIN_SECRET_LABEL)
        assert secret.latest_content
        tokens = json.loads(secret.latest_content["tokens"])
        assert tokens[PEER_MEMBER_NAME]["token"] == "join-token-1"
        assert out.get_relation(peer.id).local_app_data[CLUSTER_DATA_VERSION_KEY]

    def test_pending_join_keeps_its_token(self, context: Context[NotaryCharm], tmp_path: Path):
        peer = PeerRelation(endpoint=PEER_RELATION_NAME, interface="notary_peers")
        state = self._base_state(
            tmp_path,
            leader=False,
            peer_relation=peer,
            with_db_state=True,
            secrets={self._tokens_secret({SELF_MEMBER_NAME: "pending-token"})},
        )
        (tmp_path / "db/dqlite/join").touch()
        with patch("notary.Notary.__new__", return_value=self._cluster_mock()):
            context.run(context.on.update_status(), state)
        config = yaml.safe_load((tmp_path / "config/config.yaml").read_text())
        assert config["cluster"]["join_token"] == "pending-token"

    def test_spent_token_cleanup_does_not_require_restart(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        state = self._base_state(tmp_path, leader=True, with_db_state=True)
        with (
            patch("notary.Notary.__new__", return_value=self._cluster_mock()),
            context(context.on.update_status(), state) as manager,
        ):
            charm = manager.charm
            assert charm._configure_notary_config_file()
            config_path = tmp_path / "config/config.yaml"
            config = yaml.safe_load(config_path.read_text())
            config["cluster"]["join_token"] = "spent-token"
            config_path.write_text(yaml.safe_dump(config))
            assert not charm._configure_notary_config_file()
            assert "join_token" not in yaml.safe_load(config_path.read_text())["cluster"]
            config["port"] = 1234
            config_path.write_text(yaml.safe_dump(config))
            assert charm._configure_notary_config_file()

    def test_given_stale_token_and_member_not_joined_when_configure_then_token_reminted(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "false"}},
        )
        old_mint = datetime.now(timezone.utc) - timedelta(hours=1)
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={
                self._login_secret(),
                self._tokens_secret({PEER_MEMBER_NAME: "expired-token"}, minted_at=old_mint),
            },
        )
        mock = self._cluster_mock()

        with patch("notary.Notary.__new__", return_value=mock):
            out = context.run(context.on.update_status(), state)

        mock.create_cluster_join_token.assert_called_once_with(PEER_MEMBER_NAME, "test-token")
        secret = out.get_secret(label=CLUSTER_JOIN_SECRET_LABEL)
        assert secret.latest_content
        tokens = json.loads(secret.latest_content["tokens"])
        assert tokens[PEER_MEMBER_NAME]["token"] == "join-token-1"

    def test_given_fresh_token_and_member_not_joined_when_configure_then_token_not_reminted(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "false"}},
        )
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={
                self._login_secret(),
                self._tokens_secret({PEER_MEMBER_NAME: "valid-token"}),
            },
        )
        mock = self._cluster_mock()

        with patch("notary.Notary.__new__", return_value=mock):
            out = context.run(context.on.update_status(), state)

        mock.create_cluster_join_token.assert_not_called()
        secret = out.get_secret(label=CLUSTER_JOIN_SECRET_LABEL)
        assert secret.latest_content
        tokens = json.loads(secret.latest_content["tokens"])
        assert tokens[PEER_MEMBER_NAME]["token"] == "valid-token"

    def test_given_member_joined_when_configure_then_token_pruned(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "true"}},
        )
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={
                self._login_secret(),
                self._tokens_secret({PEER_MEMBER_NAME: "consumed-token"}),
            },
        )
        mock = self._cluster_mock(
            **{
                "list_cluster_members.return_value": [
                    _member(SELF_MEMBER_NAME, "10.0.0.1:9000"),
                    _member(PEER_MEMBER_NAME, "10.0.0.2:9000"),
                ]
            }
        )

        with patch("notary.Notary.__new__", return_value=mock):
            out = context.run(context.on.update_status(), state)

        mock.create_cluster_join_token.assert_not_called()
        secret = out.get_secret(label=CLUSTER_JOIN_SECRET_LABEL)
        assert secret.latest_content
        tokens = json.loads(secret.latest_content["tokens"])
        assert tokens == {}

    @pytest.mark.parametrize("leader", [False, True])
    @pytest.mark.parametrize(
        "peer_host", ["notary-k8s-5.notary-k8s-endpoints.model.svc", "[2001:db8::5]"]
    )
    def test_removing_unit_leaves_cluster_before_stopping(
        self, context: Context[NotaryCharm], tmp_path: Path, leader: bool, peer_host: str
    ):
        peer_url = f"https://{peer_host}:2111"
        state = self._base_state(
            tmp_path,
            leader=leader,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        mock = self._cluster_mock(
            **{
                "list_cluster_members.return_value": [
                    _member(SELF_MEMBER_NAME, "10.0.0.1:9000"),
                    _member("notary-k8s-5", f"{peer_host}:9000", "notary.example.com:2111"),
                ]
            }
        )
        peer_client = self._cluster_mock()

        with (
            patch("charm.Notary", side_effect=[mock, peer_client]) as clients,
            patch.object(ops.Container, "stop") as stop,
        ):
            calls = Mock()
            calls.attach_mock(peer_client.delete_cluster_member, "remove")
            calls.attach_mock(stop, "stop")
            context.run(context.on.remove(), state)

        assert clients.call_args_list[1].args == (
            peer_url,
            "/var/lib/juju/storage/config/0/ca.pem",
        )
        mock.delete_cluster_member.assert_not_called()
        peer_client.delete_cluster_member.assert_called_once_with(SELF_MEMBER_NAME, "test-token")
        assert [call[0] for call in calls.mock_calls] == ["remove", "stop"]

    def test_removal_accepts_confirmed_eviction_after_failed_response(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        state = self._base_state(
            tmp_path, leader=False, with_db_state=True, secrets={self._login_secret()}
        )
        survivor = _member(PEER_MEMBER_NAME, "notary-k8s-1:9000")
        local_client = self._cluster_mock(
            **{
                "list_cluster_members.return_value": [
                    _member(SELF_MEMBER_NAME, "notary-k8s-0:9000"),
                    survivor,
                ]
            }
        )
        peer_client = self._cluster_mock(
            **{
                "delete_cluster_member.return_value": False,
                "list_cluster_members.return_value": [survivor],
            }
        )
        with (
            patch("charm.Notary", side_effect=[local_client, peer_client]),
            patch.object(ops.Container, "stop") as stop,
        ):
            context.run(context.on.remove(), state)

        peer_client.delete_cluster_member.assert_called_once_with(SELF_MEMBER_NAME, "test-token")
        peer_client.list_cluster_members.assert_called_once_with("test-token")
        stop.assert_called_once_with("notary")

    @pytest.mark.parametrize("members", [None, [], [_member("", "notary-k8s-1:9000")]])
    def test_failed_removal_does_not_stop_without_confirmed_absence(
        self, context: Context[NotaryCharm], tmp_path: Path, members: list | None
    ):
        state = self._base_state(
            tmp_path, leader=False, with_db_state=True, secrets={self._login_secret()}
        )
        local_client = self._cluster_mock(
            **{
                "list_cluster_members.return_value": [
                    _member(SELF_MEMBER_NAME, "notary-k8s-0:9000"),
                    _member(PEER_MEMBER_NAME, "notary-k8s-1:9000"),
                ]
            }
        )
        peer_client = self._cluster_mock(
            **{
                "delete_cluster_member.return_value": False,
                "list_cluster_members.return_value": members,
            }
        )
        with (
            patch("charm.Notary", side_effect=[local_client, peer_client]),
            patch("charm.time.sleep"),
            patch.object(ops.Container, "stop") as stop,
        ):
            with pytest.raises(Exception, match="Cannot remove this member"):
                context.run(context.on.remove(), state)
        stop.assert_not_called()
        assert peer_client.delete_cluster_member.call_count == 3

    @pytest.mark.parametrize("local_auth_available", [False, True])
    def test_retried_remove_checks_survivor_when_local_api_is_unavailable(
        self, context: Context[NotaryCharm], tmp_path: Path, local_auth_available: bool
    ):
        peer_url = "https://notary-k8s-1:2111"
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            peers_data={1: {"api_address": peer_url}},
        )
        state = self._base_state(
            tmp_path,
            leader=False,
            with_db_state=True,
            secrets={self._login_secret()},
            peer_relation=peer,
        )
        local_client = self._cluster_mock(
            **{
                "list_cluster_members.return_value": None,
                "token_is_valid.return_value": local_auth_available,
                "login.return_value": None,
                "is_api_available.return_value": False,
            }
        )
        peer_client = self._cluster_mock(
            **{
                "list_cluster_members.return_value": [
                    _member(PEER_MEMBER_NAME, "notary-k8s-1:9000")
                ]
            }
        )
        with (
            patch("charm.Notary", side_effect=[local_client, peer_client]) as clients,
            patch.object(ops.Container, "stop") as stop,
        ):
            context.run(context.on.remove(), state)

        assert clients.call_args_list[1].args[0] == peer_url
        peer_client.list_cluster_members.assert_called_once_with("test-token")
        peer_client.delete_cluster_member.assert_not_called()
        stop.assert_called_once_with("notary")

    def test_removing_unit_tries_another_peer_when_removal_fails(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        state = self._base_state(
            tmp_path,
            leader=False,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        members = [
            _member(SELF_MEMBER_NAME, "10.0.0.1:9000"),
            _member("notary-k8s-5", "10.0.0.5:9000", "notary-k8s-5:2111"),
            _member("notary-k8s-6", "10.0.0.6:9000", "notary-k8s-6:2111"),
        ]
        local_client = self._cluster_mock(**{"list_cluster_members.return_value": members})
        first_peer = self._cluster_mock(**{"delete_cluster_member.return_value": False})
        second_peer = self._cluster_mock()

        with (
            patch("charm.Notary", side_effect=[local_client, first_peer, second_peer]),
            patch.object(ops.Container, "stop") as stop,
        ):
            context.run(context.on.remove(), state)

        first_peer.delete_cluster_member.assert_called_once_with(SELF_MEMBER_NAME, "test-token")
        second_peer.delete_cluster_member.assert_called_once_with(SELF_MEMBER_NAME, "test-token")
        stop.assert_called_once_with("notary")

    def test_removing_unit_retries_after_transient_removal_failure(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        state = self._base_state(
            tmp_path,
            leader=False,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        members = [
            _member(SELF_MEMBER_NAME, "10.0.0.1:9000"),
            _member("notary-k8s-5", "10.0.0.5:9000", "notary-k8s-5:2111"),
        ]
        local_client = self._cluster_mock(**{"list_cluster_members.return_value": members})
        peer_client = self._cluster_mock(**{"delete_cluster_member.side_effect": [False, True]})

        with (
            patch("charm.Notary", side_effect=[local_client, peer_client]),
            patch("charm.time.sleep") as sleep,
            patch.object(ops.Container, "stop") as stop,
        ):
            context.run(context.on.remove(), state)

        assert peer_client.delete_cluster_member.call_count == 2
        sleep.assert_called_once_with(2)
        stop.assert_called_once_with("notary")

    @pytest.mark.parametrize("members", [None, []])
    def test_removal_does_not_guess_membership(
        self, context: Context[NotaryCharm], tmp_path: Path, members: list | None
    ):
        state = self._base_state(
            tmp_path,
            leader=False,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        local_client = self._cluster_mock(**{"list_cluster_members.return_value": members})
        with (
            patch("charm.Notary", return_value=local_client),
            patch.object(ops.Container, "stop") as stop,
        ):
            if members is None:
                with pytest.raises(Exception, match="Cannot determine cluster membership"):
                    context.run(context.on.remove(), state)
                stop.assert_not_called()
            else:
                context.run(context.on.remove(), state)
                stop.assert_called_once_with("notary")
        local_client.delete_cluster_member.assert_not_called()

    def test_last_member_is_not_removed(self, context: Context[NotaryCharm], tmp_path: Path):
        state = self._base_state(
            tmp_path, leader=True, with_db_state=True, secrets={self._login_secret()}
        )
        mock = self._cluster_mock()
        with (
            patch("notary.Notary.__new__", return_value=mock),
            patch.object(ops.Container, "stop") as stop,
        ):
            context.run(context.on.remove(), state)
        mock.delete_cluster_member.assert_not_called()
        stop.assert_called_once_with("notary")

    def test_reconciliation_does_not_remove_unexpected_members(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "true"}},
        )
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        mock = self._cluster_mock(
            **{
                "list_cluster_members.return_value": [
                    _member(SELF_MEMBER_NAME, "10.0.0.1:9000"),
                    _member("", "10.9.9.9:9000"),
                    _member("", "10.0.0.2:9000"),
                ]
            }
        )

        with patch("notary.Notary.__new__", return_value=mock):
            context.run(context.on.update_status(), state)

        mock.delete_cluster_member.assert_not_called()

    def test_given_members_list_unavailable_when_configure_then_no_members_removed(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(endpoint=PEER_RELATION_NAME, interface="notary_peers")
        state = self._base_state(
            tmp_path,
            leader=True,
            peer_relation=peer,
            with_db_state=True,
            secrets={self._login_secret()},
        )
        mock = self._cluster_mock(**{"list_cluster_members.return_value": None})

        with patch("notary.Notary.__new__", return_value=mock):
            context.run(context.on.update_status(), state)

        mock.delete_cluster_member.assert_not_called()
        mock.create_cluster_join_token.assert_not_called()

    def test_given_leader_without_state_and_peer_reports_state_when_configure_then_no_bootstrap(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "true"}},
        )
        state = self._base_state(tmp_path, leader=True, peer_relation=peer)

        with patch(
            "notary.Notary.__new__",
            return_value=self._cluster_mock(),
        ):
            out = context.run(context.on.update_status(), state)

        root = out.get_container("notary").get_filesystem(context)
        assert not (root / "etc/notary/config/config.yaml").exists()
        assert out.unit_status == ops.WaitingStatus("waiting for cluster join token")

    def test_given_fresh_leader_when_configure_then_cluster_bootstrapped(
        self, context: Context[NotaryCharm], tmp_path: Path
    ):
        peer = PeerRelation(
            endpoint=PEER_RELATION_NAME,
            interface="notary_peers",
            peers_data={1: {"cluster_address": "10.0.0.2:9000", "has_cluster_state": "false"}},
        )
        state = self._base_state(tmp_path, leader=True, peer_relation=peer)

        with patch(
            "notary.Notary.__new__",
            return_value=self._cluster_mock(),
        ):
            out = context.run(context.on.update_status(), state)

        root = out.get_container("notary").get_filesystem(context)
        config = yaml.safe_load((root / "etc/notary/config/config.yaml").open())
        assert config["cluster"]["name"] == SELF_MEMBER_NAME
        assert "join_token" not in config["cluster"]
        assert "notary" in out.get_container("notary").plan.services
        peer_out = out.get_relation(peer.id)
        assert peer_out.local_unit_data["cluster_address"]
        assert peer_out.local_unit_data["has_cluster_state"] == "false"


class TestNotaryClient:
    @pytest.mark.parametrize("existing_cookie", [False, True])
    def test_expired_token_refresh_uses_only_the_requested_cookie(self, existing_cookie: bool):
        received_cookies: list[str | None] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cookie = self.headers.get("Cookie")
                received_cookies.append(cookie)
                self.send_response(200 if cookie == "user_token=fresh" else 401)
                self.end_headers()
                self.wfile.write(b'{"data": {}, "message": ""}')

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Set-Cookie", "user_token=fresh; Path=/; HttpOnly")
                self.end_headers()

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client = object.__new__(Notary)
            client.__init__(f"http://127.0.0.1:{server.server_port}")
            client.session.trust_env = False
            if existing_cookie:
                client.session.cookies.set("user_token", "old", domain="127.0.0.1", path="/")
            try:
                assert not client.token_is_valid("expired")
                response = client.login("admin@example.com", "password")
                assert response and response.token == "fresh"
                assert client.token_is_valid(response.token)
                assert not client.token_is_valid("expired")
                assert received_cookies == [
                    "user_token=expired",
                    "user_token=fresh",
                    "user_token=expired",
                ]
            finally:
                client.session.close()
                server.shutdown()
                thread.join()

    @pytest.mark.parametrize("operation", ["membership", "login"])
    def test_request_timeout_is_bounded_and_handled(self, operation: str):
        client = object.__new__(Notary)
        client.__init__("https://unreachable:2111", ca_path="/trusted/ca.pem")
        with patch.object(client.session, "request", side_effect=requests.Timeout) as request:
            if operation == "membership":
                assert client.list_cluster_members("token") is None
            else:
                assert client.login("admin@example.com", "password") is None
        assert request.call_args.kwargs["timeout"] == (5, 60)
        assert request.call_args.kwargs["verify"] == "/trusted/ca.pem"


class TestIntegrationDiagnostics:
    @pytest.fixture
    def helpers(self):
        path = Path(__file__).parents[1] / "integration/test_charm.py"
        spec = importlib.util.spec_from_file_location("integration_helpers", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @pytest.mark.parametrize(
        "command",
        [("stop", "notary"), ("start", "notary"), ("services",), ("logs", "-n", "200", "notary")],
    )
    def test_pebble_uses_charm_container_socket(
        self, helpers: ModuleType, command: tuple[str, ...]
    ):
        juju = Mock()
        juju.cli.return_value = "pebble output"

        assert helpers.run_notary_pebble(juju, "notary-k8s/1", *command) == "pebble output"

        juju.cli.assert_called_once_with(
            "ssh",
            "--container",
            "charm",
            "notary-k8s/1",
            "env",
            "PEBBLE_SOCKET=/charm/containers/notary/pebble.socket",
            "/charm/bin/pebble",
            *command,
        )

    def test_collection_requests_bounded_pebble_logs(
        self, helpers: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        juju = Mock()
        juju.debug_log.return_value = "hook logs"
        juju.cli.return_value = "unit data"
        juju.status.return_value.apps = {helpers.APP_NAME: Mock(units={"notary-k8s/0": Mock()})}
        with patch.object(helpers, "run_notary_pebble", return_value="workload output") as pebble:
            helpers.collect_failure_diagnostics(juju)

        assert [entry.args for entry in pebble.call_args_list] == [
            (juju, "notary-k8s/0", "services"),
            (juju, "notary-k8s/0", "logs", "-n", "200", "notary"),
        ]
        assert "workload output" in (tmp_path / "juju-debug.log").read_text()

    def test_snapshots_are_appended(
        self, helpers: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        helpers.append_diagnostic("juju-debug.log", "first", lambda: "first failure")
        helpers.append_diagnostic("juju-debug.log", "second", lambda: "later failure")
        content = (tmp_path / "juju-debug.log").read_text()
        assert "first failure" in content
        assert "later failure" in content

    def test_collection_failure_preserves_fail_fast_result(
        self, helpers: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        juju = Mock()
        juju.debug_log.side_effect = RuntimeError("controller unavailable")
        juju.status.side_effect = RuntimeError("controller unavailable")
        with patch.object(helpers.jubilant, "any_error", return_value=True):
            assert helpers.on_app_error(juju)(Mock()) is True

    def test_timeout_triggers_collection(self, helpers: ModuleType):
        request = Mock()
        request.session.testsfailed = 0
        juju = Mock()
        fixture = helpers.capture_test_failure.__wrapped__(juju, request)
        next(fixture)
        request.session.testsfailed = 1
        with patch.object(helpers, "collect_failure_diagnostics") as collect:
            with pytest.raises(StopIteration):
                next(fixture)
        collect.assert_called_once_with(juju)
