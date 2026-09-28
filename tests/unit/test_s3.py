# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from s3 import S3Parameters, s3_client


@pytest.fixture
def connection():
    return {
        "bucket": "backups",
        "endpoint": "https://s3.example.com",
        "access-key": "access",
        "secret-key": "secret",
    }


@pytest.mark.parametrize("key", ["bucket", "endpoint", "access-key", "secret-key"])
@pytest.mark.parametrize("value", [None, "", " ", 42])
def test_missing_parameters(connection: Any, key: Any, value: Any):
    connection[key] = value
    with pytest.raises(ValueError, match=key):
        S3Parameters.from_relation(connection)


def test_normalization_and_credential_redaction(connection: Any):
    connection.update(path=" /notary/backups/ ", region=" eu-west-1 ", bucket=" backups ")
    params = S3Parameters.from_relation(connection)
    assert params.path == "notary/backups/"
    assert params.region == "eu-west-1"
    assert params.bucket == "backups"
    assert "secret" not in repr(params)
    assert "access" not in repr(params)


@pytest.mark.parametrize("chain", ["certificate", [1], [""]])
def test_invalid_ca_chain(connection: Any, chain: Any):
    connection["tls-ca-chain"] = chain
    with pytest.raises(ValueError, match="tls-ca-chain"):
        S3Parameters.from_relation(connection)


@pytest.mark.parametrize("endpoint", ["s3.example.com", "ftp://s3.example.com", "https://"])
def test_invalid_endpoint(connection: Any, endpoint: Any):
    connection["endpoint"] = endpoint
    with pytest.raises(ValueError, match="endpoint"):
        S3Parameters.from_relation(connection)


def test_ca_bundle_lifetime_and_client_cleanup(connection: Any):
    connection["tls-ca-chain"] = ["CERTIFICATE ONE", "CERTIFICATE TWO"]
    ca_path = None
    with patch("s3.Session") as session:
        with pytest.raises(RuntimeError), s3_client(S3Parameters.from_relation(connection)):
            ca_path = Path(session.return_value.client.call_args.kwargs["verify"])
            assert ca_path.read_text() == "CERTIFICATE ONE\nCERTIFICATE TWO"
            raise RuntimeError("operation failed")
        assert ca_path is not None and not ca_path.exists()
        session.return_value.client.return_value.close.assert_called_once()


def test_default_tls_and_juju_proxy(connection: Any, monkeypatch: Any):
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", "http://proxy:3128")
    with patch("s3.Session") as session:
        with s3_client(S3Parameters.from_relation(connection)):
            kwargs = session.return_value.client.call_args.kwargs
            assert kwargs["verify"] is True
            assert kwargs["config"].proxies == {"https": "http://proxy:3128"}


def test_relation_join_requests_bucket():
    from scenario import Container, Context, Relation, State

    from charm import NotaryCharm

    relation = Relation("s3-parameters")
    context = Context(NotaryCharm)
    state = context.run(
        context.on.relation_joined(relation),
        State(leader=True, relations={relation}, containers={Container("notary")}),
    )
    assert state.get_relation(relation.id).local_app_data["bucket"] == f"relation-{relation.id}"


def test_relation_credentials_are_read_fresh(connection: Any):
    from scenario import Container, Context, Relation, State

    from charm import NotaryCharm

    relation = Relation("s3-parameters", remote_app_data=connection)
    context = Context(NotaryCharm)
    with context(
        context.on.relation_changed(relation),
        State(leader=True, relations={relation}, containers={Container("notary")}),
    ) as manager:
        params = S3Parameters.from_relation(manager.charm.s3_requirer.get_s3_connection_info())
        assert params.bucket == "backups"
        assert params.secret_key == "secret"
