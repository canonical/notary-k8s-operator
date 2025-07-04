#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from base64 import b64decode
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateSigningRequest,
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from juju.application import Application
from juju.client.client import SecretsFilter
from pytest_operator.plugin import OpsTest

from charm import NOTARY_LOGIN_SECRET_LABEL
from notary import Notary

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = CHARMCRAFT["name"]

LOKI_APPLICATION_NAME = "loki-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
TRAEFIK_K8S_APPLICATION_NAME = "traefik-k8s"
TLS_PROVIDER_APPLICATION_NAME = "self-signed-certificates"
TLS_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, request: pytest.FixtureRequest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    charm = Path(request.config.getoption("--charm_path")).resolve()  # type: ignore
    resources = {"notary-image": CHARMCRAFT["resources"]["notary-image"]["upstream-source"]}

    assert ops_test.model
    await ops_test.model.deploy(charm, resources=resources, application_name=APP_NAME)
    await ops_test.model.deploy(
        "self-signed-certificates",
        application_name=TLS_PROVIDER_APPLICATION_NAME,
        channel="edge",
    )
    await ops_test.model.deploy(
        "tls-certificates-requirer",
        application_name=TLS_REQUIRER_APPLICATION_NAME,
        channel="edge",
    )
    await ops_test.model.deploy(
        "prometheus-k8s",
        application_name=PROMETHEUS_APPLICATION_NAME,
        trust=True,
    )
    await ops_test.model.deploy(
        "loki-k8s", application_name=LOKI_APPLICATION_NAME, trust=True, channel="stable"
    )
    await ops_test.model.deploy(
        TRAEFIK_K8S_APPLICATION_NAME,
        application_name=TRAEFIK_K8S_APPLICATION_NAME,
        trust=True,
        channel="stable",
    )
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.abort_on_fail
async def test_given_tls_access_relation_when_related_and_unrelated_to_notary_then_certificates_replaced_appropriately(
    ops_test: OpsTest,
):
    assert ops_test.model

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_PROVIDER_APPLICATION_NAME],
        status="active",
        timeout=1000,
        raise_on_error=True,
    )

    first_ca = await get_file_from_notary(ops_test, "ca.pem")
    assert first_ca.startswith("-----BEGIN CERTIFICATE-----")

    await ops_test.model.integrate(
        relation1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:access-certificates",
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, TLS_PROVIDER_APPLICATION_NAME],
            status="active",
            timeout=1000,
            raise_on_error=True,
        )
    new_ca = await get_file_from_notary(ops_test, "ca.pem")
    assert new_ca != first_ca

    notary_app = ops_test.model.applications[APP_NAME]
    assert isinstance(notary_app, Application)
    await notary_app.remove_relation(
        "access-certificates", f"{TLS_PROVIDER_APPLICATION_NAME}:certificates"
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, TLS_PROVIDER_APPLICATION_NAME],
            status="active",
            timeout=1000,
            raise_on_error=True,
        )
    final_ca = await get_file_from_notary(ops_test, "ca.pem")
    assert final_ca != new_ca


@pytest.mark.abort_on_fail
async def test_given_notary_when_tls_requirer_related_then_csr_uploaded_to_notary_and_certificate_provided_to_requirer(
    ops_test: OpsTest,
):
    assert ops_test.model
    admin_credentials = await get_notary_credentials(ops_test)
    token = admin_credentials.get("token")
    assert token
    endpoint = await get_notary_endpoint(ops_test)
    client = Notary(url=endpoint)
    assert client.token_is_valid(token)

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:certificates",
        relation2=f"{TLS_REQUIRER_APPLICATION_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_REQUIRER_APPLICATION_NAME],
        status="active",
        timeout=1000,
        raise_on_error=True,
    )
    certificate_requests = client.list_certificate_requests(token)
    assert len(certificate_requests) == 1

    certificate_request = certificate_requests[0]
    ca_pk = generate_private_key()
    ca = generate_ca(ca_pk, timedelta(days=365), "integration-test")
    cert = generate_certificate(
        CertificateSigningRequest.from_string(certificate_request.csr),
        ca,
        ca_pk,
        timedelta(days=365),
    )
    chain = [str(cert), str(ca)]
    client.create_certificate_from_csr(certificate_request.csr, chain, token)

    certificate_requests = client.list_certificate_requests(token)
    assert certificate_requests[0].certificate_chain != ""
    assert certificate_requests[0].certificate_chain != "rejected"

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_REQUIRER_APPLICATION_NAME],
        status="active",
        timeout=1000,
        raise_on_error=True,
    )

    action_result = await run_get_certificate_action(ops_test)
    given_certificate: str = json.loads(action_result)[0].get("certificate", "")
    assert given_certificate.replace("\n", "") == str(cert).replace("\n", "")


@pytest.mark.abort_on_fail
async def test_given_loki_and_prometheus_related_to_notary_all_charm_statuses_active(
    ops_test: OpsTest,
):
    """Deploy loki and prometheus, and make sure all applications are active."""
    assert ops_test.model

    await asyncio.gather(
        ops_test.model.integrate(
            relation1=f"{APP_NAME}:logging",
            relation2=f"{LOKI_APPLICATION_NAME}",
        ),
        ops_test.model.integrate(
            relation1=f"{APP_NAME}:metrics",
            relation2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint",
        ),
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, PROMETHEUS_APPLICATION_NAME, LOKI_APPLICATION_NAME],
        status="active",
        timeout=1000,
        raise_on_error=True,
    )


@pytest.mark.abort_on_fail
async def test_given_application_deployed_when_related_to_traefik_k8s_then_all_statuses_active(
    ops_test: OpsTest,
):
    # TODO (Tracked in TLSENG-475): This is a workaround so Traefik has the same CA as Notary
    # This should be removed and certificate transfer should be used instead
    # Notary k8s implements V1 of the certificate transfer interface,
    # And the following PR is needed to get Traefik to use it too:
    # https://github.com/canonical/traefik-k8s-operator/issues/407
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
        relation2=f"{TRAEFIK_K8S_APPLICATION_NAME}",
    )
    await ops_test.model.integrate(
        relation1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:access-certificates",
    )
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:ingress",
        relation2=f"{TRAEFIK_K8S_APPLICATION_NAME}:ingress",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TRAEFIK_K8S_APPLICATION_NAME],
        status="active",
        timeout=1000,
        raise_on_error=True,
    )
    endpoint = await get_external_notary_endpoint(ops_test)
    client = Notary(url=endpoint)
    assert client.is_api_available()


async def get_notary_endpoint(ops_test: OpsTest) -> str:
    assert ops_test.model
    status = await ops_test.model.get_status()
    notary_ip = status.applications[APP_NAME].units[f"{APP_NAME}/0"].address  # type: ignore[reportOptionalMemberAccess]
    return f"https://{notary_ip}:2111"


async def get_external_notary_endpoint(ops_test: OpsTest) -> str:
    assert ops_test.model
    traefik_proxied_endpoints = await run_show_traefik_proxied_endpoints_action(ops_test)
    return json.loads(traefik_proxied_endpoints).get(APP_NAME, "").get("url", "")


async def get_notary_credentials(ops_test: OpsTest) -> dict[str, str]:
    assert ops_test.model
    secrets = await ops_test.model.list_secrets(
        filter=SecretsFilter(label=NOTARY_LOGIN_SECRET_LABEL), show_secrets=True
    )
    return {
        field: b64decode(secrets[0].value.data[field]).decode("utf-8")
        for field in ["username", "password", "token"]
    }


async def run_get_certificate_action(ops_test: OpsTest) -> str:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{TLS_REQUIRER_APPLICATION_NAME}/0"]
    action = await tls_requirer_unit.run_action(action_name="get-certificate")  # type: ignore
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=30)
    return action_output.get("certificates", "")


async def run_show_traefik_proxied_endpoints_action(ops_test: OpsTest) -> str:
    assert ops_test.model
    traefik_k8s_unit = ops_test.model.units[f"{TRAEFIK_K8S_APPLICATION_NAME}/0"]
    action = await traefik_k8s_unit.run_action(action_name="show-proxied-endpoints")  # type: ignore
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=30)
    return action_output.get("proxied-endpoints", "")


async def get_file_from_notary(ops_test: OpsTest, file_name: str) -> str:
    notary_unit = ops_test.model.units[f"{APP_NAME}/0"]  # type: ignore
    action = await notary_unit.run(f"cat /var/lib/juju/storage/config/0/{file_name}")  # type: ignore
    await action.wait()
    return action.results["stdout"]
