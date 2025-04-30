#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import jubilant
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


@pytest.fixture(scope='module')
def juju():
    with jubilant.temp_model() as juju:
        yield juju

@pytest.mark.abort_on_fail
async def test_build_and_deploy(juju: jubilant.Juju, request: pytest.FixtureRequest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    charm = Path(request.config.getoption("--charm_path")).resolve()  # type: ignore
    resources = {"notary-image": CHARMCRAFT["resources"]["notary-image"]["upstream-source"]}

    juju.model_config({"update-status-relation-interval": "10s"})
    juju.deploy(charm, resources=resources)
    juju.deploy("self-signed-certificates", channel="edge")
    juju.deploy("tls-certificates-requirer", channel="edge")
    juju.deploy("prometheus-k8s", channel="edge")
    juju.deploy("loki-k8s", channel="edge")
    juju.deploy("traefik-k8s", channel="stable")


@pytest.mark.abort_on_fail
async def test_given_tls_access_relation_when_related_and_unrelated_to_notary_then_certificates_replaced_appropriately(
    juju: jubilant.Juju,
):
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME))
    first_ca = await get_file_from_notary(juju, "ca.pem")
    assert first_ca.startswith("-----BEGIN CERTIFICATE-----")

    juju.integrate(app1=f"{APP_NAME}:certificates", app2=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates")
    juju.wait(lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME) and jubilant.all_active(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME))
    
    new_ca = await get_file_from_notary(juju, "ca.pem")
    assert new_ca != first_ca

    juju.remove_relation(app1=f"{APP_NAME}:certificates", app2=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates")
    juju.wait(lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME) and jubilant.all_active(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME))

    final_ca = await get_file_from_notary(juju, "ca.pem")
    assert final_ca != new_ca


@pytest.mark.abort_on_fail
async def test_given_notary_when_tls_requirer_related_then_csr_uploaded_to_notary_and_certificate_provided_to_requirer(
    juju: jubilant.Juju,
):
    admin_credentials = await get_notary_credentials(juju)
    token = admin_credentials["token"]
    endpoint = await get_notary_endpoint(juju)
    client = Notary(url=endpoint)
    assert client.token_is_valid(token)

    juju.integrate(
        app1=f"{APP_NAME}:certificates",
        app2=f"{TLS_REQUIRER_APPLICATION_NAME}:certificates",
    )
    juju.wait(lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME) and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME))

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

    juju.wait(lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME) and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME))

    action_result = await run_get_certificate_action(juju)
    given_certificate: str = json.loads(action_result)[0].get("certificate", "")
    assert given_certificate.replace("\n", "") == str(cert).replace("\n", "")


@pytest.mark.abort_on_fail
async def test_given_loki_and_prometheus_related_to_notary_all_charm_statuses_active(
    juju: jubilant.Juju,
):
    """Deploy loki and prometheus, and make sure all applications are active."""
    juju.integrate(app1=f"{APP_NAME}:logging", app2=f"{LOKI_APPLICATION_NAME}")
    juju.integrate(app1=f"{APP_NAME}:metrics", app2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint")
    juju.wait(lambda status: jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME) and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME))


@pytest.mark.abort_on_fail
async def test_given_application_deployed_when_related_to_traefik_k8s_then_all_statuses_active(
    juju: jubilant.Juju,
):
    # TODO (Tracked in TLSENG-475): This is a workaround so Traefik has the same CA as Notary
    # This should be removed and certificate transfer should be used instead
    # Notary k8s implements V1 of the certificate transfer interface,
    # And the following PR is needed to get Traefik to use it too:
    # https://github.com/canonical/traefik-k8s-operator/issues/407
    juju.integrate(app1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates", app2=f"{TRAEFIK_K8S_APPLICATION_NAME}")
    juju.integrate(app1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates", app2=f"{APP_NAME}:access-certificates")
    juju.integrate(app1=f"{APP_NAME}:ingress", app2=f"{TRAEFIK_K8S_APPLICATION_NAME}:ingress")
    juju.wait(lambda status: jubilant.all_agents_idle(status, APP_NAME, TRAEFIK_K8S_APPLICATION_NAME) and jubilant.all_active(status, APP_NAME, TRAEFIK_K8S_APPLICATION_NAME))
    endpoint = await get_external_notary_endpoint(juju)
    client = Notary(url=endpoint)
    assert client.is_api_available()

async def get_notary_endpoint(juju: jubilant.Juju) -> str:
    notary_ip = juju.status().apps[APP_NAME].units[f"{APP_NAME}/0"].address
    return f"https://{notary_ip}:2111"

async def get_external_notary_endpoint(juju: jubilant.Juju) -> str:
    traefik_proxied_endpoints = await run_show_traefik_proxied_endpoints_action(juju)
    return json.loads(traefik_proxied_endpoints).get(APP_NAME, "").get("url", "")


async def get_notary_credentials(juju: jubilant.Juju) -> dict[str, str]:
    print("UNTESTED CODE")
    secret = juju.secret(label=NOTARY_LOGIN_SECRET_LABEL)
    print("RECEIVED SECRET: ", secret)
    return (
        {
            "username": secret.content["username"],
            "password": secret.content["password"],
            "token": secret.content["token"],
        }
    )


async def run_get_certificate_action(juju: jubilant.Juju) -> str:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    result = juju.run(
        unit=f"{TLS_REQUIRER_APPLICATION_NAME}/0",
        action="get-certificate",
    )
    return result.stdout


async def run_show_traefik_proxied_endpoints_action(juju: jubilant.Juju) -> str:
    result = juju.run(
        unit=f"{TRAEFIK_K8S_APPLICATION_NAME}/0",
        action="show-proxied-endpoints",
    )
    return result.stdout


async def get_file_from_notary(juju: jubilant.Juju, file_name: str) -> str:
    result = juju.exec(
        unit=f"{APP_NAME}/0",
        command=f"sudo cat /var/lib/juju/storage/config/0/{file_name}",
    )
    return result.stdout
