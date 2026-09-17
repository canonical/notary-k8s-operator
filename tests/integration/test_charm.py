#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import jubilant
import pytest
import yaml
from charmlibs.interfaces.tls_certificates import (
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

# Revisions (amd64) from the last known-good run, so upstream channel moves cannot break CI.
# Loki/Prometheus stay on the 2 track: newer tracks ship on ubuntu@26.04, whose Python
# rejects the MicroK8s API CA ("CA cert does not include key usage extension").
LOKI_APPLICATION_NAME = "loki-k8s"
LOKI_CHANNEL = "2/stable"
LOKI_REVISION = 217
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
PROMETHEUS_CHANNEL = "2/stable"
PROMETHEUS_REVISION = 301
TRAEFIK_K8S_APPLICATION_NAME = "traefik-k8s"
TRAEFIK_K8S_CHANNEL = "latest/stable"
TRAEFIK_K8S_REVISION = 377
TLS_PROVIDER_APPLICATION_NAME = "self-signed-certificates"
TLS_PROVIDER_CHANNEL = "1/stable"
TLS_PROVIDER_REVISION = 586
TLS_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
TLS_REQUIRER_CHANNEL = "latest/stable"
TLS_REQUIRER_REVISION = 143

JUJU_FAST_INTERVAL = "10s"
JUJU_DEFAULT_INTERVAL = "5m"
INGRESS_READY_TIMEOUT = 5 * 60


@pytest.fixture(scope="module")
def juju(request: pytest.FixtureRequest):
    with jubilant.temp_model() as juju:
        juju.wait_timeout = 10 * 60
        yield juju
        if request.session.testsfailed:
            # Collected here because the model is destroyed before the CI archive step runs.
            Path("juju-debug.log").write_text(juju.debug_log())
            # The provider unit is included so Traefik's certificate request is visible.
            Path("juju-units.yaml").write_text(
                juju.cli(
                    "show-unit",
                    f"{APP_NAME}/0",
                    f"{TRAEFIK_K8S_APPLICATION_NAME}/0",
                    f"{TLS_PROVIDER_APPLICATION_NAME}/0",
                )
            )
            logger.info("Wrote juju-debug.log and juju-units.yaml")


@contextmanager
def fast_forward(juju: jubilant.Juju, interval: str) -> Iterator[None]:
    """Temporarily shorten the model's update-status interval."""
    config = juju.model_config() or {}
    previous = config.get("update-status-hook-interval", JUJU_DEFAULT_INTERVAL)
    juju.model_config({"update-status-hook-interval": interval})
    try:
        yield
    finally:
        juju.model_config({"update-status-hook-interval": previous})


def test_build_and_deploy(juju: jubilant.Juju, request: pytest.FixtureRequest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    charm = Path(request.config.getoption("--charm_path")).resolve()  # type: ignore
    resources = {"notary-image": CHARMCRAFT["resources"]["notary-image"]["upstream-source"]}

    juju.deploy(charm, resources=resources, trust=True)
    juju.deploy(
        TLS_PROVIDER_APPLICATION_NAME,
        channel=TLS_PROVIDER_CHANNEL,
        revision=TLS_PROVIDER_REVISION,
        trust=True,
    )
    juju.deploy(
        TLS_REQUIRER_APPLICATION_NAME,
        channel=TLS_REQUIRER_CHANNEL,
        revision=TLS_REQUIRER_REVISION,
        trust=True,
    )
    juju.deploy(
        PROMETHEUS_APPLICATION_NAME,
        channel=PROMETHEUS_CHANNEL,
        revision=PROMETHEUS_REVISION,
        trust=True,
    )
    juju.deploy(LOKI_APPLICATION_NAME, channel=LOKI_CHANNEL, revision=LOKI_REVISION, trust=True)
    juju.deploy(
        TRAEFIK_K8S_APPLICATION_NAME,
        channel=TRAEFIK_K8S_CHANNEL,
        revision=TRAEFIK_K8S_REVISION,
        trust=True,
    )


def test_given_tls_access_relation_when_related_and_unrelated_to_notary_then_certificates_replaced_correctly(
    juju: jubilant.Juju,
):
    juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME),
        error=lambda status: jubilant.any_error(status, APP_NAME),
    )
    first_ca = get_file_from_notary(juju, "ca.pem")
    assert first_ca.startswith("-----BEGIN CERTIFICATE-----")

    juju.integrate(
        app1=f"{APP_NAME}:access-certificates",
        app2=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
    )
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME)
            and jubilant.all_active(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME)
            and get_file_from_notary(juju, "ca.pem") != first_ca
        ),
        error=lambda status: jubilant.any_error(status, APP_NAME),
    )

    new_ca = get_file_from_notary(juju, "ca.pem")
    assert new_ca != first_ca

    juju.remove_relation(
        app1=f"{APP_NAME}:access-certificates",
        app2=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
    )
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME)
            and jubilant.all_active(status, APP_NAME, TLS_PROVIDER_APPLICATION_NAME)
            and get_file_from_notary(juju, "ca.pem") != new_ca
        ),
        error=lambda status: jubilant.any_error(status, APP_NAME),
    )

    final_ca = get_file_from_notary(juju, "ca.pem")
    assert final_ca != new_ca


def test_given_notary_when_tls_requirer_related_then_csr_uploaded_to_notary_and_certificate_provided_to_requirer(
    juju: jubilant.Juju,
):
    admin_credentials = get_notary_credentials(juju)
    endpoint = get_notary_endpoint(juju)
    client = Notary(url=endpoint, ca_path=False)

    login_response = client.login(admin_credentials["email"], admin_credentials["password"])
    assert login_response is not None
    assert login_response.token
    token = login_response.token
    assert client.token_is_valid(token)

    juju.integrate(
        app1=f"{APP_NAME}:certificates",
        app2=f"{TLS_REQUIRER_APPLICATION_NAME}:certificates",
    )
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
            and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
        ),
        error=lambda status: jubilant.any_error(status, APP_NAME),
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

    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
            and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
        ),
        error=lambda status: jubilant.any_error(status, APP_NAME),
    )

    given_certificate = get_first_certificate_from_requirer(juju)
    assert given_certificate.replace("\n", "") == str(cert).replace("\n", "")


def test_given_loki_and_prometheus_related_to_notary_all_charm_statuses_active(
    juju: jubilant.Juju,
):
    """Deploy loki and prometheus, and make sure all applications are active."""
    juju.integrate(app1=f"{APP_NAME}:logging", app2=f"{LOKI_APPLICATION_NAME}")
    juju.integrate(
        app1=f"{APP_NAME}:metrics", app2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint"
    )
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
            and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
        )
    )


def test_given_application_deployed_when_related_to_traefik_k8s_then_all_statuses_active(
    juju: jubilant.Juju,
):
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, TRAEFIK_K8S_APPLICATION_NAME)
            and jubilant.all_active(status, TRAEFIK_K8S_APPLICATION_NAME)
        ),
        error=lambda status: jubilant.any_error(status, APP_NAME),
    )
    # TODO (Tracked in TLSENG-475): This is a workaround so Traefik has the same CA as Notary
    # This should be removed and certificate transfer should be used instead
    # Notary k8s implements V1 of the certificate transfer interface,
    # And the following PR is needed to get Traefik to use it too:
    # https://github.com/canonical/traefik-k8s-operator/issues/407
    juju.integrate(
        app1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
        app2=f"{TRAEFIK_K8S_APPLICATION_NAME}",
    )
    juju.integrate(
        app1=f"{TLS_PROVIDER_APPLICATION_NAME}:certificates",
        app2=f"{APP_NAME}:access-certificates",
    )
    juju.integrate(app1=f"{APP_NAME}:ingress", app2=f"{TRAEFIK_K8S_APPLICATION_NAME}:ingress")
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda status: (
                jubilant.all_agents_idle(status, APP_NAME, TRAEFIK_K8S_APPLICATION_NAME)
                and jubilant.all_active(status, APP_NAME, TRAEFIK_K8S_APPLICATION_NAME)
            ),
            error=lambda status: jubilant.any_error(status, APP_NAME),
        )

        with tempfile.NamedTemporaryFile("w+") as f:
            cert = get_file_from_notary(juju, "certificate.pem")
            ca = get_file_from_notary(juju, "ca.pem")
            f.write(cert + "\n" + ca)
            f.flush()

            assert_notary_reachable_through_ingress(juju, ca_path=f.name)


def assert_notary_reachable_through_ingress(juju: jubilant.Juju, ca_path: str) -> None:
    """Poll the ingress endpoint until Traefik serves the CA-issued certificate.

    Traefik serves a temporary self-signed certificate until its own request is
    fulfilled, so TLS verification fails until then.
    """
    deadline = time.time() + INGRESS_READY_TIMEOUT
    while time.time() < deadline:
        endpoint = get_external_notary_endpoint(juju)
        if endpoint and Notary(url=endpoint, ca_path=ca_path).is_api_available():
            return
        time.sleep(5)
    raise AssertionError("Notary was not reachable through the Traefik ingress endpoint")


def get_notary_endpoint(juju: jubilant.Juju) -> str:
    notary_ip = juju.status().apps[APP_NAME].units[f"{APP_NAME}/0"].address
    return f"https://{notary_ip}:2111"


def get_notary_credentials(juju: jubilant.Juju) -> dict[str, str]:
    secret = juju.show_secret(NOTARY_LOGIN_SECRET_LABEL, reveal=True)
    return {
        "email": secret.content["email"],
        "password": secret.content["password"],
        "token": secret.content["token"],
    }


def get_first_certificate_from_requirer(juju: jubilant.Juju) -> str:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        juju (Juju): juju

    Returns:
        dict: Action output
    """
    result = juju.run(
        unit=f"{TLS_REQUIRER_APPLICATION_NAME}/0",
        action="get-certificate",
    )
    obj = json.loads(result.results.get("certificates", "{}"))
    return obj[0].get("certificate", "")


def get_external_notary_endpoint(juju: jubilant.Juju) -> str:
    result = juju.run(
        unit=f"{TRAEFIK_K8S_APPLICATION_NAME}/0",
        action="show-proxied-endpoints",
    )
    obj = json.loads(result.results.get("proxied-endpoints", "{}")).get(APP_NAME, {})
    return obj.get("url", "")


def get_file_from_notary(juju: jubilant.Juju, file_name: str) -> str:
    result = juju.exec(
        unit=f"{APP_NAME}/0",
        command=f"sudo cat /var/lib/juju/storage/config/0/{file_name}",
    )
    return result.stdout
