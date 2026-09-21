#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import tempfile
import time
from collections.abc import Callable, Iterator
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
    generate_csr,
    generate_private_key,
)

from charm import NOTARY_LOGIN_SECRET_LABEL
from notary import ClusterMember, Notary

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
    for name in ("juju-debug.log", "juju-units.yaml"):
        Path(name).unlink(missing_ok=True)
    with jubilant.temp_model() as juju:
        juju.wait_timeout = 10 * 60
        yield juju
        if request.session.testsfailed:
            collect_failure_diagnostics(juju)


@pytest.fixture(autouse=True)
def capture_test_failure(juju: jubilant.Juju, request: pytest.FixtureRequest):
    failures_before = request.session.testsfailed
    yield
    if request.session.testsfailed > failures_before:
        collect_failure_diagnostics(juju)


def append_diagnostic(path: str, label: str, collect: Callable[[], str]) -> None:
    """Append a snapshot without masking the original test failure."""
    try:
        content = collect()
        with Path(path).open("a") as output:
            output.write(f"\n---\n# {label}\n{content}\n")
    except Exception:
        logger.exception("Could not collect %s", label)


def run_notary_pebble(juju: jubilant.Juju, unit: str, *command: str) -> str:
    """Access workload Pebble through the charm container's shared socket."""
    return juju.cli(
        "ssh",
        "--container",
        "charm",
        unit,
        "env",
        "PEBBLE_SOCKET=/charm/containers/notary/pebble.socket",
        "/charm/bin/pebble",
        *command,
    )


def collect_failure_diagnostics(juju: jubilant.Juju) -> None:
    """Capture hook logs, relation data, and workload failures."""
    append_diagnostic("juju-debug.log", "Juju debug log", juju.debug_log)
    try:
        status = juju.status()
    except Exception:
        logger.exception("Could not read model status for diagnostics")
        return
    units = [unit for app in status.apps.values() for unit in app.units]
    if units:
        append_diagnostic("juju-units.yaml", "Unit data", lambda: juju.cli("show-unit", *units))
    app = status.apps.get(APP_NAME)
    if app is None:
        return
    for unit in app.units:
        for command in (("services",), ("logs", "-n", "200", "notary")):
            append_diagnostic(
                "juju-debug.log",
                f"{unit}: pebble {' '.join(command)}",
                lambda unit=unit, command=command: run_notary_pebble(juju, unit, *command),
            )


def on_app_error(juju: jubilant.Juju) -> Callable[[jubilant.Status], bool]:
    """Capture diagnostics when Notary enters an error state."""

    def _check(status: jubilant.Status) -> bool:
        if not jubilant.any_error(status, APP_NAME):
            return False
        logger.error("Notary entered error state: %s", status)
        collect_failure_diagnostics(juju)
        return True

    return _check


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
        error=on_app_error(juju),
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
        error=on_app_error(juju),
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
        error=on_app_error(juju),
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
        error=on_app_error(juju),
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
        error=on_app_error(juju),
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
        error=on_app_error(juju),
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
            error=on_app_error(juju),
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


def test_given_notary_when_scaled_out_then_dqlite_cluster_forms_and_scales_back(
    juju: jubilant.Juju,
):
    """Check replicated data, leader failover, restart, and graceful scale-down."""
    admin_credentials = get_notary_credentials(juju)
    client = Notary(url=get_notary_endpoint(juju), ca_path=False)
    login_response = client.login(admin_credentials["email"], admin_credentials["password"])
    assert login_response and login_response.token
    token = login_response.token
    csr = str(generate_csr(private_key=generate_private_key(), common_name="scaling-test"))
    assert client.create_certificate_request(csr, token)

    juju.add_unit(APP_NAME, num_units=2)
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME)
            and jubilant.all_active(status, APP_NAME)
            and len(status.apps[APP_NAME].units) == 3
        ),
        error=on_app_error(juju),
    )
    members = _wait_for_cluster_members(client, token, 3, voters=3)

    units = juju.status().apps[APP_NAME].units
    clients = {
        unit: Notary(url=f"https://{details.address}:2111", ca_path=False)
        for unit, details in units.items()
    }
    for unit_client in clients.values():
        _wait_for_request(unit_client, token, csr)

    leader = next(member for member in members if member.leader)
    leader_unit = next(unit for unit in units if unit.replace("/", "-") == leader.name)
    survivor = next(unit_client for unit, unit_client in clients.items() if unit != leader_unit)
    with fast_forward(juju, "60m"):
        try:
            run_notary_pebble(juju, leader_unit, "stop", "notary")
            assert not clients[leader_unit].is_api_available()
            _wait_for_request(survivor, token, csr)
            failover_csr = str(
                generate_csr(private_key=generate_private_key(), common_name="failover-test")
            )
            assert survivor.create_certificate_request(failover_csr, token)
        finally:
            run_notary_pebble(juju, leader_unit, "start", "notary")
    _wait_for_request(clients[leader_unit], token, failover_csr)
    for remaining in (2, 1):
        _wait_for_cluster_members(client, token, remaining + 1)
        juju.remove_unit(APP_NAME, num_units=1)
        juju.wait(
            lambda status: (
                jubilant.all_agents_idle(status, APP_NAME)
                and jubilant.all_active(status, APP_NAME)
                and len(status.apps[APP_NAME].units) == remaining
            ),
            error=on_app_error(juju),
        )
        clients = {
            unit: Notary(url=f"https://{details.address}:2111", ca_path=False)
            for unit, details in juju.status().apps[APP_NAME].units.items()
        }
        client = next(iter(clients.values()))
        _wait_for_cluster_members(client, token, remaining)
        _wait_for_request(client, token, failover_csr)


def _wait_for_request(client: Notary, token: str, csr: str, timeout: int = 120) -> None:
    """Wait for persisted data to be readable through a specific unit."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(request.csr == csr for request in client.list_certificate_requests(token)):
            return
        time.sleep(5)
    raise AssertionError(f"Certificate request not readable through {client.url}")


def _wait_for_cluster_members(
    client: Notary, token: str, count: int, timeout: int = 300, voters: int | None = None
) -> list[ClusterMember]:
    """Wait for named membership and, when requested, completed voter promotion."""
    deadline = time.monotonic() + timeout
    members = None
    while time.monotonic() < deadline:
        members = client.list_cluster_members(token)
        if (
            members is not None
            and len(members) == count
            and all(member.name for member in members)
            and any(member.leader for member in members)
            and (voters is None or sum(member.role == "voter" for member in members) == voters)
        ):
            return members
        time.sleep(10)
    raise AssertionError(f"expected {count} named members with voters={voters}, got {members}")


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
