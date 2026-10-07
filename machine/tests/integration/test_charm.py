import json
from datetime import timedelta
from pathlib import Path

import jubilant
import pytest
from charmlibs.interfaces.tls_certificates import (
    CertificateSigningRequest,
    generate_ca,
    generate_certificate,
    generate_private_key,
)
from conftest import fast_forward

from notary import Notary

APP_NAME = "notary"
TLS_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
TLS_REQUIRER_CHANNEL = "latest/stable"
TLS_REQUIRER_REVISION = 143


@pytest.fixture(scope="module", autouse=True)
def deploy_notary(juju: jubilant.Juju, charm_path: Path):
    """Deploy a ready Notary instance for the module's integration tests."""
    juju.deploy(charm_path, trust=True)
    juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME),
        error=lambda status: jubilant.any_error(status, APP_NAME),
        timeout=10 * 60,
    )


def test_given_managed_csr_signed_through_api_when_update_status_then_certificate_is_provided(
    juju: jubilant.Juju,
):
    juju.deploy(
        TLS_REQUIRER_APPLICATION_NAME,
        channel=TLS_REQUIRER_CHANNEL,
        revision=TLS_REQUIRER_REVISION,
        trust=True,
    )
    credentials = _notary_credentials(juju)
    client = Notary(url=_notary_endpoint(juju), ca_path=False)
    login = client.login(credentials["email"], credentials["password"])
    assert login is not None and login.token
    token = login.token

    juju.integrate(
        app1=f"{APP_NAME}:managed-certificates",
        app2=f"{TLS_REQUIRER_APPLICATION_NAME}:certificates",
    )
    juju.wait(
        lambda status: (
            jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
            and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
            and len(client.list_certificate_requests(token)) == 1
        ),
        error=lambda status: jubilant.any_error(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME),
    )

    certificate_request = client.list_certificate_requests(token)[0]
    ca_private_key = generate_private_key()
    ca = generate_ca(ca_private_key, timedelta(days=365), "integration-test")
    certificate = generate_certificate(
        CertificateSigningRequest.from_string(certificate_request.csr),
        ca,
        ca_private_key,
        timedelta(days=365),
    )
    assert client.create_certificate_from_csr(
        certificate_request.csr, [str(certificate), str(ca)], token
    )

    with fast_forward(juju):
        juju.wait(
            lambda status: (
                jubilant.all_agents_idle(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
                and jubilant.all_active(status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME)
                and status.apps[TLS_REQUIRER_APPLICATION_NAME]
                .units[f"{TLS_REQUIRER_APPLICATION_NAME}/0"]
                .workload_status.message
                == "1/1 certificate requests are fulfilled"
            ),
            error=lambda status: jubilant.any_error(
                status, APP_NAME, TLS_REQUIRER_APPLICATION_NAME
            ),
        )

    provided = _first_requirer_certificate(juju)
    assert provided["certificate"].replace("\n", "") == str(certificate).replace("\n", "")


def _notary_endpoint(juju: jubilant.Juju) -> str:
    status = json.loads(juju.cli("status", "--format=json"))
    unit = status["applications"][APP_NAME]["units"][f"{APP_NAME}/0"]
    address = status["machines"][unit["machine"]]["ip-addresses"][0]
    return f"https://{address}:2111"


def _notary_credentials(juju: jubilant.Juju) -> dict[str, str]:
    secret = juju.show_secret("Notary Login Details", reveal=True)
    return {
        "email": secret.content["email"],
        "password": secret.content["password"],
    }


def _first_requirer_certificate(juju: jubilant.Juju) -> dict[str, str]:
    result = juju.run(unit=f"{TLS_REQUIRER_APPLICATION_NAME}/0", action="get-certificate")
    return json.loads(result.results["certificates"])[0]
