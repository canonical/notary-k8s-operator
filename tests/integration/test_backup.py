# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Opt-in round trip against a real S3 bucket and a single-unit Notary deployment."""

import base64
import json
import os
from pathlib import Path
from uuid import uuid4

import jubilant
import pytest
import yaml
from charmlibs.interfaces.tls_certificates import CertificateRequestAttributes, PrivateKey

from charm import NOTARY_LOGIN_SECRET_LABEL
from notary import Notary


@pytest.fixture(scope="module")
def s3_configuration() -> dict[str, str]:
    required = ("S3_TEST_ENDPOINT", "S3_TEST_BUCKET", "S3_TEST_ACCESS_KEY", "S3_TEST_SECRET_KEY")
    if any(not os.environ.get(name) for name in required):
        pytest.skip(
            "Set S3_TEST_ENDPOINT, S3_TEST_BUCKET, S3_TEST_ACCESS_KEY and S3_TEST_SECRET_KEY"
        )
    return {name: os.environ[name] for name in required}


@pytest.mark.parametrize("custom_ca", [False, True], ids=["standard", "private-ca"])
def test_backup_list_restore_round_trip(
    request: pytest.FixtureRequest, s3_configuration: dict[str, str], custom_ca: bool
) -> None:
    """Restore removes post-backup writes while preserving pre-backup data."""
    endpoint = s3_configuration["S3_TEST_ENDPOINT"]
    ca_bundle = ""
    if custom_ca:
        endpoint = os.environ.get("S3_TLS_TEST_ENDPOINT", "")
        ca_path = os.environ.get("S3_TEST_CA_FILE", "")
        if not endpoint or not ca_path:
            pytest.skip("Set S3_TLS_TEST_ENDPOINT and S3_TEST_CA_FILE for private CA coverage")
        assert endpoint.startswith("https://")
        ca_bundle = base64.b64encode(Path(ca_path).read_bytes()).decode()
    charm = Path(str(request.config.getoption("--charm_path"))).resolve()
    metadata = yaml.safe_load(Path("charmcraft.yaml").read_text())
    app = "notary-backup-test"
    prefix = f"notary-integration/{uuid4().hex}"
    with jubilant.temp_model() as juju:
        juju.wait_timeout = 600
        juju.deploy(
            charm,
            app=app,
            resources={"notary-image": metadata["resources"]["notary-image"]["upstream-source"]},
            trust=True,
        )
        juju.deploy(
            "s3-integrator",
            channel="latest/stable",
            config={
                "endpoint": endpoint,
                "bucket": s3_configuration["S3_TEST_BUCKET"],
                "region": os.environ.get("S3_TEST_REGION", "us-east-1"),
                "path": prefix,
            },
        )
        juju.wait(lambda status: jubilant.all_agents_idle(status, "s3-integrator"))
        juju.run(
            "s3-integrator/leader",
            "sync-s3-credentials",
            {
                "access-key": s3_configuration["S3_TEST_ACCESS_KEY"],
                "secret-key": s3_configuration["S3_TEST_SECRET_KEY"],
            },
        ).raise_on_failure()
        juju.integrate(f"{app}:s3-parameters", "s3-integrator:s3-credentials")
        juju.wait(lambda status: jubilant.all_active(status, app, "s3-integrator"))
        if custom_ca:
            with pytest.raises(jubilant.TaskError) as failure:
                juju.run(f"{app}/leader", "create-backup", wait=600)
            assert "SSLError" in failure.value.task.message
            juju.config("s3-integrator", {"tls-ca-chain": ca_bundle})
            juju.wait(lambda status: jubilant.all_agents_idle(status, app, "s3-integrator"))
        address = juju.status().apps[app].units[f"{app}/0"].address
        client = Notary(f"https://{address}:2111", ca_path=False)
        credentials = juju.show_secret(NOTARY_LOGIN_SECRET_LABEL, reveal=True).content
        login = client.login(credentials["email"], credentials["password"])
        assert login is not None
        before = str(
            CertificateRequestAttributes(common_name="before.example").generate_csr(
                PrivateKey.generate()
            )
        )
        after = str(
            CertificateRequestAttributes(common_name="after.example").generate_csr(
                PrivateKey.generate()
            )
        )
        assert client.create_certificate_request(before, login.token) is not None
        created = juju.run(f"{app}/leader", "create-backup", wait=600)
        created.raise_on_failure()
        key = created.results["backup-id"]
        assert key.startswith(f"{prefix}/notary-backup-")
        listed = juju.run(f"{app}/leader", "list-backups")
        listed.raise_on_failure()
        assert key in json.loads(listed.results["backup-ids"])
        assert client.create_certificate_request(after, login.token) is not None
        assert after in {entry.csr for entry in client.list_certificate_requests(login.token)}
        restored = juju.run(
            f"{app}/leader",
            "restore-backup",
            {"backup-id": key.removeprefix(f"{prefix}/")},
            wait=600,
        )
        restored.raise_on_failure()
        assert restored.results["restored"] == key.removeprefix(f"{prefix}/")
        juju.wait(lambda status: jubilant.all_active(status, app))
        login = client.login(credentials["email"], credentials["password"])
        assert login is not None
        requests = {entry.csr for entry in client.list_certificate_requests(login.token)}
        assert before in requests
        assert after not in requests
