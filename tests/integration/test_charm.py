#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = CHARMCRAFT["name"]

LOKI_APPLICATION_NAME = "loki-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
TRAEIK_K8S_APPLICATION_NAME = "traefik-k8s"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, request):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    charm = Path(request.config.getoption("--charm_path")).resolve()
    resources = {"gocert-image": CHARMCRAFT["resources"]["gocert-image"]["upstream-source"]}

    # Deploy the charm and wait for active status
    await asyncio.gather(
        ops_test.model.deploy(charm, resources=resources, application_name=APP_NAME),
        ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000),
    )


@pytest.mark.abort_on_fail
async def test_given_loki_and_prometheus_related_to_gocert_all_charm_statuses_active(
    ops_test: OpsTest,
):
    """Deploy loki and prometheus, and make sure all applications are active."""
    deploy_prometheus = ops_test.model.deploy(
        "prometheus-k8s",
        application_name=PROMETHEUS_APPLICATION_NAME,
        trust=True,
    )
    deploy_loki = ops_test.model.deploy(
        "loki-k8s", application_name=LOKI_APPLICATION_NAME, trust=True, channel="stable"
    )

    await asyncio.gather(
        deploy_loki,
        deploy_prometheus,
    )
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
    await ops_test.model.deploy(
        TRAEIK_K8S_APPLICATION_NAME, application_name=TRAEIK_K8S_APPLICATION_NAME, trust=True
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TRAEIK_K8S_APPLICATION_NAME],
        status="active",
        timeout=1000,
        raise_on_error=True,
    )
