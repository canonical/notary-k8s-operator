import jubilant


def test_given_machine_charm_deployed_when_workload_configured_then_status_is_active(
    juju: jubilant.Juju, charm_path: str
):
    juju.deploy(charm_path, trust=True)
    juju.wait(
        lambda status: jubilant.all_active(status, "notary"),
        error=lambda status: jubilant.any_error(status, "notary"),
        timeout=10 * 60,
    )
