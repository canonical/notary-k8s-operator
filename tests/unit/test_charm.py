# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import ops
import ops.testing
import pytest
from charm import GocertCharm


class TestCharm:
    @pytest.fixture(scope="function", autouse=True)
    def setUp(self):
        self.harness = ops.testing.Harness(GocertCharm)

    def test_start_charm(self):
        self.harness.begin_with_initial_hooks()
        assert self.harness.model.unit.status == ops.ActiveStatus()
