# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import ops
import ops.testing
import pytest
from charm import GocertCharm
from scenario import Context, Event, State


class TestCharm:
    @pytest.fixture(scope="function", autouse=True)
    def context(self):
        yield Context(GocertCharm)

    def test_start_charm(self, context):
        out = context.run(Event("start"), State())
        assert out.unit_status == ops.ActiveStatus()
