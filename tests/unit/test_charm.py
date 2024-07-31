# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Dict, List

import ops
import ops.testing
import pytest
from charm import GocertCharm
from scenario import Container, Context, Event, Network, Relation, State, Storage


class TestCharm:
    @pytest.fixture(scope="function", autouse=True)
    def context(self):
        yield Context(GocertCharm)

    @pytest.mark.parametrize(
        "storages_state",
        [
            pytest.param([{"name": "config"}], id="config-storage"),
            pytest.param([{"name": "database"}], id="database-storage"),
            pytest.param([{"name": "config"}, {"name": "database"}], id="both-storages"),
        ],
    )
    @pytest.mark.parametrize(
        "containers_state",
        [
            pytest.param([], id="no-containers"),
            pytest.param([{"name": "gocert", "can_connect": False}], id="container-cant-connect"),
            pytest.param([{"name": "gocert", "can_connect": True}], id="container-can-connect"),
        ],
    )
    def test_storage_attached_event(
        self,
        storages_state: List[Dict[str, str]],
        containers_state: List[Dict[str, str]],
        context: Context,
    ):
        state = State(
            storage=[Storage(name=storage.get("name")) for storage in storages_state],
            containers=[
                Container(name=container.get("name"), can_connect=container.get("can_connect"))
                for container in containers_state
            ],
            relations=[Relation(endpoint="juju-info", interface="juju-info")],
            networks={"juju-info": Network.default(private_address="4.4.4.4")},
            leader=True,
        )
        for storage in storages_state:
            out = context.run(
                Event(
                    f"{storage.get("name")}-storage-attached",
                    storage=Storage(name=storage.get("name")),
                ),
                state,
            )
            assert out.unit_status == ops.BlockedStatus()

    def test_config_changed_event(self, context: Context):
        pass

    def test_start_event(self, context: Context):
        pass
        # state = State()
        # out = context.run(Event("start"), state)
        # assert out.unit_status == ops.ActiveStatus()
