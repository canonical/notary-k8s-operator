# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Dict, List
from unittest.mock import patch

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
            pytest.param([{"name": "gocert", "can_connect": True}], id="container-can-connect"),
        ],
    )
    def test_storage_attached_event_happy_path(
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
            leader=True,
        )
        for storage in storages_state:
            out = context.run(
                Event(
                    f"{storage.get('name')}-storage-attached",
                    storage=Storage(name=storage.get("name")),
                ),
                state,
            )
            assert out.unit_status == ops.BlockedStatus("storages not yet available")

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
            # this SHOULD fail, it's ok
            pytest.param([], id="no-containers"),
            # this SHOULD NOT fail, it currently fails because your charm is missing a leader guard (there's a bug!)
            pytest.param([{"name": "gocert", "can_connect": False}], id="container-cant-connect"),
        ],
    )
    def test_storage_attached_event_errors(
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
            leader=True,
        )
        for storage in storages_state:
            # todo catch specific exception
            with pytest.raises(Exception):
                out = context.run(
                    Event(
                        f"{storage.get('name')}-storage-attached",
                        storage=Storage(name=storage.get("name")),
                    ),
                    state,
                )


    def test_config_changed_event(self, context: Context):
        pass

    def test_start_event(self, context: Context):
        pass
        # state = State()
        # out = context.run(Event("start"), state)
        # assert out.unit_status == ops.ActiveStatus()
