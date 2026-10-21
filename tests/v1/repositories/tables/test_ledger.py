"""5 · Ledger repositories: layers per repository and one event per decision."""

from __future__ import annotations

import pytest

from tests.v1.repositories.tables.conftest import Seed, same_rows
from traust_core.v1.errors import ConflictError


def test_layers_per_repository_and_line(seed: Seed) -> None:
    repo = seed.repository()
    repo_layer = seed.layer(repo)
    branch = seed.layer(repo, line="release-4.22")
    seed.layer()
    assert same_rows(seed.uow.layers.list_for_repository(repo.id), [repo_layer, branch])


def test_signing_a_root_updates_the_layer(seed: Seed) -> None:
    layer = seed.layer()
    signed = seed.uow.layers.update(
        layer.model_copy(
            update={"merkle_root": "ab12", "merkle_size": 1, "merkle_root_signature": "sig"}
        )
    )
    assert seed.uow.layers.get(layer.id) == signed


def test_events_append_in_sequence(seed: Seed) -> None:
    events = seed.uow.events
    layer = seed.layer()
    assert events.last_seq(layer.id) is None
    e0 = seed.event(layer, seq=0)
    e1 = seed.event(layer, seq=1, event_payload=b"\xff" * 64)
    assert events.last_seq(layer.id) == 1
    assert events.list_for_layer(layer.id) == [e0, e1]
    assert events.get(e1.id).event_payload == b"\xff" * 64


def test_each_decision_is_proved_once_and_seq_is_unique(seed: Seed) -> None:
    events = seed.uow.events
    layer, decision = seed.layer(), seed.decision()
    proof = seed.event(layer, decision, seq=0)
    assert events.find_by_decision(decision.id) == proof
    with pytest.raises(ConflictError):
        seed.event(seed.layer(), decision)  # same decision, another layer
    seed.uow.rollback()


def test_seq_is_unique_per_layer(seed: Seed) -> None:
    layer = seed.layer()
    seed.event(layer, seq=0)
    with pytest.raises(ConflictError):
        seed.event(layer, seq=0)
