"""Forge-observation storage.

NEED(contracts): repository_observation — an append-only measurements table
(repository_id, observed_at, status, comparison metrics). Until it lands there is
deliberately no SQL implementation: core never invents a table (AGENTS.md rule).
The in-memory store carries the same stale-write semantics the table will have.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.observation import ForgeFacts


class ObservationStore(Protocol):
    def save(self, facts: ForgeFacts) -> None: ...
    def find(self, repository_id: UUID) -> ForgeFacts | None: ...


class InMemoryObservationStore:
    def __init__(self) -> None:
        self.rows: dict[str, ForgeFacts] = {}

    def save(self, facts: ForgeFacts) -> None:
        previous = self.rows.get(facts.repository_id)
        if previous is not None and previous.observed_at > facts.observed_at:
            return  # a newer observation already exists; never move time backwards
        self.rows[facts.repository_id] = facts

    def find(self, repository_id: UUID) -> ForgeFacts | None:
        return self.rows.get(repository_id)
