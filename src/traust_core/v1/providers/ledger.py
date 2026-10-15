from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.ledger import AppendReceipt, Checkpoint, LedgerEvent, VerifyResult
from traust_core.v1.providers.base import Readiness


# NEED(ledger-adapter): the one implementation = core repository for events/layers in the
# configured record store (SQLite for local users, Postgres on a server) + traust-ledger for
# hashing, Merkle and signing. No file backend, no layer snapshots, no ledger REST hop.
class LedgerClient(Protocol):
    def check(self) -> Readiness: ...

    def open_stream(self, owner_id: UUID) -> UUID: ...

    def append(self, stream_id: UUID, events: Sequence[LedgerEvent]) -> AppendReceipt: ...

    def checkpoint(self, stream_id: UUID) -> Checkpoint: ...

    def verify(self, checkpoint: Checkpoint) -> VerifyResult: ...
