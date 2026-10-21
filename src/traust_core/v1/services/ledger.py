from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.findings import Decision
from traust_core.v1.models.ledger import AppendReceipt, Checkpoint, VerifyResult
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.ledger import LedgerClient


# NEED(ledger-optional): the integrity chain is optional; decisions live in the decision table
# either way. When on, it always works: its tables sit in the configured record store
# (SQLite locally, Postgres on a server). No file-backed ledger, no snapshot mode.
class LedgerService:
    def __init__(self, client: LedgerClient, clock: Clock) -> None:
        self._client = client
        self._clock = clock

    def append_decision(self, decision: Decision, owner_id: UUID) -> AppendReceipt:
        raise NotImplementedError("stub: replaces emit_*_ledger_events append_to_layer")

    def checkpoint(self, owner_id: UUID) -> Checkpoint:
        raise NotImplementedError("stub: replaces engine ledger/service checkpoint, layer_ref")

    def verify(self, checkpoint: Checkpoint) -> VerifyResult:
        raise NotImplementedError("stub: replaces build_cumulative.verify_claim_hashes")
