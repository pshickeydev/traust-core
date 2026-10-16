from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.attestation import Attestation
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Principal
from traust_core.v1.models.findings import Decision


# Members land with the Ledger slice (from traust-ledger _internal/kinds.py).
class LedgerEventKind(StrEnum): ...


# Shapes land with their implementation slice.
class AppendReceipt(Model): ...


class VerifyResult(Model): ...


class LedgerEvent(Model):
    event_id: UUID
    stream_id: UUID
    kind: LedgerEventKind
    actor: Principal
    occurred_at: datetime
    recorded_at: datetime
    payload: bytes

    @classmethod
    def from_decision(cls, decision: Decision, stream_id: UUID) -> LedgerEvent:
        raise NotImplementedError("stub: replaces ledger events/builders.py, lib/event_time.py")

    @classmethod
    def from_attestation(cls, attestation: Attestation, stream_id: UUID) -> LedgerEvent:
        raise NotImplementedError("stub: replaces ledger events/builders.build_human_event")


class Checkpoint(Model):
    stream_id: UUID
    owner_id: UUID
    merkle_root: str
    size: int
    epoch: int
    signature: str
