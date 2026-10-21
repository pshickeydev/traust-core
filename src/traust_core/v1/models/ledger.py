from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.common import Principal
from traust_core.v1.models.findings import Decision


class Layer(Entity):
    """5 · one Merkle tree of decision events for a repository (or one line), signed per root."""

    repository_id: UUID
    line: str | None = None
    merkle_root: str | None = None
    merkle_epoch: int | None = None
    merkle_size: int | None = None
    merkle_root_signature: str | None = None
    merkle_signing_method: str
    merkle_signature_format: int | None = None


class Event(AppendOnly):
    """5 · the proof of one decision: its leaf in a layer."""

    layer_id: UUID
    decision_id: UUID
    seq: int
    event_payload: bytes


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


class Checkpoint(Model):
    stream_id: UUID
    owner_id: UUID
    merkle_root: str
    size: int
    epoch: int
    signature: str
