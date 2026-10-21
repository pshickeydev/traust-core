"""Rows of the traust_ledger namespace, 5 · Ledger - one model per contract table."""

from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Entity


class LayerRecord(Entity):
    repository_id: UUID
    line: str | None = None
    merkle_root: str | None = None
    merkle_epoch: int | None = None
    merkle_size: int | None = None
    merkle_root_signature: str | None = None
    merkle_signing_method: str
    merkle_signature_format: int | None = None


class EventRecord(AppendOnly):
    layer_id: UUID
    decision_id: UUID
    seq: int
    event_payload: bytes
