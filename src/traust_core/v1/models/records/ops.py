"""Rows of the traust_ops namespace, 4 · Operations - one model per contract table."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Entity


class RunBatchRecord(Entity):
    kind: str
    period: str


class RunOrderRecord(Entity):
    run_batch_id: UUID | None = None
    repository_id: UUID | None = None
    artifact_id: UUID | None = None
    rule: str | None = None
    event_source: str | None = None
    lane: str
    state: str
    priority: int
    reason: str | None = None
    requested_by: str
    lease_holder: str | None = None
    lease_expires_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class SpendEventRecord(AppendOnly):
    run_order_id: UUID | None = None
    provider: str
    model: str
    skill: str | None = None
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    occurred_at: datetime


class FeedSnapshotRecord(AppendOnly):
    run_order_id: UUID | None = None
    artifact_id: UUID
    feed: str
    retrieved_at: datetime


class AssessmentInputRecord(AppendOnly):
    assessment_id: UUID
    feed_snapshot_id: UUID
