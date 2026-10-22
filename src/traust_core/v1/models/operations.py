from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import AppendOnly, Dto, Entity, Model
from traust_core.v1.models.vocabulary import BudgetEnforcement

AssetName = NewType("AssetName", str)
WorkerId = NewType("WorkerId", str)
LaneName = NewType("LaneName", str)
ProviderName = NewType("ProviderName", str)
ModelName = NewType("ModelName", str)
SkillName = NewType("SkillName", str)


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    REFUSED = "refused"
    FAILED = "failed"


class JobResult(Model):
    outcome: Outcome
    degraded: Mapping[str, int] = Field(default_factory=dict)
    reason: str | None = None
    written: tuple[str, ...] = ()

    @classmethod
    def succeeded(cls, written: tuple[str, ...] = ()) -> JobResult:
        return cls(outcome=Outcome.SUCCEEDED, written=written)

    @classmethod
    def partly(cls, degraded: Mapping[str, int], written: tuple[str, ...] = ()) -> JobResult:
        if not degraded:
            return cls.succeeded(written)
        return cls(outcome=Outcome.DEGRADED, degraded=dict(degraded), written=written)

    @classmethod
    def refused(cls, reason: str) -> JobResult:
        return cls(outcome=Outcome.REFUSED, reason=reason)

    @classmethod
    def failed(cls, reason: str) -> JobResult:
        return cls(outcome=Outcome.FAILED, reason=reason)


class AssetRequest(Dto):
    asset: AssetName
    run_id: str
    partition: str | None = None
    params: Mapping[str, str] = Field(default_factory=dict)


class Refusal(Dto):
    subject: str
    lane: LaneName
    reason: str


class Route(Dto):
    lane: LaneName | None
    priority: int
    reason: str


# Becomes contracts.enum("run-order-state") once contracts registers it; values match the DDL.
class OrderState(StrEnum):
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    QUEUED = "queued"
    LEASED = "leased"
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    REFUSED = "refused"
    WITHHELD = "withheld"
    FAILED = "failed"


class OrderRequest(Model):
    """What admission puts on the queue: one asset for one partition, routed or not."""

    asset: AssetName
    priority: int
    repository_id: UUID | None = None
    run_batch_id: UUID | None = None
    lane: LaneName | None = None
    rule: str | None = None
    event_source: str | None = None


# Shapes land with their implementation slice.
class OrderProgress(Model): ...


class SchedulePlan(Model): ...


class OrderFilter(Model): ...


class ThroughputPoint(Model): ...


class SpendSource(Model): ...


class SpendAttribution(Model): ...


class BudgetVerdict(Model): ...


class SpendFilter(Model): ...


class SpendDimension(Model): ...


class SpendRollup(Model): ...


class StaleItem(Model): ...


class RunBatch(Entity):
    """4a · a tranche: one per (kind, period), e.g. drain_tranche / 2026-W31."""

    kind: str
    period: str


class RunOrder(Entity):
    """4a · one unit of work; queued, leased by a worker, finished with an outcome."""

    run_batch_id: UUID | None = None
    repository_id: UUID | None = None
    artifact_id: UUID | None = None
    rule: str | None = None
    event_source: str | None = None
    asset: str
    lane: str | None = None
    state: OrderState
    priority: int
    reason: str | None = None
    requested_by: str
    lease_holder: str | None = None
    lease_expires_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class SpendEvent(AppendOnly):
    run_order_id: UUID | None = None
    provider: str
    model: str
    skill: str | None = None
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    occurred_at: datetime


class FeedSnapshot(AppendOnly):
    run_order_id: UUID | None = None
    artifact_id: UUID
    feed: str
    retrieved_at: datetime


class AssessmentInput(AppendOnly):
    """Which feed snapshot an assessment used."""

    assessment_id: UUID
    feed_snapshot_id: UUID


class Budget(Model):
    lane: LaneName
    monthly_usd: Decimal
    enforcement: BudgetEnforcement

    def verdict(self, spent: Decimal, estimate: Decimal) -> BudgetVerdict:
        raise NotImplementedError("stub: replaces budget_shadow.shadow_verdict")
