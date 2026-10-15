from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Dto, Entity, Model
from traust_core.v1.models.common import Principal
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


# Members land with the Operations slice (traust-engine run loop).
class OrderState(StrEnum): ...


class OrderEventKind(StrEnum): ...


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


class Order(Entity):
    request: AssetRequest
    state: OrderState
    requested_by: Principal
    depends_on_ids: tuple[UUID, ...] = ()
    progress: OrderProgress | None = None

    def transition(self, event: OrderEventKind, at: datetime) -> Order:
        raise NotImplementedError("stub: replaces cron/subprocess orchestration state")


class Lease(Model):
    order_id: UUID
    worker: WorkerId
    expires_at: datetime

    def expired(self, now: datetime) -> bool:
        raise NotImplementedError("stub: order lease for the traust-engine run loop")


class OrderEvent(Entity):
    order_id: UUID
    kind: OrderEventKind
    detail: str | None = None


class SpendEvent(Entity):
    order_id: UUID | None = None
    provider: ProviderName
    model: ModelName | None = None
    skill: SkillName | None = None
    tokens: int | None = None
    cost_usd: Decimal
    at: datetime


class Budget(Model):
    lane: LaneName
    monthly_usd: Decimal
    enforcement: BudgetEnforcement

    def verdict(self, spent: Decimal, estimate: Decimal) -> BudgetVerdict:
        raise NotImplementedError("stub: replaces budget_shadow.shadow_verdict")
