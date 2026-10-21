from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Protocol, TypeVar
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest, Principal, TimeBucket, TimeWindow
from traust_core.v1.models.operations import (
    AssetName,
    AssetRequest,
    Budget,
    BudgetVerdict,
    JobResult,
    LaneName,
    OrderFilter,
    OrderProgress,
    Refusal,
    Route,
    RunOrder,
    SchedulePlan,
    SpendAttribution,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    SpendRollup,
    SpendSource,
    StaleItem,
    ThroughputPoint,
    WorkerId,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.traust_ops import OpsUnitOfWork
from traust_core.v1.services.provider_catalog import ProviderCatalog

S = TypeVar("S", contravariant=True)
E = TypeVar("E", contravariant=True)


class Materializer(Protocol):
    asset: AssetName

    def materialize(self, request: AssetRequest) -> JobResult: ...


class Router(Protocol[S, E]):
    def route(self, state: S, events: Sequence[E], refusals: Sequence[Refusal]) -> Route: ...


class OpsService:
    def __init__(self, uow: OpsUnitOfWork, clock: Clock) -> None:
        self._uow = uow
        self._clock = clock

    def submit(self, request: AssetRequest, principal: Principal) -> RunOrder:
        raise NotImplementedError("stub: replaces cron/subprocess orchestration, */ops.py facades")

    def claim(self, worker: WorkerId, lease_for: timedelta) -> RunOrder | None:
        raise NotImplementedError("stub: order lease for the traust-engine run loop")

    def heartbeat(self, order_id: UUID, worker: WorkerId, lease_for: timedelta) -> RunOrder:
        raise NotImplementedError("stub: order lease renewal for the traust-engine run loop")

    def save_progress(self, order_id: UUID, progress: OrderProgress) -> UUID:
        """Progress goes to the run manifest artifact; returns its artifact id."""
        raise NotImplementedError("stub: replaces cli/checkpoint.py skill phase state")

    def complete(self, order_id: UUID, result: JobResult) -> RunOrder:
        raise NotImplementedError("stub: replaces per-CLI exit codes and progress files")

    def approve(self, order_id: UUID, decision_id: UUID) -> RunOrder:
        raise NotImplementedError("stub: replaces remediation push gates")

    def schedule(self, plan: SchedulePlan) -> list[RunOrder]:
        raise NotImplementedError("stub: replaces refresh_dashboards.build_stages")

    def get(self, order_id: UUID) -> RunOrder:
        raise NotImplementedError("stub: order read")

    def list(self, filter: OrderFilter, page: PageRequest) -> Page[RunOrder]:
        raise NotImplementedError("stub: order read")

    def timeline(self, filter: OrderFilter, bucket: TimeBucket) -> list[ThroughputPoint]:
        raise NotImplementedError("stub: replaces metrics/history.py, collect_harness_metrics")


class SpendService:
    def __init__(self, uow: OpsUnitOfWork, budgets: Sequence[Budget]) -> None:
        self._uow = uow
        self._budgets = budgets

    def record(self, event: SpendEvent) -> None:
        raise NotImplementedError("stub: replaces metrics/collect_spend.append_rows")

    def collect(self, source: SpendSource, window: TimeWindow) -> int:
        raise NotImplementedError("stub: replaces metrics/collect_spend.py")

    def attribute(self, window: TimeWindow) -> SpendAttribution:
        raise NotImplementedError("stub: replaces metrics/attribute_spend.py")

    def check_budget(self, lane: LaneName, estimate: Decimal) -> BudgetVerdict:
        raise NotImplementedError("stub: replaces cli/budget_shadow.py")

    def summary(self, filter: SpendFilter, group_by: SpendDimension) -> list[SpendRollup]:
        raise NotImplementedError("stub: replaces metrics/spend.py, financial-tracking")


class FreshnessQuery:
    def __init__(self, providers: ProviderCatalog, feeds: Sequence[FeedProvider[object]]) -> None:
        self._providers = providers
        self._feeds = feeds

    def stale(self) -> list[StaleItem]:
        raise NotImplementedError("stub: replaces cli/check_drift.py")
