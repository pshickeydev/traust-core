from __future__ import annotations

from collections.abc import Sequence
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
    Lease,
    Order,
    OrderEvent,
    OrderFilter,
    OrderProgress,
    Refusal,
    Route,
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
from traust_core.v1.repositories.operations import OpsUnitOfWork, SpendUnitOfWork
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

    def submit(self, request: AssetRequest, principal: Principal) -> Order:
        raise NotImplementedError("stub: replaces cron/subprocess orchestration, */ops.py facades")

    def claim(self, worker: WorkerId) -> Lease | None:
        raise NotImplementedError("stub: order lease for the traust-engine run loop")

    def heartbeat(self, lease: Lease) -> Lease:
        raise NotImplementedError("stub: order lease renewal for the traust-engine run loop")

    def save_progress(self, lease: Lease, progress: OrderProgress) -> Order:
        raise NotImplementedError("stub: replaces cli/checkpoint.py skill phase state")

    def complete(self, lease: Lease, result: JobResult) -> Order:
        raise NotImplementedError("stub: replaces per-CLI exit codes and progress files")

    def approve(self, order_id: UUID, attestation_id: UUID) -> Order:
        raise NotImplementedError("stub: replaces remediation push gates")

    def schedule(self, plan: SchedulePlan) -> list[Order]:
        raise NotImplementedError("stub: replaces refresh_dashboards.build_stages")

    def get(self, order_id: UUID) -> Order:
        raise NotImplementedError("stub: order read")

    def list(self, filter: OrderFilter, page: PageRequest) -> Page[Order]:
        raise NotImplementedError("stub: order read")

    def events(self, order_id: UUID) -> list[OrderEvent]:
        raise NotImplementedError("stub: order event read")

    def timeline(self, filter: OrderFilter, bucket: TimeBucket) -> list[ThroughputPoint]:
        raise NotImplementedError("stub: replaces metrics/history.py, collect_harness_metrics")


class SpendService:
    def __init__(self, uow: SpendUnitOfWork, budgets: Sequence[Budget]) -> None:
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
