from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import ConflictError
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
    OrderRequest,
    OrderState,
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

log = logging.getLogger(__name__)

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

    def submit(self, request: OrderRequest, principal: Principal) -> RunOrder:
        order = RunOrder(
            **request.model_dump(), state=OrderState.QUEUED, requested_by=principal.ref
        )
        with self._uow as uow:
            saved = uow.run_orders.add(order)
            uow.commit()
        log.info("order %s queued: %s by %s", saved.id, saved.asset, saved.requested_by)
        return saved

    def claim(self, worker: WorkerId, lease_for: timedelta) -> RunOrder | None:
        with self._uow as uow:
            order = uow.run_orders.claim(worker, self._clock.now(), lease_for)
            uow.commit()
        if order is not None:
            log.info("order %s leased to %s", order.id, worker)
        return order

    def heartbeat(self, order_id: UUID, worker: WorkerId, lease_for: timedelta) -> RunOrder:
        now = self._clock.now()
        with self._uow as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, OrderState.LEASED, worker)
            if order.lease_expires_at is None or order.lease_expires_at < now:
                raise ConflictError(f"order {order_id}: lease expired at {order.lease_expires_at}")
            saved = uow.run_orders.update(
                order.model_copy(update={"lease_expires_at": now + lease_for})
            )
            uow.commit()
        return saved

    def save_progress(self, order_id: UUID, progress: OrderProgress) -> UUID:
        """Progress goes to the run manifest artifact; returns its artifact id."""
        raise NotImplementedError("stub: needs the run-manifest artifact schema in contracts")

    def complete(self, order_id: UUID, worker: WorkerId, result: JobResult) -> RunOrder:
        """Finish the order; results link to it by `run_order_id`, written by their own domain."""
        outcome = OrderState(result.outcome)
        with self._uow as uow:
            order = uow.run_orders.get_for_update(order_id)
            if order.state == outcome:
                return order  # a retried complete
            _require(order, OrderState.LEASED, worker)
            saved = uow.run_orders.update(
                order.model_copy(
                    update={
                        "state": outcome,
                        "reason": result.reason,
                        "finished_at": self._clock.now(),
                        "lease_holder": None,
                        "lease_expires_at": None,
                    }
                )
            )
            uow.commit()
        log.info("order %s %s", saved.id, saved.state)
        if result.degraded:
            # NEED(run-manifest): degraded keys belong in the order's run manifest.
            log.warning("order %s degraded: %s", saved.id, dict(result.degraded))
        return saved

    def approve(self, order_id: UUID, principal: Principal) -> RunOrder:
        with self._uow as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, OrderState.AWAITING_APPROVAL)
            saved = uow.run_orders.update(order.model_copy(update={"state": OrderState.QUEUED}))
            uow.commit()
        # NEED(run-manifest): record the approver in the order's run manifest.
        log.info("order %s approved by %s", saved.id, principal.ref)
        return saved

    def requeue_expired(self) -> int:
        with self._uow as uow:
            count = uow.run_orders.requeue_expired(self._clock.now())
            uow.commit()
        if count:
            log.warning("%d expired leases requeued", count)
        return count

    def schedule(self, plan: SchedulePlan) -> list[RunOrder]:
        raise NotImplementedError("stub: replaces refresh_dashboards.build_stages")

    def get(self, order_id: UUID) -> RunOrder:
        raise NotImplementedError("stub: order read")

    def list(self, filter: OrderFilter, page: PageRequest) -> Page[RunOrder]:
        raise NotImplementedError("stub: order read")

    def timeline(self, filter: OrderFilter, bucket: TimeBucket) -> list[ThroughputPoint]:
        raise NotImplementedError("stub: replaces metrics/history.py, collect_harness_metrics")


def _require(order: RunOrder, state: OrderState, worker: WorkerId | None = None) -> None:
    if order.state != state:
        raise ConflictError(f"order {order.id} is {order.state}, not {state}")
    if worker is not None and order.lease_holder != worker:
        raise ConflictError(f"order {order.id} is leased to {order.lease_holder}, not {worker}")


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
    def __init__(self, providers: ProviderCatalog, feeds: Sequence[FeedProvider]) -> None:
        self._providers = providers
        self._feeds = feeds

    def stale(self) -> list[StaleItem]:
        raise NotImplementedError("stub: replaces cli/check_drift.py")
