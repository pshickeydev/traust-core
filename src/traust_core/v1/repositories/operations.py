from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest, TimeWindow
from traust_core.v1.models.operations import (
    Lease,
    Order,
    OrderEvent,
    OrderFilter,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    SpendRollup,
    WorkerId,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class OrderRepository(Protocol):
    def get(self, order_id: UUID) -> Order: ...
    def add(self, order: Order) -> Order: ...
    def update(self, order: Order) -> Order: ...
    def claim(self, worker: WorkerId, now: datetime) -> Lease | None: ...
    def list(self, filter: OrderFilter, page: PageRequest) -> Page[Order]: ...


class OrderEventRepository(Protocol):
    def append(self, event: OrderEvent) -> OrderEvent: ...
    def list_for(self, order_id: UUID) -> list[OrderEvent]: ...


class SpendRepository(Protocol):
    def append(self, event: SpendEvent) -> SpendEvent: ...
    def list(self, filter: SpendFilter, page: PageRequest) -> Page[SpendEvent]: ...
    def aggregate(self, filter: SpendFilter, group_by: SpendDimension) -> list[SpendRollup]: ...
    def unattributed(self, window: TimeWindow) -> list[SpendEvent]: ...


class OpsUnitOfWork(UnitOfWork, Protocol):
    orders: OrderRepository
    order_events: OrderEventRepository


class SpendUnitOfWork(UnitOfWork, Protocol):
    spend: SpendRepository
