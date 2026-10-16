from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.remediation import (
    FleetFix,
    Verification,
    VerificationFilter,
    WorkItem,
    WorkItemFilter,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class WorkItemRepository(Protocol):
    def get(self, work_item_id: UUID) -> WorkItem: ...
    def add(self, work_item: WorkItem) -> WorkItem: ...
    def update(self, work_item: WorkItem) -> WorkItem: ...
    def list(self, filter: WorkItemFilter, page: PageRequest) -> Page[WorkItem]: ...
    def next_pending(self, filter: WorkItemFilter) -> WorkItem | None: ...


class FleetFixRepository(Protocol):
    def get(self, fleet_fix_id: UUID) -> FleetFix: ...
    def add(self, fleet_fix: FleetFix) -> FleetFix: ...
    def update(self, fleet_fix: FleetFix) -> FleetFix: ...


class VerificationRepository(Protocol):
    def add(self, verification: Verification) -> Verification: ...
    def list_for(self, work_item_id: UUID) -> list[Verification]: ...
    def list(self, filter: VerificationFilter, page: PageRequest) -> Page[Verification]: ...


class RemediationUnitOfWork(UnitOfWork, Protocol):
    work_items: WorkItemRepository
    fleet_fixes: FleetFixRepository
    verifications: VerificationRepository
