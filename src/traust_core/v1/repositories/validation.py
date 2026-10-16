from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.validation import ValidationAttempt, ValidationFilter, ValidationPlan
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class ValidationPlanRepository(Protocol):
    def get(self, plan_id: UUID) -> ValidationPlan: ...
    def add(self, plan: ValidationPlan) -> ValidationPlan: ...
    def update(self, plan: ValidationPlan) -> ValidationPlan: ...
    def list_for(self, finding_id: UUID) -> list[ValidationPlan]: ...


class ValidationAttemptRepository(Protocol):
    def add(self, attempt: ValidationAttempt) -> ValidationAttempt: ...
    def list_for(self, plan_id: UUID) -> list[ValidationAttempt]: ...
    def list(self, filter: ValidationFilter, page: PageRequest) -> Page[ValidationAttempt]: ...


class ValidationUnitOfWork(UnitOfWork, Protocol):
    plans: ValidationPlanRepository
    attempts: ValidationAttemptRepository
