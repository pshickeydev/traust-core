from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.assessment import (
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    Population,
    Threat,
    ThreatFilter,
)
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.pqc import PqcReadiness
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class AssessmentRepository(Protocol):
    def get(self, assessment_id: UUID) -> Assessment: ...
    def add(self, assessment: Assessment) -> Assessment: ...
    def latest(self, code_line_id: UUID, kind: AssessmentKind) -> Assessment | None: ...
    def list(self, filter: AssessmentFilter, page: PageRequest) -> Page[Assessment]: ...
    def population(self, as_of: datetime, filter: AssessmentFilter) -> Population: ...


class ThreatRepository(Protocol):
    def add_many(self, threats: Sequence[Threat]) -> list[Threat]: ...
    def list(self, filter: ThreatFilter, page: PageRequest) -> Page[Threat]: ...


class PqcRepository(Protocol):
    def add(self, readiness: PqcReadiness) -> PqcReadiness: ...
    def update(self, readiness: PqcReadiness) -> PqcReadiness: ...
    def get(self, assessment_id: UUID) -> PqcReadiness: ...
    def list(self, page: PageRequest) -> Page[PqcReadiness]: ...


class AssessmentUnitOfWork(UnitOfWork, Protocol):
    assessments: AssessmentRepository
    threats: ThreatRepository


class PqcUnitOfWork(UnitOfWork, Protocol):
    pqc: PqcRepository
