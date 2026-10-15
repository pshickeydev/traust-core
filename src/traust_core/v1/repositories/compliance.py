from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.compliance import (
    Adr,
    ComplianceAssessment,
    ComplianceFilter,
    ComplianceScope,
    DocVariance,
    DocVarianceFilter,
    ScopeFilter,
)
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class ComplianceScopeRepository(Protocol):
    def get(self, scope_id: UUID) -> ComplianceScope: ...
    def add(self, scope: ComplianceScope) -> ComplianceScope: ...
    def update(self, scope: ComplianceScope) -> ComplianceScope: ...
    def list(self, filter: ScopeFilter, page: PageRequest) -> Page[ComplianceScope]: ...


class ComplianceAssessmentRepository(Protocol):
    def add(self, assessment: ComplianceAssessment) -> ComplianceAssessment: ...
    def latest(
        self, scope_id: UUID, framework: ComplianceFramework
    ) -> ComplianceAssessment | None: ...
    def list(self, filter: ComplianceFilter, page: PageRequest) -> Page[ComplianceAssessment]: ...


class AdrRepository(Protocol):
    def replace_for(self, product_id: UUID, adrs: Sequence[Adr]) -> list[Adr]: ...
    def list_for(self, product_id: UUID) -> list[Adr]: ...


class DocVarianceRepository(Protocol):
    def add_many(self, variances: Sequence[DocVariance]) -> list[DocVariance]: ...
    def list(self, filter: DocVarianceFilter, page: PageRequest) -> Page[DocVariance]: ...


class ComplianceUnitOfWork(UnitOfWork, Protocol):
    scopes: ComplianceScopeRepository
    assessments: ComplianceAssessmentRepository
    adrs: AdrRepository
    doc_variances: DocVarianceRepository
