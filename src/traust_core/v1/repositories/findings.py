from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Finding,
    FindingFilter,
    FindingView,
    Occurrence,
)
from traust_core.v1.models.integrity import Fingerprint
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class FindingRepository(Protocol):
    def get(self, finding_id: UUID) -> Finding: ...
    def find_by_match_key(self, repository_id: UUID, key: Fingerprint) -> Finding | None: ...
    def add(self, finding: Finding) -> Finding: ...
    def update(self, finding: Finding) -> Finding: ...


class OccurrenceRepository(Protocol):
    def add(self, occurrence: Occurrence) -> Occurrence: ...
    def list_for_finding(self, finding_id: UUID) -> list[Occurrence]: ...
    def list_for_assessment(self, assessment_id: UUID) -> list[Occurrence]: ...


class DecisionRepository(Protocol):
    def add(self, decision: Decision) -> Decision: ...
    def list_for_finding(self, finding_id: UUID) -> list[Decision]: ...
    def list_since(self, since: datetime, page: PageRequest) -> Page[Decision]: ...


# Severity/SLA are stored at write time (repos never run policies); rebuild_dispositions refreshes.
class DispositionView(Protocol):
    def get(self, finding_id: UUID, code_line_id: UUID) -> Disposition: ...
    def put(self, disposition: Disposition) -> None: ...
    def list(self, filter: FindingFilter, page: PageRequest) -> Page[FindingView]: ...
    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int: ...


class FindingUnitOfWork(UnitOfWork, Protocol):
    findings: FindingRepository
    occurrences: OccurrenceRepository
    decisions: DecisionRepository
    dispositions: DispositionView
