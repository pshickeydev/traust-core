from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.artifacts import AssessmentArtifact
from traust_core.v1.models.assessment import (
    Assessment,
    AssessmentFilter,
    AssessmentInput,
    AssessmentKind,
    CoverageRow,
    Freshness,
    Population,
    PrivilegeProfile,
    Threat,
    ThreatFilter,
    ToolName,
    ToolRun,
)
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.repositories.assessment import AssessmentUnitOfWork
from traust_core.v1.services.findings.intake import FindingIntake


class AssessmentService:
    def __init__(self, uow: AssessmentUnitOfWork, intake: FindingIntake) -> None:
        self._uow = uow
        self._intake = intake

    def run_tools(self, revision_id: UUID, tools: Sequence[ToolName]) -> ToolRun:
        raise NotImplementedError("stub: replaces run_checkov.py, adapters _contract_bridge")

    def prepare(
        self, revision_id: UUID, kind: AssessmentKind, base_id: UUID | None
    ) -> AssessmentInput:
        raise NotImplementedError(
            "stub: replaces build_diff_packet.py, resolve_baseline.py, threat-model inputs"
        )

    def record(
        self, doc: AssessmentArtifact, revision_id: UUID, provenance: Provenance
    ) -> Assessment:
        raise NotImplementedError("stub: replaces corpus/store_ingest.py, threat_model.py")

    def get(self, assessment_id: UUID) -> Assessment:
        raise NotImplementedError("stub: assessment read")

    def latest(self, code_line_id: UUID, kind: AssessmentKind) -> Assessment | None:
        raise NotImplementedError("stub: replaces corpus/resolver latest report")

    def list(self, filter: AssessmentFilter, page: PageRequest) -> Page[Assessment]:
        raise NotImplementedError("stub: replaces corpus/resolver.walk_reports")

    def population(self, as_of: datetime, filter: AssessmentFilter) -> Population:
        raise NotImplementedError("stub: replaces census/build_census.py, corpus/resolver")

    def freshness(self, code_line_id: UUID) -> Freshness:
        raise NotImplementedError("stub: replaces build_rescan_worklist audit_age / churn")

    def threats(self, filter: ThreatFilter, page: PageRequest) -> Page[Threat]:
        raise NotImplementedError("stub: replaces threat_current, threat-register parse_model")

    def coverage(self, filter: AssessmentFilter) -> list[CoverageRow]:
        raise NotImplementedError("stub: replaces build_coverage_gap_rollup.py")

    def privileges(self, filter: AssessmentFilter) -> list[PrivilegeProfile]:
        raise NotImplementedError("stub: replaces operator_privilege, load_least_priv")
