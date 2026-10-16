from __future__ import annotations

from collections.abc import Sequence
from typing import overload
from uuid import UUID

from traust_core.v1.models.artifacts import (
    FleetFixArtifact,
    RemediationArtifact,
    VerificationArtifact,
)
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.remediation import (
    EvidenceItem,
    FleetFix,
    FleetFixMatcher,
    FleetTarget,
    Fork,
    PatchResult,
    Propagation,
    RemediationInput,
    Verification,
    VerificationFilter,
    VerificationInput,
    WorkItem,
    WorkItemFilter,
)
from traust_core.v1.models.vocabulary import FixStrategy, RemediationStatus
from traust_core.v1.repositories.remediation import RemediationUnitOfWork
from traust_core.v1.services.findings.service import FindingService


class RemediationService:
    def __init__(self, uow: RemediationUnitOfWork, findings: FindingService) -> None:
        self._uow = uow
        self._findings = findings

    def open(
        self, finding_ids: Sequence[UUID], component_id: UUID, strategy: FixStrategy | None
    ) -> WorkItem:
        raise NotImplementedError("stub: replaces build_remediation_manifest.build_rows")

    def prepare(self, work_item_id: UUID) -> RemediationInput:
        raise NotImplementedError("stub: replaces build_remediation_manifest.py")

    def resolve_fork(self, repository_id: UUID) -> Fork:
        raise NotImplementedError("stub: replaces remediate-finding/fork_map.py")

    def record_progress(self, work_item_id: UUID, status: RemediationStatus) -> WorkItem:
        raise NotImplementedError("stub: replaces update_remediation_progress.py")

    def record_evidence(self, work_item_id: UUID, evidence: EvidenceItem) -> WorkItem:
        raise NotImplementedError("stub: replaces property_evidence.py, mutation_evidence.py")

    @overload
    def record(self, doc: RemediationArtifact, provenance: Provenance) -> WorkItem: ...
    @overload
    def record(self, doc: FleetFixArtifact, provenance: Provenance) -> FleetFix: ...
    def record(
        self, doc: RemediationArtifact | FleetFixArtifact, provenance: Provenance
    ) -> WorkItem | FleetFix:
        raise NotImplementedError("stub: replaces emit_remediation_report.py, fleet-fix specs")

    def fleet_targets(self, matcher: FleetFixMatcher) -> list[FleetTarget]:
        raise NotImplementedError("stub: replaces fleet-fix/fleet_targets.py")

    def apply_fleet_fix(
        self, fleet_fix_id: UUID, target_id: UUID, approval_id: UUID
    ) -> PatchResult:
        raise NotImplementedError("stub: replaces fleet-fix/apply_fleet_fix.py")

    def get(self, work_item_id: UUID) -> WorkItem:
        raise NotImplementedError("stub: remediation read")

    def next_pending(self, filter: WorkItemFilter) -> WorkItem | None:
        raise NotImplementedError("stub: replaces next_pending_remediation.py")

    def list(self, filter: WorkItemFilter, page: PageRequest) -> Page[WorkItem]:
        raise NotImplementedError("stub: replaces emit_product_index.py, remediation_current")


class VerificationService:
    def __init__(self, uow: RemediationUnitOfWork, findings: FindingService) -> None:
        self._uow = uow
        self._findings = findings

    def prepare(self, work_item_id: UUID) -> VerificationInput:
        raise NotImplementedError("stub: replaces verify-remediation/build_verify_sweep.py")

    def differential(self, work_item_id: UUID, revision_id: UUID) -> EvidenceItem:
        raise NotImplementedError("stub: replaces verify-remediation/scanner_differential.py")

    def propagation(self, work_item_id: UUID, component_id: UUID) -> Propagation:
        raise NotImplementedError("stub: replaces check_fix_propagation.py")

    def record(self, doc: VerificationArtifact, provenance: Provenance) -> Verification:
        raise NotImplementedError("stub: replaces emit_verification_ledger_events.py")

    def list(self, filter: VerificationFilter, page: PageRequest) -> Page[Verification]:
        raise NotImplementedError("stub: replaces verification_current")
