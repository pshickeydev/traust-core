from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.common import ArtifactRef, Location, Principal, Provenance
from traust_core.v1.models.integrity import Fingerprint
from traust_core.v1.models.vocabulary import (
    DispositionAssurance,
    DispositionEmbargo,
    DispositionResolution,
    EvidenceGrade,
    FindingOrigin,
    Severity,
    Validity,
)

Label = NewType("Label", str)
Cwe = NewType("Cwe", str)
Category = NewType("Category", str)
Confidence = NewType("Confidence", float)
Rationale = NewType("Rationale", str)
StatementKey = NewType("StatementKey", str)
EvidenceRef = NewType("EvidenceRef", str)


class CandidateFormat(StrEnum):
    SARIF = "sarif"
    DEPENDABOT = "dependabot"
    GOVULNCHECK = "govulncheck"


class FindingDimension(StrEnum):
    SEVERITY = "severity"
    CWE = "cwe"
    CATEGORY = "category"
    LABEL = "label"
    ORIGIN = "origin"
    VALIDITY = "validity"
    RESOLUTION = "resolution"
    REPOSITORY = "repository"


# Shapes land with their implementation slice.
class WeaknessLabels(Model): ...


class SeverityOverride(Model): ...


class ReviewContext(Model): ...


class PrecedentReason(Model): ...


class IdentityMove(Model): ...


class IntakeResult(Model): ...


class RecordDecision(Model): ...


class TriageRecorded(Model): ...


class ReviewCase(Model): ...


class ReviewFilter(Model): ...


class FindingFilter(Model): ...


class FindingRollup(Model): ...


class RatingInputs(Model): ...


class RiskRating(Model): ...


class FindingCandidate(Model):
    label: Label
    repository_id: UUID
    title: str
    cwes: tuple[Cwe, ...] = ()
    category: Category | None = None
    locations: tuple[Location, ...] = ()
    reported_severity: Severity
    confidence: Confidence
    origin: FindingOrigin

    @classmethod
    def parse_many(cls, raw: bytes, format: CandidateFormat) -> list[FindingCandidate]:
        raise NotImplementedError("stub: replaces triage/normalize_input.py")


class Finding(Entity):
    repository_id: UUID
    match_key: Fingerprint
    title: str
    cwes: tuple[Cwe, ...] = ()
    category: Category | None = None
    labels: WeaknessLabels
    origin: FindingOrigin
    first_seen_at: datetime


class Occurrence(Entity):
    finding_id: UUID
    assessment_id: UUID
    label: Label
    locations: tuple[Location, ...] = ()
    reported_severity: Severity
    confidence: Confidence
    artifact: ArtifactRef


class Decision(Entity):
    finding_id: UUID
    code_line_id: UUID | None = None
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    severity_override: SeverityOverride | None = None
    evidence_grade: EvidenceGrade
    evidence: tuple[EvidenceRef, ...] = ()
    embargo: DispositionEmbargo | None = None
    actor: Principal
    provenance: Provenance
    rationale: Rationale
    review: ReviewContext | None = None
    restates_id: UUID | None = None

    def statement_key(self) -> StatementKey:
        raise NotImplementedError("stub: replaces ledger compute_event_id (classifier steps 9/12)")


class Disposition(Model):
    finding_id: UUID
    code_line_id: UUID
    validity: Validity
    resolution: DispositionResolution
    assurance: DispositionAssurance
    conflict: bool = False
    fp_overridden: bool = False
    fp_reassertion_blocked: bool = False
    awaiting_signoff: bool = False
    last_decision_at: datetime | None = None

    @classmethod
    def fold(cls, finding_id: UUID, decisions: Sequence[Decision]) -> Disposition:
        raise NotImplementedError("stub: replaces ledger derive_disposition, corpus/disposition.py")

    def admit(self, decision: Decision) -> Disposition:
        raise NotImplementedError("stub: replaces ledger _internal/gates.py")

    def is_open(self) -> bool:
        raise NotImplementedError("stub: replaces build_trends.state_of")


class Precedent(Model):
    decision: Decision
    similarity: float
    reason: PrecedentReason


class FindingView(Model):
    finding: Finding
    occurrence: Occurrence | None = None
    disposition: Disposition | None = None
    effective_severity: Severity
    sla_due: datetime | None = None


class SubjectRef(Model): ...


class FindingContext(Model):
    baseline: tuple[FindingView, ...] = ()
    precedents: tuple[Precedent, ...] = ()


class SkillInput(Model):
    subject: SubjectRef
    findings: FindingContext
    prepared_at: datetime


class TriageInput(SkillInput): ...


class FindingSeriesPoint(Model):
    bucket: datetime
    open_by_severity: Mapping[Severity, int]
    new: int
    resolved: int
    accepted: int
    hardening: int
    false_positives: int
    regressions: int
    mttr_days: float | None = None
    risk_index: float


# Legacy triage row; becomes a Decision in the Findings slice.
class TriageVerdict(Model):
    binding_id: str
    artifact_digest: str
    finding_id: str
    source_finding_id: str | None = None
    triage_completed: str
    verdict: str
    severity: str | None = None
    vote_breakdown: Mapping[str, int] | None = None
    rationale: str | None = None
