from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.findings import Label, SkillInput
from traust_core.v1.models.vocabulary import (
    AuditProfile,
    ChainSeverity,
    IsolationPosture,
    PeachBoundaryType,
    TenancyProfile,
    ThreatActor,
    ThreatImpact,
    ThreatLikelihood,
    ThreatStatus,
)

ToolName = NewType("ToolName", str)


class AssessmentKind(StrEnum):
    SECURE_CODE = "secure-code"
    CONTAINER = "container"
    RPM = "rpm"
    CLOUD_CONFIG = "cloud-config"
    VULN_SCAN = "vuln-scan"
    THREAT_MODEL = "threat-model"
    ISOLATION_REVIEW = "isolation-review"
    PRIV_PROFILE = "priv-profile"
    PQC_READINESS = "pqc-readiness"
    FUZZ = "fuzz"


# Shapes land with their implementation slice.
class CoverageGap(Model): ...


class AttackTechnique(Model): ...


class Permission(Model): ...


class IsolationCheck(Model): ...


class PopulationRow(Model): ...


class CoverageRow(Model): ...


class ToolRun(Model): ...


class AssessmentFilter(Model): ...


class ThreatFilter(Model): ...


class AssessmentInput(SkillInput): ...


class Coverage(Model):
    examined: int
    total: int
    gaps: tuple[CoverageGap, ...] = ()

    def ratio(self) -> float:
        raise NotImplementedError("stub: replaces build_coverage_gap_rollup.build_rollup")


class Assessment(Entity):
    revision_id: UUID
    kind: AssessmentKind
    profile: AuditProfile | None = None
    artifact: ArtifactRef
    assessed_at: datetime
    coverage: Coverage | None = None


class Threat(Entity):
    assessment_id: UUID
    label: Label
    title: str
    status: ThreatStatus
    actor: ThreatActor
    likelihood: ThreatLikelihood
    impact: ThreatImpact
    boundary: PeachBoundaryType | None = None
    techniques: tuple[AttackTechnique, ...] = ()


class AttackChain(Entity):
    assessment_id: UUID
    threat_ids: tuple[UUID, ...]
    severity: ChainSeverity


class PrivilegeProfile(Model):
    assessment_id: UUID
    permissions: tuple[Permission, ...] = ()
    tenancy: TenancyProfile


class IsolationResult(Model):
    assessment_id: UUID
    posture: IsolationPosture
    checks: tuple[IsolationCheck, ...] = ()


class Freshness(Model):
    code_line_id: UUID
    last_assessed_at: datetime | None = None
    churn_ratio: float | None = None

    def age_days(self, now: datetime) -> int | None:
        raise NotImplementedError("stub: replaces build_rescan_worklist audit_age_days")


class Population(Model):
    as_of: datetime
    rows: tuple[PopulationRow, ...] = ()
    never_assessed_code_line_ids: tuple[UUID, ...] = ()
