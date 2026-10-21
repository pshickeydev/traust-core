from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.dependencies import AdvisoryIdentifier
from traust_core.v1.models.vocabulary import (
    BenchmarkTargetEmbargo,
    BenchmarkTargetEvidenceKind,
    BenchmarkTargetInjectionClass,
    BenchmarkTargetProvenance,
    ComplianceFramework,
)


# Shapes land with their implementation slice.
class Scorecard(Model): ...


class RuleRef(Model): ...


class RuleDraftSource(Model): ...


class RuleDraftStatus(Model): ...


class Language(Model): ...


class CalibrationDelta(Model): ...


class MissReason(Model): ...


class Canary(Model): ...


class InjectionScreen(Model): ...


class BenchmarkFilter(Model): ...


class MissFilter(Model): ...


class BenchmarkTarget(Model):
    advisory: AdvisoryIdentifier
    repository_id: UUID
    fix_repository_ref_id: UUID
    provenance: BenchmarkTargetProvenance
    embargo: BenchmarkTargetEmbargo
    evidence: BenchmarkTargetEvidenceKind
    injection_class: BenchmarkTargetInjectionClass | None = None


class BenchmarkMatch(Model):
    target_id: UUID
    matched: bool
    finding_id: UUID | None = None
    injection_score: float | None = None


class BenchmarkRun(Model):
    rule_pack_id: UUID
    started_at: datetime
    matches: tuple[BenchmarkMatch, ...] = ()

    def scorecard(self) -> Scorecard:
        raise NotImplementedError("stub: replaces match_benchmark.score, sweep/benchmark.cmd_score")


class RulePack(Model):
    name: str
    version: str
    rules: tuple[RuleRef, ...] = ()


class RuleDraft(Model):
    source: RuleDraftSource
    language: Language
    artifact: ArtifactRef
    status: RuleDraftStatus


class Calibration(Model):
    subject_id: UUID
    precision: float
    reachability: float
    delta: CalibrationDelta


class CriticalMiss(Model):
    advisory: AdvisoryIdentifier
    repository_id: UUID
    reason: MissReason


class ComplianceCalibration(Model):
    framework: ComplianceFramework
    precision: float
    efficacy: float
