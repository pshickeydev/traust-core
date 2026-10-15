from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.artifacts import BenchmarkTargetArtifact
from traust_core.v1.models.common import Page, PageRequest, Provenance, TimeWindow
from traust_core.v1.models.detection_quality import (
    BenchmarkFilter,
    BenchmarkRun,
    BenchmarkTarget,
    Calibration,
    Canary,
    ComplianceCalibration,
    CriticalMiss,
    InjectionScreen,
    MissFilter,
    RuleDraft,
    RuleDraftStatus,
    RulePack,
    Scorecard,
)
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.repositories.detection_quality import DetectionQualityUnitOfWork


class DetectionQualityService:
    def __init__(self, uow: DetectionQualityUnitOfWork) -> None:
        self._uow = uow

    def record(self, doc: BenchmarkTargetArtifact, provenance: Provenance) -> BenchmarkTarget:
        raise NotImplementedError("stub: replaces bootstrap_benchmark_targets.py")

    def build_canaries(self, target_ids: Sequence[UUID]) -> list[Canary]:
        raise NotImplementedError("stub: replaces recall-benchmark/build_canaries.py")

    def run_benchmark(self, rule_pack_id: UUID, target_ids: Sequence[UUID]) -> BenchmarkRun:
        raise NotImplementedError("stub: replaces match_benchmark.py, sweep/benchmark.py")

    def screen_injection(self, artifact_id: UUID) -> InjectionScreen:
        raise NotImplementedError("stub: replaces recall-benchmark/screen_injection.py")

    def mine_rules(self, since: datetime) -> list[RuleDraft]:
        raise NotImplementedError("stub: replaces sweep/mining, sweep/engine, emit_rule_drafts")

    def calibrate(self, subject_id: UUID) -> Calibration:
        raise NotImplementedError("stub: replaces calibrate_rule_pack.py, sweep/calibration.py")

    def admit_rule(self, draft_id: UUID, approval_id: UUID) -> RulePack:
        raise NotImplementedError("stub: replaces sweep rule_lane admission")

    def critical_misses(self, window: TimeWindow) -> list[CriticalMiss]:
        raise NotImplementedError("stub: replaces build_critical_misses.py, cve_replay_monitor.py")

    def calibrate_compliance(self, framework: ComplianceFramework) -> ComplianceCalibration:
        raise NotImplementedError(
            "stub: replaces calibrate_compliance, compliance_precision, score_compliance_efficacy"
        )

    def scorecards(self, filter: BenchmarkFilter) -> list[Scorecard]:
        raise NotImplementedError("stub: replaces sweep/benchmark.cmd_scorecard")

    def rule_packs(self) -> list[RulePack]:
        raise NotImplementedError("stub: replaces opengrep resolve_rule_pack_dir")

    def drafts(self, status: RuleDraftStatus) -> list[RuleDraft]:
        raise NotImplementedError("stub: replaces sweep/engine.existing_rule_ids")

    def misses(self, filter: MissFilter, page: PageRequest) -> Page[CriticalMiss]:
        raise NotImplementedError("stub: replaces critical-misses report reads")
