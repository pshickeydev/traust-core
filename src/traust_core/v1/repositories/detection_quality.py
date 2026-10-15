from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.detection_quality import (
    BenchmarkFilter,
    BenchmarkRun,
    BenchmarkTarget,
    CriticalMiss,
    MissFilter,
    RuleDraft,
    RuleDraftStatus,
    RulePack,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class BenchmarkRepository(Protocol):
    def add_targets(self, targets: Sequence[BenchmarkTarget]) -> list[BenchmarkTarget]: ...
    def targets(self, target_ids: Sequence[UUID]) -> list[BenchmarkTarget]: ...
    def add_run(self, run: BenchmarkRun) -> BenchmarkRun: ...
    def runs(self, filter: BenchmarkFilter) -> list[BenchmarkRun]: ...


class RuleRepository(Protocol):
    def add_pack(self, pack: RulePack) -> RulePack: ...
    def packs(self) -> list[RulePack]: ...
    def add_draft(self, draft: RuleDraft) -> RuleDraft: ...
    def update_draft(self, draft: RuleDraft) -> RuleDraft: ...
    def drafts(self, status: RuleDraftStatus) -> list[RuleDraft]: ...


class MissRepository(Protocol):
    def add_many(self, misses: Sequence[CriticalMiss]) -> list[CriticalMiss]: ...
    def list(self, filter: MissFilter, page: PageRequest) -> Page[CriticalMiss]: ...


class DetectionQualityUnitOfWork(UnitOfWork, Protocol):
    benchmarks: BenchmarkRepository
    rules: RuleRepository
    misses: MissRepository
