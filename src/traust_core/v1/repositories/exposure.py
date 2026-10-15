from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.exposure import (
    Advisory,
    AdvisoryIdentifier,
    AdvisorySymbols,
    Dependency,
    FeedName,
    FeedRun,
    ImpactAnalysis,
    ImpactFilter,
    Package,
    Version,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class AdvisoryRepository(Protocol):
    def get(self, advisory_id: UUID) -> Advisory: ...
    def find_by_identifier(self, identifier: AdvisoryIdentifier) -> Advisory | None: ...
    def add(self, advisory: Advisory) -> Advisory: ...
    def update(self, advisory: Advisory) -> Advisory: ...
    def list_affecting(self, package: Package, version: Version) -> list[Advisory]: ...
    def put_symbols(self, symbols: AdvisorySymbols) -> None: ...
    def symbols(self, advisory_id: UUID) -> AdvisorySymbols | None: ...


class FeedRunRepository(Protocol):
    def last(self, feed: FeedName) -> FeedRun | None: ...
    def add(self, run: FeedRun) -> FeedRun: ...


class DependencyRepository(Protocol):
    def replace_for(
        self, revision_id: UUID, dependencies: Sequence[Dependency]
    ) -> list[Dependency]: ...
    def list_for(self, revision_id: UUID) -> list[Dependency]: ...
    def dependents(self, package: Package) -> list[UUID]: ...


class ImpactRepository(Protocol):
    def add(self, analysis: ImpactAnalysis) -> ImpactAnalysis: ...
    def list(self, filter: ImpactFilter, page: PageRequest) -> Page[ImpactAnalysis]: ...


class ExposureUnitOfWork(UnitOfWork, Protocol):
    advisories: AdvisoryRepository
    feed_runs: FeedRunRepository
    dependencies: DependencyRepository
    impacts: ImpactRepository
