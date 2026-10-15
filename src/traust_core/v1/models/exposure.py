from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.vocabulary import (
    DependencyEvidenceLevel,
    Ecosystem,
    ImpactClassification,
    ImpactTier,
    Severity,
)

AdvisoryIdentifier = NewType("AdvisoryIdentifier", str)
Version = NewType("Version", str)
QualifiedSymbol = NewType("QualifiedSymbol", str)
FeedName = NewType("FeedName", str)


class VexStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


# Shapes land with their implementation slice.
class SymbolSource(Model): ...


class ImpactEvidence(Model): ...


class DependencyIngest(Model): ...


class DependencyProvenance(Model): ...


class ProvenanceCheck(Model): ...


class AffectedDependency(Model): ...


class ImpactFilter(Model): ...


class ExposureFilter(Model): ...


class ExposureDimension(Model): ...


class ExposureRollup(Model): ...


class ImpactInput(SkillInput): ...


class FeedRun(Entity):
    feed: FeedName
    error: str | None = None


class Package(Model):
    ecosystem: Ecosystem
    name: str


class AffectedRange(Model):
    package: Package
    introduced: Version | None = None
    fixed: Version | None = None

    def contains(self, version: Version) -> bool:
        raise NotImplementedError("stub: replaces impact/analyzer.version_in_range")


class Advisory(Entity):
    identifier: AdvisoryIdentifier
    aliases: tuple[AdvisoryIdentifier, ...] = ()
    summary: str
    severity: Severity | None = None
    affected: tuple[AffectedRange, ...] = ()
    published_at: datetime | None = None
    kev: bool = False
    epss: float | None = None

    def affects(self, package: Package, version: Version) -> bool:
        raise NotImplementedError("stub: replaces dependency-watch/fleet_sweep.fixed_range")

    def fixed_in(self, package: Package) -> Version | None:
        raise NotImplementedError("stub: replaces adapters/osv.fixed_version")


class AdvisorySymbols(Model):
    advisory_id: UUID
    symbols: tuple[QualifiedSymbol, ...] = ()
    entry_points: tuple[QualifiedSymbol, ...] = ()
    source: SymbolSource


class Dependency(Entity):
    revision_id: UUID
    package: Package
    version: Version
    direct: bool
    evidence: DependencyEvidenceLevel


class ImpactAnalysis(Entity):
    advisory_id: UUID
    revision_id: UUID
    classification: ImpactClassification
    tier: ImpactTier
    evidence: tuple[ImpactEvidence, ...] = ()
    artifact: ArtifactRef


class VexStatement(Model):
    advisory: AdvisoryIdentifier
    product_id: UUID
    status: VexStatus
