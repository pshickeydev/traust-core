from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryIdentifier,
    AdvisoryPackage,
    AffectedDependency,
    Dependency,
    DependencyIngest,
    DependencyProvenance,
    ExposureDimension,
    ExposureFilter,
    ExposureRollup,
    FeedName,
    ImpactAnalysis,
    ImpactFilter,
    ImpactInput,
    Package,
    ProvenanceCheck,
    Sbom,
    Version,
    VexStatus,
)
from traust_core.v1.providers.feeds import FeedStatus
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.intake import FindingIntake


class ExposureService:
    def __init__(self, uow: TraustUnitOfWork, intake: FindingIntake) -> None:
        self._uow = uow
        self._intake = intake

    def refresh_feed(self, feed: FeedName) -> FeedStatus:
        raise NotImplementedError("stub: replaces fetch_feeds.py, registry/feeds.py")

    def ingest_sbom(self, artifact_id: UUID) -> Sbom:
        """CycloneDX / SPDX from standard tools; deduplicated by normalized package-list digest."""
        raise NotImplementedError("stub: replaces portfolio/graph.build_deps, parsers.py")

    def ingest_dependencies(self, repository_ref_id: UUID) -> DependencyIngest:
        raise NotImplementedError("stub: replaces portfolio/graph.build_deps, parsers.py")

    def resolve_symbols(self, advisory_id: UUID) -> UUID:
        """Symbols land as an artifact; returns its artifact id."""
        raise NotImplementedError(
            "stub: replaces resolve_advisory_symbols.py, expand_advisory_entry_points.py"
        )

    def prepare(self, advisory_id: UUID, repository_ref_id: UUID) -> ImpactInput:
        raise NotImplementedError("stub: replaces impact/analyzer evidence collection")

    def record(self, doc: ImpactAnalysisArtifact, provenance: Provenance) -> ImpactAnalysis:
        raise NotImplementedError("stub: replaces impact/analyzer.emit_impact_analysis")

    def affects(self, advisory_id: UUID, package_id: UUID, version: Version) -> bool:
        raise NotImplementedError("stub: replaces dependency-watch/fleet_sweep.fixed_range")

    def fixed_in(self, advisory_id: UUID, package_id: UUID) -> Version | None:
        raise NotImplementedError("stub: replaces adapters/osv.fixed_version")

    def packages_affected(self, advisory_id: UUID) -> list[AdvisoryPackage]:
        raise NotImplementedError("stub: advisory -> package links from feeds")

    def verify_dependency(self, package: Package, version: Version) -> DependencyProvenance:
        raise NotImplementedError("stub: replaces verify_dep_provenance.py")

    def reconcile_provenance(self, finding_id: UUID) -> ProvenanceCheck:
        raise NotImplementedError("stub: replaces reconcile_cve_provenance.py")

    def get_advisory(self, advisory_id: UUID) -> Advisory:
        raise NotImplementedError("stub: exposure read")

    def find_advisory(self, identifier: AdvisoryIdentifier) -> Advisory | None:
        raise NotImplementedError("stub: replaces fetch_advisory.py")

    def advisories_for(self, finding_id: UUID) -> list[Advisory]:
        raise NotImplementedError("stub: replaces enrich_findings_cves.py")

    def affected(self, advisory_id: UUID) -> list[AffectedDependency]:
        raise NotImplementedError("stub: replaces fleet_sweep.py, run_impact_sweep.py")

    def dependencies(self, repository_ref_id: UUID) -> list[Dependency]:
        raise NotImplementedError("stub: replaces portfolio-graph dependency reads")

    def dependents(self, package_id: UUID) -> list[UUID]:
        raise NotImplementedError("stub: replaces portfolio/graph dependents, smoke_deps_multi")

    def impacts(self, filter: ImpactFilter, page: PageRequest) -> Page[ImpactAnalysis]:
        raise NotImplementedError("stub: replaces impact_analysis reads")

    def summary(self, filter: ExposureFilter, group_by: ExposureDimension) -> list[ExposureRollup]:
        raise NotImplementedError("stub: replaces *_exposure queries, exposure_trend")

    def vex_status(self, advisory: AdvisoryIdentifier, product_id: UUID) -> VexStatus | None:
        raise NotImplementedError("stub: replaces fetch_feeds.vex_product_status")

    def feed_status(self, feed: FeedName) -> FeedStatus:
        raise NotImplementedError("stub: replaces registry/feeds.feed_status")
