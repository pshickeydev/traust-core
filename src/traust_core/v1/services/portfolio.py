from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.inventory import (
    Component,
    ComponentFilter,
    ExposureClass,
    ForgeHost,
    Liveness,
    OrgName,
    Ownership,
    OwnershipSource,
    Product,
    ProductSlug,
    RefName,
    Release,
    ReleaseChange,
    Repository,
    RepositoryFilter,
    RepositoryRef,
    RepoState,
    RiskTier,
    SyncReport,
    VersionLabel,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.repositories.traust.inventory import InventoryUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.service import FindingService


class PortfolioService:
    def __init__(self, uow: InventoryUnitOfWork) -> None:
        self._uow = uow

    def register_product(self, slug: ProductSlug, name: str) -> Product:
        raise NotImplementedError("stub: replaces registry/products.py, inventory.py")

    def register_repository(self, url: HttpsRepoUrl, public: bool) -> Repository:
        raise NotImplementedError("stub: replaces corpus_intake.py, add-inputs")

    def register_ref(
        self, repository_id: UUID, sha: GitSha, name: RefName | None, kind: RefKind | None
    ) -> RepositoryRef:
        raise NotImplementedError("stub: replaces product_repo (product, repo, ref) rows")

    def record_release(self, product_id: UUID, version: VersionLabel) -> Release:
        raise NotImplementedError("stub: replaces product_repo_version, build_release_events")

    def add_component(self, release_id: UUID, repository_ref_id: UUID) -> Component:
        raise NotImplementedError("stub: replaces product_repo upserts")

    def release_changes(self, release_id: UUID, previous_id: UUID) -> ReleaseChange:
        raise NotImplementedError("stub: replaces build_release_events.diff_container")

    def assign_owner(self, repository_id: UUID, team: str, at: datetime) -> Ownership:
        raise NotImplementedError("stub: replaces repo_owner, subject_ownership")

    def exposure_class(self, repository_id: UUID, liveness: Liveness) -> ExposureClass:
        raise NotImplementedError("stub: replaces build_rescan_worklist.exposure_class")

    def is_dormant(self, liveness: Liveness, now: datetime, after: timedelta) -> bool:
        raise NotImplementedError("stub: replaces check_repo_liveness.classify")

    def risk_tier(self, repository_id: UUID, open_critical_high: int, now: datetime) -> RiskTier:
        raise NotImplementedError("stub: replaces build_rescan_worklist.risk_tier")

    def get_repository(self, repository_id: UUID) -> Repository:
        raise NotImplementedError("stub: portfolio read")

    def find_repository(self, url: HttpsRepoUrl) -> Repository | None:
        raise NotImplementedError("stub: replaces canon_repo / normalize_repo lookups")

    def list_repositories(self, filter: RepositoryFilter, page: PageRequest) -> Page[Repository]:
        raise NotImplementedError("stub: replaces build_org_index.py, repo-graph")

    def get_product(self, product_id: UUID) -> Product:
        raise NotImplementedError("stub: portfolio read")

    def find_product(self, slug: ProductSlug) -> Product | None:
        raise NotImplementedError("stub: replaces registry/products.resolve_product")

    def list_components(self, filter: ComponentFilter, page: PageRequest) -> Page[Component]:
        raise NotImplementedError("stub: replaces corpus/resolver ownership cuts")


class PortfolioSync:
    def __init__(self, portfolio: PortfolioService, sources: SourceProvider) -> None:
        self._portfolio = portfolio
        self._sources = sources

    def liveness(self, repository_id: UUID) -> Liveness:
        raise NotImplementedError("stub: replaces check_repo_liveness.gh_repo_info")

    def import_org(self, org: OrgName, host: ForgeHost) -> SyncReport:
        raise NotImplementedError("stub: replaces corpus_intake.py org import")

    def import_owners(self, source: OwnershipSource) -> SyncReport:
        raise NotImplementedError("stub: replaces fetch_forge_owners.py")


class RepoStateQuery:
    def __init__(
        self, portfolio: PortfolioService, assessments: AssessmentService, findings: FindingService
    ) -> None:
        self._portfolio = portfolio
        self._assessments = assessments
        self._findings = findings

    def repo_state(self, repository_id: UUID) -> RepoState:
        raise NotImplementedError("stub: replaces traust#58 observe_repo")

    def list(self, filter: RepositoryFilter, page: PageRequest) -> Page[RepoState]:
        raise NotImplementedError("stub: replaces build_rescan_worklist, build_crown_jewel_tiers")
