from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.portfolio import (
    CodeLine,
    Component,
    ComponentFilter,
    ComponentSpec,
    Designation,
    ForgeHost,
    ImageRef,
    Liveness,
    OrgName,
    Ownership,
    OwnershipSource,
    Product,
    ProductSlug,
    RefName,
    Release,
    Repository,
    RepositoryFilter,
    RepoState,
    Revision,
    Segment,
    SyncReport,
    VersionLabel,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.repositories.portfolio import PortfolioUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.service import FindingService


class PortfolioService:
    def __init__(self, uow: PortfolioUnitOfWork) -> None:
        self._uow = uow

    def register_product(self, slug: ProductSlug, segment: Segment | None) -> Product:
        raise NotImplementedError("stub: replaces registry/products.py, inventory.py")

    def register_repository(self, url: HttpsRepoUrl) -> Repository:
        raise NotImplementedError("stub: replaces corpus_intake.py, add-inputs")

    def register_code_line(self, repository_id: UUID, ref: RefName, kind: RefKind) -> CodeLine:
        raise NotImplementedError("stub: replaces product_repo (product, repo, ref) rows")

    def register_revision(self, repository_id: UUID, sha: GitSha) -> Revision:
        raise NotImplementedError("stub: replaces corpus/store_ingest repo@sha keys")

    def add_component(self, product_id: UUID, code_line_id: UUID, spec: ComponentSpec) -> Component:
        raise NotImplementedError("stub: replaces product_repo upserts")

    def record_release(
        self, component_id: UUID, version: VersionLabel, images: Sequence[ImageRef]
    ) -> Release:
        raise NotImplementedError("stub: replaces product_repo_version, build_release_events")

    def assign_ownership(self, component_id: UUID, ownership: Ownership) -> Component:
        raise NotImplementedError("stub: replaces repo_owner, subject_ownership")

    def set_designation(self, repository_id: UUID, designation: Designation) -> Repository:
        raise NotImplementedError("stub: replaces build_rescan_worklist.load_designations")

    def record_liveness(self, repository_id: UUID, liveness: Liveness) -> Repository:
        raise NotImplementedError("stub: replaces check_repo_liveness.py")

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

    def refresh(self, repository_id: UUID) -> Repository:
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
