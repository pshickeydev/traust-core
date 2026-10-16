from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.assessment import Freshness
from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import OwnershipClass, RefKind

ProductSlug = NewType("ProductSlug", str)
RefName = NewType("RefName", str)
VersionLabel = NewType("VersionLabel", str)
TeamName = NewType("TeamName", str)
BusinessUnit = NewType("BusinessUnit", str)
OrgName = NewType("OrgName", str)
ImageRef = NewType("ImageRef", str)


class Designation(StrEnum):
    EXTERNAL = "external"
    INTERNAL_TOOLING = "internal-tooling"


class ExposureClass(StrEnum):
    PUBLIC_EXTERNAL = "public-external"
    PUBLIC_INTERNAL = "public-internal"
    PRIVATE_EXTERNAL = "private-external"
    PRIVATE_INTERNAL = "private-internal"


class RiskTier(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Visibility(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


class ForgeHost(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"


# Shapes land with their implementation slice.
class Segment(Model): ...


class ProductLifecycle(Model): ...


class Contact(Model): ...


class TrackerTarget(Model): ...


class OwnershipSource(Model): ...


class ResourceType(Model): ...


class ComponentSpec(Model): ...


class ReleaseChange(Model): ...


class SyncReport(Model): ...


class RepositoryFilter(Model): ...


class ComponentFilter(Model): ...


class Liveness(Model):
    archived: bool
    pushed_at: datetime | None = None
    observed_at: datetime


class Ownership(Model):
    team: TeamName
    business_unit: BusinessUnit
    ownership: OwnershipClass
    manager: str | None = None
    tracker: TrackerTarget | None = None
    source: OwnershipSource


class Product(Entity):
    slug: ProductSlug
    segment: Segment | None = None
    lifecycle: ProductLifecycle | None = None
    contacts: tuple[Contact, ...] = ()


class Repository(Entity):
    url: HttpsRepoUrl
    visibility: Visibility | None = None
    has_public_upstream: bool = False
    designation: Designation | None = None
    liveness: Liveness | None = None

    def exposure_class(self) -> ExposureClass:
        raise NotImplementedError("stub: replaces build_rescan_worklist.exposure_class")

    def is_dormant(self, now: datetime, after: timedelta) -> bool:
        raise NotImplementedError("stub: replaces check_repo_liveness.classify")

    def risk_tier(self, open_critical_high: int, now: datetime) -> RiskTier:
        raise NotImplementedError("stub: replaces build_rescan_worklist.risk_tier")


class CodeLine(Entity):
    repository_id: UUID
    ref: RefName
    kind: RefKind


class Revision(Entity):
    repository_id: UUID
    sha: GitSha


class Component(Entity):
    product_id: UUID
    code_line_id: UUID
    sub_service: str | None = None
    resource_type: ResourceType | None = None
    ownership: Ownership | None = None


class Release(Entity):
    component_id: UUID
    version: VersionLabel
    category: str | None = None
    images: tuple[ImageRef, ...] = ()

    def diff(self, previous: Release) -> ReleaseChange:
        raise NotImplementedError("stub: replaces build_release_events.diff_container")


class CrownJewelTier(Model): ...


class RepoState(Model):
    repository_id: UUID
    exposure: ExposureClass
    risk_tier: RiskTier
    crown_jewel: CrownJewelTier | None = None
    freshness: Freshness | None = None
    open_critical_high: int
    liveness: Liveness | None = None
