from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.base import Model
from traust_core.v1.models.operations import AssetRequest
from traust_core.v1.models.portfolio import (
    Designation,
    OrgName,
    Ownership,
    ProductSlug,
    RefName,
    Segment,
)
from traust_core.v1.models.values import HttpsRepoUrl


class Gap(Model): ...


class RepositorySpec(Model):
    url: HttpsRepoUrl
    refs: tuple[RefName, ...] = ()
    designation: Designation | None = None
    ownership: Ownership | None = None


class OnboardingRequest(Model):
    product: ProductSlug
    segment: Segment | None = None
    repositories: tuple[RepositorySpec, ...] = ()
    org: OrgName | None = None
    baseline: tuple[AssessmentKind, ...] = ()


class OnboardingPlan(Model):
    new: tuple[RepositorySpec, ...] = ()
    existing_repository_ids: tuple[UUID, ...] = ()
    gaps: tuple[Gap, ...] = ()
    orders: tuple[AssetRequest, ...] = ()


class OnboardingResult(Model):
    product_id: UUID
    repository_ids: tuple[UUID, ...] = ()
    order_ids: tuple[UUID, ...] = ()
