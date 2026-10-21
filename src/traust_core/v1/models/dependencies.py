"""2 · Dependencies - third-party code and known vulnerabilities.

Table models mirror the traust contracts DDL; ranges, symbols and impact
detail live in artifacts (scanner output, impact analysis), not columns.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.findings import SkillInput

AdvisoryIdentifier = NewType("AdvisoryIdentifier", str)
Version = NewType("Version", str)
FeedName = NewType("FeedName", str)


class Package(Entity):
    source_repository_id: UUID | None = None
    sbom_id: UUID | None = None
    ecosystem: str
    name: str


class Sbom(AppendOnly):
    digest: str
    artifact_id: UUID | None = None


class Dependency(AppendOnly):
    sbom_id: UUID
    package_id: UUID
    version: str
    direct: bool


class Image(AppendOnly):
    digest: str
    platform: str | None = None
    repository_ref_id: UUID | None = None
    sbom_id: UUID | None = None


class Advisory(Entity):
    alias_of_id: UUID | None = None
    identifier: str
    published_at: datetime | None = None


class AdvisoryPackage(Entity):
    advisory_id: UUID
    package_id: UUID


class VexStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


# Shapes land with their implementation slice.
class ImpactEvidence(Model): ...


class DependencyIngest(Model): ...


class DependencyProvenance(Model): ...


class ProvenanceCheck(Model): ...


class AffectedDependency(Model): ...


class ImpactFilter(Model): ...


class ExposureFilter(Model): ...


class ExposureDimension(Model): ...


class ExposureRollup(Model): ...


class ImpactAnalysis(Model):
    """Read from the impact-analysis artifact of an assessment."""


class ImpactInput(SkillInput): ...
