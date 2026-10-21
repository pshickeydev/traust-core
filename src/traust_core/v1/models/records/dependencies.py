"""Rows of the traust namespace, 2 · Dependencies - one model per contract table."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Entity


class PackageRecord(Entity):
    source_repository_id: UUID | None = None
    sbom_id: UUID | None = None
    ecosystem: str
    name: str


class SbomRecord(AppendOnly):
    digest: str
    artifact_id: UUID | None = None


class DependencyRecord(AppendOnly):
    sbom_id: UUID
    package_id: UUID
    version: str
    direct: bool


class ImageRecord(AppendOnly):
    digest: str
    platform: str | None = None
    repository_ref_id: UUID | None = None
    sbom_id: UUID | None = None


class AdvisoryRecord(Entity):
    alias_of_id: UUID | None = None
    identifier: str
    published_at: datetime | None = None


class AdvisoryPackageRecord(Entity):
    advisory_id: UUID
    package_id: UUID
