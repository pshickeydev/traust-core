"""Rows of the traust namespace, 1 · Inventory - one model per contract table."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.base import Entity


class ProductRecord(Entity):
    slug: str
    name: str


class ReleaseRecord(Entity):
    product_id: UUID
    version: str


class ComponentRecord(Entity):
    release_id: UUID
    repository_ref_id: UUID


class RepositoryRecord(Entity):
    upstream_id: UUID | None = None
    url: str
    public: bool


class RepositoryRefRecord(Entity):
    repository_id: UUID
    name: str | None = None
    kind: str | None = None
    is_default: bool = False
    sha: str
    manifest_sbom_id: UUID | None = None


class TeamRecord(Entity):
    name: str


class OwnershipRecord(Entity):
    repository_id: UUID
    team_id: UUID
    valid_from: datetime
    valid_to: datetime | None = None
