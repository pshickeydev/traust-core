from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

REPOSITORY_REF = TableSpec(
    TRAUST,
    "repository_ref",
    lambda: (
        uuid_column("repository_id"),
        text_column("name", nullable=True),
        text_column("kind", nullable=True),
        sa.Column("is_default", sa.Boolean, nullable=False),
        text_column("sha"),
        uuid_column("manifest_sbom_id", nullable=True),
    ),
)


class RepositoryRefRepository(MutableRecordRepository[RepositoryRef], Protocol):
    def find(self, repository_id: UUID, name: str | None, sha: str) -> RepositoryRef | None:
        """A named ref by (repository, name, sha); name None = the bare commit."""
        ...

    def list_for(self, repository_id: UUID) -> list[RepositoryRef]: ...
    def default(self, repository_id: UUID) -> RepositoryRef | None: ...
    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]: ...


class SqlRepositoryRefRepository(SqlMutableRepository[RepositoryRef]):
    spec = REPOSITORY_REF
    record = RepositoryRef

    def find(self, repository_id: UUID, name: str | None, sha: str) -> RepositoryRef | None:
        c = self.table.c
        named = c.name.is_(None) if name is None else c.name == name
        return self._one(
            f"find {name or 'bare'}@{sha}", c.repository_id == repository_id, named, c.sha == sha
        )

    def list_for(self, repository_id: UUID) -> list[RepositoryRef]:
        return self._many(f"list for {repository_id}", self.table.c.repository_id == repository_id)

    def default(self, repository_id: UUID) -> RepositoryRef | None:
        """The latest ref recorded as the default branch."""
        c = self.table.c
        stmt = (
            self._select()
            .where(c.repository_id == repository_id, c.is_default.is_(True))
            .order_by(c.created_at.desc())
            .limit(1)
        )
        row = self._execute(f"default for {repository_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]:
        return self._many(f"list for sbom {sbom_id}", self.table.c.manifest_sbom_id == sbom_id)
