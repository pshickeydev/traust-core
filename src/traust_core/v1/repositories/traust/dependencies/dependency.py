from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.records import DependencyRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

DEPENDENCY = TableSpec(
    TRAUST,
    "dependency",
    lambda: (
        uuid_column("sbom_id"),
        uuid_column("package_id"),
        text_column("version"),
        sa.Column("direct", sa.Boolean, nullable=False),
    ),
    append_only=True,
)


class DependencyRepository(RecordRepository[DependencyRecord], Protocol):
    def list_for_sbom(self, sbom_id: UUID) -> list[DependencyRecord]: ...
    def list_for_package(self, package_id: UUID) -> list[DependencyRecord]: ...


class SqlDependencyRepository(SqlAppendOnlyRepository[DependencyRecord]):
    spec = DEPENDENCY
    record = DependencyRecord

    def list_for_sbom(self, sbom_id: UUID) -> list[DependencyRecord]:
        return self._many(f"list for sbom {sbom_id}", self.table.c.sbom_id == sbom_id)

    def list_for_package(self, package_id: UUID) -> list[DependencyRecord]:
        """SBOMs that include the package (advisory sweep, usage query)."""
        return self._many(f"list for package {package_id}", self.table.c.package_id == package_id)
