from __future__ import annotations

from typing import Protocol

import sqlalchemy as sa

from traust_core.v1.models.records import RepositoryRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

REPOSITORY = TableSpec(
    TRAUST,
    "repository",
    lambda: (
        uuid_column("upstream_id", nullable=True),
        text_column("url"),
        sa.Column("public", sa.Boolean, nullable=False),
    ),
)


class RepositoryRepository(MutableRecordRepository[RepositoryRecord], Protocol):
    def find_by_url(self, url: str) -> RepositoryRecord | None: ...


class SqlRepositoryRepository(SqlMutableRepository[RepositoryRecord]):
    spec = REPOSITORY
    record = RepositoryRecord

    def find_by_url(self, url: str) -> RepositoryRecord | None:
        return self._one(f"find {url}", self.table.c.url == url)
