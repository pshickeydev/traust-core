from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.dependencies import Sbom
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

SBOM = TableSpec(
    TRAUST,
    "sbom",
    lambda: (text_column("digest"), uuid_column("artifact_id", nullable=True)),
    append_only=True,
)


class SbomRepository(RecordRepository[Sbom], Protocol):
    def find_by_digest(self, digest: str) -> Sbom | None: ...


class SqlSbomRepository(SqlAppendOnlyRepository[Sbom]):
    spec = SBOM
    record = Sbom

    def find_by_digest(self, digest: str) -> Sbom | None:
        return self._one(f"find {digest}", self.table.c.digest == digest)
