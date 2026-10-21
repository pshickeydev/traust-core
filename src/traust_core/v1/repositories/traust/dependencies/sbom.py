from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.records import SbomRecord
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


class SbomRepository(RecordRepository[SbomRecord], Protocol):
    def find_by_digest(self, digest: str) -> SbomRecord | None: ...


class SqlSbomRepository(SqlAppendOnlyRepository[SbomRecord]):
    spec = SBOM
    record = SbomRecord

    def find_by_digest(self, digest: str) -> SbomRecord | None:
        return self._one(f"find {digest}", self.table.c.digest == digest)
