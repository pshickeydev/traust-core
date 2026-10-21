from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import ReleaseRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

RELEASE = TableSpec(TRAUST, "release", lambda: (uuid_column("product_id"), text_column("version")))


class ReleaseRepository(MutableRecordRepository[ReleaseRecord], Protocol):
    def find(self, product_id: UUID, version: str) -> ReleaseRecord | None: ...
    def list_for_product(self, product_id: UUID) -> list[ReleaseRecord]: ...


class SqlReleaseRepository(SqlMutableRepository[ReleaseRecord]):
    spec = RELEASE
    record = ReleaseRecord

    def find(self, product_id: UUID, version: str) -> ReleaseRecord | None:
        c = self.table.c
        return self._one(f"find {version}", c.product_id == product_id, c.version == version)

    def list_for_product(self, product_id: UUID) -> list[ReleaseRecord]:
        return self._many(f"list for {product_id}", self.table.c.product_id == product_id)
