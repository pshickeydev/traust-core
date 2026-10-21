from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.inventory import Release
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

RELEASE = TableSpec(TRAUST, "release", lambda: (uuid_column("product_id"), text_column("version")))


class ReleaseRepository(MutableRecordRepository[Release], Protocol):
    def find(self, product_id: UUID, version: str) -> Release | None: ...
    def list_for_product(self, product_id: UUID) -> list[Release]: ...


class SqlReleaseRepository(SqlMutableRepository[Release]):
    spec = RELEASE
    record = Release

    def find(self, product_id: UUID, version: str) -> Release | None:
        c = self.table.c
        return self._one(f"find {version}", c.product_id == product_id, c.version == version)

    def list_for_product(self, product_id: UUID) -> list[Release]:
        return self._many(f"list for {product_id}", self.table.c.product_id == product_id)
