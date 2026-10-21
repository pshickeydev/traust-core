from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.records import ProductRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

PRODUCT = TableSpec(TRAUST, "product", lambda: (text_column("slug"), text_column("name")))


class ProductRepository(MutableRecordRepository[ProductRecord], Protocol):
    def find_by_slug(self, slug: str) -> ProductRecord | None: ...


class SqlProductRepository(SqlMutableRepository[ProductRecord]):
    spec = PRODUCT
    record = ProductRecord

    def find_by_slug(self, slug: str) -> ProductRecord | None:
        return self._one(f"find {slug}", self.table.c.slug == slug)
