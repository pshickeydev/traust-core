from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.inventory import Product
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

PRODUCT = TableSpec(TRAUST, "product", lambda: (text_column("slug"), text_column("name")))


class ProductRepository(MutableRecordRepository[Product], Protocol):
    def find_by_slug(self, slug: str) -> Product | None: ...


class SqlProductRepository(SqlMutableRepository[Product]):
    spec = PRODUCT
    record = Product

    def find_by_slug(self, slug: str) -> Product | None:
        return self._one(f"find {slug}", self.table.c.slug == slug)
