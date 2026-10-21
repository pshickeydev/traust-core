from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.records import CweRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

CWE = TableSpec(
    TRAUST,
    "cwe",
    lambda: (
        text_column("identifier"),
        text_column("abstraction", nullable=True),
        text_column("mapping_usage", nullable=True),
        text_column("catalog_version", nullable=True),
    ),
)


class CweRepository(MutableRecordRepository[CweRecord], Protocol):
    def find_by_identifier(self, identifier: str) -> CweRecord | None: ...


class SqlCweRepository(SqlMutableRepository[CweRecord]):
    spec = CWE
    record = CweRecord

    def find_by_identifier(self, identifier: str) -> CweRecord | None:
        return self._one(f"find {identifier}", self.table.c.identifier == identifier)
