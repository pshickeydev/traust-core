from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import AdvisoryRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

ADVISORY = TableSpec(
    TRAUST,
    "advisory",
    lambda: (
        uuid_column("alias_of_id", nullable=True),
        text_column("identifier"),
        timestamp_column("published_at", nullable=True),
    ),
)


class AdvisoryRepository(MutableRecordRepository[AdvisoryRecord], Protocol):
    def find_by_identifier(self, identifier: str) -> AdvisoryRecord | None: ...
    def list_aliases(self, advisory_id: UUID) -> list[AdvisoryRecord]: ...


class SqlAdvisoryRepository(SqlMutableRepository[AdvisoryRecord]):
    spec = ADVISORY
    record = AdvisoryRecord

    def find_by_identifier(self, identifier: str) -> AdvisoryRecord | None:
        return self._one(f"find {identifier}", self.table.c.identifier == identifier)

    def list_aliases(self, advisory_id: UUID) -> list[AdvisoryRecord]:
        return self._many(f"aliases of {advisory_id}", self.table.c.alias_of_id == advisory_id)
