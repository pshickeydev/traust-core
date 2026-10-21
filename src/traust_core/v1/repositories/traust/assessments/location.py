from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.records import LocationRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

LOCATION = TableSpec(
    TRAUST,
    "location",
    lambda: (
        uuid_column("occurrence_id"),
        text_column("path"),
        sa.Column("line_start", sa.Integer, nullable=True),
        sa.Column("line_end", sa.Integer, nullable=True),
        text_column("language", nullable=True),
        text_column("symbol", nullable=True),
    ),
    append_only=True,
)


class LocationRepository(RecordRepository[LocationRecord], Protocol):
    def list_for_occurrence(self, occurrence_id: UUID) -> list[LocationRecord]: ...


class SqlLocationRepository(SqlAppendOnlyRepository[LocationRecord]):
    spec = LOCATION
    record = LocationRecord

    def list_for_occurrence(self, occurrence_id: UUID) -> list[LocationRecord]:
        c = self.table.c
        return self._many(
            f"list for {occurrence_id}",
            c.occurrence_id == occurrence_id,
            order_by=(c.path, c.line_start),
        )
