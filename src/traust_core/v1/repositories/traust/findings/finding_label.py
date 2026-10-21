from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import FindingLabelRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

FINDING_LABEL = TableSpec(
    TRAUST,
    "finding_label",
    lambda: (uuid_column("finding_id"), text_column("taxonomy"), text_column("label")),
)


class FindingLabelRepository(MutableRecordRepository[FindingLabelRecord], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingLabelRecord]: ...
    def list_with(self, taxonomy: str, label: str) -> list[FindingLabelRecord]: ...


class SqlFindingLabelRepository(SqlMutableRepository[FindingLabelRecord]):
    spec = FINDING_LABEL
    record = FindingLabelRecord

    def list_for_finding(self, finding_id: UUID) -> list[FindingLabelRecord]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_with(self, taxonomy: str, label: str) -> list[FindingLabelRecord]:
        c = self.table.c
        return self._many(f"list {taxonomy}:{label}", c.taxonomy == taxonomy, c.label == label)
