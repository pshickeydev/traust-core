from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import FindingExternalRefRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

FINDING_EXTERNAL_REF = TableSpec(
    TRAUST,
    "finding_external_ref",
    lambda: (uuid_column("finding_id"), text_column("system"), text_column("ref")),
)


class FindingExternalRefRepository(MutableRecordRepository[FindingExternalRefRecord], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingExternalRefRecord]: ...
    def list_for_ref(self, system: str, ref: str) -> list[FindingExternalRefRecord]: ...


class SqlFindingExternalRefRepository(SqlMutableRepository[FindingExternalRefRecord]):
    spec = FINDING_EXTERNAL_REF
    record = FindingExternalRefRecord

    def list_for_finding(self, finding_id: UUID) -> list[FindingExternalRefRecord]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_ref(self, system: str, ref: str) -> list[FindingExternalRefRecord]:
        c = self.table.c
        return self._many(f"list {system}:{ref}", c.system == system, c.ref == ref)
