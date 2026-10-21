from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import FindingCweRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    uuid_column,
)

FINDING_CWE = TableSpec(
    TRAUST, "finding_cwe", lambda: (uuid_column("finding_id"), uuid_column("cwe_id"))
)


class FindingCweRepository(MutableRecordRepository[FindingCweRecord], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingCweRecord]: ...
    def list_for_cwe(self, cwe_id: UUID) -> list[FindingCweRecord]: ...


class SqlFindingCweRepository(SqlMutableRepository[FindingCweRecord]):
    spec = FINDING_CWE
    record = FindingCweRecord

    def list_for_finding(self, finding_id: UUID) -> list[FindingCweRecord]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_cwe(self, cwe_id: UUID) -> list[FindingCweRecord]:
        return self._many(f"list for cwe {cwe_id}", self.table.c.cwe_id == cwe_id)
