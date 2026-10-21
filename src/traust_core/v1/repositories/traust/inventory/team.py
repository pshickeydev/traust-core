from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.records import TeamRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

TEAM = TableSpec(TRAUST, "team", lambda: (text_column("name"),))


class TeamRepository(MutableRecordRepository[TeamRecord], Protocol):
    def find_by_name(self, name: str) -> TeamRecord | None: ...


class SqlTeamRepository(SqlMutableRepository[TeamRecord]):
    spec = TEAM
    record = TeamRecord

    def find_by_name(self, name: str) -> TeamRecord | None:
        return self._one(f"find {name}", self.table.c.name == name)
