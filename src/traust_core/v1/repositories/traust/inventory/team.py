from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.inventory import Team
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

TEAM = TableSpec(TRAUST, "team", lambda: (text_column("name"),))


class TeamRepository(MutableRecordRepository[Team], Protocol):
    def find_by_name(self, name: str) -> Team | None: ...


class SqlTeamRepository(SqlMutableRepository[Team]):
    spec = TEAM
    record = Team

    def find_by_name(self, name: str) -> Team | None:
        return self._one(f"find {name}", self.table.c.name == name)
