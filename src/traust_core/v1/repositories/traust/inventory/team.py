from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import RecordBudget
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
    def get_or_add(self, record: Team) -> Team: ...
    def find_by_name(self, name: str) -> Team | None: ...
    def list_by_ids(
        self, team_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Team]: ...


class SqlTeamRepository(SqlMutableRepository[Team]):
    spec = TEAM
    record = Team

    def get_or_add(self, record: Team) -> Team:
        return self._get_or_add(
            record,
            ("name",),
            lambda: self.find_by_name(record.name),
        )

    def find_by_name(self, name: str) -> Team | None:
        return self._one(f"find {name}", self.table.c.name == name)

    def list_by_ids(
        self, team_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Team]:
        return self._many_in(
            f"list {len(team_ids)} by id", self.table.c.id, team_ids, read_budget=read_budget
        )
