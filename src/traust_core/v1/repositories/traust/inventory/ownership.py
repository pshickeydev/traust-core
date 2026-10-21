from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.records import OwnershipRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    timestamp_column,
    uuid_column,
)

OWNERSHIP = TableSpec(
    TRAUST,
    "ownership",
    lambda: (
        uuid_column("repository_id"),
        uuid_column("team_id"),
        timestamp_column("valid_from"),
        timestamp_column("valid_to", nullable=True),
    ),
)


class OwnershipRepository(MutableRecordRepository[OwnershipRecord], Protocol):
    def current(self, repository_id: UUID) -> list[OwnershipRecord]: ...
    def as_of(self, repository_id: UUID, at: datetime) -> list[OwnershipRecord]: ...
    def list_for_team(self, team_id: UUID) -> list[OwnershipRecord]: ...


class SqlOwnershipRepository(SqlMutableRepository[OwnershipRecord]):
    spec = OWNERSHIP
    record = OwnershipRecord

    def current(self, repository_id: UUID) -> list[OwnershipRecord]:
        c = self.table.c
        return self._many(
            f"current for {repository_id}", c.repository_id == repository_id, c.valid_to.is_(None)
        )

    def as_of(self, repository_id: UUID, at: datetime) -> list[OwnershipRecord]:
        c = self.table.c
        return self._many(
            f"as of {at} for {repository_id}",
            c.repository_id == repository_id,
            c.valid_from <= at,
            sa.or_(c.valid_to.is_(None), c.valid_to > at),
        )

    def list_for_team(self, team_id: UUID) -> list[OwnershipRecord]:
        return self._many(f"list for team {team_id}", self.table.c.team_id == team_id)
