from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.remediation_scheduling import Remediation
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableFactory,
    TableSpec,
    text_column,
    uuid_column,
)
from traust_core.v1.repositories.traust.findings.remediation_finding import REMEDIATION_FINDING

REMEDIATION = TableSpec(
    TRAUST,
    "remediation",
    lambda: (
        text_column("fork_url"),
        text_column("fork_branch"),
        text_column("status"),
        uuid_column("assessment_id", nullable=True),
    ),
)


class RemediationRepository(MutableRecordRepository[Remediation], Protocol):
    def find_by_assessment(self, assessment_id: UUID) -> Remediation | None: ...
    def find_by_assessment_for_update(self, assessment_id: UUID) -> Remediation | None: ...
    def get_for_update(self, remediation_id: UUID) -> Remediation: ...
    def list_by_ids(self, remediation_ids: Collection[UUID]) -> list[Remediation]: ...
    def list_by_status(self, status: RemediationStatus) -> list[Remediation]: ...
    def list_all(self) -> list[Remediation]: ...
    def search(
        self,
        *,
        status: RemediationStatus | None,
        repository_id: UUID | None,
        finding_id: UUID | None,
        limit: int,
        after: tuple[datetime, UUID] | None,
    ) -> list[Remediation]: ...


class SqlRemediationRepository(SqlMutableRepository[Remediation]):
    spec = REMEDIATION
    record = Remediation

    def find_by_assessment(self, assessment_id: UUID) -> Remediation | None:
        return self._one(
            f"find by assessment {assessment_id}", self.table.c.assessment_id == assessment_id
        )

    def find_by_assessment_for_update(self, assessment_id: UUID) -> Remediation | None:
        """The row a status sync moves, locked until the transaction ends (Postgres; SQLite's
        caller holds its write lock) so two syncs can't interleave."""
        stmt = self._select().where(self.table.c.assessment_id == assessment_id).with_for_update()
        row = self._execute(f"lock by assessment {assessment_id}", stmt).mappings().one_or_none()
        return None if row is None else self._to_record(row)

    def get_for_update(self, remediation_id: UUID) -> Remediation:
        stmt = self._select().where(self.table.c.id == remediation_id).with_for_update()
        row = self._execute(f"lock {remediation_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"remediation {remediation_id}")
        return self._to_record(row)

    def list_by_ids(self, remediation_ids: Collection[UUID]) -> list[Remediation]:
        return self._many_in("list by id", self.table.c.id, remediation_ids)

    def list_by_status(self, status: RemediationStatus) -> list[Remediation]:
        return self._many(f"list {status}", self.table.c.status == status)

    def list_all(self) -> list[Remediation]:
        return self._many("list all")

    def search(
        self,
        *,
        status: RemediationStatus | None,
        repository_id: UUID | None,
        finding_id: UUID | None,
        limit: int,
        after: tuple[datetime, UUID] | None,
    ) -> list[Remediation]:
        """A keyset page of efforts, oldest first: at a status, scheduled on a repository's or
        a finding's rows (each filter given applies).

        The repository and finding filters read `remediation_finding` — the junction
        table `SqlRemediationFindingRepository` owns — in this one keyset query over
        the aggregate's child table, the same deliberate read `spend_event` makes of
        `run_order`. `ScheduledRemediations` owns the table's writes; resolving the
        ids through it instead (two queries, an id set handed to `search`) is a
        decision for the owners, not this repository's to make silently.
        """
        c = self.table.c
        where: list[sa.ColumnElement[bool]] = []
        if status is not None:
            where.append(c.status == status)
        linked = TableFactory.for_bind(self._connection).table(REMEDIATION_FINDING).c
        filters = ((linked.repository_id, repository_id), (linked.finding_id, finding_id))
        for column, value in filters:
            if value is not None:
                where.append(c.id.in_(sa.select(linked.remediation_id).where(column == value)))
        return self._page("search", *where, limit=limit, after=after, oldest_first=True)
