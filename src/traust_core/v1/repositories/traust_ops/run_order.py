from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.operations import RunOrder
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

RUN_ORDER = TableSpec(
    TRAUST_OPS,
    "run_order",
    lambda: (
        uuid_column("run_batch_id", nullable=True),
        uuid_column("repository_id", nullable=True),
        uuid_column("artifact_id", nullable=True),
        text_column("rule", nullable=True),
        text_column("event_source", nullable=True),
        text_column("lane"),
        text_column("state"),
        sa.Column("priority", sa.Integer, nullable=False),
        text_column("reason", nullable=True),
        text_column("requested_by"),
        text_column("lease_holder", nullable=True),
        timestamp_column("lease_expires_at", nullable=True),
        timestamp_column("started_at", nullable=True),
        timestamp_column("finished_at", nullable=True),
    ),
)

# run_order.state values the queue mechanics depend on (contracts enum, to add).
QUEUED = "queued"
LEASED = "leased"


class RunOrderRepository(MutableRecordRepository[RunOrder], Protocol):
    def claim(self, worker: str, now: datetime, lease_for: timedelta) -> RunOrder | None:
        """Lease the next queued order (priority, then age); None when the queue is empty."""
        ...

    def release_expired(self, now: datetime) -> int: ...
    def list_for_batch(self, run_batch_id: UUID) -> list[RunOrder]: ...
    def list_for_repository(self, repository_id: UUID, state: str) -> list[RunOrder]: ...


class SqlRunOrderRepository(SqlMutableRepository[RunOrder]):
    spec = RUN_ORDER
    record = RunOrder

    def claim(self, worker: str, now: datetime, lease_for: timedelta) -> RunOrder | None:
        c = self.table.c
        # SKIP LOCKED on Postgres; SQLite serialises writers and drops FOR UPDATE.
        next_id = (
            sa.select(c.id)
            .where(c.state == QUEUED)
            .order_by(c.priority, c.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            sa.update(self.table)
            .where(c.id == next_id, c.state == QUEUED)
            .values(state=LEASED, lease_holder=worker, lease_expires_at=now + lease_for)
            .returning(c.id)
        )
        claimed = self._execute(f"claim for {worker}", stmt).scalar_one_or_none()
        return None if claimed is None else self.get(claimed)

    def release_expired(self, now: datetime) -> int:
        """Return expired leases to the queue; the count released."""
        c = self.table.c
        stmt = (
            sa.update(self.table)
            .where(c.state == LEASED, c.lease_expires_at < now)
            .values(state=QUEUED, lease_holder=None, lease_expires_at=None)
        )
        return self._execute(f"release expired at {now}", stmt).rowcount

    def list_for_batch(self, run_batch_id: UUID) -> list[RunOrder]:
        return self._many(
            f"list for batch {run_batch_id}", self.table.c.run_batch_id == run_batch_id
        )

    def list_for_repository(self, repository_id: UUID, state: str) -> list[RunOrder]:
        c = self.table.c
        return self._many(
            f"list {state} for {repository_id}",
            c.repository_id == repository_id,
            c.state == state,
            order_by=(c.priority,),
        )
