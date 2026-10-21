from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.operations import SpendEvent
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

SPEND_EVENT = TableSpec(
    TRAUST_OPS,
    "spend_event",
    lambda: (
        uuid_column("run_order_id", nullable=True),
        text_column("provider"),
        text_column("model"),
        text_column("skill", nullable=True),
        sa.Column("tokens_in", sa.BigInteger, nullable=False),
        sa.Column("tokens_out", sa.BigInteger, nullable=False),
        sa.Column("cost_usd", sa.Numeric, nullable=False),
        timestamp_column("occurred_at"),
    ),
    append_only=True,
)


class SpendEventRepository(RecordRepository[SpendEvent], Protocol):
    def list_for_order(self, run_order_id: UUID) -> list[SpendEvent]: ...
    def list_between(self, start: datetime, end: datetime) -> list[SpendEvent]: ...


class SqlSpendEventRepository(SqlAppendOnlyRepository[SpendEvent]):
    spec = SPEND_EVENT
    record = SpendEvent

    def list_for_order(self, run_order_id: UUID) -> list[SpendEvent]:
        return self._many(f"list for {run_order_id}", self.table.c.run_order_id == run_order_id)

    def list_between(self, start: datetime, end: datetime) -> list[SpendEvent]:
        """Spend with start <= occurred_at < end."""
        c = self.table.c
        return self._many(
            f"list {start}..{end}",
            c.occurred_at >= start,
            c.occurred_at < end,
            order_by=(c.occurred_at,),
        )
