from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.operations import SpendDimension, SpendEvent, SpendFilter, SpendRollup
from traust_core.v1.repositories.sql import UtcMonth
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
        text_column("lane", nullable=True),
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
    def sum_by(
        self, filter: SpendFilter, group_by: SpendDimension | None = None
    ) -> list[SpendRollup]:
        """Spend in the filter's window, one rollup per group (one total when ungrouped)."""
        ...


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

    def sum_by(
        self, filter: SpendFilter, group_by: SpendDimension | None = None
    ) -> list[SpendRollup]:
        c = self.table.c
        where = [c.occurred_at >= filter.window.start, c.occurred_at < filter.window.end]
        if filter.lane is not None:
            where.append(c.lane == filter.lane)
        if filter.attributed is not None:
            where.append(
                c.run_order_id.is_not(None) if filter.attributed else c.run_order_id.is_(None)
            )
        keys: dict[SpendDimension, sa.ColumnElement[Any]] = {
            SpendDimension.MONTH: UtcMonth(c.occurred_at),
            SpendDimension.LANE: c.lane,
            SpendDimension.PROVIDER: c.provider,
            SpendDimension.MODEL: c.model,
            SpendDimension.SKILL: c.skill,
        }
        grouped = () if group_by is None else (keys[group_by],)
        stmt = (
            sa.select(
                *(k.label("key") for k in grouped),
                sa.func.count().label("events"),
                sa.cast(sa.func.sum(c.tokens_in), sa.BigInteger).label("tokens_in"),
                sa.cast(sa.func.sum(c.tokens_out), sa.BigInteger).label("tokens_out"),
                sa.func.sum(c.cost_usd, type_=sa.Numeric(asdecimal=True)).label("cost_usd"),
            )
            .where(*where)
            .group_by(*grouped)
            .having(sa.func.count() > 0)
            .order_by(*(k.asc().nulls_last() for k in grouped))
        )
        rows = self._execute(f"sum by {group_by} {filter}", stmt).mappings()
        return [SpendRollup.model_validate(dict(r)) for r in rows]
