from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.operations import RunBatch
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

RUN_BATCH = TableSpec(TRAUST_OPS, "run_batch", lambda: (text_column("kind"), text_column("period")))


class RunBatchRepository(MutableRecordRepository[RunBatch], Protocol):
    def find(self, kind: str, period: str) -> RunBatch | None: ...


class SqlRunBatchRepository(SqlMutableRepository[RunBatch]):
    spec = RUN_BATCH
    record = RunBatch

    def find(self, kind: str, period: str) -> RunBatch | None:
        c = self.table.c
        return self._one(f"find {kind}/{period}", c.kind == kind, c.period == period)
