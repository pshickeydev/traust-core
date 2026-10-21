from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.records import RunBatchRecord
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

RUN_BATCH = TableSpec(TRAUST_OPS, "run_batch", lambda: (text_column("kind"), text_column("period")))


class RunBatchRepository(MutableRecordRepository[RunBatchRecord], Protocol):
    def find(self, kind: str, period: str) -> RunBatchRecord | None: ...


class SqlRunBatchRepository(SqlMutableRepository[RunBatchRecord]):
    spec = RUN_BATCH
    record = RunBatchRecord

    def find(self, kind: str, period: str) -> RunBatchRecord | None:
        c = self.table.c
        return self._one(f"find {kind}/{period}", c.kind == kind, c.period == period)
