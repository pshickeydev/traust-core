"""4 · Operations (traust_ops) - what traust ran, with what, and what it cost.

One repository per table. SQLite carries the namespace as the `ops_` prefix.
"""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.tables import SqlTablesUnitOfWork
from traust_core.v1.repositories.traust_ops.assessment_input import (
    ASSESSMENT_INPUT,
    AssessmentInputRepository,
    SqlAssessmentInputRepository,
)
from traust_core.v1.repositories.traust_ops.feed_snapshot import (
    FEED_SNAPSHOT,
    FeedSnapshotRepository,
    SqlFeedSnapshotRepository,
)
from traust_core.v1.repositories.traust_ops.run_batch import (
    RUN_BATCH,
    RunBatchRepository,
    SqlRunBatchRepository,
)
from traust_core.v1.repositories.traust_ops.run_order import (
    RUN_ORDER,
    RunOrderRepository,
    SqlRunOrderRepository,
)
from traust_core.v1.repositories.traust_ops.spend_event import (
    SPEND_EVENT,
    SpendEventRepository,
    SqlSpendEventRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (RUN_BATCH, RUN_ORDER, SPEND_EVENT, FEED_SNAPSHOT, ASSESSMENT_INPUT)


class OpsUnitOfWork(UnitOfWork, Protocol):
    run_batches: RunBatchRepository
    run_orders: RunOrderRepository
    spend_events: SpendEventRepository
    feed_snapshots: FeedSnapshotRepository
    assessment_inputs: AssessmentInputRepository


class SqlOpsUnitOfWork(SqlTablesUnitOfWork):
    def _open_repositories(self) -> None:
        conn, tables = self.connection, self.tables
        self.run_batches = SqlRunBatchRepository(conn, tables)
        self.run_orders = SqlRunOrderRepository(conn, tables)
        self.spend_events = SqlSpendEventRepository(conn, tables)
        self.feed_snapshots = SqlFeedSnapshotRepository(conn, tables)
        self.assessment_inputs = SqlAssessmentInputRepository(conn, tables)


__all__ = [
    "TABLES",
    "AssessmentInputRepository",
    "FeedSnapshotRepository",
    "OpsUnitOfWork",
    "RunBatchRepository",
    "RunOrderRepository",
    "SpendEventRepository",
    "SqlAssessmentInputRepository",
    "SqlFeedSnapshotRepository",
    "SqlOpsUnitOfWork",
    "SqlRunBatchRepository",
    "SqlRunOrderRepository",
    "SqlSpendEventRepository",
]
