from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import AssessmentInputRecord
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    uuid_column,
)

ASSESSMENT_INPUT = TableSpec(
    TRAUST_OPS,
    "assessment_input",
    lambda: (uuid_column("assessment_id"), uuid_column("feed_snapshot_id")),
    append_only=True,
)


class AssessmentInputRepository(RecordRepository[AssessmentInputRecord], Protocol):
    def list_for_assessment(self, assessment_id: UUID) -> list[AssessmentInputRecord]: ...
    def list_for_snapshot(self, feed_snapshot_id: UUID) -> list[AssessmentInputRecord]: ...


class SqlAssessmentInputRepository(SqlAppendOnlyRepository[AssessmentInputRecord]):
    spec = ASSESSMENT_INPUT
    record = AssessmentInputRecord

    def list_for_assessment(self, assessment_id: UUID) -> list[AssessmentInputRecord]:
        return self._many(f"list for {assessment_id}", self.table.c.assessment_id == assessment_id)

    def list_for_snapshot(self, feed_snapshot_id: UUID) -> list[AssessmentInputRecord]:
        return self._many(
            f"list for snapshot {feed_snapshot_id}",
            self.table.c.feed_snapshot_id == feed_snapshot_id,
        )
