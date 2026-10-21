from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.operations import AssessmentInput
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


class AssessmentInputRepository(RecordRepository[AssessmentInput], Protocol):
    def list_for_assessment(self, assessment_id: UUID) -> list[AssessmentInput]: ...
    def list_for_snapshot(self, feed_snapshot_id: UUID) -> list[AssessmentInput]: ...


class SqlAssessmentInputRepository(SqlAppendOnlyRepository[AssessmentInput]):
    spec = ASSESSMENT_INPUT
    record = AssessmentInput

    def list_for_assessment(self, assessment_id: UUID) -> list[AssessmentInput]:
        return self._many(f"list for {assessment_id}", self.table.c.assessment_id == assessment_id)

    def list_for_snapshot(self, feed_snapshot_id: UUID) -> list[AssessmentInput]:
        return self._many(
            f"list for snapshot {feed_snapshot_id}",
            self.table.c.feed_snapshot_id == feed_snapshot_id,
        )
