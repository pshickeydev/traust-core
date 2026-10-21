from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import AssessmentRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

ASSESSMENT = TableSpec(
    TRAUST,
    "assessment",
    lambda: (
        uuid_column("repository_ref_id"),
        uuid_column("image_id", nullable=True),
        uuid_column("baseline_assessment_id", nullable=True),
        uuid_column("run_order_id", nullable=True),
        text_column("kind"),
        text_column("status"),
        text_column("assessor"),
        text_column("assessor_version"),
        timestamp_column("occurred_at"),
    ),
    append_only=True,
)


class AssessmentRepository(RecordRepository[AssessmentRecord], Protocol):
    def latest(self, repository_ref_id: UUID, kind: str) -> AssessmentRecord | None: ...
    def list_for_ref(self, repository_ref_id: UUID) -> list[AssessmentRecord]: ...
    def list_for_run_order(self, run_order_id: UUID) -> list[AssessmentRecord]: ...


class SqlAssessmentRepository(SqlAppendOnlyRepository[AssessmentRecord]):
    spec = ASSESSMENT
    record = AssessmentRecord

    def latest(self, repository_ref_id: UUID, kind: str) -> AssessmentRecord | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.repository_ref_id == repository_ref_id, c.kind == kind)
            .order_by(c.occurred_at.desc(), c.created_at.desc())
            .limit(1)
        )
        row = self._execute(f"latest {kind} for {repository_ref_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def list_for_ref(self, repository_ref_id: UUID) -> list[AssessmentRecord]:
        c = self.table.c
        return self._many(
            f"list for {repository_ref_id}",
            c.repository_ref_id == repository_ref_id,
            order_by=(c.occurred_at,),
        )

    def list_for_run_order(self, run_order_id: UUID) -> list[AssessmentRecord]:
        return self._many(
            f"list for order {run_order_id}", self.table.c.run_order_id == run_order_id
        )
