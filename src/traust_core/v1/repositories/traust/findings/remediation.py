from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.remediation_scheduling import Remediation
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

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
    def list_by_ids(self, remediation_ids: Collection[UUID]) -> list[Remediation]: ...
    def list_by_status(self, status: RemediationStatus) -> list[Remediation]: ...
    def list_all(self) -> list[Remediation]: ...


class SqlRemediationRepository(SqlMutableRepository[Remediation]):
    spec = REMEDIATION
    record = Remediation

    def find_by_assessment(self, assessment_id: UUID) -> Remediation | None:
        return self._one(
            f"find by assessment {assessment_id}", self.table.c.assessment_id == assessment_id
        )

    def list_by_ids(self, remediation_ids: Collection[UUID]) -> list[Remediation]:
        return self._many_in("list by id", self.table.c.id, remediation_ids)

    def list_by_status(self, status: RemediationStatus) -> list[Remediation]:
        return self._many(f"list {status}", self.table.c.status == status)

    def list_all(self) -> list[Remediation]:
        return self._many("list all")
