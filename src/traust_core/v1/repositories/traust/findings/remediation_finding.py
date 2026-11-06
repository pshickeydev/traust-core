from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.remediation_scheduling import RemediationFinding
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    uuid_column,
)

REMEDIATION_FINDING = TableSpec(
    TRAUST,
    "remediation_finding",
    lambda: (
        uuid_column("remediation_id"),
        uuid_column("finding_id"),
        uuid_column("repository_id"),
    ),
)


class RemediationFindingRepository(MutableRecordRepository[RemediationFinding], Protocol):
    def list_for_remediation(self, remediation_id: UUID) -> list[RemediationFinding]: ...
    def list_for_finding(self, finding_id: UUID) -> list[RemediationFinding]: ...
    def list_for_findings(self, finding_ids: Collection[UUID]) -> list[RemediationFinding]: ...
    def list_for_repository(self, repository_id: UUID) -> list[RemediationFinding]: ...


class SqlRemediationFindingRepository(SqlMutableRepository[RemediationFinding]):
    spec = REMEDIATION_FINDING
    record = RemediationFinding

    def list_for_remediation(self, remediation_id: UUID) -> list[RemediationFinding]:
        return self._many(
            f"list for {remediation_id}", self.table.c.remediation_id == remediation_id
        )

    def list_for_finding(self, finding_id: UUID) -> list[RemediationFinding]:
        return self._many(f"list for finding {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_findings(self, finding_ids: Collection[UUID]) -> list[RemediationFinding]:
        return self._many_in("list for findings", self.table.c.finding_id, finding_ids)

    def list_for_repository(self, repository_id: UUID) -> list[RemediationFinding]:
        return self._many(
            f"list for repository {repository_id}", self.table.c.repository_id == repository_id
        )
