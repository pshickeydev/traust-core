from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import ComponentRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    uuid_column,
)

COMPONENT = TableSpec(
    TRAUST, "component", lambda: (uuid_column("release_id"), uuid_column("repository_ref_id"))
)


class ComponentRepository(MutableRecordRepository[ComponentRecord], Protocol):
    def find(self, release_id: UUID, repository_ref_id: UUID) -> ComponentRecord | None: ...
    def list_for_release(self, release_id: UUID) -> list[ComponentRecord]: ...
    def list_for_ref(self, repository_ref_id: UUID) -> list[ComponentRecord]: ...


class SqlComponentRepository(SqlMutableRepository[ComponentRecord]):
    spec = COMPONENT
    record = ComponentRecord

    def find(self, release_id: UUID, repository_ref_id: UUID) -> ComponentRecord | None:
        c = self.table.c
        return self._one(
            f"find {release_id}/{repository_ref_id}",
            c.release_id == release_id,
            c.repository_ref_id == repository_ref_id,
        )

    def list_for_release(self, release_id: UUID) -> list[ComponentRecord]:
        return self._many(f"list for {release_id}", self.table.c.release_id == release_id)

    def list_for_ref(self, repository_ref_id: UUID) -> list[ComponentRecord]:
        return self._many(
            f"list for ref {repository_ref_id}", self.table.c.repository_ref_id == repository_ref_id
        )
