from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.records import ArtifactRecord
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

ARTIFACT = TableSpec(
    TRAUST,
    "artifact",
    lambda: (
        uuid_column("assessment_id", nullable=True),
        text_column("digest"),
        text_column("kind"),
        text_column("uri"),
    ),
    append_only=True,
)


class ArtifactRepository(RecordRepository[ArtifactRecord], Protocol):
    def find(self, assessment_id: UUID | None, digest: str) -> ArtifactRecord | None:
        """By (assessment, digest); assessment None = an imported artifact."""
        ...

    def list_for_assessment(self, assessment_id: UUID) -> list[ArtifactRecord]: ...


class SqlArtifactRepository(SqlAppendOnlyRepository[ArtifactRecord]):
    spec = ARTIFACT
    record = ArtifactRecord

    def find(self, assessment_id: UUID | None, digest: str) -> ArtifactRecord | None:
        c = self.table.c
        produced = (
            c.assessment_id.is_(None)
            if assessment_id is None
            else (c.assessment_id == assessment_id)
        )
        return self._one(f"find {digest}", produced, c.digest == digest)

    def list_for_assessment(self, assessment_id: UUID) -> list[ArtifactRecord]:
        return self._many(f"list for {assessment_id}", self.table.c.assessment_id == assessment_id)
