from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import (
    ArtifactName,
    ArtifactRef,
    Page,
    PageRequest,
    Provenance,
)


class ArtifactFilter(Model): ...


# NEED(storage): local mode = SQLite as the index + files for blobs; server mode = Postgres
# + object storage. Same IDs both ways: rows point at blobs by UUID, never by path.
# NEED(query-first): a document read whole stays a blob a service loads on demand; a field
# becomes a column only when a service filters, groups, sorts or joins on it (D1).
class ArtifactStore(Protocol):
    def put(self, name: ArtifactName, payload: bytes) -> ArtifactRef: ...
    def get(self, artifact_id: UUID) -> bytes: ...
    def stat(self, artifact_id: UUID) -> ArtifactRef: ...


class ArtifactIndex(Protocol):
    def record(self, ref: ArtifactRef, provenance: Provenance) -> None: ...
    def get(self, artifact_id: UUID) -> ArtifactRef: ...
    def list(self, filter: ArtifactFilter, page: PageRequest) -> Page[ArtifactRef]: ...
