from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Generic, NewType, TypeVar
from uuid import UUID

from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.vocabulary import ActorKind, SourceType

T = TypeVar("T")

Sha256 = NewType("Sha256", str)
ArtifactName = NewType("ArtifactName", str)
RepoPath = NewType("RepoPath", str)
Cursor = NewType("Cursor", str)


class Role(StrEnum):
    ADMIN = "admin"
    RESTATE = "restate"


class IdentitySource(StrEnum):
    LOCAL_USER = "local-user"
    DATABASE = "database"
    OIDC = "oidc"


class TimeBucket(StrEnum):
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


class TimeWindow(Model):
    start: datetime
    end: datetime


class ArtifactRef(Model):
    id: UUID
    name: ArtifactName
    digest: Sha256


class Provenance(Model):
    run_id: UUID
    artifact: ArtifactRef | None = None
    source: SourceType
    occurred_at: datetime


class Principal(Model):
    id: UUID
    kind: ActorKind
    display: str
    verified_by: IdentitySource | None = None
    roles: frozenset[Role] = frozenset()

    @property
    def ref(self) -> str:
        """The principal id rows store (`requested_by`, `actor`): `<kind>:<id>`."""
        return f"{self.kind}:{self.id}"

    def is_verified_human(self) -> bool:
        raise NotImplementedError(
            "stub: replaces ledger is_actor_verified / require_verified_human"
        )

    def has_role(self, role: Role) -> bool:
        raise NotImplementedError("stub: replaces ledger require_admin / restatement authority")


class CodeSpan(Model):
    path: RepoPath
    line: int | None = None

    @classmethod
    def parse(cls, raw: str) -> CodeSpan:
        raise NotImplementedError("stub: replaces check_location_paths.py")


class PageRequest(Dto):
    limit: int = 100
    cursor: Cursor | None = None


class Page(Dto, Generic[T]):
    items: tuple[T, ...]
    next: Cursor | None = None
