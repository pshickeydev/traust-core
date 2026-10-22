"""Who is acting: principals, the sources that verify them, their roles."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.vocabulary import ActorKind


class Role(StrEnum):
    ADMIN = "admin"
    RESTATE = "restate"


class IdentitySource(StrEnum):
    LOCAL_USER = "local-user"
    DATABASE = "database"
    OIDC = "oidc"


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
        """A person whose identity a trusted source proved (verified_by is set only then)."""
        return self.kind == ActorKind.HUMAN and self.verified_by is not None

    def has_role(self, role: Role) -> bool:
        return self.is_verified_human() and role in self.roles


# Shapes land with caller identity.
class Credential(Model): ...


class DirectoryStatus(Model): ...
