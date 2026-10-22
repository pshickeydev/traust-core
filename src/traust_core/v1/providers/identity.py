from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.identity import Credential, DirectoryStatus, Principal
from traust_core.v1.providers.base import Readiness


# NEED(identity): "verified" means the Context factory wired a verifying provider from config
# (OIDC, directory); Principal.verified_by records which. No ldap_verified-style flags in documents.
class IdentityProvider(Protocol):
    def check(self) -> Readiness: ...

    def authenticate(self, credential: Credential) -> Principal: ...

    def get(self, principal_id: UUID) -> Principal: ...


class Directory(Protocol):
    def check(self) -> Readiness: ...

    def status(self, principal: Principal) -> DirectoryStatus: ...
