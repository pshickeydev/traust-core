from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.providers.identity import IdentityProvider


class IdentityService:
    def __init__(self, provider: IdentityProvider) -> None:
        self._provider = provider

    def authenticate(self, credential: Credential) -> Principal:
        raise NotImplementedError("stub: replaces compliance_scope_intake.verify_identity")

    def get(self, principal_id: UUID) -> Principal:
        raise NotImplementedError("stub: principal lookup (local user / DB / OIDC)")
