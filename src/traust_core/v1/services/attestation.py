from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.attestation import (
    Attestation,
    AttestationDecision,
    Comment,
    CommentSourceName,
    Credential,
    ReviewItem,
    ReviewSubject,
    Statement,
    TrustTier,
)
from traust_core.v1.models.common import Page, PageRequest, Principal
from traust_core.v1.models.findings import ReviewFilter
from traust_core.v1.models.portfolio import Ownership
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import ReviewReason
from traust_core.v1.providers.collaboration import CommentSource
from traust_core.v1.providers.identity import IdentityProvider
from traust_core.v1.repositories.attestation import AttestationUnitOfWork
from traust_core.v1.services.ledger import LedgerService


class StatementPolicy:
    def trust(
        self, comment: Comment, author: Principal | None, ownership: Ownership | None
    ) -> TrustTier:
        raise NotImplementedError("stub: replaces track-findings human-statement trust tiers")


class AttestationService:
    def __init__(
        self,
        uow: AttestationUnitOfWork,
        ledger: LedgerService | None,
        comments: CommentSource,
        policy: StatementPolicy,
    ) -> None:
        self._uow = uow
        self._ledger = ledger
        self._comments = comments
        self._policy = policy

    def request(self, subject: ReviewSubject, reason: ReviewReason) -> ReviewItem:
        raise NotImplementedError("stub: replaces countersign inbox writes, fleet-fix batch review")

    def attest(
        self,
        review_item_id: UUID,
        principal: Principal,
        decision: AttestationDecision,
        statement: Statement | None,
    ) -> Attestation:
        raise NotImplementedError("stub: replaces countersign.py, ledger cli countersign")

    def import_statements(self, source: CommentSourceName, ref: ExternalRef) -> list[Attestation]:
        raise NotImplementedError("stub: replaces track-findings MR/Jira comment reads")

    def pending(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewItem]:
        raise NotImplementedError("stub: replaces countersign.discover_pending")

    def for_subject(self, subject: ReviewSubject) -> list[Attestation]:
        raise NotImplementedError("stub: replaces countersign baseline_for")


class IdentityService:
    def __init__(self, provider: IdentityProvider) -> None:
        self._provider = provider

    def authenticate(self, credential: Credential) -> Principal:
        raise NotImplementedError("stub: replaces compliance_scope_intake.verify_identity")

    def get(self, principal_id: UUID) -> Principal:
        raise NotImplementedError("stub: principal lookup (local user / DB / OIDC)")
