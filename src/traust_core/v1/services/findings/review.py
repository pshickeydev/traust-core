from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    ReviewCase,
    ReviewFilter,
    ReviewItem,
)
from traust_core.v1.models.vocabulary import ReviewReason, TenancyProfile
from traust_core.v1.repositories.contract import TraustUnitOfWork


class ReviewPolicy:
    def needs_signoff(
        self, decision: Decision, disposition: Disposition, profile: TenancyProfile
    ) -> ReviewReason | None:
        raise NotImplementedError(
            "stub: replaces emit_triage is_auto_accept, track-findings countersign rule"
        )


class FindingReview:
    def __init__(self, uow: TraustUnitOfWork, policy: ReviewPolicy) -> None:
        self._uow = uow
        self._policy = policy

    def queue(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewCase]:
        raise NotImplementedError("stub: replaces countersign.discover_pending")

    def request_signoff(self, finding_id: UUID, reason: ReviewReason) -> ReviewItem:
        raise NotImplementedError("stub: replaces ledger needs_review payloads")

    def resolve(self, review_item_id: UUID, decision_id: UUID) -> ReviewItem:
        raise NotImplementedError("stub: replaces ledger resolve_handler, cli countersign/resolve")
