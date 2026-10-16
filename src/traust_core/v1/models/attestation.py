from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.common import Principal
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason, SourceType

CommentSourceName = NewType("CommentSourceName", str)
ExternalHandle = NewType("ExternalHandle", str)


class ReviewSubjectKind(StrEnum):
    FINDING = "finding"
    WORK_ITEM = "work-item"
    ORDER = "order"
    FLEET_FIX = "fleet-fix"
    RULE_DRAFT = "rule-draft"
    IDENTITY_MOVE = "identity-move"


class AttestationDecision(StrEnum):
    CONFIRM = "confirm"
    REJECT = "reject"


# Members land with the Attestation slice (track-findings trust tiers).
class TrustTier(StrEnum): ...


# Shapes land with their implementation slice.
class Credential(Model): ...


class DirectoryStatus(Model): ...


class Comment(Model):
    source: SourceType
    author: ExternalHandle
    body: str
    at: datetime
    url: str | None = None


class ReviewSubject(Model):
    kind: ReviewSubjectKind
    id: UUID


class Statement(Model):
    source: SourceType
    author: Principal | None = None
    body: str
    url: str | None = None
    at: datetime
    trust: TrustTier


class Attestation(Entity):
    review_item_id: UUID
    principal: Principal
    decision: AttestationDecision
    statement: Statement | None = None


class ReviewItem(Entity):
    subject: ReviewSubject
    reason: ReviewReason
    status: ReviewItemStatus

    def resolve(self, attestation: Attestation) -> ReviewItem:
        raise NotImplementedError("stub: replaces ledger resolve_handler.resolve_review_item")
