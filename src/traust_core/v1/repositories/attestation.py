from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.attestation import Attestation, ReviewItem, ReviewSubject
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import ReviewFilter
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class ReviewItemRepository(Protocol):
    def get(self, review_item_id: UUID) -> ReviewItem: ...
    def add(self, review_item: ReviewItem) -> ReviewItem: ...
    def update(self, review_item: ReviewItem) -> ReviewItem: ...
    def list(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewItem]: ...


class AttestationRepository(Protocol):
    def get(self, attestation_id: UUID) -> Attestation: ...
    def add(self, attestation: Attestation) -> Attestation: ...
    def list_for(self, subject: ReviewSubject) -> list[Attestation]: ...


class AttestationUnitOfWork(UnitOfWork, Protocol):
    review_items: ReviewItemRepository
    attestations: AttestationRepository
