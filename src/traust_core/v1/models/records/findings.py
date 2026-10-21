"""Rows of the traust namespace, 3 · Assessments & findings - one model per contract table.

Classifying columns (kind, status, severity, validity, ...) are str here: their
values come from contracts registries, checked at intake by services.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Entity


class AssessmentRecord(AppendOnly):
    repository_ref_id: UUID
    image_id: UUID | None = None
    baseline_assessment_id: UUID | None = None
    run_order_id: UUID | None = None
    kind: str
    status: str
    assessor: str
    assessor_version: str
    occurred_at: datetime


class ArtifactRecord(AppendOnly):
    assessment_id: UUID | None = None
    digest: str
    kind: str
    uri: str


class OccurrenceRecord(AppendOnly):
    finding_id: UUID
    assessment_id: UUID
    severity: str
    cvss_vector: str | None = None
    cvss_score: Decimal | None = None
    rule: str | None = None


class LocationRecord(AppendOnly):
    occurrence_id: UUID
    path: str
    line_start: int | None = None
    line_end: int | None = None
    language: str | None = None
    symbol: str | None = None


class FindingRecord(Entity):
    repository_id: UUID
    advisory_id: UUID | None = None
    advisory_match: str | None = None
    fingerprint_algo: str
    fingerprint: str
    kind: str | None = None
    title: str


class CweRecord(Entity):
    identifier: str
    abstraction: str | None = None
    mapping_usage: str | None = None
    catalog_version: str | None = None


class FindingCweRecord(Entity):
    finding_id: UUID
    cwe_id: UUID


class FindingLabelRecord(Entity):
    finding_id: UUID
    taxonomy: str
    label: str


class FindingExternalRefRecord(Entity):
    finding_id: UUID
    system: str
    ref: str


class DecisionRecord(AppendOnly):
    finding_id: UUID
    assessment_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    repository_ref_id: UUID | None = None
    restates_id: UUID | None = None
    artifact_id: UUID | None = None
    statement_key: str
    validity: str | None = None
    resolution: str | None = None
    evidence_grade: str | None = None
    reason: str | None = None
    severity: str | None = None
    source_channel: str | None = None
    actor: str | None = None
    occurred_at: datetime


class ReviewItemRecord(Entity):
    finding_id: UUID
    decision_id: UUID | None = None
    resolved_by_decision_id: UUID | None = None
    reason: str | None = None
    status: str
