from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest, TimeBucket
from traust_core.v1.models.findings import (
    Decision,
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
    FindingView,
)
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.findings import FindingUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import FindingReview


class FindingService:
    def __init__(
        self,
        uow: FindingUnitOfWork,
        intake: FindingIntake,
        decisions: FindingDecisions,
        review: FindingReview,
        precedents: FindingPrecedents,
    ) -> None:
        self._uow = uow
        self.intake = intake
        self.decisions = decisions
        self.review = review
        self.precedents = precedents

    def get(self, finding_id: UUID) -> FindingView:
        raise NotImplementedError("stub: replaces ledger api/findings.resolve_layer_findings")

    def list(self, filter: FindingFilter, page: PageRequest) -> Page[FindingView]:
        raise NotImplementedError("stub: replaces corpus/findings_db.py, open_findings")

    def history(self, finding_id: UUID) -> list[Decision]:
        raise NotImplementedError("stub: replaces finding_timeline, layer_event reads")

    def baseline(self, repository_id: UUID, as_of: datetime) -> list[FindingView]:
        raise NotImplementedError("stub: replaces vuln-scan/resolve_baseline.py, baseline_claims")

    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        raise NotImplementedError("stub: replaces traust#58 live_crit_high")

    def summary(self, filter: FindingFilter, group_by: FindingDimension) -> list[FindingRollup]:
        raise NotImplementedError("stub: replaces findings_summary, pattern_exposure, dashboards")

    def timeline(self, filter: FindingFilter, bucket: TimeBucket) -> list[FindingSeriesPoint]:
        raise NotImplementedError("stub: replaces build_cumulative.py, build_trends buckets")
