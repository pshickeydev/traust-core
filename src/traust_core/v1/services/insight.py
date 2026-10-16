from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from traust_core.v1.models.common import Provenance
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.models.operations import Order
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishResult
from traust_core.v1.services.operations import OpsService


class View(Protocol):
    name: ViewName

    def build(self, filter: ViewFilter) -> ViewModel: ...


class InsightService:
    def __init__(
        self, views: Sequence[View], publisher: ArtifactPublisher, ops: OpsService
    ) -> None:
        self._views = {v.name: v for v in views}
        self._publisher = publisher
        self._ops = ops

    def build(self, view: ViewName, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError("stub: replaces each dashboard builder's main()")

    def publish(self, view: ViewName, filter: ViewFilter, provenance: Provenance) -> PublishResult:
        raise NotImplementedError("stub: replaces dashboards' md/html/json writes")

    def refresh(self, views: Sequence[ViewName] | None) -> list[Order]:
        raise NotImplementedError("stub: replaces cli/refresh_dashboards.py")


# Registered views (internal); each replaces the dashboard named in its stub.
class _StubView:
    name: ViewName
    replaces = ""

    def build(self, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError(f"stub: replaces {self.replaces}")


class FindingsRollupView(_StubView):
    name, replaces = ViewName.FINDINGS_ROLLUP, "insecure-patterns, rbac-tenancy-rollup, team report"


class FindingsTrendView(_StubView):
    name, replaces = ViewName.FINDINGS_TREND, "findings-trends"


class CoverageView(_StubView):
    name, replaces = ViewName.COVERAGE, "census"


class LocView(_StubView):
    name, replaces = ViewName.LOC, "loc-dashboard"


class AttackCoverageView(_StubView):
    name, replaces = ViewName.ATTACK_COVERAGE, "attack-coverage"


class ThreatRegisterView(_StubView):
    name, replaces = ViewName.THREAT_REGISTER, "threat-register"


class ExposureView(_StubView):
    name, replaces = ViewName.EXPOSURE, "refresh-dashboards/build_dependency_exposure"


class ValidationFuzzView(_StubView):
    name, replaces = ViewName.VALIDATION_FUZZ, "validation-fuzz-dashboard"


class PqcView(_StubView):
    name, replaces = ViewName.PQC, "pqc dashboard, product reports, vendor/xcrypto trackers"


class ComplianceDashboardView(_StubView):
    name, replaces = ViewName.COMPLIANCE, "compliance/dashboard.py"


class ProgramView(_StubView):
    name, replaces = ViewName.PROGRAM, "traust-metrics, financial-tracking"


class ExecutiveSummaryView(_StubView):
    name, replaces = ViewName.EXECUTIVE_SUMMARY, "executive-summary-findings"


class ReviewCardView(_StubView):
    name, replaces = ViewName.REVIEW_CARD, "countersign render_*_card"


class TriageView(_StubView):
    name, replaces = ViewName.TRIAGE, "triage/render_triage.py"


class SarifExport(_StubView):
    name, replaces = ViewName.SARIF, "reporting/sarif.py"


class OscalExport(_StubView):
    name, replaces = ViewName.OSCAL, "run_compliance_check.export_oscal"
