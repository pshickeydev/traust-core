"""Which assessments speak as execution evidence, and the re-rating a disposition carries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.findings import Decision, Disposition, report_sources
from traust_core.v1.models.vocabulary import Severity, SourceType

T0 = datetime(2026, 10, 1, tzinfo=UTC)
FINDING = uuid4()


def assessment(kind: str, **kw: Any) -> Assessment:
    values: dict[str, Any] = {
        "id": uuid4(),
        "repository_ref_id": uuid4(),
        "kind": kind,
        "status": "completed",
        "assessor": "skill:x",
        "assessor_version": "1",
        "occurred_at": T0,
    }
    return Assessment(**{**values, **kw})


@pytest.mark.parametrize(
    ("kind", "source"),
    [
        ("validation", SourceType.VALIDATION_REPORT),
        ("verification", SourceType.VERIFICATION_REPORT),
    ],
)
def test_execution_reports_speak_as_their_report(kind: str, source: SourceType) -> None:
    a = assessment(kind)
    assert report_sources([a]) == {a.id: source}


@pytest.mark.parametrize("kind", ["triage", "secure-code", "vuln-scan"])
def test_static_assessments_have_no_report_source(kind: str) -> None:
    assert report_sources([assessment(kind)]) == {}


def test_an_unsaved_assessment_has_no_source() -> None:
    assert report_sources([assessment("validation", id=None)]) == {}


def test_disposition_carries_the_latest_re_rating() -> None:
    def at(day: int, **kw: Any) -> Decision:
        return Decision(
            id=uuid4(),
            finding_id=FINDING,
            statement_key=f"k{day}",
            occurred_at=T0 + timedelta(days=day),
            **kw,
        )

    rated = [at(1, severity="high"), at(2, validity="confirmed"), at(3, severity="medium")]
    assert Disposition.fold(FINDING, rated).severity is Severity.MEDIUM
    assert Disposition.fold(FINDING, [at(1, validity="confirmed")]).severity is None
