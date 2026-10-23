"""RatingPolicy: effective severity (the finding_status rule) and SLA deadlines, ported from
traust-engine metrics/sla.py resolve_days_for at 435225b."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.findings import Disposition, Occurrence
from traust_core.v1.models.vocabulary import DispositionAssurance, Severity
from traust_core.v1.services.findings.rating import CvssFloor, RatingConfig, RatingPolicy, SlaConfig

T0 = datetime(2026, 10, 1, tzinfo=UTC)
DEFAULT = RatingPolicy(RatingConfig())


def occurrence(severity: str = "high") -> Occurrence:
    return Occurrence(finding_id=uuid4(), assessment_id=uuid4(), severity=severity)


def disposition(severity: Severity | None) -> Disposition:
    return Disposition(
        finding_id=uuid4(), assurance=DispositionAssurance.CLAIMED, severity=severity
    )


def test_a_re_rating_wins_over_the_report() -> None:
    assert DEFAULT.effective_severity(occurrence("high"), disposition(Severity.LOW)) is Severity.LOW


@pytest.mark.parametrize("judged", [None, disposition(None)])
def test_without_a_re_rating_the_report_rates_it(judged: Disposition | None) -> None:
    assert DEFAULT.effective_severity(occurrence("critical"), judged) is Severity.CRITICAL


def test_a_re_rating_alone_is_enough() -> None:
    assert DEFAULT.effective_severity(None, disposition(Severity.MEDIUM)) is Severity.MEDIUM


def test_no_report_and_no_re_rating_is_an_error() -> None:
    with pytest.raises(ValidationError, match="no severity"):
        DEFAULT.effective_severity(None, None)


@pytest.mark.parametrize(
    ("severity", "days"),
    [
        (Severity.CRITICAL, 30),
        (Severity.HIGH, 60),
        (Severity.MEDIUM, 90),
        (Severity.LOW, None),
        (Severity.INFORMATIONAL, None),
    ],
)
def test_default_deadlines(severity: Severity, days: int | None) -> None:
    due = DEFAULT.sla_due(severity, T0)
    assert due == (None if days is None else T0 + timedelta(days=days))


FLOORED = RatingPolicy(
    RatingConfig(
        sla=SlaConfig(
            resolve_days={Severity.MEDIUM: 90},
            cvss_floor=CvssFloor(threshold=Decimal("4.0"), resolve_days=30),
        )
    )
)


@pytest.mark.parametrize(
    ("severity", "cvss", "days"),
    [
        (Severity.LOW, Decimal("4.0"), 30),
        (Severity.MEDIUM, Decimal("9.8"), 30),
        (Severity.MEDIUM, Decimal("3.9"), 90),
        (Severity.MEDIUM, None, 90),
        (Severity.HIGH, None, None),
    ],
)
def test_cvss_floor_overrides_severity_at_or_above_the_threshold(
    severity: Severity, cvss: Decimal | None, days: int | None
) -> None:
    due = FLOORED.sla_due(severity, T0, cvss)
    assert due == (None if days is None else T0 + timedelta(days=days))
