from __future__ import annotations

import pytest

from traust_core.v1.models.detection_quality import CheckPrecision, ComplianceCalibration
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.rendering.compliance_precision import compliance_precision_markdown

NIST = ComplianceFramework("nist-800-53-rev5")


def test_precision_report_preserves_check_counts_custom_gate_and_review_flags() -> None:
    report = ComplianceCalibration(
        framework=NIST,
        assessments=3,
        gate=0.75,
        checks=(
            CheckPrecision(check_id="tls", fired=4, dismissed=1, gate=0.75),
            CheckPrecision(check_id="mfa", fired=4, dismissed=0, gate=0.75),
        ),
    )
    out = compliance_precision_markdown(report)
    assert "Framework: nist-800-53-rev5. Assessments: 3." in out
    assert "precision ≤ 0.750" in out
    assert "| tls | 4 | 1 | 0.750 | flagged |" in out
    assert "| mfa | 4 | 0 | 1.000 | not flagged |" in out
    assert "not automatic demotion" in out


@pytest.mark.parametrize("assessments", [0, 2])
def test_precision_with_no_firing_population_is_unmeasured(assessments: int) -> None:
    out = compliance_precision_markdown(
        ComplianceCalibration(framework=NIST, assessments=assessments)
    )
    assert "field precision is unmeasured" in out
    assert "| Check |" not in out
    assert "0.000" not in out


def test_zero_precision_is_distinct_from_unmeasured_precision() -> None:
    out = compliance_precision_markdown(
        ComplianceCalibration(
            framework=NIST,
            assessments=1,
            checks=(
                CheckPrecision(check_id="dismissed", fired=2, dismissed=2),
                CheckPrecision(check_id="unmeasured", fired=0, dismissed=0),
            ),
        )
    )
    assert "| dismissed | 2 | 2 | 0.000 | flagged |" in out
    assert "| unmeasured | 0 | 0 | unmeasured | not flagged |" in out


def test_check_labels_are_literal_markdown_without_forged_rows() -> None:
    hostile = "[act](https://evil.invalid)<img src=x>\n|forged\u202e"
    out = compliance_precision_markdown(
        ComplianceCalibration(
            framework=NIST,
            assessments=1,
            checks=(CheckPrecision(check_id=hostile, fired=1, dismissed=1),),
        )
    )
    assert "[act](" not in out and "<img" not in out
    assert "\u202e" not in out and "\n|forged" not in out
    assert r"\[act\]" in out and r"\|forged" in out
