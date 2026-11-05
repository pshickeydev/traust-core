from __future__ import annotations

from traust_core.v1.models.detection_quality import CheckPrecision, ComplianceCalibration
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.rendering.compliance_precision import compliance_precision_markdown

NIST = ComplianceFramework("nist-800-53-rev5")


def test_each_check_renders_its_precision_and_flag_at_the_report_gate() -> None:
    report = ComplianceCalibration(
        framework=NIST,
        assessments=2,
        gate=0.6,
        checks=(
            CheckPrecision(check_id="tls", fired=2, dismissed=1, gate=0.6),
            CheckPrecision(check_id="rbac", fired=4, dismissed=0, gate=0.6),
        ),
    )
    out = compliance_precision_markdown(report)
    assert "Demotion review gate: precision ≤ 0.600." in out
    assert "| tls | 2 | 1 | 0.500 | flagged |" in out
    assert "| rbac | 4 | 0 | 1.000 | not flagged |" in out


def test_no_assessments_and_no_firings_are_unmeasured_not_zero() -> None:
    empty = compliance_precision_markdown(ComplianceCalibration(framework=NIST, assessments=0))
    assert "No assessments recorded; field precision is unmeasured." in empty
    quiet = compliance_precision_markdown(ComplianceCalibration(framework=NIST, assessments=3))
    assert "No automatic check firings; field precision is unmeasured." in quiet
    assert "| Check |" not in quiet


def test_a_hostile_check_id_cannot_forge_rows_or_links() -> None:
    hostile = "[x](https://evil.invalid)\n| forged | row |"
    report = ComplianceCalibration(
        framework=NIST,
        assessments=1,
        checks=(CheckPrecision(check_id=hostile, fired=1, dismissed=1),),
    )
    out = compliance_precision_markdown(report)
    assert "[x](" not in out and "\n| forged" not in out
    assert r"\[x\]\(https://evil.invalid\) \| forged \| row \|" in out
    assert "| 1 | 1 | 0.000 | flagged |" in out
