from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from traust_core.v1.models.remediation import SweepEntry, SweepHeadSource, VerifySweep
from traust_core.v1.rendering.markdown import MarkdownRenderer
from traust_core.v1.rendering.verification import verification_sweep

WHEN = datetime(2026, 11, 4, tzinfo=UTC)
REPOSITORY_ID = UUID("00000000-0000-4000-8000-000000000001")


def test_worklist_contains_every_classified_target_and_unknown_value() -> None:
    sweep = VerifySweep.of(
        (
            SweepEntry(
                repository_id=REPOSITORY_ID,
                ref_name="release-1",
                head_source=SweepHeadSource.REGISTERED_BRANCH,
                head_sha="b" * 40,
                pinned_sha="a" * 40,
                open_findings=2,
                criticals=1,
                highs=1,
            ),
            SweepEntry(repository_id=REPOSITORY_ID),
        )
    )
    before = sweep.model_dump_json()
    report = verification_sweep(sweep, {REPOSITORY_ID: "https://example.com/team/widget"}, WHEN)
    summary, targets = report.sections
    assert report.generated_at == WHEN
    assert summary.table is not None and targets.table is not None
    assert dict(summary.table.rows) == {"T1": "0", "T2": "1", "T3": "0", "T4": "0"}
    assert targets.table.rows == (
        (
            "T2",
            "https://example.com/team/widget",
            "release-1",
            "registered_branch",
            "a" * 40,
            "b" * 40,
            "2",
            "1",
            "1",
            "0",
            "unknown",
        ),
        (
            "unobserved",
            "https://example.com/team/widget",
            "(default)",
            "observed_default",
            "unknown",
            "unobserved",
            "0",
            "0",
            "0",
            "0",
            "unknown",
        ),
    )
    assert sweep.model_dump_json() == before


def test_empty_worklist_still_reports_all_tiers() -> None:
    report = verification_sweep(VerifySweep.of(()), {}, WHEN)
    assert report.sections[0].table is not None
    assert all(count == "0" for _, count in report.sections[0].table.rows)
    assert report.sections[1].table is not None and report.sections[1].table.rows == ()


def test_untrusted_repository_and_branch_names_cannot_forge_rows() -> None:
    sweep = VerifySweep.of(
        (
            SweepEntry(
                repository_id=REPOSITORY_ID,
                ref_name="release\n| forged |",
                head_sha="a" * 40,
                open_findings=1,
            ),
        )
    )
    report = verification_sweep(sweep, {REPOSITORY_ID: "repo\n## injected"}, WHEN)
    markdown = MarkdownRenderer().render(report).decode()
    assert "\n| forged |" not in markdown
    assert "\n## injected" not in markdown
    assert "release \\| forged \\|" in markdown
