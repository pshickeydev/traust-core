from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest

from tests.v1.repositories.tables.conftest import T0
from tests.v1.services import test_detection_quality_doors as doors
from tests.v1.services.test_detection_quality import FP, finding, target
from tests.v1.services.test_detection_quality_doors import World, audited
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.detection_quality import BenchmarkFilter
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.insight import BenchmarkScorecardsView, InsightService

engine, world = doors.engine, doors.world


@pytest.mark.parametrize("excluded", [{"held_out": True}, {"admitted": False}])
def test_excluded_only_auditor_versions_do_not_become_phantom_scorecards(
    world: World, excluded: dict[str, bool]
) -> None:
    world.key(target(**excluded))
    world.attach(audited(), AssessmentKind.BENCHMARK_AUDIT, "excluded-version")
    assert world.service().scorecards(BenchmarkFilter()) == []
    assert BenchmarkScorecardsView(world.service()).build(ViewFilter()).scorecards == ()


def test_only_eligible_versions_are_published_without_losing_skipped_targets(world: World) -> None:
    held_repo = "https://github.com/org/held"
    world.key(
        target(),
        target(id="bt-missing", repo_url="https://github.com/org/missing"),
        target(id="bt-held", repo_url=held_repo, held_out=True),
    )
    world.attach(audited(finding(fingerprint=FP)), AssessmentKind.BENCHMARK_AUDIT, "eligible")
    world.attach(audited(repository=held_repo), AssessmentKind.BENCHMARK_AUDIT, "held-only")
    cards = world.service().scorecards(BenchmarkFilter())
    assert [
        (card.auditor_versions, card.targets_scored, card.targets_skipped) for card in cards
    ] == [(("eligible",), 1, 1)]
    release = world.service().scorecards(BenchmarkFilter(include_held_out=True))
    assert {card.auditor_versions for card in release} == {("eligible",), ("held-only",)}


def test_a_commit_less_audit_of_a_shared_repository_does_not_fall_to_the_eligible_target(
    world: World,
) -> None:
    """Qodo 393: eligibility is applied after resolution, not before."""
    shared = "https://github.com/org/shared"
    world.key(
        target(repo_url=shared),
        target(id="bt-held-shared", repo_url=shared, held_out=True),
    )
    world.attach(
        audited(finding(fingerprint=FP), repository=shared),
        AssessmentKind.BENCHMARK_AUDIT,
        "h-1",
    )
    # The audit is ambiguous between the two targets and matches neither: it must not
    # fall to the eligible one just because the held-out one was excluded up front.
    assert world.service().scorecards(BenchmarkFilter()) == []
    # Release scoring sees both candidates, so the same ambiguity holds there.
    assert world.service().scorecards(BenchmarkFilter(include_held_out=True)) == []


def test_routine_refresh_does_not_render_or_fail_on_demand_scorecards_without_a_key(
    world: World,
) -> None:
    view = BenchmarkScorecardsView(world.service())
    insight = InsightService([view], FixedClock(T0))
    refreshed = insight.refresh(None, ViewFilter())
    assert ViewName.BENCHMARK_SCORECARDS not in refreshed.rendered
    assert ViewName.BENCHMARK_SCORECARDS not in refreshed.failed
    with pytest.raises(NotFoundError):
        insight.publish(ViewName.BENCHMARK_SCORECARDS, ViewFilter())
    world.key(target())
    explicit = insight.refresh([ViewName.BENCHMARK_SCORECARDS], ViewFilter())
    assert explicit.failed == {}
    assert explicit.rendered[ViewName.BENCHMARK_SCORECARDS].model.scorecards == ()


def test_cumulative_history_budget_refuses_before_reading_any_audit_body(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.key(target())
    for index in range(10):
        world.attach(
            audited(),
            AssessmentKind.BENCHMARK_AUDIT,
            "version",
            occurred_at=T0 + timedelta(seconds=index),
        )

    def forbid_report_read(*args: object, **kwargs: object) -> None:
        raise AssertionError("over-budget history reached an audit body")

    monkeypatch.setattr(world.publisher, "read", forbid_report_read)
    with pytest.raises(ValidationError):
        world.service().scorecards(BenchmarkFilter(), max_records=6)


def test_audit_findings_share_the_cumulative_budget(world: World) -> None:
    world.key(target())
    world.attach(
        audited(*(finding(fingerprint=f"{index:064x}") for index in range(20))),
        AssessmentKind.BENCHMARK_AUDIT,
    )
    with pytest.raises(ValidationError):
        world.service().scorecards(BenchmarkFilter(), max_records=12)
    (card,) = world.service().scorecards(BenchmarkFilter(), max_records=1000)
    assert (card.targets_scored, card.overall.expected, card.overall.detected) == (1, 1, 1)


def test_bounded_complete_results_reuse_reports_read_for_matching(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.key(target(), target(id="bt-unused", repo_url="https://github.com/org/unused"))
    for index in range(2):
        world.attach(
            audited(finding(fingerprint=FP)),
            AssessmentKind.BENCHMARK_AUDIT,
            "known-version",
            occurred_at=T0 + timedelta(seconds=index),
        )
    read = world.publisher.read
    seen = set()

    def read_once(
        artifact_id: UUID, kind: type[ReportArtifact], *, read_budget: RecordBudget | None = None
    ) -> ReportArtifact:
        if artifact_id in seen:
            raise AssertionError("matching/scoring reloaded the same audit report")
        seen.add(artifact_id)
        return read(artifact_id, kind, read_budget=read_budget)

    monkeypatch.setattr(world.publisher, "read", read_once)
    (card,) = world.service().scorecards(BenchmarkFilter(), max_records=1000)
    assert (card.auditor_versions, card.targets_scored, card.targets_skipped) == (
        ("known-version",),
        1,
        1,
    )
    assert (card.overall.expected, card.overall.detected, card.mean_stability) == (1, 1, 1.0)


def test_recorded_but_unmatched_audits_are_an_empty_eligible_population(world: World) -> None:
    world.key(target())
    audit_id = world.attach(
        audited(commit="1234567"), AssessmentKind.BENCHMARK_AUDIT, "known-version"
    )
    model = BenchmarkScorecardsView(world.service()).build(ViewFilter())
    assert model.scorecards == ()
    assert [
        audit.id for audit in AssessmentLog(world.uow).list_of(AssessmentKind.BENCHMARK_AUDIT)
    ] == [audit_id]
