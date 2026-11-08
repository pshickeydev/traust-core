"""The benchmark-scorecards Insight view: DetectionQualityService.scorecards over the recorded
benchmark audits, validated against its contracts view schema and rendered as a report."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tests.v1.repositories.tables.conftest import T0
from tests.v1.services import test_detection_quality_doors as doors
from tests.v1.services.test_detection_quality import FP, finding, target
from tests.v1.services.test_detection_quality_doors import DAY, World, audited
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.detection_quality import InjectionSummary, Recall, Scorecard
from traust_core.v1.models.insight import BenchmarkScorecards, ViewFilter, ViewName
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer
from traust_core.v1.services.insight import BenchmarkScorecardsView

AT = datetime(2026, 11, 6, tzinfo=UTC)
engine, world = doors.engine, doors.world  # the doors' fixtures: SQLite and Postgres


def card(**changes: object) -> Scorecard:
    values: dict[str, object] = {
        "overall": Recall(detected=3, expected=5),
        "near_misses": 1,
        "by_cwe": {"CWE-79": Recall(detected=1, expected=1)},
        "by_severity": {"low": Recall(detected=0, expected=0)},
        "by_provenance": {},
        "by_language": {},
        "by_split": {},
        "injection": InjectionSummary(total=0, passed=0, reported=0),
        "targets_scored": 2,
        "targets_skipped": 1,
        "auditor_versions": ("h-1",),
    }
    return Scorecard(**{**values, **changes})


def test_the_view_scores_each_recorded_auditor_version(world: World) -> None:
    world.key(target(), target(id="bt-y-001", repo_url="https://github.com/org/y"))
    hit, miss = audited(finding(fingerprint=FP)), audited()
    for doc, version, day in ((hit, "h-1", 0), (miss, "h-2", 1), (hit, "h-2", 2)):
        world.attach(doc, AssessmentKind.BENCHMARK_AUDIT, version, occurred_at=T0 + day * DAY)
    model = BenchmarkScorecardsView(world.service()).build(ViewFilter())
    assert isinstance(model, BenchmarkScorecards)
    assert [(c.auditor_versions, c.overall.detected) for c in model.scorecards] == [
        (("h-1",), 1),
        (("h-2",), 0),
    ]


def test_no_answer_key_is_not_found_rather_than_an_empty_view(world: World) -> None:
    with pytest.raises(NotFoundError, match="no benchmark answer key"):
        BenchmarkScorecardsView(world.service()).build(ViewFilter())


@pytest.mark.parametrize(
    "filter",
    [
        ViewFilter(as_of=AT),
        ViewFilter(window=TimeWindow(start=AT, end=AT.replace(day=7))),
        ViewFilter(product_ids=(uuid4(),)),
    ],
)
def test_the_view_takes_no_filters(filter: ViewFilter, world: World) -> None:
    view = BenchmarkScorecardsView(world.service())
    with pytest.raises(ValidationError, match="takes no filters"):
        view.build(filter)


def test_untrusted_labels_stay_inert_in_every_render(world: World) -> None:
    hostile = "[act](https://evil.invalid)<img src=x>\n|forged‮"
    view = BenchmarkScorecardsView(world.service())
    model = BenchmarkScorecards(
        scorecards=(
            card(by_cwe={hostile: Recall(detected=1, expected=1)}, auditor_versions=(hostile,)),
        )
    )
    report = view.report(model, AT)
    markdown = MarkdownRenderer().render(report).decode()
    html = HtmlRenderer().render(report).decode()
    assert "<img" not in markdown and "<img" not in html
    assert "[act](" not in markdown  # the link's brackets are escaped: inert text
    assert not any(line.startswith("|forged") for line in markdown.splitlines())
    assert "\u202e" not in markdown


def test_the_view_is_registered(tmp_path: object) -> None:
    from traust_core.v1.context import Config, Context

    insight = Context(Config(home=tmp_path)).services().insight  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        insight.build(ViewName.BENCHMARK_SCORECARDS, ViewFilter())
