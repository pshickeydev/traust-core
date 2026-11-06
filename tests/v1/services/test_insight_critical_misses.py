from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_detection_quality import report
from tests.v1.services.test_detection_quality_doors import DAY, WINDOW, Campaign, World
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import DocumentError, ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.detection_quality import MissReason
from traust_core.v1.models.insight import CriticalMisses, ExecutivePanel, ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.insight import CriticalMissesView


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path / "home"), clock=FixedClock(T0 + 2 * DAY))
    context.__dict__["database"] = engine
    return context


@pytest.fixture
def campaign(context: Context, engine: Engine) -> Campaign:
    uow = SqlTraustUnitOfWork(engine)
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(SecurityAuditArtifact)), context.object_store, uow
    )
    return Campaign(World(engine, uow, publisher)).build()


def test_native_population_and_provenance_survive_all_insight_doors(
    context: Context, campaign: Campaign
) -> None:
    services = context.services()
    filter = ViewFilter(window=WINDOW)
    expected = tuple(services.detection_quality.critical_misses(WINDOW))
    built = services.insight.build(ViewName.CRITICAL_MISSES, filter)
    assert isinstance(built, CriticalMisses)
    assert built.window == WINDOW and built.misses == expected
    assert {row.title: row.reason for row in built.misses} == {
        "area": MissReason.AREA_REPORTED,
        "missed": MissReason.MISSED,
        "benchmark-first": MissReason.MISSED,
    }
    assert {(row.found_by, row.missed_by, row.found_at) for row in built.misses} == {
        (campaign.ids["later"], campaign.ids["audit"], T0 + 2 * DAY)
    }
    rendered = services.insight.publish(ViewName.CRITICAL_MISSES, filter)
    assert rendered.model == built
    document = json.loads(rendered.model_dump_json())["model"]
    contracts.validate_view("critical-misses", document)
    assert document == built.model_dump(mode="json")
    assert set(document) == {"window", "misses"}
    report_model = services.insight.report(ViewName.CRITICAL_MISSES, filter)
    row_cells = [
        row
        for section in report_model.sections[1:]
        if section.table is not None
        for row in section.table.rows
    ]
    assert set(row_cells) == {
        (
            str(miss.finding_id),
            str(miss.repository_id),
            miss.title,
            str(miss.found_by),
            miss.found_at.isoformat(),
            str(miss.missed_by),
            miss.reason.value,
            "Unknown",
        )
        for miss in expected
    }
    missed, adjudication = report_model.sections[1:]
    assert missed.table is not None and adjudication.table is not None
    assert {row[6] for row in missed.table.rows} == {"missed"}
    assert {row[6] for row in adjudication.table.rows} == {"area_reported"}
    for miss in expected:
        for value in (miss.finding_id, miss.repository_id, miss.found_by, miss.missed_by):
            assert str(value) in rendered.markdown and str(value) in rendered.html


@pytest.mark.parametrize(
    ("window", "included"),
    [
        (TimeWindow(start=T0 + 2 * DAY, end=T0 + 3 * DAY), True),
        (TimeWindow(start=T0 + DAY, end=T0 + 2 * DAY), False),
        (TimeWindow(start=T0 + 3 * DAY, end=T0 + 4 * DAY), False),
        (
            TimeWindow(
                start=(T0 + 2 * DAY).astimezone(timezone(timedelta(hours=5))),
                end=(T0 + 3 * DAY).astimezone(timezone(timedelta(hours=5))),
            ),
            True,
        ),
    ],
)
def test_window_is_inclusive_at_start_and_exclusive_at_end(
    context: Context, campaign: Campaign, window: TimeWindow, included: bool
) -> None:
    model = context.services().insight.build(ViewName.CRITICAL_MISSES, ViewFilter(window=window))
    assert isinstance(model, CriticalMisses)
    assert bool(model.misses) is included
    assert all(window.start <= miss.found_at < window.end for miss in model.misses)


@pytest.mark.parametrize("door", ["build", "report", "publish"])
def test_invalid_or_missing_windows_are_refused_before_any_repository_read(
    context: Context, engine: Engine, door: str
) -> None:
    insight = context.services().insight
    filters = [
        ViewFilter(),
        ViewFilter(window=TimeWindow(start=T0.replace(tzinfo=None), end=T0 + DAY)),
        ViewFilter(window=TimeWindow(start=T0, end=(T0 + DAY).replace(tzinfo=None))),
        ViewFilter(window=TimeWindow(start=T0, end=T0)),
        ViewFilter(window=TimeWindow(start=T0 + DAY, end=T0)),
    ]

    def refuse_read(*args: Any) -> None:
        raise AssertionError("invalid view input reached storage")

    sa.event.listen(engine, "before_cursor_execute", refuse_read)
    try:
        for filter in filters:
            with pytest.raises(ValidationError, match="critical-misses requires"):
                getattr(insight, door)(ViewName.CRITICAL_MISSES, filter)
    finally:
        sa.event.remove(engine, "before_cursor_execute", refuse_read)


def test_every_unsupported_scope_or_historical_filter_is_refused_before_reads(
    context: Context, engine: Engine
) -> None:
    insight = context.services().insight
    unsupported = {
        "product_ids": (uuid4(),),
        "team_ids": (uuid4(),),
        "categories": ("crypto",),
        "as_of": T0,
        "bucket": TimeBucket.DAY,
        "artifact_id": uuid4(),
        "repository_id": uuid4(),
        "executive_panels": (ExecutivePanel.ATTACK,),
        "assessment_id": uuid4(),
        "report_stem": "audit",
        "compare_as_of": T0 - DAY,
        "first_party_divisor": Decimal("2"),
    }

    def refuse_read(*args: Any) -> None:
        raise AssertionError("unsupported view scope reached storage")

    sa.event.listen(engine, "before_cursor_execute", refuse_read)
    try:
        for field, value in unsupported.items():
            filter = ViewFilter.model_validate({"window": WINDOW, field: value})
            with pytest.raises(ValidationError, match=field):
                insight.publish(ViewName.CRITICAL_MISSES, filter)
    finally:
        sa.event.remove(engine, "before_cursor_execute", refuse_read)


def test_empty_output_does_not_claim_coverage_or_invent_denominators(context: Context) -> None:
    rendered = context.services().insight.publish(
        ViewName.CRITICAL_MISSES, ViewFilter(window=WINDOW)
    )
    assert isinstance(rendered.model, CriticalMisses) and rendered.model.misses == ()
    assert rendered.model.model_dump(mode="json") == {
        "window": WINDOW.model_dump(mode="json"),
        "misses": [],
    }
    contracts.validate_view("critical-misses", rendered.model.model_dump(mode="json"))
    for text in (rendered.markdown, rendered.html):
        assert "100%" not in text and "0%" not in text


def test_refresh_keeps_the_existing_current_month_fallback(
    context: Context, campaign: Campaign
) -> None:
    result = context.services().insight.refresh([ViewName.CRITICAL_MISSES], ViewFilter())
    assert not result.failed
    model = result.rendered[ViewName.CRITICAL_MISSES].model
    assert isinstance(model, CriticalMisses)
    assert model.window == TimeWindow.month_of(context.clock.now())
    assert {row.finding_id for row in model.misses} == {
        campaign.ids[name] for name in ("area", "missed", "benchmark-first")
    }


def test_current_disposition_is_retained_without_a_historical_claim(
    context: Context, campaign: Campaign
) -> None:
    with campaign.world.uow as uow:
        finding = uow.findings.get(campaign.ids["missed"])
        campaign.world.seed.decision(
            finding,
            validity="confirmed",
            actor="human:analyst@example.com",
            rationale="Confirmed by a human review after the reporting window.",
            occurred_at=WINDOW.end + DAY,
        )
        uow.commit()
    rendered = context.services().insight.publish(
        ViewName.CRITICAL_MISSES, ViewFilter(window=WINDOW)
    )
    assert isinstance(rendered.model, CriticalMisses)
    miss = next(row for row in rendered.model.misses if row.finding_id == finding.id)
    assert miss.validity == "confirmed"


def test_hostile_persisted_titles_are_raw_model_data_and_inert_structured_cells(
    context: Context, campaign: Campaign
) -> None:
    hostile = "<script>alert(1)</script>\n## forged\n| a | b | ![click](javascript:alert(1))\u202e"
    with campaign.world.uow as uow:
        finding = uow.findings.get(campaign.ids["missed"])
        uow.findings.update(finding.model_copy(update={"title": hostile}))
        uow.commit()
    services = context.services()
    filter = ViewFilter(window=WINDOW)
    rendered = services.insight.publish(ViewName.CRITICAL_MISSES, filter)
    assert isinstance(rendered.model, CriticalMisses)
    miss = next(row for row in rendered.model.misses if row.finding_id == finding.id)
    assert miss.title == hostile
    structured = services.insight.report(ViewName.CRITICAL_MISSES, filter)
    assert any(
        hostile == row[2]
        for section in structured.sections[1:]
        if section.table is not None
        for row in section.table.rows
    )
    assert hostile not in "\n".join(section.body for section in structured.sections)
    assert "\n## forged" not in rendered.markdown
    assert "\n| a | b |" not in rendered.markdown
    assert "![click](javascript:" not in rendered.markdown
    assert "<script>" not in rendered.markdown and "<script>" not in rendered.html
    assert "<img" not in rendered.html and "<a href" not in rendered.html
    assert "&lt;script&gt;" in rendered.markdown and "&lt;script&gt;" in rendered.html
    assert "\u202e" not in rendered.markdown and "\u202e" not in rendered.html


@pytest.mark.parametrize(
    "validity", [None, "historical-custom-verdict", "", "<b>[review]</b>\n| x |"]
)
def test_validity_remains_nullable_arbitrary_text_at_the_view_boundary(
    context: Context, campaign: Campaign, validity: str | None
) -> None:
    services = context.services()
    native = services.insight.build(ViewName.CRITICAL_MISSES, ViewFilter(window=WINDOW))
    assert isinstance(native, CriticalMisses)
    row = native.misses[0].model_copy(update={"validity": validity})
    model = CriticalMisses(window=WINDOW, misses=(row,))
    contracts.validate_view("critical-misses", model.model_dump(mode="json"))
    structured = CriticalMissesView(services.detection_quality).report(model, context.clock.now())
    cells = [
        cells
        for section in structured.sections[1:]
        if section.table is not None
        for cells in section.table.rows
    ]
    if validity is not None:
        assert cells[0][-1] == validity
    assert "<b>" not in HtmlRenderer().render(structured).decode()
    assert "\n| x |" not in MarkdownRenderer().render(structured).decode()


def test_native_published_data_is_checked_with_uuid_and_datetime_formats(
    context: Context, campaign: Campaign
) -> None:
    rendered = context.services().insight.publish(
        ViewName.CRITICAL_MISSES, ViewFilter(window=WINDOW)
    )
    for field, invalid in (("finding_id", "not-a-uuid"), ("found_at", "2026-10-07")):
        document = rendered.model.model_dump(mode="json")
        document["misses"][0][field] = invalid
        with pytest.raises(DocumentError) as error:
            contracts.validate_view("critical-misses", document)
        assert f"misses/0/{field}" in {issue.path for issue in error.value.issues}
    document = rendered.model.model_dump(mode="json")
    del document["misses"][0]["validity"]
    with pytest.raises(DocumentError):
        contracts.validate_view("critical-misses", document)


def test_reading_and_publishing_write_neither_sql_nor_object_bytes(
    context: Context, campaign: Campaign, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = report()
    artifact = campaign.world.publisher.publish_artifact(document)
    with campaign.world.uow as uow:
        AssessmentLog(uow).attach(
            campaign.ids["audit"], artifact.artifact_id, sha256_hex(document.payload)
        )
        uow.commit()
    store = context.object_store
    before = {key: store.get(store.stat(key)) for key in store.list()}
    assert before
    services = context.services()

    def refuse_object_write(*args: Any) -> None:
        raise AssertionError("publishing a view wrote object bytes")

    def refuse_sql_write(
        conn: Any, cursor: Any, statement: str, parameters: Any, execution: Any, many: bool
    ) -> None:
        assert not (execution.isinsert or execution.isupdate or execution.isdelete)
        assert statement.lstrip().split()[0].upper() not in {
            "INSERT",
            "UPDATE",
            "DELETE",
            "CREATE",
            "ALTER",
            "DROP",
            "TRUNCATE",
        }

    monkeypatch.setattr(store, "put", refuse_object_write)
    sa.event.listen(engine, "before_cursor_execute", refuse_sql_write)
    try:
        filter = ViewFilter(window=WINDOW)
        services.detection_quality.critical_misses(WINDOW)
        services.insight.build(ViewName.CRITICAL_MISSES, filter)
        services.insight.report(ViewName.CRITICAL_MISSES, filter)
        services.insight.publish(ViewName.CRITICAL_MISSES, filter)
    finally:
        sa.event.remove(engine, "before_cursor_execute", refuse_sql_write)
    assert {key: store.get(store.stat(key)) for key in store.list()} == before
