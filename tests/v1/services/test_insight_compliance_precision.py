from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_detection_quality_doors import (
    NIST,
    PCI,
    World,
    check,
    compliance,
    overridden,
)
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ComplianceAssessmentArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import (
    CompliancePrecision,
    ExecutivePanel,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.insight import CompliancePrecisionView, InsightService

FRAMEWORK = ComplianceFramework(NIST)
HOSTILE = "<img src=x onerror=alert(1)> [docs](javascript:alert(1))\n| forged | `check`"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path / "home"), clock=FixedClock(T0))
    context.__dict__["database"] = engine
    return context


def recorded(context: Context) -> World:
    uow = SqlTraustUnitOfWork(context.database)
    return World(
        context.database,
        uow,
        ArtifactPublisher(
            PublishSpecs(PublishSpec(ComplianceAssessmentArtifact)), context.object_store, uow
        ),
    )


def seed_calibration(context: Context) -> None:
    world = recorded(context)
    document = compliance(
        check(HOSTILE, "not_satisfied"),
        overridden(HOSTILE),
        check("mfa", "not_satisfied"),
        check("satisfied", "satisfied"),
        check("agent-only", "not_satisfied", "agent"),
        check("pci-only", "not_satisfied", framework=PCI),
        frameworks=(NIST, PCI),
    )
    world.attach(document, AssessmentKind.COMPLIANCE)
    world.attach(document, AssessmentKind.COMPLIANCE)
    world.attach(
        compliance(check("pci-second", "not_satisfied", framework=PCI), frameworks=(PCI,)),
        AssessmentKind.COMPLIANCE,
    )


def snapshot(context: Context) -> dict[str, object]:
    with SqlTraustUnitOfWork(context.database) as uow:
        rows: dict[str, object] = {}
        for spec in CONTRACT_TABLES:
            table = uow.tables.table(spec)
            rows[table.fullname] = tuple(
                tuple(row)
                for row in uow.connection.execute(sa.select(table).order_by(*table.primary_key))
            )
    rows["objects"] = tuple(
        (str(key), context.object_store.get(context.object_store.stat(key)))
        for key in context.object_store.list()
    )
    return rows


def test_native_population_deduplication_and_override_attribution_survive_publication(
    context: Context,
) -> None:
    seed_calibration(context)
    before = snapshot(context)
    insight = context.services().insight
    scope = ViewFilter(framework=FRAMEWORK)
    built = insight.build(ViewName.COMPLIANCE_PRECISION, scope)
    assert isinstance(built, CompliancePrecision)
    assert built.calibration.assessments == 1
    assert {
        row.check_id: (row.fired, row.dismissed, row.precision, row.flagged)
        for row in built.calibration.checks
    } == {HOSTILE: (2, 1, 0.5, True), "mfa": (1, 0, 1.0, False)}
    report = insight.report(ViewName.COMPLIANCE_PRECISION, scope)
    assert report.sections[1].table is not None
    assert set(report.sections[1].table.rows) == {
        (HOSTILE, "2", "1", "0.5", "flagged"),
        ("mfa", "1", "0", "1.0", "not flagged"),
    }
    rendered = insight.publish(ViewName.COMPLIANCE_PRECISION, scope)
    document = rendered.model.model_dump(mode="json")
    contracts.validate_view("compliance-precision", document)
    assert set(document) == {"calibration"}
    assert document["calibration"]["checks"][0]["check_id"] == HOSTILE
    assert "<img" not in rendered.markdown and "<img" not in rendered.html
    assert "[docs](javascript:" not in rendered.markdown
    assert "\n| forged" not in rendered.markdown
    assert "agent-only" not in rendered.markdown and "pci-only" not in rendered.markdown
    assert snapshot(context) == before


@pytest.mark.parametrize("gate", [0, 0.49, 0.5, 0.6, 1])
def test_precision_gate_is_inclusive_and_never_changes_the_recorded_population(
    context: Context, gate: float
) -> None:
    seed_calibration(context)
    before = snapshot(context)
    model = context.services().insight.build(
        ViewName.COMPLIANCE_PRECISION, ViewFilter(framework=FRAMEWORK, precision_gate=gate)
    )
    assert isinstance(model, CompliancePrecision)
    assert model.calibration.assessments == 1
    rows = {row.check_id: row for row in model.calibration.checks}
    assert (rows[HOSTILE].fired, rows[HOSTILE].dismissed, rows[HOSTILE].precision) == (2, 1, 0.5)
    assert rows[HOSTILE].flagged is (gate >= 0.5)
    assert rows["mfa"].flagged is (gate == 1)
    assert model.calibration.gate == gate
    assert snapshot(context) == before


@pytest.mark.parametrize("assessments", [0, 1])
def test_no_assessments_or_no_firings_never_fabricate_precision(
    context: Context, assessments: int
) -> None:
    if assessments:
        recorded(context).attach(compliance(check("quiet", "satisfied")), AssessmentKind.COMPLIANCE)
    rendered = context.services().insight.publish(
        ViewName.COMPLIANCE_PRECISION, ViewFilter(framework=FRAMEWORK)
    )
    assert isinstance(rendered.model, CompliancePrecision)
    assert rendered.model.calibration.assessments == assessments
    assert rendered.model.calibration.checks == ()
    report = context.services().insight.report(
        ViewName.COMPLIANCE_PRECISION, ViewFilter(framework=FRAMEWORK)
    )
    assert report.sections[1].table is None


def test_selecting_another_framework_counts_only_its_recorded_documents(context: Context) -> None:
    seed_calibration(context)
    model = context.services().insight.build(
        ViewName.COMPLIANCE_PRECISION, ViewFilter(framework=ComplianceFramework(PCI))
    )
    assert isinstance(model, CompliancePrecision)
    assert model.calibration.assessments == 2
    assert {row.check_id: row.fired for row in model.calibration.checks} == {
        "pci-only": 1,
        "pci-second": 1,
    }


@pytest.mark.parametrize(
    "scope",
    [
        ViewFilter(),
        ViewFilter(framework=FRAMEWORK, as_of=T0),
        ViewFilter(framework=FRAMEWORK, window=TimeWindow(start=T0, end=T0 + timedelta(days=1))),
        ViewFilter(framework=FRAMEWORK, product_ids=(uuid4(),)),
        ViewFilter(framework=FRAMEWORK, team_ids=(uuid4(),)),
        ViewFilter(framework=FRAMEWORK, categories=("authorization",)),
        ViewFilter(framework=FRAMEWORK, repository_id=uuid4()),
        ViewFilter(framework=FRAMEWORK, artifact_id=uuid4()),
        ViewFilter(framework=FRAMEWORK, assessment_id=uuid4()),
        ViewFilter(framework=FRAMEWORK, report_stem="report"),
        ViewFilter(framework=FRAMEWORK, executive_panels=(ExecutivePanel.ATTACK,)),
        ViewFilter(framework=FRAMEWORK, compare_as_of=T0),
        ViewFilter(framework=FRAMEWORK, first_party_divisor=Decimal(2)),
        ViewFilter(framework=FRAMEWORK, bucket=TimeBucket.DAY),
    ],
)
def test_missing_framework_and_unsupported_scope_refuse_without_writes(
    context: Context, scope: ViewFilter
) -> None:
    before = snapshot(context)
    with pytest.raises(ValidationError):
        context.services().insight.publish(ViewName.COMPLIANCE_PRECISION, scope)
    assert snapshot(context) == before


def test_implicit_refresh_skips_missing_framework_and_selects_only_compatible_views(
    context: Context,
) -> None:
    seed_calibration(context)
    services = context.services()
    only_precision = InsightService(
        [CompliancePrecisionView(services.detection_quality)], context.clock
    )
    skipped = only_precision.refresh(None, ViewFilter())
    assert skipped.rendered == {} and skipped.failed == {}
    result = services.insight.refresh(None, ViewFilter(framework=FRAMEWORK))
    assert set(result.rendered) == {ViewName.COMPLIANCE_PRECISION}
    assert result.failed == {}
    assert isinstance(result.rendered[ViewName.COMPLIANCE_PRECISION].model, CompliancePrecision)
    assert result.rendered[ViewName.COMPLIANCE_PRECISION].model.calibration.assessments == 1


@pytest.mark.parametrize("scope", [ViewFilter(framework=FRAMEWORK), ViewFilter(precision_gate=0.4)])
def test_other_views_cannot_silently_ignore_calibration_parameters(
    context: Context, scope: ViewFilter
) -> None:
    with pytest.raises(ValidationError):
        context.services().insight.publish(ViewName.FINDINGS_ROLLUP, scope)
