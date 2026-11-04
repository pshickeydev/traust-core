from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_assessment_record import authored_report
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingState
from traust_core.v1.models.insight import ContainerFindings, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

DAY = timedelta(days=1)


def attached_report(context: Context, assessment_id: UUID) -> UUID:
    [artifact] = context.services().artifacts.list_for_assessment(assessment_id, kind="report")
    assert artifact.id is not None
    return artifact.id


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    context.__dict__["database"] = engine
    return context


def record_container(
    context: Context,
    ref_id: UUID,
    image: str,
    day: int,
    indices: tuple[int, ...] = (0, 1),
    *,
    description: str | None = None,
) -> UUID:
    body = json.loads(authored_report().payload)
    body["title"] = f"Container assessment {day}: {image}"
    body["metadata"] = {
        "date": (T0 + day * DAY).date().isoformat(),
        "repository": image,
        "commit": str(day % 10) * 64,
        "audit_profile": "container",
        "scope": image,
    }
    body["findings"] = [body["findings"][i] for i in indices]
    for finding in body["findings"]:
        finding.pop("validation_status", None)
        finding.pop("disposition", None)
        finding.pop("effective_severity", None)
        if description is not None:
            finding["description"] = description
    saved = context.services().assessment.record(
        SecurityAuditArtifact.from_document(body),
        ref_id,
        AssessmentKind.CONTAINER,
        "skill:secure-container-audit",
        "test",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0 + day * DAY),
    )
    assert saved.id is not None
    return saved.id


def test_container_population_is_cumulative_image_scoped_and_decision_driven(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        uow.commit()
    assert ref.id is not None
    first = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:aaa", 0)
    second = record_container(context, ref.id, "registry.example:5000/apps/widget:release", 1, (0,))
    empty = record_container(context, ref.id, "registry.example:5000/apps/widget@sha256:ccc", 2, ())
    record_container(context, ref.id, "registry.example:5000/apps/other@sha256:ddd", 3, (2,))
    findings = context.services().findings
    initial = findings.occurrences(assessment_id=first)
    assert len(initial) == 2
    repeated = findings.occurrences(assessment_id=second)[0].finding_id
    absent = next(o.finding_id for o in initial if o.finding_id != repeated)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        code = seed.assessment(ref, kind="secure-code", occurred_at=T0 + 4 * DAY)
        original = uow.findings.get(repeated)
        seed.occurrence(original, code, severity="critical")
        seed.occurrence(
            seed.finding(uow.repositories.get(ref.repository_id)), code, severity="high"
        )
        seed.decision(
            original,
            validity="confirmed",
            resolution="resolved",
            actor="human:analyst@example.com",
            occurred_at=T0 + 5 * DAY,
        )
        uow.commit()
    scope = ViewFilter(artifact_id=attached_report(context, empty))
    rendered = context.services().insight.publish(ViewName.CONTAINER_FINDINGS, scope)
    model = rendered.model
    assert isinstance(model, ContainerFindings)
    assert rendered.stem == "widget-container-audit-findings-current"
    assert model.image_repository == "registry.example:5000/apps/widget"
    assert [r.assessment_id for r in model.reports] == [first, second, empty]
    by_id = {row.view.finding.id: row for row in model.findings}
    assert set(by_id) == {repeated, absent}
    assert len(by_id[repeated].occurrences) == 2
    assert by_id[repeated].view.occurrence.assessment_id == second
    assert by_id[repeated].view.effective_severity == "high"
    assert by_id[repeated].description == authored_report().findings[0].description
    assert by_id[repeated].view.state() == FindingState.RESOLVED
    assert by_id[absent].view.state() == FindingState.OPEN
    assert model.total.resolved == 1 and model.total.open.total == 1
    assert len(by_id[repeated].history) == 1
    before_decision = context.services().insight.build(
        ViewName.CONTAINER_FINDINGS, scope.model_copy(update={"as_of": T0 + 3 * DAY})
    )
    assert before_decision.total.open.total == 2
    assert before_decision.total.resolved == 0
    assert all(not row.history for row in before_decision.findings)
    payload = json.loads(model.model_dump_json())
    assert {row["view"]["finding"]["id"] for row in payload["findings"]} == set(map(str, by_id))
    report = context.services().insight.report(ViewName.CONTAINER_FINDINGS, scope)
    table = next(section.table for section in report.sections if section.heading == "Findings")
    assert {row[0]: row[3] for row in table.rows} == {
        str(repeated): "resolved",
        str(absent): "open",
    }


def test_container_view_requires_an_attached_container_report_and_honors_its_cutoff(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    assessment_id = record_container(
        context,
        ref.id,
        "registry.example/apps/widget:release",
        1,
        (),
    )
    artifact_id = attached_report(context, assessment_id)
    detached = (
        context.artifact_publisher(PublishSpecs(PublishSpec(SecurityAuditArtifact)))
        .publish_artifact(authored_report())
        .artifact_id
    )
    for scope in (
        ViewFilter(),
        ViewFilter(artifact_id=detached),
        ViewFilter(artifact_id=artifact_id, as_of=T0),
    ):
        with pytest.raises(ValidationError):
            context.services().insight.build(ViewName.CONTAINER_FINDINGS, scope)


def test_container_view_rejects_a_source_code_report_anchor(
    context: Context,
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    saved = context.services().assessment.record(
        authored_report(),
        ref.id,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "fixture",
        "1",
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=T0),
    )
    assert saved.id is not None
    with pytest.raises(ValidationError, match="not a container"):
        context.services().insight.build(
            ViewName.CONTAINER_FINDINGS, ViewFilter(artifact_id=attached_report(context, saved.id))
        )


def test_container_single_item_view_is_excluded_from_dashboard_refresh(context: Context) -> None:
    from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
    from traust_core.v1.services.insight import ContainerFindingsView, InsightService

    services = context.services()
    view = ContainerFindingsView(
        services.findings,
        services.portfolio,
        services.assessment,
        RatingPolicy(RatingConfig()),
        services.artifacts,
    )
    refreshed = InsightService([view], FixedClock(T0)).refresh(None, ViewFilter())
    assert refreshed.rendered == {} and refreshed.failed == {}


def test_container_body_values_are_literal_after_storage_and_publication(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    image_repository = "registry.example/apps/widget<img src=x onerror=alert(2)>"
    description = "<iframe src=x></iframe> [open](javascript:alert(1))\n## Injected heading"
    assessment_id = record_container(
        context,
        ref.id,
        f"{image_repository}:latest",
        1,
        (0,),
        description=description,
    )
    rendered = context.services().insight.publish(
        ViewName.CONTAINER_FINDINGS,
        ViewFilter(artifact_id=attached_report(context, assessment_id)),
    )
    assert rendered.model.image_repository == image_repository
    assert rendered.model.findings[0].description == description
    assert "<img" not in rendered.markdown
    assert "<iframe" not in rendered.markdown
    assert "&lt;img" in rendered.markdown and "&lt;iframe" in rendered.markdown
    assert "[open](javascript:" not in rendered.markdown
    assert "\n## Injected heading" not in rendered.markdown
