from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    CloudConfigAuditArtifact,
    IsolationReviewArtifact,
    PrivProfileArtifact,
)
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.insight import (
    ExecutivePanel,
    ExecutiveSummary,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.insight import ExecutiveSummaryView

DAY = timedelta(days=1)
FIXTURES = Path(__file__).parents[2] / "fixtures"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def attach(
    context: Context,
    uow: SqlTraustUnitOfWork,
    ref: RepositoryRef,
    kind: AssessmentKind,
    document: ArtifactDocument,
    occurred_at: datetime = T0,
    assessor_version: str = "test",
) -> Assessment:
    assessment = Seed(uow).assessment(
        ref, kind=kind, occurred_at=occurred_at, assessor_version=assessor_version
    )
    published = ArtifactPublisher(
        PublishSpecs(PublishSpec(type(document))), context.object_store, uow
    ).publish_artifact(document)
    AssessmentLog(uow).attach(assessment.id, published.artifact_id, sha256_hex(document.payload))
    return assessment


def executive(context: Context, filter: ViewFilter) -> ExecutiveSummary:
    model = context.services().insight.build(ViewName.EXECUTIVE_SUMMARY, filter)
    assert isinstance(model, ExecutiveSummary)
    return model


def test_optional_panels_read_latest_domain_documents_and_render_the_same_composition(
    context: Context,
    engine: Engine,
) -> None:
    review = json.loads((FIXTURES / "assessments/widget-isolation-review.json").read_text())
    review["metadata"]["service"] = "<script>tenant</script>"
    review["posture"]["overall"] = "weak"
    cloud = CloudConfigAuditArtifact.parse(
        (FIXTURES / "cloud_config/myrepo-cloud-config-audit.json").read_bytes()
    )
    profile = json.loads((FIXTURES / "assessments/widget-operator-priv-profile.json").read_text())
    profile["tier2_required_vs_granted"]["shipped_not_declared_count"] = 7
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/myrepo")
        ref = seed.repository_ref(repo, is_default=True)
        attach(
            context,
            uow,
            ref,
            AssessmentKind.ISOLATION_REVIEW_CANONICAL,
            IsolationReviewArtifact.from_document(review),
        )
        review["posture"]["overall"] = "strong"
        attach(
            context,
            uow,
            ref,
            AssessmentKind.ISOLATION_REVIEW_CANONICAL,
            IsolationReviewArtifact.from_document(review),
            T0 + 5 * DAY,
        )
        audit = attach(context, uow, ref, AssessmentKind.CLOUD_CONFIG_CANONICAL, cloud)
        found = seed.finding(repo)
        seed.occurrence(found, audit, severity="critical")
        seed.decision(
            found, validity="confirmed", actor="human:analyst@example.com", occurred_at=T0
        )
        attach(
            context,
            uow,
            ref,
            AssessmentKind.PRIV_PROFILE_CANONICAL,
            PrivProfileArtifact.from_document(profile),
        )
        uow.commit()
    scope = ViewFilter(
        as_of=T0 + DAY, executive_panels=(ExecutivePanel.ISOLATION, ExecutivePanel.IAC)
    )
    built = executive(context, scope)
    assert built.isolation is not None and built.iac is not None
    (isolation,) = built.isolation.reviews
    assert (isolation.posture, isolation.interfaces, isolation.gaps) == ("weak", 1, 1)
    assert built.rollup.as_of == built.isolation.threat_register.as_of == scope.as_of
    assert isolation.dimensions == {"yes": 3, "partial": 1, "na": 1}
    (target,) = built.iac.targets
    assert (target.unsuppressed, target.suppressed, target.needs_review, target.ledgered) == (
        5,
        1,
        1,
        1,
    )
    assert target.severities.critical == 3
    later = executive(context, scope.model_copy(update={"as_of": T0 + 6 * DAY}))
    assert later.isolation is not None and later.isolation.reviews[0].posture == "strong"
    rendered = context.services().insight.publish(ViewName.EXECUTIVE_SUMMARY, scope)
    assert rendered.model == built
    assert "&lt;script&gt;tenant&lt;/script&gt;" in rendered.html
    assert "<script>tenant</script>" not in rendered.html
    headings = {
        s.heading
        for s in context.services().insight.report(ViewName.EXECUTIVE_SUMMARY, scope).sections
    }
    assert {
        "Tenant-isolation posture (PEACH)",
        "Declared IaC targets",
    } <= headings
    plain = executive(context, ViewFilter())
    assert (plain.attack, plain.pqc, plain.isolation, plain.iac) == (None, None, None, None)


def test_attack_and_pqc_are_embedded_models_and_rendered_panels(context: Context) -> None:
    attack = FIXTURES / "insight/attack"
    context.register_attack_catalog(
        attack / "attack-techniques.json", attack / "attack-mapping.json"
    )
    scope = ViewFilter(executive_panels=(ExecutivePanel.ATTACK, ExecutivePanel.PQC))
    model = executive(context, scope)
    service = context.services().insight
    assert model.attack is not None
    assert model.attack.as_of == T0 + 20 * DAY
    assert model.attack == service.build(ViewName.ATTACK_COVERAGE, ViewFilter())
    assert model.pqc == service.build(ViewName.PQC_PORTFOLIO, ViewFilter())
    rendered = service.publish(ViewName.EXECUTIVE_SUMMARY, scope)
    assert rendered.model == model
    sections = service.report(ViewName.EXECUTIVE_SUMMARY, scope).sections
    assert any(section.heading.startswith("ATT&CK") for section in sections)
    assert any(section.heading.startswith("PQC") for section in sections)


def test_historical_pqc_panel_states_its_gap_instead_of_substituting_current_data(
    context: Context,
) -> None:
    model = executive(context, ViewFilter(as_of=T0, executive_panels=(ExecutivePanel.PQC,)))
    assert model.pqc is None
    assert model.pqc_unavailable is not None and "Historical PQC" in model.pqc_unavailable
    sections = (
        context.services()
        .insight.report(
            ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=T0, executive_panels=(ExecutivePanel.PQC,))
        )
        .sections
    )
    assert "PQC — snapshot availability" in {s.heading for s in sections}


def test_a_panel_without_its_view_wired_is_a_config_error(context: Context) -> None:
    services = context.services()
    view = ExecutiveSummaryView(
        services.findings,
        services.portfolio,
        services.assessment,
        services.code_facts,
        services.exposure,
    )
    for panel in ExecutivePanel:
        with pytest.raises(ConfigError):
            view.build(ViewFilter(executive_panels=(panel,)))
    assert view.build(ViewFilter()).isolation is None


def test_panels_render_their_empty_population_explicitly(context: Context) -> None:
    scope = ViewFilter(executive_panels=(ExecutivePanel.ISOLATION, ExecutivePanel.IAC))
    model = executive(context, scope)
    assert model.isolation is not None and model.isolation.reviews == ()
    assert model.iac is not None and (model.iac.assessments, model.iac.targets) == (0, ())
    sections = {
        s.heading: s
        for s in context.services().insight.report(ViewName.EXECUTIVE_SUMMARY, scope).sections
    }
    assert sections["Tenant-isolation posture (PEACH)"].table is None
    assert sections["Declared IaC targets"].body == "_No declared IaC audits recorded._"
