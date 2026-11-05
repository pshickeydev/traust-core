"""SarifView: findings sarif as a registered Insight view over FindingService.baseline."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, saved_id
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.findings import RecordDecision
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.insight import SarifLog, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import SarifExport

HOSTILE = "a | b `tick` <img src=x onerror=alert(1)> [docs](javascript:alert(1))"
REVIEWER = Principal(
    identity="reviewer@example.com",
    kind=ActorKind.HUMAN,
    display="reviewer",
    verified_by=IdentitySource.OIDC,
)


@pytest.fixture(params=SQL_BACKENDS)
def core(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Context]:
    with contract_db(request.param, tmp_path) as engine:
        url = engine.url.render_as_string(hide_password=False)
        config = tmp_path / "traust.yaml"
        config.write_text(f"home: {tmp_path / 'home'}\ndatabase:\n  url: {url}\nrating: {{}}\n")
        yield Context.from_file(config)


def reported(core: Context) -> tuple[UUID, list[UUID]]:
    """A repository with two findings reported at T0: one plain, one with a hostile title."""
    with SqlTraustUnitOfWork(core.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        repository = uow.repositories.get(ref.repository_id)
        assessment = seed.assessment(ref, occurred_at=T0)
        ids = []
        for title in ("token compared with ==", HOSTILE):
            finding = seed.finding(repository, title=title)
            seed.location(seed.occurrence(finding, assessment))
            ids.append(saved_id(finding))
        uow.commit()
    return ref.repository_id, ids


def test_the_sarif_view_is_the_projection_of_the_baseline(core: Context) -> None:
    repository_id, ids = reported(core)
    services = core.services()
    services.findings.decisions.decide(
        RecordDecision(
            finding_id=ids[1],
            validity="false_positive",
            rationale="The comparison is constant-time in this build.",
            occurred_at=T0 + timedelta(days=1),
        ),
        REVIEWER,
    )
    scope = ViewFilter(repository_id=repository_id, as_of=T0 + timedelta(days=2))
    rendered = services.insight.publish(ViewName.SARIF, scope)

    assert isinstance(rendered.model, SarifLog)
    repository = services.portfolio.get_repository(repository_id)
    views = services.findings.baseline(repository_id, T0 + timedelta(days=2))
    expected = SarifExport().document(views, repository.url)
    assert json.loads(rendered.model.model_dump_json()) == expected
    assert expected["$schema"] and expected["version"] == "2.1.0"
    (run,) = expected["runs"]
    by_id = {r["partialFingerprints"]["traustFindingId/v1"]: r for r in run["results"]}
    plain, hostile = (by_id[str(i)] for i in ids)
    assert len(by_id) == 2 and "suppressions" not in plain and hostile["suppressions"]

    rows = [line for line in rendered.markdown.splitlines() if line.startswith("| ")]
    assert len(rows) == 3  # the header and one row per finding: a title cannot forge rows
    assert "a \\| b" in rendered.markdown and "false_positive" in rendered.markdown
    assert "<img" not in rendered.html


def test_the_sarif_view_states_the_repository_as_it_stood(core: Context) -> None:
    repository_id, _ = reported(core)
    before = ViewFilter(repository_id=repository_id, as_of=T0 - timedelta(days=1))
    model = core.services().insight.build(ViewName.SARIF, before)
    assert isinstance(model, SarifLog)
    (run,) = model.runs
    assert run["results"] == []
    assert "_No findings._" in core.services().insight.publish(ViewName.SARIF, before).markdown


def test_the_sarif_view_needs_a_known_repository(core: Context) -> None:
    insight = core.services().insight
    with pytest.raises(ValidationError, match="name its repository_id"):
        insight.build(ViewName.SARIF, ViewFilter())
    with pytest.raises(NotFoundError):
        insight.build(ViewName.SARIF, ViewFilter(repository_id=uuid4()))


def test_the_sarif_view_is_one_repository_never_a_product_or_team(core: Context) -> None:
    repository_id, _ = reported(core)
    insight = core.services().insight
    for scope in ({"product_ids": (uuid4(),)}, {"team_ids": (uuid4(),)}):
        with pytest.raises(ValidationError, match="takes no product or team"):
            insight.build(ViewName.SARIF, ViewFilter(repository_id=repository_id, **scope))


def test_a_category_scope_keeps_only_findings_with_those_labels(core: Context) -> None:
    repository_id, ids = reported(core)
    with SqlTraustUnitOfWork(core.database) as uow:
        seed, labelled = Seed(uow), uow.findings.get(ids[0])
        for label in ("crypto", "injection"):  # the second label counts as much as the first
            seed.finding_label(labelled, taxonomy="category", label=label)
        uow.commit()
    insight = core.services().insight

    def results(*categories: str) -> list[str]:
        scope = ViewFilter(repository_id=repository_id, categories=categories)
        (run,) = SarifLog.model_validate(insight.build(ViewName.SARIF, scope)).runs
        return [r["partialFingerprints"]["traustFindingId/v1"] for r in run["results"]]

    assert sorted(results()) == sorted(map(str, ids))
    assert results("crypto") == results("injection") == [str(ids[0])]
    assert results("uncategorized") == [str(ids[1])]  # the rule SARIF files it under
    assert results("secrets") == []


def test_a_refresh_leaves_the_per_repository_sarif_view_out(tmp_path: Path) -> None:
    insight = Context(Config(home=tmp_path)).services().insight
    assert ViewName.SARIF not in insight.refresh(None, ViewFilter()).rendered
