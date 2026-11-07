from __future__ import annotations

import csv
import io
import json
import shutil
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from tests.v1.services.test_portfolio_product_map import PROVENANCE
from tests.v1.services.test_pqc_worklist import snapshot
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import ProductDefinitionsMapArtifact
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import ExecutivePanel, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import InsightService, InventoryExportView
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine = table_fixtures.engine
FIXTURE = Path(__file__).parents[2] / "fixtures" / "inventory" / "product-definitions"
COLUMNS = (
    "Repository",
    "URL",
    "Host",
    "Organization/Group",
    "Repo Name",
    "Owner Team",
    "Products",
    "Accountable Contacts",
)


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    config = Config(home=tmp_path / "home")
    config = config.model_copy(
        update={
            "locations": config.locations.model_copy(
                update={"feeds_cache": str(tmp_path / "feeds")}
            ),
        }
    )
    context = Context(config, clock=FixedClock(T0))
    context.__dict__["database"] = engine
    return context


@pytest.fixture
def cache(context: Context) -> Path:
    destination = context.config.locations.feeds_cache_dir()
    assert destination is not None
    return Path(shutil.copytree(FIXTURE, destination))


def test_all_registered_repositories_keep_legacy_newest_first_order_and_url_parts(
    context: Context,
) -> None:
    urls = (
        "https://example.com/zeta/nested/project.git",
        "https://example.com/alpha/empty",
        "loose-repository-name",
        "https://example.com/",
    )
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        for url in urls:
            seed.repository(url=url)
            apart()
        uow.commit()
    rows = context.services().portfolio.inventory_export()
    assert tuple(row.url for row in rows) == tuple(reversed(urls))
    assert [
        (row.repository, row.host, row.organization, row.repo_name) for row in reversed(rows)
    ] == [
        ("zeta/nested/project.git", "example.com", "zeta/nested", "project.git"),
        ("alpha/empty", "example.com", "alpha", "empty"),
        ("loose-repository-name", "", "", "loose-repository-name"),
        ("", "example.com", "", ""),
    ]
    assert all(row.owner_teams == row.products == row.accountable_contacts == () for row in rows)


def test_current_owners_and_shipping_products_are_sorted_without_duplicates(
    context: Context,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        seed.ownership(repository, seed.team(name="zeta"))
        seed.ownership(repository, seed.team(name="Alpha"), valid_from=T0 + timedelta(days=90))
        seed.ownership(repository, seed.team(name="closed"), valid_to=T0 + timedelta(days=1))
        main = seed.repository_ref(repository)
        tag = seed.repository_ref(repository, name="v2", kind="tag", sha="b" * 40)
        zeta, alpha = seed.product(slug="zeta"), seed.product(slug="alpha")
        release = seed.release(zeta)
        seed.component(release, main)
        seed.component(release, tag)
        seed.component(seed.release(zeta), tag)
        seed.component(seed.release(alpha), main)
        seed.component(seed.release(seed.product(slug="unrelated")), seed.repository_ref())
        uow.commit()
    rows = {row.url: row for row in context.services().portfolio.inventory_export()}
    row = rows.pop(repository.url)
    (unrelated,) = rows.values()
    assert row.owner_teams == ("Alpha", "zeta")
    assert row.products == ("alpha", "zeta")
    assert unrelated.products == ("unrelated",)
    assert unrelated.owner_teams == ()


def test_export_reads_stay_batched_as_the_inventory_grows(context: Context) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        team, release = seed.team(), seed.release()
        repository = seed.repository()
        seed.ownership(repository, team)
        seed.component(release, seed.repository_ref(repository))
        uow.commit()
    portfolio = context.services().portfolio
    statements: list[str] = []

    def read_only(
        _connection: sa.Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        execution: sa.ExecutionContext,
        _many: bool,
    ) -> None:
        assert execution.compiled is not None
        assert execution.compiled.statement.is_select
        statements.append(statement)

    sa.event.listen(context.database, "before_cursor_execute", read_only)
    try:
        assert len(portfolio.inventory_export()) == 1
    finally:
        sa.event.remove(context.database, "before_cursor_execute", read_only)
    initial_reads = len(statements)
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        for index in range(24):
            repository = seed.repository(url=f"https://github.com/example/growth-{index}")
            seed.ownership(repository, team)
            seed.component(release, seed.repository_ref(repository))
        uow.commit()
    statements.clear()
    sa.event.listen(context.database, "before_cursor_execute", read_only)
    try:
        rows = portfolio.inventory_export()
    finally:
        sa.event.remove(context.database, "before_cursor_execute", read_only)
    assert len(rows) == 25
    assert all(row.owner_teams == (team.name,) for row in rows)
    assert all(row.products for row in rows)
    assert initial_reads > 0
    assert len(statements) == initial_reads


def test_cached_contacts_and_recorded_mapping_override_are_used_without_writes(
    context: Context,
    cache: Path,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/acme/widget-api")
        uow.commit()
    portfolio = context.services().portfolio
    before = snapshot(context)
    (row,) = portfolio.inventory_export()
    assert row.accountable_contacts == (
        "embargoperson (private_tracker_cc; embargo_cleared=True)",
        "componentperson (component_cc; embargo_cleared=False)",
        "publicperson (default_cc; embargo_cleared=False)",
    )
    assert snapshot(context) == before
    portfolio.record_product_map(
        ProductDefinitionsMapArtifact.from_document(
            {
                "mappings": {"repos": {"github.com/acme/widget-api": "relic"}},
            }
        ),
        PROVENANCE,
    )
    before = snapshot(context)
    (row,) = portfolio.inventory_export()
    assert row.accountable_contacts == ("relicperson (default_cc; embargo_cleared=False)",)
    assert row.products == ()
    assert snapshot(context) == before


@pytest.mark.parametrize("cache_contents", [None, "not json", "{}"])
def test_unavailable_optional_cache_keeps_registered_inventory(
    context: Context,
    cache_contents: str | None,
) -> None:
    if cache_contents is not None:
        directory = context.config.locations.feeds_cache_dir()
        assert directory is not None
        directory.mkdir(parents=True)
        (directory / "product_definitions.json").write_text(cache_contents)
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository()
        uow.commit()
    (row,) = context.services().portfolio.inventory_export()
    assert row.accountable_contacts == ()
    assert row.repository


def test_empty_inventory_has_no_rows(context: Context) -> None:
    assert context.services().portfolio.inventory_export() == ()
    assert context.services().insight.build(
        ViewName.INVENTORY_EXPORT,
        ViewFilter(),
    ).model_dump(mode="json") == {"rows": []}


def test_missing_product_definitions_injection_is_a_clear_configuration_error(
    context: Context,
) -> None:
    portfolio = PortfolioService(SqlTraustUnitOfWork(context.database), PortfolioPolicy())
    with pytest.raises(ConfigError):
        portfolio.inventory_export()


def test_repository_budget_refuses_instead_of_returning_a_prefix(context: Context) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        seed.repository()
        apart()
        seed.repository()
        uow.commit()
    portfolio = context.services().portfolio
    with pytest.raises(ValidationError):
        portfolio.inventory_export(max_records=1)
    assert len(portfolio.inventory_export(max_records=2)) == 2


@pytest.mark.parametrize("related", ["owners", "shipping"])
def test_related_rows_share_the_repository_budget(context: Context, related: str) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        if related == "owners":
            for name in ("alpha", "zeta"):
                seed.ownership(repository, seed.team(name=name))
        else:
            release = seed.release(seed.product())
            for name in ("main", "other"):
                seed.component(release, seed.repository_ref(repository, name=name))
        uow.commit()
    before = snapshot(context)
    with pytest.raises(ValidationError):
        context.services().portfolio.inventory_export(max_records=4)
    assert snapshot(context) == before
    assert len(context.services().portfolio.inventory_export(max_records=100)) == 1


def test_product_definition_contact_work_is_bounded_before_any_output(
    context: Context,
    cache: Path,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/acme/widget-api")
        uow.commit()
    portfolio = context.services().portfolio
    assert len(portfolio.inventory_export(max_records=100)) == 1
    path = cache / "product_definitions.json"
    document = json.loads(path.read_text())
    document["ps_modules"]["widget-1"]["default_cc"] = [f"contact{n}" for n in range(101)]
    path.write_text(json.dumps(document))
    with pytest.raises(ValidationError):
        portfolio.inventory_export(max_records=100)
    assert len(portfolio.inventory_export(max_records=10_000)[0].accountable_contacts) == 103


def test_recorded_product_mappings_share_the_export_budget(context: Context, cache: Path) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/acme/widget-api")
        uow.commit()
    portfolio = context.services().portfolio
    assert len(portfolio.inventory_export(max_records=100)) == 1
    portfolio.record_product_map(
        ProductDefinitionsMapArtifact.from_document(
            {
                "mappings": {
                    "repos": {f"example.com/group/repo-{n}": "widget" for n in range(101)}
                },
            }
        ),
        PROVENANCE,
    )
    with pytest.raises(ValidationError):
        portfolio.inventory_export(max_records=100)
    assert len(portfolio.inventory_export(max_records=10_000)) == 1


def test_product_definition_index_work_shares_the_export_budget(
    context: Context,
    cache: Path,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/acme/widget-api")
        uow.commit()
    portfolio = context.services().portfolio
    assert len(portfolio.inventory_export(max_records=100)) == 1
    path = cache / "product_definitions.json"
    document = json.loads(path.read_text())
    document["ps_update_streams"]["widget-1-default"]["managed_service_components"].extend(
        {"name": f"component-{n}", "git_repo_url": f"https://example.com/group/repo-{n}"}
        for n in range(101)
    )
    path.write_text(json.dumps(document))
    with pytest.raises(ValidationError):
        portfolio.inventory_export(max_records=100)
    assert len(portfolio.inventory_export(max_records=10_000)) == 1


UNSUPPORTED_FILTERS = [
    ViewFilter(product_ids=(uuid4(),)),
    ViewFilter(team_ids=(uuid4(),)),
    ViewFilter(categories=("crypto",)),
    ViewFilter(as_of=T0),
    ViewFilter(window=TimeWindow(start=T0, end=T0 + timedelta(days=1))),
    ViewFilter(bucket=TimeBucket.DAY),
    ViewFilter(artifact_id=uuid4()),
    ViewFilter(repository_id=uuid4()),
    ViewFilter(executive_panels=(ExecutivePanel.ATTACK,)),
    ViewFilter(assessment_id=uuid4()),
    ViewFilter(report_stem="inventory"),
    ViewFilter(compare_as_of=T0),
    ViewFilter(first_party_divisor=Decimal("2")),
    ViewFilter(repository_ref_ids=()),
    ViewFilter(repository_ref_ids=(uuid4(),)),
    ViewFilter(pqc_chokepoints=("gateway",)),
    ViewFilter(framework=next(iter(ComplianceFramework))),
    ViewFilter(precision_gate=0.5),
]


@pytest.mark.parametrize("filter", UNSUPPORTED_FILTERS)
def test_inventory_view_refuses_every_nondefault_scope(
    context: Context, filter: ViewFilter
) -> None:
    insight = InsightService([InventoryExportView(context.services().portfolio)], context.clock)
    with pytest.raises(ValidationError):
        insight.build(ViewName.INVENTORY_EXPORT, filter)
    with pytest.raises(ValidationError):
        insight.publish(ViewName.INVENTORY_EXPORT, filter)


def test_implicit_refresh_skips_inventory_but_explicit_refresh_builds_real_rows(
    context: Context,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository()
        uow.commit()
    insight = InsightService([InventoryExportView(context.services().portfolio)], context.clock)
    implicit = insight.refresh(None, ViewFilter())
    assert implicit.rendered == implicit.failed == {}
    explicit = insight.refresh([ViewName.INVENTORY_EXPORT], ViewFilter())
    assert explicit.failed == {}
    assert len(explicit.rendered[ViewName.INVENTORY_EXPORT].model.rows) == 1


def test_refused_budget_is_not_published_as_partial_inventory(context: Context) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        seed.repository()
        seed.repository()
        uow.commit()
    insight = InsightService(
        [InventoryExportView(context.services().portfolio, max_records=1)],
        context.clock,
    )
    with pytest.raises(ValidationError):
        insight.publish(ViewName.INVENTORY_EXPORT, ViewFilter())
    refreshed = insight.refresh([ViewName.INVENTORY_EXPORT], ViewFilter())
    assert not refreshed.rendered
    assert set(refreshed.failed) == {ViewName.INVENTORY_EXPORT}


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_published_formats_keep_hostile_inventory_inert_without_changing_json(
    context: Context,
    prefix: str,
) -> None:
    hostile = f"{prefix}SUM(1,2)|<script>alert(1)</script>\r\n| forged | row |"
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://example.com/group/repository")
        seed.ownership(repository, seed.team(name=hostile))
        seed.ownership(repository, seed.team(name="ordinary"))
        uow.commit()
    before = snapshot(context)
    rendered = context.services().insight.publish(ViewName.INVENTORY_EXPORT, ViewFilter())
    document = rendered.model.model_dump(mode="json")
    assert document["rows"][0]["Owner Team"] == [hostile, "ordinary"]
    assert tuple(document["rows"][0]) == COLUMNS
    assert rendered.csv is not None
    csv_rows = list(csv.reader(io.StringIO(rendered.csv)))
    assert csv_rows[0] == list(COLUMNS)
    assert len(csv_rows) == 2 and len(csv_rows[1]) == 8
    assert csv_rows[1][5].startswith("'" + prefix)
    assert "\r" not in csv_rows[1][5] and "\n" not in csv_rows[1][5]
    assert "; ordinary" in csv_rows[1][5]
    assert "<script>" not in rendered.html and "<script>" not in rendered.markdown
    assert "&lt;script&gt;" in rendered.html
    assert "\\| forged \\| row \\|" in rendered.markdown
    assert not any(line.startswith("| forged") for line in rendered.markdown.splitlines())
    assert snapshot(context) == before


def test_build_report_and_export_never_execute_or_fetch_and_write_nothing(
    context: Context,
    cache: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/acme/widget-api")
        uow.commit()
    services = context.services()
    before = snapshot(context)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("inventory export executed external work or wrote object bytes")

    def only_select(
        _connection: sa.Connection,
        _cursor: object,
        _statement: str,
        _parameters: object,
        execution: sa.ExecutionContext,
        _many: bool,
    ) -> None:
        assert execution.compiled is not None
        assert execution.compiled.statement.is_select

    monkeypatch.setattr(context.object_store, "put", forbidden)
    monkeypatch.setattr(context.http, "_send", forbidden)
    monkeypatch.setattr(ProcessRunner, "run", forbidden)
    sa.event.listen(context.database, "before_cursor_execute", only_select)
    try:
        (row,) = services.portfolio.inventory_export()
        first_contact = "embargoperson (private_tracker_cc; embargo_cleared=True)"
        assert row.accountable_contacts[0] == first_contact
        services.insight.build(ViewName.INVENTORY_EXPORT, ViewFilter())
        services.insight.report(ViewName.INVENTORY_EXPORT, ViewFilter())
        rendered = services.insight.publish(ViewName.INVENTORY_EXPORT, ViewFilter())
        assert rendered.csv is not None
        (record,) = csv.DictReader(io.StringIO(rendered.csv))
        assert record["URL"] == "https://github.com/acme/widget-api"
        assert record["Accountable Contacts"].startswith(first_contact)
    finally:
        sa.event.remove(context.database, "before_cursor_execute", only_select)
    assert snapshot(context) == before
