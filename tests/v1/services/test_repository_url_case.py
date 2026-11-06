"""One URL rule across services: a GitHub repository is found in any case of owner/repo,
on every configured GitHub host (core#368)."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories import create_database_engine
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import Inventory, PortfolioPolicy, PortfolioService

ENTERPRISE = {"github.com": "github", "github.example.com": "github", "gitlab.com": "gitlab"}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_an_enterprise_github_repository_resolves_in_any_case_in_every_service(
    tmp_path: Path,
) -> None:
    services = Context(Config(home=tmp_path, forge_hosts=ENTERPRISE)).services()
    registered = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.example.com/Org/Repo", ENTERPRISE), public=False
    )
    other_case = "https://github.example.com/org/REPO"
    found = services.portfolio.find_repository(HttpsRepoUrl.parse(other_case, ENTERPRISE))
    assert found is not None and found.id == registered.id
    try:  # resolved by the assessment service's own inventory, not "not in inventory"
        services.assessment.observation_target(repo_url=other_case)
    except NotFoundError as e:
        assert "not in inventory" not in str(e)


@pytest.mark.parametrize("raw", ["https://[bad/org/repo", "https://github.com:x/org/repo", ""])
def test_a_malformed_url_finds_nothing_instead_of_raising(engine: Engine, raw: str) -> None:
    assert Inventory(SqlTraustUnitOfWork(engine)).find_repository(raw) is None


def test_a_second_spelling_waits_for_the_first_writer_and_reuses_its_row(engine: Engine) -> None:
    # writer A holds the write lock with its row inserted but not committed; writer B (its own
    # engine, another spelling) must wait for A rather than read "none" and insert a second
    with SqlTraustUnitOfWork(engine).write() as a:
        a.repositories.lock_url("https://github.com/example-org/api")
        first = a.repositories.get_or_add(
            Repository(url="https://github.com/example-org/api", public=False)
        )
        done: list[object] = []

        def second() -> None:
            own = create_database_engine(engine.url.render_as_string(hide_password=False))
            try:
                portfolio = PortfolioService(SqlTraustUnitOfWork(own), PortfolioPolicy())
                url = HttpsRepoUrl.parse("https://github.com/Example-Org/API", ["github.com"])
                done.append(portfolio.register_repository(url, public=True).id)
            finally:
                own.dispose()

        writer = threading.Thread(target=second)
        writer.start()
        writer.join(timeout=1)
        assert writer.is_alive() and done == []  # B waits on A's lock
        a.commit()
    writer.join(timeout=30)
    assert done == [first.id]


def test_a_mixed_case_configured_host_finds_a_repository_in_any_case(tmp_path: Path) -> None:
    hosts = {"github.com": "github", "GitHub.Example.com": "github"}
    config = Config(home=tmp_path, forge_hosts=hosts)
    assert config.forge_hosts == {"github.com": "github", "github.example.com": "github"}
    services = Context(config).services()
    registered = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.example.com/Org/Repo", config.forge_hosts), public=False
    )
    other_case = HttpsRepoUrl.parse("https://github.example.com/org/REPO", config.forge_hosts)
    found = services.portfolio.find_repository(other_case)
    assert found is not None and found.id == registered.id


@pytest.mark.parametrize(
    "spelling", ["https://github.com/example-org/api", "https://github.com/Example-Org/API"]
)
def test_a_waiting_writer_keeps_the_first_writers_repository_as_it_was(
    engine: Engine, spelling: str
) -> None:
    # A registers private and holds the write lock; B asks for public in the same or another
    # spelling: B waits, then gets A's row unchanged
    with SqlTraustUnitOfWork(engine).write() as a:
        a.repositories.lock_url("https://github.com/example-org/api")
        first = a.repositories.get_or_add(
            Repository(url="https://github.com/example-org/api", public=False)
        )
        done: list[Repository] = []

        def second() -> None:
            own = create_database_engine(engine.url.render_as_string(hide_password=False))
            try:
                portfolio = PortfolioService(SqlTraustUnitOfWork(own), PortfolioPolicy())
                url = HttpsRepoUrl.parse(spelling, ["github.com"])
                done.append(portfolio.register_repository(url, public=True))
            finally:
                own.dispose()

        writer = threading.Thread(target=second)
        writer.start()
        writer.join(timeout=1)
        assert writer.is_alive() and done == []
        a.commit()
    writer.join(timeout=30)
    assert done == [first]  # every field as the first writer stored it, public included
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repositories.get(first.id) == first  # type: ignore[arg-type]


@pytest.mark.integration
def test_a_metadata_write_waits_for_a_visibility_change_and_keeps_it(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("row locks are Postgres's; SQLite has one writer")
    portfolio = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())
    fork = portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/mirror-org/api", ["github.com"]), public=False
    )
    parent = HttpsRepoUrl.parse("https://github.com/example-org/api", ["github.com"])
    assert fork.id is not None
    with SqlTraustUnitOfWork(engine).write() as a:  # another import, changing visibility
        held = a.repositories.get_for_update(fork.id)
        a.repositories.update(held.model_copy(update={"public": True}))
        done: list[Repository] = []

        def link() -> None:  # this import's forge said nothing of visibility
            own = create_database_engine(engine.url.render_as_string(hide_password=False))
            try:
                other = PortfolioService(SqlTraustUnitOfWork(own), PortfolioPolicy())
                done.append(other.record_repo_info(fork.id, None, parent))  # type: ignore[arg-type]
            finally:
                own.dispose()

        writer = threading.Thread(target=link)
        writer.start()
        writer.join(timeout=1)
        assert writer.is_alive() and done == []  # it waits for the row
        a.commit()
    writer.join(timeout=30)
    assert done and done[0].public is True and done[0].upstream_id is not None
    assert portfolio.get_repository(fork.id).public is True  # the change stands
