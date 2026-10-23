"""Repository reads on SQLite and Postgres: by id, and by URL."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


def test_get_and_find_a_repository(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/example/operator")
    portfolio = PortfolioService(uow, PortfolioPolicy())
    assert portfolio.get_repository(repo.id) == repo  # type: ignore[arg-type]
    url = HttpsRepoUrl.parse("https://github.com/example/operator", ["github.com"])
    assert portfolio.find_repository(url) == repo


def test_an_unknown_repository(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    portfolio = PortfolioService(uow, PortfolioPolicy())
    with pytest.raises(NotFoundError):
        portfolio.get_repository(uuid4())
    url = HttpsRepoUrl.parse("https://github.com/example/missing", ["github.com"])
    assert portfolio.find_repository(url) is None
