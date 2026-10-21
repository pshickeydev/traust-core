from __future__ import annotations

import os
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.example import repository as example_repository
from traust_core.v1 import contracts
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import contract_dialect

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
SQL_BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.integration)]
CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))


def apply_contract_ddl(engine: Engine, area: contracts.Area) -> None:
    apply_schema(engine, contracts.ddl(area, contract_dialect(engine)))


def apply_contract_db(engine: Engine) -> None:
    apply_schema(engine, contracts.database_ddl(contract_dialect(engine)))


def _engine(kind: str, tmp_path: Path) -> Engine:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    return create_database_engine(PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/t.db")


@contextmanager
def database(
    kind: str, tmp_path: Path, metadata: sa.MetaData = example_repository.metadata
) -> Generator[Engine]:
    eng = _engine(kind, tmp_path)
    metadata.create_all(eng)
    try:
        yield eng
    finally:
        metadata.drop_all(eng)
        eng.dispose()


@contextmanager
def contract_db(kind: str, tmp_path: Path) -> Generator[Engine]:
    """A fresh database bootstrapped from the whole contracts db (every namespace)."""
    eng = _engine(kind, tmp_path)
    if kind == "postgres":
        _drop_namespaces(eng)
    apply_contract_db(eng)
    try:
        yield eng
    finally:
        if kind == "postgres":
            _drop_namespaces(eng)
        eng.dispose()


def _drop_namespaces(engine: Engine) -> None:
    with engine.begin() as conn:
        for area in reversed(contracts.AREAS):
            conn.exec_driver_sql(f"DROP SCHEMA IF EXISTS {area} CASCADE")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if mark := item.get_closest_marker("todo"):
            item.add_marker(pytest.mark.skip(reason=f"todo({mark.args[0]}): parked"))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with database(request.param, tmp_path) as eng:
        yield eng
