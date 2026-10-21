from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.conftest import SQL_BACKENDS, contract_db
from traust_core.v1 import contracts
from traust_core.v1.repositories.contract import CONTRACT_TABLES, contract_drift, contract_tables
from traust_core.v1.repositories.sql import Dialect
from traust_core.v1.repositories.tables import (
    TRAUST,
    TRAUST_LEDGER,
    TRAUST_OPS,
    TableFactory,
)
from traust_core.v1.repositories.traust.inventory import REPOSITORY
from traust_core.v1.repositories.traust_ledger import EVENTS
from traust_core.v1.repositories.traust_ops import RUN_ORDER


@pytest.mark.parametrize(
    ("namespace", "postgres", "sqlite"),
    [
        (TRAUST, ("traust", "finding"), (None, "finding")),
        (TRAUST_OPS, ("traust_ops", "finding"), (None, "ops_finding")),
        (TRAUST_LEDGER, ("traust_ledger", "finding"), (None, "ledger_finding")),
    ],
)
def test_namespace_places_a_table_per_dialect(namespace, postgres, sqlite) -> None:
    assert namespace.locate("finding", Dialect.POSTGRES) == postgres
    assert namespace.locate("finding", Dialect.SQLITE) == sqlite


@pytest.mark.parametrize(
    ("dialect", "names"),
    [
        (Dialect.POSTGRES, ["traust.repository", "traust_ops.run_order", "traust_ledger.events"]),
        (Dialect.SQLITE, ["repository", "ops_run_order", "ledger_events"]),
    ],
)
def test_factory_builds_contract_names(dialect: Dialect, names: list[str]) -> None:
    tables = TableFactory.for_dialect(dialect)
    assert [tables.table(s).fullname for s in (REPOSITORY, RUN_ORDER, EVENTS)] == names


def test_factory_is_one_per_dialect_and_builds_each_table_once() -> None:
    tables = TableFactory.for_dialect(Dialect.SQLITE)
    assert TableFactory.for_dialect(Dialect.SQLITE) is tables
    assert TableFactory.for_dialect(Dialect.POSTGRES) is not tables
    assert tables.table(REPOSITORY) is tables.table(REPOSITORY)


def test_factory_follows_the_engine(tmp_path: Path) -> None:
    engine = sa.create_engine(f"sqlite:///{tmp_path}/f.db")
    assert TableFactory.for_bind(engine) is TableFactory.for_dialect(Dialect.SQLITE)


def test_append_only_tables_have_no_updated_at() -> None:
    tables = contract_tables(Dialect.SQLITE)
    for spec in CONTRACT_TABLES:
        assert ("updated_at" in tables.table(spec).c) is not spec.append_only, spec.name


@pytest.mark.parametrize("dialect", list(Dialect))
def test_every_contract_table_has_exactly_one_spec(dialect: Dialect) -> None:
    files = [p.stem for a in contracts.AREAS for p in contracts.ddl_files(a, dialect)]
    contract = sorted(f for f in files if f != "namespace" and not _is_view(f, dialect))
    specs = sorted(spec.name for spec in CONTRACT_TABLES)
    assert specs == contract


def _is_view(stem: str, dialect: Dialect) -> bool:
    return any(
        p.stem == stem and p.parent.name == "views"
        for a in contracts.AREAS
        for p in contracts.ddl_files(a, dialect)
    )


@pytest.mark.parametrize("kind", SQL_BACKENDS)
def test_declared_tables_match_the_contracts_ddl(kind: str, tmp_path: Path) -> None:
    with contract_db(kind, tmp_path) as engine:
        assert contract_drift(engine) == []
