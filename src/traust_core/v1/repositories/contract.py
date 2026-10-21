"""The whole contracts db as table specs: every namespace, every table, once."""

from __future__ import annotations

from sqlalchemy.engine import Engine

from traust_core.v1.repositories import traust_ledger, traust_ops
from traust_core.v1.repositories.sql import Dialect, schema_drift
from traust_core.v1.repositories.tables import TableFactory, TableSpec
from traust_core.v1.repositories.traust import assessments, dependencies, findings, inventory

CONTRACT_TABLES: tuple[TableSpec, ...] = (
    *inventory.TABLES,
    *dependencies.TABLES,
    *assessments.TABLES,
    *findings.TABLES,
    *traust_ops.TABLES,
    *traust_ledger.TABLES,
)


def contract_tables(dialect: Dialect) -> TableFactory:
    """The dialect's factory with every contract table built onto its MetaData."""
    tables = TableFactory.for_dialect(dialect)
    for spec in CONTRACT_TABLES:
        tables.table(spec)
    return tables


def contract_drift(engine: Engine) -> list[str]:
    """Where the database and the declared tables disagree; empty = in step."""
    return schema_drift(engine, contract_tables(Dialect.of(engine)).metadata)
