from __future__ import annotations

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from perf.seed import REPOSITORIES
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@pytest.mark.parametrize("max_records", [1, REPOSITORIES], ids=["overflow", "exact"])
def test_inventory_repository_enumeration_is_one_sql_bounded_read(
    explained: Profile, max_records: int
) -> None:
    def read(uow: SqlTraustUnitOfWork) -> None:
        budget = RecordBudget(max_records, "inventory export")
        if max_records < REPOSITORIES:
            with pytest.raises(ValidationError):
                uow.repositories.list_all(read_budget=budget)
        else:
            rows = uow.repositories.list_all(read_budget=budget)
            assert len(rows) == REPOSITORIES
            assert budget.remaining == 0

    (statement,) = explained(read)
    assert "Limit" in statement.plan[0], statement.plan
    assert statement.execution_ms < 100, statement.plan


@pytest.mark.parametrize(
    "table,column,method",
    [
        ("ownerships", "repository_id", "current_for_repositories"),
        ("teams", "id", "list_by_ids"),
        ("components", "repository_ref_id", "list_for_refs"),
        ("releases", "id", "list_by_ids"),
        ("products", "id", "list_by_ids"),
    ],
)
def test_inventory_related_batches_use_sql_bounds_and_table_owned_reads(
    engine: sa.Engine,
    explained: Profile,
    table: str,
    column: str,
    method: str,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        repository = getattr(uow, table)
        query = sa.select(repository.table.c[column]).distinct().limit(200)
        if table == "ownerships":
            query = query.where(repository.table.c.valid_to.is_(None))
        ids = list(uow.connection.scalars(query))
    assert ids

    def read(uow: SqlTraustUnitOfWork) -> None:
        budget = RecordBudget(10_000, "inventory export")
        rows = getattr(getattr(uow, table), method)(ids, read_budget=budget)
        assert {getattr(row, column) for row in rows} == set(ids)
        assert budget.remaining == 10_000 - len(rows)

    (statement,) = explained(read)
    assert "Limit" in statement.plan[0], statement.plan
    assert statement.execution_ms < 30, statement.plan


def test_inventory_release_single_id_lookup_uses_primary_key(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        release_id = uow.connection.scalar(sa.select(uow.releases.table.c.id).limit(1))
    assert release_id is not None
    (statement,) = explained(
        lambda uow: uow.releases.list_by_ids(
            [release_id], read_budget=RecordBudget(1, "inventory export")
        )
    )
    assert statement.uses_index("release_pkey"), statement.plan
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 30, statement.plan


def test_inventory_components_span_bounded_indexed_batches(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ids = list(
            uow.connection.scalars(
                sa.select(uow.components.table.c.repository_ref_id).distinct().limit(1200)
            )
        )
    assert len(ids) == 1200

    def read(uow: SqlTraustUnitOfWork) -> None:
        budget = RecordBudget(1200, "inventory export")
        rows = uow.components.list_for_refs(ids, read_budget=budget)
        assert len(rows) == 1200
        assert budget.remaining == 0

    statements = explained(read)
    assert len(statements) == 3
    for statement in statements:
        assert "Limit" in statement.plan[0], statement.plan
        assert statement.uses_index("idx_component_repository_ref"), statement.plan
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 30, statement.plan
