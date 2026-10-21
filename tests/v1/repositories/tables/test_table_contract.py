"""Every contract table, both backends: what the database guarantees for each row.

Parametrized over CONTRACT_TABLES, so a new table is covered as soon as it has a
spec, a repository and a Seed builder.
"""

from __future__ import annotations

from time import sleep
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import Seed, repository_for
from traust_core.v1.errors import ConflictError, NotFoundError, RepositoryError
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork

TABLES = [spec.name for spec in CONTRACT_TABLES]
MUTABLE = [spec.name for spec in CONTRACT_TABLES if not spec.append_only]
APPEND_ONLY = [spec.name for spec in CONTRACT_TABLES if spec.append_only]
# Tables whose rows have no natural key: two identical rows are two facts.
NO_NATURAL_KEY = {
    "assessment",
    "review_item",
    "run_order",
    "spend_event",
    "feed_snapshot",
    "layers",
}


@pytest.mark.parametrize("table", TABLES)
def test_database_generates_id_and_timestamps(seed: Seed, table: str) -> None:
    saved = repository_for(seed.uow, table).add(seed.new(table))
    assert isinstance(saved.id, UUID) and saved.id.version == 4
    assert saved.created_at is not None and saved.created_at.tzinfo is not None
    if table in MUTABLE:
        assert saved.updated_at is not None and saved.updated_at >= saved.created_at
    else:
        assert "updated_at" not in type(saved).model_fields


@pytest.mark.parametrize("table", TABLES)
def test_saved_row_round_trips_after_commit(seed: Seed, engine: sa.Engine, table: str) -> None:
    saved = repository_for(seed.uow, table).add(seed.new(table))
    seed.uow.commit()
    with SqlTraustUnitOfWork(engine) as other:
        assert repository_for(other, table).get(saved.id) == saved


@pytest.mark.parametrize("table", TABLES)
def test_get_missing_row_raises_not_found(uow: SqlTraustUnitOfWork, table: str) -> None:
    with pytest.raises(NotFoundError):
        repository_for(uow, table).get(uuid4())


@pytest.mark.parametrize("table", TABLES)
def test_natural_key_rejects_a_duplicate(seed: Seed, table: str) -> None:
    repository = repository_for(seed.uow, table)
    row = seed.new(table)
    first = repository.add(row)
    if table in NO_NATURAL_KEY:
        assert repository.add(row).id != first.id
        return
    with pytest.raises(ConflictError):
        repository.add(row)


@pytest.mark.parametrize("table", MUTABLE)
def test_update_saves_and_the_database_touches_updated_at(seed: Seed, table: str) -> None:
    repository = repository_for(seed.uow, table)
    saved = repository.add(seed.new(table))
    seed.uow.commit()
    sleep(0.01)  # the touch trigger has millisecond precision on SQLite
    updated = repository.update(saved)
    assert updated.id == saved.id and updated.created_at == saved.created_at
    assert updated.updated_at > saved.updated_at
    assert repository.get(saved.id) == updated


@pytest.mark.parametrize("table", MUTABLE)
def test_update_of_a_missing_row_raises_not_found(seed: Seed, table: str) -> None:
    repository = repository_for(seed.uow, table)
    with pytest.raises(NotFoundError):
        repository.update(seed.new(table).model_copy(update={"id": uuid4()}))


@pytest.mark.parametrize("table", APPEND_ONLY)
def test_append_only_repository_has_no_update(uow: SqlTraustUnitOfWork, table: str) -> None:
    assert not hasattr(repository_for(uow, table), "update")


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("statement", ["update", "delete"])
def test_database_rejects_mutating_append_only_rows(seed: Seed, table: str, statement: str) -> None:
    repository = repository_for(seed.uow, table)
    saved = repository.add(seed.new(table))
    where = repository.table.c.id == saved.id
    stmt = (
        sa.update(repository.table).where(where).values(created_at=saved.created_at)
        if statement == "update"
        else sa.delete(repository.table).where(where)
    )
    with pytest.raises((RepositoryError, ConflictError), match="append-only"):
        repository._execute(f"raw {statement}", stmt)
