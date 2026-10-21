"""Every table repository, on SQLite and Postgres: save a row, get it back, update it.

Parametrized over CONTRACT_TABLES, so a new table is covered once it has a spec,
a repository and a Seed builder.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import Seed, apart, repository_for
from traust_core.v1.errors import ConflictError, NotFoundError
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork

TABLES = [spec.name for spec in CONTRACT_TABLES]
MUTABLE = [spec.name for spec in CONTRACT_TABLES if not spec.append_only]


@pytest.mark.parametrize("table", TABLES)
def test_add_returns_the_saved_row(seed: Seed, table: str) -> None:
    row = seed.new(table)
    saved = repository_for(seed.uow, table).add(row)
    assert isinstance(saved.id, UUID)
    assert saved.created_at is not None
    assert saved.model_copy(update={"id": None, "created_at": None, **_no_updated_at(row)}) == row


@pytest.mark.parametrize("table", TABLES)
def test_get_returns_the_committed_row(seed: Seed, engine: sa.Engine, table: str) -> None:
    saved = repository_for(seed.uow, table).add(seed.new(table))
    seed.uow.commit()
    with SqlTraustUnitOfWork(engine) as other:
        assert repository_for(other, table).get(saved.id) == saved


@pytest.mark.parametrize("table", TABLES)
def test_get_missing_raises_not_found(uow: SqlTraustUnitOfWork, table: str) -> None:
    with pytest.raises(NotFoundError):
        repository_for(uow, table).get(uuid4())


@pytest.mark.parametrize("table", MUTABLE)
def test_update_saves_the_row(seed: Seed, table: str) -> None:
    repository = repository_for(seed.uow, table)
    saved = repository.add(seed.new(table))
    seed.uow.commit()
    apart()
    updated = repository.update(saved)
    assert (updated.id, updated.created_at) == (saved.id, saved.created_at)
    assert updated.updated_at > saved.updated_at
    assert repository.get(saved.id) == updated


@pytest.mark.parametrize("table", MUTABLE)
def test_update_missing_raises_not_found(seed: Seed, table: str) -> None:
    with pytest.raises(NotFoundError):
        repository_for(seed.uow, table).update(seed.new(table).model_copy(update={"id": uuid4()}))


def test_a_rejected_write_raises_conflict(seed: Seed) -> None:
    repository = seed.repository(url="https://github.com/org/dup")
    with pytest.raises(ConflictError):
        seed.repository(url=repository.url)


def _no_updated_at(row: object) -> dict[str, None]:
    return {"updated_at": None} if "updated_at" in type(row).model_fields else {}
