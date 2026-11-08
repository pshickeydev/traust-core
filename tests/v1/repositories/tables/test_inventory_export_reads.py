from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import T0, Seed, repository_for, saved_id
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Entity
from traust_core.v1.models.common import RecordBudget


@dataclass(frozen=True)
class BatchRead:
    read: Callable[[Collection[UUID], RecordBudget | None], Sequence[Entity]]
    ids: tuple[UUID, ...]
    rows: tuple[Entity, ...]


@pytest.fixture(params=["ownerships", "teams", "components", "releases", "products"])
def batch_read(request: pytest.FixtureRequest, seed: Seed) -> BatchRead:
    uow = seed.uow
    rows: Sequence[Entity]
    read: Callable[..., Sequence[Entity]]
    match request.param:
        case "ownerships":
            owned = [seed.ownership() for _ in range(4)]
            rows = owned[:3]
            ids = tuple(row.repository_id for row in owned[:3])
            read = uow.ownerships.current_for_repositories
        case "teams":
            teams = [seed.team() for _ in range(4)]
            rows = teams[:3]
            ids = tuple(saved_id(row) for row in rows)
            read = uow.teams.list_by_ids
        case "components":
            components = [seed.component() for _ in range(4)]
            rows = components[:3]
            ids = tuple(row.repository_ref_id for row in components[:3])
            read = uow.components.list_for_refs
        case "releases":
            releases = [seed.release() for _ in range(4)]
            rows = releases[:3]
            ids = tuple(saved_id(row) for row in rows)
            read = uow.releases.list_by_ids
        case "products":
            products = [seed.product() for _ in range(4)]
            rows = products[:3]
            ids = tuple(saved_id(row) for row in rows)
            read = uow.products.list_by_ids
        case _:
            raise AssertionError(request.param)
    return BatchRead(
        lambda values, budget: read(values, read_budget=budget),
        ids,
        tuple(sorted(rows, key=lambda row: (row.created_at, row.id))),
    )


def test_batch_reads_isolate_ids_deduplicate_and_preserve_registration_order(
    batch_read: BatchRead,
) -> None:
    ids = [*reversed(batch_read.ids), batch_read.ids[0], uuid4()]
    assert tuple(batch_read.read(ids, None)) == batch_read.rows
    budget = RecordBudget(3, "inventory export")
    assert tuple(batch_read.read(ids, budget)) == batch_read.rows
    assert budget.remaining == 0


def test_empty_and_missing_batches_do_not_spend_an_exhausted_budget(batch_read: BatchRead) -> None:
    budget = RecordBudget(1, "inventory export")
    budget.consume(1)
    assert batch_read.read([], budget) == []
    assert batch_read.read([uuid4()], budget) == []
    assert budget.remaining == 0


def test_batch_reads_refuse_overflow_instead_of_returning_partial_rows(
    batch_read: BatchRead,
) -> None:
    budget = RecordBudget(4, "inventory export")
    budget.consume(2)
    with pytest.raises(ValidationError):
        batch_read.read(batch_read.ids, budget)


def test_batch_reads_merge_global_order_and_share_budget_across_sql_batches(
    batch_read: BatchRead,
) -> None:
    ids = [uuid4() for _ in range(1201)]
    ids[0], ids[600], ids[1200] = reversed(batch_read.ids)
    ids.append(batch_read.ids[0])
    budget = RecordBudget(3, "inventory export")
    assert tuple(batch_read.read(ids, budget)) == batch_read.rows
    assert budget.remaining == 0
    with pytest.raises(ValidationError):
        batch_read.read(ids, RecordBudget(2, "inventory export"))


def test_current_ownership_batch_includes_future_starts_but_not_closed_rows(seed: Seed) -> None:
    repo, other = seed.repository(), seed.repository()
    current = seed.ownership(repo)
    future = seed.ownership(repo, valid_from=T0 + timedelta(days=36500))
    seed.ownership(repo, valid_from=T0, valid_to=T0 + timedelta(days=1))
    seed.ownership(other)
    expected = sorted((current, future), key=lambda row: (row.created_at, row.id))
    budget = RecordBudget(2, "inventory export")
    assert (
        seed.uow.ownerships.current_for_repositories([saved_id(repo)], read_budget=budget)
        == expected
    )
    assert budget.remaining == 0


def test_repository_list_all_is_empty_even_with_an_exhausted_budget(seed: Seed) -> None:
    budget = RecordBudget(1, "inventory export")
    budget.consume(1)
    assert seed.uow.repositories.list_all(read_budget=budget) == []
    assert seed.uow.repositories.list_all() == []


def test_repository_list_all_keeps_legacy_newest_first_order_and_uuid_ties(seed: Seed) -> None:
    last = seed.repository(url="https://forge.example/a")
    tied = [seed.repository(url=f"https://forge.example/z-{n}") for n in range(3)]
    table = repository_for(seed.uow, "repository").table
    seed.uow.connection.execute(
        sa.update(table).where(table.c.id.in_([row.id for row in tied])).values(created_at=T0)
    )
    expected = [last] + [
        seed.uow.repositories.get(saved_id(row))
        for row in sorted(tied, key=lambda row: row.id, reverse=True)
    ]
    assert seed.uow.repositories.search(limit=4, after=None) == expected
    assert seed.uow.repositories.list_all() == expected
    budget = RecordBudget(4, "inventory export")
    assert seed.uow.repositories.list_all(read_budget=budget) == expected
    assert budget.remaining == 0
    with pytest.raises(ValidationError):
        seed.uow.repositories.list_all(read_budget=RecordBudget(3, "inventory export"))


def test_inventory_reads_share_one_cumulative_budget(seed: Seed) -> None:
    repo = seed.repository()
    owner = seed.ownership(repo)
    ref = seed.repository_ref(repo)
    component = seed.component(ref=ref)
    budget = RecordBudget(7, "inventory export")
    assert seed.uow.repositories.list_all(read_budget=budget) == [repo]
    assert seed.uow.ownerships.current_for_repositories([saved_id(repo)], read_budget=budget) == [
        owner
    ]
    assert seed.uow.teams.list_by_ids([owner.team_id], read_budget=budget)
    assert seed.uow.repository_refs.list_for_repositories([saved_id(repo)], read_budget=budget) == [
        ref
    ]
    assert seed.uow.components.list_for_refs([saved_id(ref)], read_budget=budget) == [component]
    releases = seed.uow.releases.list_by_ids([component.release_id], read_budget=budget)
    assert len(releases) == 1
    assert seed.uow.products.list_by_ids([releases[0].product_id], read_budget=budget)
    assert budget.remaining == 0
    with pytest.raises(ValidationError):
        seed.uow.teams.list_by_ids([owner.team_id], read_budget=budget)


def test_related_row_fanout_is_bounded_even_for_one_requested_parent(seed: Seed) -> None:
    repo = seed.repository()
    ref = seed.repository_ref(repo)
    components = [seed.component(ref=ref) for _ in range(5)]
    owners = [seed.ownership(repo) for _ in range(5)]
    with pytest.raises(ValidationError):
        seed.uow.components.list_for_refs(
            [saved_id(ref)], read_budget=RecordBudget(4, "inventory export")
        )
    with pytest.raises(ValidationError):
        seed.uow.ownerships.current_for_repositories(
            [saved_id(repo)], read_budget=RecordBudget(4, "inventory export")
        )
    assert seed.uow.components.list_for_refs(
        [saved_id(ref)], read_budget=RecordBudget(5, "inventory export")
    ) == sorted(components, key=lambda row: (row.created_at, row.id))
    assert seed.uow.ownerships.current_for_repositories(
        [saved_id(repo)], read_budget=RecordBudget(5, "inventory export")
    ) == sorted(owners, key=lambda row: (row.created_at, row.id))
