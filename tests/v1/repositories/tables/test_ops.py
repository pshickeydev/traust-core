"""4 · Operations repositories: the run-order queue, spend windows and feed freshness."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.errors import NotFoundError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

LEASE = timedelta(minutes=5)


def test_claim_takes_priority_then_age_and_skips_non_queued(seed: Seed) -> None:
    orders = seed.uow.run_orders
    seed.run_order(state="planned", priority=0)
    seed.run_order(state="succeeded", priority=0)
    later = seed.run_order(priority=5)
    soon_old = seed.run_order(priority=1)
    seed.uow.commit()  # separate transactions: distinct created_at on Postgres
    apart()
    soon_new = seed.run_order(priority=1)
    claimed = [orders.claim(f"w{i}", T0, LEASE) for i in range(4)]
    assert [c.id if c else None for c in claimed] == [soon_old.id, soon_new.id, later.id, None]


def test_claim_records_the_lease(seed: Seed) -> None:
    order = seed.run_order()
    claimed = seed.uow.run_orders.claim("worker-1", T0, LEASE)
    assert claimed is not None and claimed.id == order.id
    assert (claimed.state, claimed.lease_holder) == ("leased", "worker-1")
    assert claimed.lease_expires_at == T0 + LEASE
    assert claimed.updated_at >= order.updated_at


def test_claim_stamps_when_work_started(seed: Seed) -> None:
    seed.run_order()
    claimed = seed.uow.run_orders.claim("worker-1", T0, LEASE)
    assert claimed is not None and claimed.started_at == T0


def test_get_for_update_reads_the_order_and_refuses_unknown_ids(seed: Seed) -> None:
    order = seed.run_order(asset="feeds_cache", lane=None)
    assert seed.uow.run_orders.get_for_update(order.id) == order
    with pytest.raises(NotFoundError):
        seed.uow.run_orders.get_for_update(uuid4())


def test_expired_leases_return_to_the_queue(seed: Seed) -> None:
    orders = seed.uow.run_orders
    expired, live = seed.run_order(priority=1), seed.run_order(priority=2)
    orders.claim("w1", T0, LEASE)
    orders.claim("w2", T0 + LEASE, LEASE)
    assert orders.requeue_expired(T0 + LEASE + timedelta(seconds=1)) == 1
    released = orders.get(expired.id)
    assert (released.state, released.lease_holder, released.lease_expires_at) == (
        "queued",
        None,
        None,
    )
    assert orders.get(live.id).state == "leased"


def test_orders_by_batch_and_by_repository_state(seed: Seed) -> None:
    orders = seed.uow.run_orders
    batch, repo = seed.run_batch(), seed.repository()
    in_batch = seed.run_order(run_batch_id=batch.id)
    planned = seed.run_order(repository_id=repo.id, state="planned", priority=2)
    urgent = seed.run_order(repository_id=repo.id, state="planned", priority=1)
    seed.run_order(repository_id=repo.id)
    assert orders.list_for_batch(batch.id) == [in_batch]
    assert orders.list_for_repository(repo.id, "planned") == [urgent, planned]


def test_one_batch_per_kind_and_period(seed: Seed) -> None:
    batch = seed.run_batch(kind="drain_tranche", period="2026-W31")
    assert seed.uow.run_batches.find("drain_tranche", "2026-W31") == batch
    assert seed.uow.run_batches.find("router_run", "2026-W31") is None


def test_spend_by_order_and_half_open_window(seed: Seed) -> None:
    spend = seed.uow.spend_events
    order = seed.run_order()
    start = seed.spend_event(run_order_id=order.id, occurred_at=T0)
    inside = seed.spend_event(occurred_at=T0 + timedelta(hours=23))
    seed.spend_event(occurred_at=T0 + timedelta(days=1))  # end is exclusive
    assert spend.list_for_order(order.id) == [start]
    assert spend.list_between(T0, T0 + timedelta(days=1)) == [start, inside]


def test_latest_feed_snapshot_by_retrieval_time(seed: Seed) -> None:
    feeds = seed.uow.feed_snapshots
    assert feeds.latest("osv") is None
    new = seed.feed_snapshot(feed="osv", retrieved_at=T0 + timedelta(days=1))
    seed.feed_snapshot(feed="osv", retrieved_at=T0)
    seed.feed_snapshot(feed="epss", retrieved_at=T0 + timedelta(days=9))
    assert feeds.latest("osv") == new


def test_assessment_inputs_link_results_to_snapshots(seed: Seed) -> None:
    inputs = seed.uow.assessment_inputs
    snapshot, assessment = seed.feed_snapshot(), seed.assessment()
    link = seed.assessment_input(assessment, snapshot)
    assert inputs.list_for_assessment(assessment.id) == [link]
    assert inputs.list_for_snapshot(snapshot.id) == [link]


@pytest.mark.integration
def test_concurrent_workers_never_claim_the_same_order(engine: Engine) -> None:
    """Postgres row locks: an uncommitted lease is skipped, not waited on or doubled."""
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite serialises writers; concurrency is a Postgres property")
    with SqlTraustUnitOfWork(engine) as setup:
        seed = Seed(setup)
        first, second = seed.run_order(priority=1), seed.run_order(priority=2)
        setup.commit()
    with SqlTraustUnitOfWork(engine) as a, SqlTraustUnitOfWork(engine) as b:
        got_a = a.run_orders.claim("a", T0, LEASE)
        got_b = b.run_orders.claim("b", T0, LEASE)  # a's lease is not committed yet
        assert got_a is not None and got_b is not None
        assert {got_a.id, got_b.id} == {first.id, second.id}
        a.commit()
        b.commit()
