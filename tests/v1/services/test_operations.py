"""OpsService order lifecycle on SQLite and Postgres: submit, claim, heartbeat, complete,
approve, requeue."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConflictError, NotFoundError
from traust_core.v1.models.common import Principal
from traust_core.v1.models.operations import (
    JobResult,
    OrderRequest,
    OrderState,
    Outcome,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import OpsService

LEASE = timedelta(minutes=5)
W1, W2 = WorkerId("w1"), WorkerId("w2")
OPERATOR = Principal(id=uuid4(), kind=ActorKind("human"), display="operator")
RESULTS = {
    Outcome.SUCCEEDED: JobResult.succeeded(),
    Outcome.DEGRADED: JobResult.partly({"unreachable": 2}),
    Outcome.REFUSED: JobResult.refused("diff-too-large"),
    Outcome.FAILED: JobResult.failed("runner-crashed"),
}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def ops(engine: Engine, at: timedelta = timedelta()) -> OpsService:
    return OpsService(SqlTraustUnitOfWork(engine), FixedClock(T0 + at))


def seeded(engine: Engine, **kw: Any) -> RunOrder:
    with SqlTraustUnitOfWork(engine) as uow:
        order = Seed(uow).run_order(**kw)
        uow.commit()
    return order


def stored(engine: Engine, order: RunOrder) -> RunOrder:
    assert order.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.run_orders.get(order.id)


def leased(engine: Engine, worker: WorkerId = W1) -> RunOrder:
    seeded(engine)
    order = ops(engine).claim(worker, LEASE)
    assert order is not None
    return order


def test_submit_queues_the_asset_for_its_requester(engine: Engine) -> None:
    order = ops(engine).submit(OrderRequest(asset="feeds_cache", priority=3), OPERATOR)
    assert stored(engine, order) == order
    assert (order.asset, order.lane, order.state) == ("feeds_cache", None, OrderState.QUEUED)
    assert order.requested_by == f"human:{OPERATOR.id}"


def test_submit_refuses_an_order_both_routed_and_injected(engine: Engine) -> None:
    request = OrderRequest(asset="diff_scan", priority=1, rule="rule-4", event_source="cve")
    with pytest.raises(ConflictError):
        ops(engine).submit(request, OPERATOR)


def test_claim_leases_the_next_order_and_none_when_the_queue_is_empty(engine: Engine) -> None:
    service = ops(engine)
    assert service.claim(W1, LEASE) is None
    queued = seeded(engine)
    order = service.claim(W1, LEASE)
    assert order is not None and order.id == queued.id
    assert (order.state, order.lease_holder, order.started_at) == (OrderState.LEASED, W1, T0)
    assert service.claim(W2, LEASE) is None


def test_heartbeat_extends_the_holders_lease(engine: Engine) -> None:
    order = leased(engine)
    renewed = ops(engine, timedelta(minutes=4)).heartbeat(order.id, W1, LEASE)
    assert renewed.lease_expires_at == T0 + timedelta(minutes=9)
    assert stored(engine, order).lease_expires_at == renewed.lease_expires_at


@pytest.mark.parametrize(
    ("worker", "at"),
    [(W2, timedelta()), (W1, LEASE + timedelta(seconds=1))],
    ids=["another worker", "expired lease"],
)
def test_heartbeat_is_refused(engine: Engine, worker: WorkerId, at: timedelta) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine, at).heartbeat(order.id, worker, LEASE)
    assert stored(engine, order).lease_expires_at == T0 + LEASE


def test_heartbeat_refuses_an_order_that_is_not_leased(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).heartbeat(order.id, W1, LEASE)


def test_unknown_orders_are_not_found(engine: Engine) -> None:
    service, missing = ops(engine), uuid4()
    with pytest.raises(NotFoundError):
        service.heartbeat(missing, W1, LEASE)
    with pytest.raises(NotFoundError):
        service.complete(missing, W1, JobResult.succeeded())
    with pytest.raises(NotFoundError):
        service.approve(missing, OPERATOR)


@pytest.mark.parametrize("outcome", list(Outcome))
def test_complete_finishes_the_order_with_its_outcome(engine: Engine, outcome: Outcome) -> None:
    order = leased(engine)
    result = RESULTS[outcome]
    done = ops(engine, timedelta(minutes=2)).complete(order.id, W1, result)
    assert stored(engine, order) == done
    assert (done.state, done.reason) == (OrderState(outcome), result.reason)
    assert (done.lease_holder, done.lease_expires_at) == (None, None)
    assert (done.started_at, done.finished_at) == (T0, T0 + timedelta(minutes=2))


def test_complete_retried_with_the_same_outcome_changes_nothing(engine: Engine) -> None:
    order = leased(engine)
    done = ops(engine).complete(order.id, W1, JobResult.succeeded())
    assert ops(engine, timedelta(minutes=1)).complete(order.id, W1, JobResult.succeeded()) == done


def test_complete_refuses_a_second_different_outcome(engine: Engine) -> None:
    order = leased(engine)
    ops(engine).complete(order.id, W1, JobResult.succeeded())
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W1, JobResult.failed("late"))
    assert stored(engine, order).state == OrderState.SUCCEEDED


def test_complete_refuses_a_worker_that_does_not_hold_the_lease(engine: Engine) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W2, JobResult.succeeded())
    assert stored(engine, order).state == OrderState.LEASED


def test_complete_refuses_an_order_that_was_never_leased(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W1, JobResult.succeeded())
    assert stored(engine, order).state == OrderState.QUEUED


def test_complete_accepts_an_expired_lease_the_reaper_has_not_taken(engine: Engine) -> None:
    order = leased(engine)
    done = ops(engine, LEASE + timedelta(minutes=1)).complete(order.id, W1, JobResult.succeeded())
    assert done.state == OrderState.SUCCEEDED


def test_complete_after_the_reaper_requeued_is_refused(engine: Engine) -> None:
    order = leased(engine)
    later = ops(engine, LEASE + timedelta(seconds=1))
    assert later.requeue_expired() == 1
    with pytest.raises(ConflictError):
        later.complete(order.id, W1, JobResult.succeeded())


def test_approve_queues_an_order_awaiting_approval(engine: Engine) -> None:
    order = seeded(engine, state="awaiting_approval")
    approved = ops(engine).approve(order.id, OPERATOR)
    assert approved.state == stored(engine, order).state == OrderState.QUEUED


@pytest.mark.parametrize("state", ["planned", "queued", "withheld", "succeeded"])
def test_approve_refuses_an_order_not_awaiting_approval(engine: Engine, state: str) -> None:
    order = seeded(engine, state=state)
    with pytest.raises(ConflictError):
        ops(engine).approve(order.id, OPERATOR)
    assert stored(engine, order).state == state


def test_requeue_expired_returns_lapsed_leases_and_keeps_live_ones(engine: Engine) -> None:
    lapsed = leased(engine, W1)
    live = seeded(engine)
    ops(engine, LEASE).claim(W2, LEASE)
    service = ops(engine, LEASE + timedelta(seconds=1))
    assert service.requeue_expired() == 1
    assert (stored(engine, lapsed).state, stored(engine, live).state) == (
        OrderState.QUEUED,
        OrderState.LEASED,
    )
    assert service.requeue_expired() == 0
    reclaimed = service.claim(W1, LEASE)
    assert reclaimed is not None and reclaimed.id == lapsed.id


@pytest.mark.integration
def test_ten_concurrent_claimers_never_lease_the_same_order(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite serialises writers; concurrency is a Postgres property")
    orders = {seeded(engine, priority=i).id for i in range(7)}
    start, got = threading.Barrier(10), []

    def claimer(n: int) -> None:
        start.wait()
        got.append(ops(engine).claim(WorkerId(f"w{n}"), LEASE))

    threads = [threading.Thread(target=claimer, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    claimed = [o.id for o in got if o is not None]
    assert sorted(map(str, claimed)) == sorted(map(str, orders))
    assert got.count(None) == 3
