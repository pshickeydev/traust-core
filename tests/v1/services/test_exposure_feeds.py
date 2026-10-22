"""ExposureService feed refresh and status on SQLite and Postgres, with a feed provider double."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy

EPSS = FeedName("epss")
FILENAME = "epss_scores-current.csv.gz"
DAY = timedelta(hours=24)
GOOD = gzip.compress(b"cve,epss,percentile\nCVE-2026-1111,0.72,0.9\n")


class FakeFeed:
    """Returns the queued payloads (or raises the queued errors) in order."""

    def __init__(self, *outcomes: bytes | Exception) -> None:
        self.name = EPSS
        self.filename = FILENAME
        self.max_age = DAY
        self._outcomes = list(outcomes)
        self.fetched_at = T0

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def fetch(self) -> Result[bytes]:
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return Result(outcome, Acquisition(provider=self.name, acquired_at=self.fetched_at))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(engine: Engine, feed: FeedProvider, objects: InMemoryObjectStore) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    feeds: ProviderRegistry[FeedProvider] = ProviderRegistry("feed")
    feeds.register(feed.name, lambda: feed)
    intake = FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy())
    return ExposureService(uow, intake, feeds=feeds, objects=objects)


def latest(engine: Engine) -> FeedSnapshot | None:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.feed_snapshots.latest(EPSS)


def run_order(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        order = Seed(uow).run_order(asset="feeds_cache", lane=None)
        uow.commit()
    assert order.id is not None
    return order.id


def seed_snapshot(engine: Engine) -> FeedSnapshot:
    with SqlTraustUnitOfWork(engine) as uow:
        snapshot = Seed(uow).feed_snapshot(feed=EPSS, retrieved_at=T0)
        uow.commit()
    return snapshot


def test_first_refresh_records_object_artifact_and_snapshot(engine: Engine) -> None:
    objects = InMemoryObjectStore()
    order = run_order(engine)
    status = service(engine, FakeFeed(GOOD), objects).refresh_feed(EPSS, order)
    snapshot = latest(engine)
    assert snapshot is not None and snapshot.run_order_id == order
    assert snapshot.retrieved_at == T0
    with SqlTraustUnitOfWork(engine) as uow:
        artifact = uow.artifacts.get(snapshot.artifact_id)
    assert artifact.kind == "feed" and artifact.assessment_id is None
    assert len(list(objects.list("feeds/epss/"))) == 1
    assert status.fetched_at == T0 and not status.stale(T0 + timedelta(hours=1))


def test_retried_refresh_of_the_same_order_writes_nothing_new(engine: Engine) -> None:
    objects = InMemoryObjectStore()
    order = run_order(engine)
    svc = service(engine, FakeFeed(GOOD, GOOD), objects)
    svc.refresh_feed(EPSS, order)
    first = latest(engine)
    svc.refresh_feed(EPSS, order)
    assert latest(engine) == first
    assert len(list(objects.list("feeds/epss/"))) == 1


def test_new_order_with_unchanged_bytes_records_a_new_snapshot_of_the_same_artifact(
    engine: Engine,
) -> None:
    feed = FakeFeed(GOOD, GOOD)
    svc = service(engine, feed, InMemoryObjectStore())
    svc.refresh_feed(EPSS, run_order(engine))
    first = latest(engine)
    feed.fetched_at = T0 + DAY
    status = svc.refresh_feed(EPSS, run_order(engine))
    second = latest(engine)
    assert first is not None and second is not None
    assert second.id != first.id and second.artifact_id == first.artifact_id
    assert status.fetched_at == T0 + DAY


def test_new_bytes_record_a_new_artifact(engine: Engine) -> None:
    changed = gzip.compress(b"cve,epss,percentile\nCVE-2026-2222,0.10,0.5\n")
    svc = service(engine, FakeFeed(GOOD, changed), InMemoryObjectStore())
    svc.refresh_feed(EPSS, run_order(engine))
    first = latest(engine)
    svc.refresh_feed(EPSS, run_order(engine))
    second = latest(engine)
    assert first is not None and second is not None
    assert second.artifact_id != first.artifact_id


def test_failed_fetch_writes_nothing_and_the_old_snapshot_goes_stale(engine: Engine) -> None:
    old = seed_snapshot(engine)
    objects = InMemoryObjectStore()
    give_up = ServiceError("https://feed.test: gave up after 4 attempts (no vpn)")
    svc = service(engine, FakeFeed(give_up), objects)
    with pytest.raises(ServiceError, match="no vpn"):
        svc.refresh_feed(EPSS, run_order(engine))
    assert latest(engine) == old
    assert list(objects.list()) == []
    status = svc.feed_status(EPSS)
    assert status.fetched_at == T0 and status.stale(T0 + timedelta(hours=48))


def test_corrupt_download_writes_nothing_and_keeps_the_old_snapshot(engine: Engine) -> None:
    old = seed_snapshot(engine)
    objects = InMemoryObjectStore()
    svc = service(engine, FakeFeed(b"not a gzip payload"), objects)
    with pytest.raises(ValidationError, match="corrupt"):
        svc.refresh_feed(EPSS, run_order(engine))
    assert latest(engine) == old
    assert list(objects.list()) == []


def test_feed_never_fetched_is_stale(engine: Engine) -> None:
    status = service(engine, FakeFeed(), InMemoryObjectStore()).feed_status(EPSS)
    assert status.fetched_at is None and status.stale(T0)
    assert status.max_age == DAY


def test_unknown_feed_is_a_config_error(engine: Engine) -> None:
    svc = service(engine, FakeFeed(), InMemoryObjectStore())
    with pytest.raises(ConfigError, match="unknown feed provider 'kev'"):
        svc.refresh_feed(FeedName("kev"))
