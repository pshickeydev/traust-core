"""ExposureService.refresh_advisory_cvss and advisory_cvss, on SQLite and Postgres: the daily
ranked build of every authority's scores, and its read, parsed once per publication."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_advisory_names import (
    AT,
    FIXTURES,
    LOG4SHELL,
    LOG4SHELL_GHSA,
    TEMPLATES,
    Http,
    advisory,
    alias_id,
    engine,  # noqa: F401 - the SQLite and Postgres fixture
    finding,
)
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.cvss import AdvisoryCvss, CvssSource
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ADVISORY_CVSS_FEED, AdvisoryCvssCache, ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy

NVD = "https://nvd.test/cves?cveId=CVE-2021-44228"
OSV = f"https://osv.test/v1/vulns/{LOG4SHELL_GHSA}"


class World:
    """One store and one cache shared by every service it wires, as the Context shares them."""

    def __init__(self, db: Engine, sources: tuple[str, ...] = ("nvd", "ghsa")) -> None:
        self.engine = db
        self.http = Http()
        self.objects = InMemoryObjectStore()
        self.cache = AdvisoryCvssCache()
        self.sources = sources

    def service(self) -> ExposureService:
        registry: ProviderRegistry[FeedSource] = ProviderRegistry("feed-source")
        for name in self.sources:
            template, ident = TEMPLATES[name]
            source = FeedSource(
                name, template, template=template, ident=ident, post=False, probe=None,
                http=self.http, probe_http=self.http,  # type: ignore[arg-type]
                clock=FixedClock(AT),
            )  # fmt: skip
            registry.register(name, lambda source=source: source)
        uow = SqlTraustUnitOfWork(self.engine)
        return ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry[FeedProvider]("feed"),
            feed_sources=registry,
            objects=self.objects,
            clock=FixedClock(AT),
            advisory_cvss=self.cache,
        )

    def serve_log4shell(self) -> None:
        self.http.answers[NVD] = (FIXTURES / "nvd-CVE-2021-44228.json").read_bytes()
        self.http.answers[OSV] = (FIXTURES / "osv-GHSA-jfh8-c2jp-5v3q.json").read_bytes()

    def builds(self) -> list[UUID]:
        """Each build snapshot's artifact id, oldest first."""
        with SqlTraustUnitOfWork(self.engine) as uow:
            table = uow.feed_snapshots.table
            query = sa.select(table.c.artifact_id).where(table.c.feed == ADVISORY_CVSS_FEED)
            return list(uow.connection.scalars(query.order_by(table.c.retrieved_at)))


@pytest.fixture
def world(engine: Engine) -> World:  # noqa: F811
    return World(engine)


def test_the_document_refresh_ranks_every_authoritys_scores_by_canonical_advisory(
    world: World,
) -> None:
    canonical = advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    assert canonical.id is not None
    read = world.service().advisory_cvss([canonical.id])
    assert read.built_at == AT
    scores = read.scores[canonical.id]
    assert [s.source for s in scores][:1] == [CvssSource.NIST]  # precedence order
    assert {s.source for s in scores} >= {CvssSource.NIST, CvssSource.GHSA}
    assert all(s.acquired_at == AT for s in scores)  # each from its kept document
    nist = scores[0]
    assert (nist.score, nist.document) == (Decimal("10.0"), f"nvd:{LOG4SHELL}")


def test_an_alias_asked_reads_its_canonicals_scores_keyed_as_asked(world: World) -> None:
    canonical = advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    alias = alias_id(world.engine, LOG4SHELL)
    read = world.service().advisory_cvss([alias, canonical.id])  # type: ignore[list-item]
    assert set(read.scores) == {alias, canonical.id}
    assert read.scores[alias] == read.scores[canonical.id]  # type: ignore[index]


def test_before_the_first_build_nothing_is_scored_and_no_build_time_is_claimed(
    world: World,
) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    assert canonical.id is not None
    read = world.service().advisory_cvss([canonical.id])
    assert (dict(read.scores), read.built_at) == ({}, None)


def test_an_advisory_no_authority_scored_is_absent_and_an_unparsed_document_is_named(
    world: World,
) -> None:
    scored = advisory(world.engine, LOG4SHELL)
    bare = advisory(world.engine, "CVE-2026-0003")  # its NVD answer is `{}`: no NVD record
    finding(world.engine, scored.id)
    finding(world.engine, bare.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    build = world.service().refresh_advisory_cvss()
    assert set(build.scores) == {scored.id}
    assert build.unreadable == ("nvd:CVE-2026-0003",)
    assert bare.id is not None
    assert bare.id not in world.service().advisory_cvss([bare.id]).scores


def test_an_unchanged_day_is_one_artifact_and_a_retry_in_its_order_adds_no_build(
    world: World,
) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL).id)
    world.serve_log4shell()
    with SqlTraustUnitOfWork(world.engine) as uow:
        order = Seed(uow).run_order(asset="feeds_cache", lane=None).id
        uow.commit()
    svc = world.service()
    svc.refresh_advisory_documents(order)
    svc.refresh_advisory_cvss(order)  # the retry
    assert len(world.builds()) == 1
    svc.refresh_advisory_cvss()  # another order, the same scores: a new snapshot, one artifact
    builds = world.builds()
    assert len(builds) == 2 and len(set(builds)) == 1


def test_with_no_source_registered_the_refresh_builds_nothing(engine: Engine) -> None:  # noqa: F811
    world = World(engine, sources=())
    finding(engine, advisory(engine, LOG4SHELL).id)
    assert world.service().refresh_advisory_documents() == []
    assert world.builds() == []


def test_a_build_is_parsed_once_per_publication_across_services(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    parses = counting(monkeypatch)
    assert canonical.id is not None
    first = world.service().advisory_cvss([canonical.id])
    second = world.service().advisory_cvss([canonical.id])  # a new request's service
    assert first == second and parses() == 1
    world.http.answers[NVD] = (FIXTURES / "nvd-CVE-2026-9277.json").read_bytes()  # NVD changed
    world.service().refresh_advisory_documents()
    world.service().advisory_cvss([canonical.id])
    assert parses() == 2  # the new publication, parsed once


def test_an_unreadable_build_is_remembered_until_the_next_one() -> None:
    cache, reads = AdvisoryCvssCache(), []
    one, two = uuid4(), uuid4()

    def corrupt() -> bytes:
        reads.append(1)
        return b"not json"

    assert cache.parse(one, corrupt) is None
    assert cache.parse(one, corrupt) is None and len(reads) == 1  # never read again
    good = AdvisoryCvss(scores={}).to_bytes()
    assert cache.parse(two, lambda: good) == AdvisoryCvss(scores={})


def test_a_build_that_is_not_one_is_refused() -> None:
    with pytest.raises(ValidationError, match="not an advisory CVSS build"):
        AdvisoryCvss.from_bytes(b'{"scores": {"x": []}}')


def test_the_build_is_in_feed_freshness_once_made_and_names_the_document_refresh(
    world: World,
) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL).id)
    assert ADVISORY_CVSS_FEED not in {s.name for s in world.service().feed_statuses()}
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    [status] = [s for s in world.service().feed_statuses() if s.name == ADVISORY_CVSS_FEED]
    assert (status.fetched_at, status.max_age) == (AT, timedelta(hours=24))
    assert status.refresh == "refresh the advisory documents (refresh_advisory_documents)"
    assert not status.stale(AT + timedelta(hours=23))


def counting(monkeypatch: pytest.MonkeyPatch) -> Callable[[], int]:
    calls: list[int] = []
    real = AdvisoryCvss.from_bytes

    def parse(raw: bytes) -> AdvisoryCvss:
        calls.append(1)
        return real(raw)

    monkeypatch.setattr(AdvisoryCvss, "from_bytes", staticmethod(parse))
    return lambda: len(calls)
