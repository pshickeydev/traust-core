from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_pqc import PROVENANCE
from tests.v1.services.test_pqc_rules import STAMPS, hit, scan
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import PageRequest, TimeBucket, TimeWindow
from traust_core.v1.models.insight import ExecutivePanel, PqcWorklist, ViewFilter, ViewName
from traust_core.v1.models.inventory import (
    Liveness,
    Product,
    Repository,
    RepositoryFilter,
    RepositoryRef,
)
from traust_core.v1.models.pqc import (
    PqcFilter,
    PqcScan,
    PqcStamps,
    PqcWorklistRoute,
    PqcWorklistTier,
)
from traust_core.v1.models.vocabulary import ComparisonStatus, PqcReadinessBucket
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork
from traust_core.v1.services.insight import InsightService, PqcWorklistView
from traust_core.v1.services.pqc import facts as pqc_facts
from traust_core.v1.services.pqc.service import WorklistPriorityPolicy


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path / "home"), clock=FixedClock(T0))
    context.__dict__["database"] = engine
    return context


@dataclass
class Fleet:
    product: Product
    repositories: dict[str, Repository]
    refs: dict[str, RepositoryRef]


@pytest.fixture
def fleet(context: Context) -> Fleet:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        product = seed.product(slug="pqc-fixture")
        release = seed.release(product)
        repositories, refs = {}, {}
        for name in ("oauth-gateway", "transport", "alpha", "empty", "omega"):
            repository = seed.repository(url=f"https://github.com/example/{name}")
            repositories[name] = repository
            if name != "empty":
                refs[name] = seed.repository_ref(repository, sha="a" * 40, is_default=True)
        refs["gateway-other"] = seed.repository_ref(
            repositories["oauth-gateway"], sha="b" * 40, is_default=False
        )
        finding = seed.finding(repositories["transport"])
        seed.finding_cwe(finding, seed.cwe(identifier="CWE-327"))
        seed.component(release, refs["oauth-gateway"])
        seed.component(release, refs["alpha"])
        uow.commit()
    return Fleet(product, repositories, refs)


def snapshot(context: Context) -> dict[str, object]:
    with SqlTraustUnitOfWork(context.database) as uow:
        rows: dict[str, object] = {}
        for spec in CONTRACT_TABLES:
            table = uow.tables.table(spec)
            rows[table.fullname] = tuple(
                tuple(row)
                for row in uow.connection.execute(sa.select(table).order_by(*table.primary_key))
            )
    rows["objects"] = tuple(
        (str(key), context.object_store.get(context.object_store.stat(key)))
        for key in context.object_store.list()
    )
    return rows


def test_native_worklist_preserves_inventory_ranking_commit_selection_and_cursors(
    context: Context, fleet: Fleet
) -> None:
    before = snapshot(context)
    entries = context.services().pqc.worklist(PqcFilter(), chokepoints=(" OAuth-Gateway ",))
    assert [entry.repository.rsplit("/", 1)[-1] for entry in entries] == [
        "oauth-gateway",
        "transport",
        "alpha",
        "empty",
        "omega",
    ]
    assert [entry.priority_tier for entry in entries] == [
        PqcWorklistTier.CHOKEPOINT,
        PqcWorklistTier.CRYPTO_CWE,
        PqcWorklistTier.TAIL,
        PqcWorklistTier.TAIL,
        PqcWorklistTier.TAIL,
    ]
    assert len({entry.repository_id for entry in entries}) == 5
    assert entries[0].repository_ref_id == fleet.refs["oauth-gateway"].id
    assert entries[0].sha != fleet.refs["gateway-other"].sha
    assert entries[0].cursor == "0|https://github.com/example/oauth-gateway"
    assert entries[1].cursor == "1|https://github.com/example/transport"
    assert [entry.cursor for entry in entries] == sorted(entry.cursor for entry in entries)
    empty = next(
        entry for entry in entries if entry.repository_id == fleet.repositories["empty"].id
    )
    assert (empty.repository_ref_id, empty.sha, empty.scan) == (None, None, None)
    assert empty.route == PqcWorklistRoute.ACCESS_REQUEST
    assert empty.reason == "no-registered-commit"
    assert entries[0].route == PqcWorklistRoute.SOURCE
    assert entries[0].scan is not None
    assert entries[0].scan.assessment_id is None and entries[0].scan.current is None
    assert entries[0].access.observed_at is None and entries[0].access.archived is None
    assert snapshot(context) == before


def test_product_and_explicit_ref_scope_intersect_without_widening(
    context: Context, fleet: Fleet
) -> None:
    service = context.services().pqc
    assert fleet.product.id is not None
    selected = service.worklist(PqcFilter(product_id=fleet.product.id))
    assert {entry.repository_id for entry in selected} == {
        fleet.repositories["oauth-gateway"].id,
        fleet.repositories["alpha"].id,
    }
    included, excluded = fleet.refs["oauth-gateway"].id, fleet.refs["transport"].id
    assert included is not None and excluded is not None
    intersection = service.worklist(
        PqcFilter(product_id=fleet.product.id, repository_ref_ids=(included, excluded))
    )
    assert [entry.repository_ref_id for entry in intersection] == [included]
    assert service.worklist(PqcFilter(repository_ref_ids=())) == ()
    assert service.worklist(PqcFilter(product_id=fleet.product.id, repository_ref_ids=())) == ()
    other = fleet.refs["gateway-other"].id
    assert other is not None
    assert [
        entry.repository_ref_id
        for entry in service.worklist(PqcFilter(repository_ref_ids=(other,)))
    ] == [other]
    assert (
        service.worklist(PqcFilter(product_id=fleet.product.id, repository_ref_ids=(other,))) == ()
    )
    with pytest.raises(NotFoundError):
        service.worklist(PqcFilter(product_id=uuid4()))


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (ComparisonStatus.NO_CREDENTIALS, PqcWorklistRoute.ACCESS_REQUEST),
        (ComparisonStatus.UNREACHABLE, PqcWorklistRoute.SBOM_ONLY),
    ],
)
def test_routing_preserves_availability_evidence_without_reinterpreting_policy(
    context: Context,
    fleet: Fleet,
    monkeypatch: pytest.MonkeyPatch,
    status: ComparisonStatus,
    expected: PqcWorklistRoute,
) -> None:
    services = context.services()
    target = fleet.repositories["alpha"]
    assert target.id is not None and fleet.refs["alpha"].id is not None
    availability = Liveness(
        repository_id=target.id, url=target.url, unobserved=status, reason="recorded"
    )
    monkeypatch.setattr(services.portfolio, "liveness_in", lambda _: {target.id: availability})
    (entry,) = services.pqc.worklist(PqcFilter(repository_ref_ids=(fleet.refs["alpha"].id,)))
    assert (entry.route, entry.reason, entry.access.unobserved) == (expected, status.value, status)


class StampOnlyScanner:
    def __init__(self) -> None:
        self.pack = STAMPS

    def stamps(self) -> PqcStamps:
        return self.pack

    def scan(self, request: object) -> PqcScan:
        raise AssertionError("read-only worklist invoked the scanner")


def test_recorded_scan_currency_is_true_false_or_unknown_without_rescanning(
    context: Context, fleet: Fleet
) -> None:
    scanner = StampOnlyScanner()
    context.pqc_scanner = scanner
    target = fleet.refs["alpha"]
    assert target.id is not None
    raw_scan = scan(hit("API_GO_CRYPTO_RSA", "keys.go", match="2048"))
    facts = pqc_facts.source_facts(raw_scan, [])
    doc = pqc_facts.facts_document(fleet.repositories["alpha"].url, STAMPS, facts, raw_scan)
    done = context.services().pqc.record(target.id, doc, PROVENANCE)
    scope = PqcFilter(repository_ref_ids=(target.id,))
    before = snapshot(context)
    (current,) = context.services().pqc.worklist(scope)
    assert current.scan is not None
    assert (current.scan.assessment_id, current.scan.current) == (done.assessment_id, True)
    scanner.pack = STAMPS.model_copy(update={"rules_sha256": "cd" * 32})
    (stale,) = context.services().pqc.worklist(scope)
    assert stale.scan is not None and stale.scan.current is False
    context.pqc_scanner = None
    (unknown,) = context.services().pqc.worklist(scope)
    assert unknown.scan is not None and unknown.scan.current is None
    assert unknown.scan.assessment_id == done.assessment_id
    assert snapshot(context) == before


def test_registered_view_retains_scope_and_entries_and_is_read_only(
    context: Context, fleet: Fleet
) -> None:
    before = snapshot(context)
    insight = context.services().insight
    scope = ViewFilter(pqc_chokepoints=("OAuth-Gateway",))
    model = insight.build(ViewName.PQC_WORKLIST, scope)
    assert isinstance(model, PqcWorklist)
    assert model.product_id is None and model.repository_ref_ids is None
    assert model.chokepoints == ("OAuth-Gateway",)
    assert model.entries[0].repository_id == fleet.repositories["oauth-gateway"].id
    published = insight.publish(ViewName.PQC_WORKLIST, scope)
    contracts.validate_view("pqc-worklist", published.model.model_dump(mode="json"))
    assert published.csv is None
    report = insight.report(ViewName.PQC_WORKLIST, scope)
    assert report.sections[1].table is not None
    assert [row[1] for row in report.sections[1].table.rows] == [
        entry.repository for entry in model.entries
    ]
    assert snapshot(context) == before


@pytest.mark.parametrize("empty", [False, True])
def test_empty_inventory_and_explicit_empty_scope_do_not_claim_readiness(
    context: Context, empty: bool
) -> None:
    model = context.services().insight.build(
        ViewName.PQC_WORKLIST, ViewFilter(repository_ref_ids=() if empty else None)
    )
    assert isinstance(model, PqcWorklist)
    assert model.entries == ()
    assert model.repository_ref_ids == (() if empty else None)


@pytest.mark.parametrize(
    "scope",
    [
        ViewFilter(product_ids=(uuid4(), uuid4())),
        ViewFilter(as_of=T0),
        ViewFilter(window=TimeWindow(start=T0, end=T0 + timedelta(days=1))),
        ViewFilter(team_ids=(uuid4(),)),
        ViewFilter(categories=("crypto",)),
        ViewFilter(repository_id=uuid4()),
        ViewFilter(artifact_id=uuid4()),
        ViewFilter(assessment_id=uuid4()),
        ViewFilter(report_stem="report"),
        ViewFilter(compare_as_of=T0),
        ViewFilter(first_party_divisor=Decimal(2)),
        ViewFilter(executive_panels=(ExecutivePanel.PQC,)),
        ViewFilter(bucket=TimeBucket.DAY),
        ViewFilter(pqc_chokepoints=("  ",)),
    ],
)
def test_unsupported_or_blank_scope_refuses_without_writes(
    context: Context, scope: ViewFilter
) -> None:
    before = snapshot(context)
    with pytest.raises(ValidationError):
        context.services().insight.publish(ViewName.PQC_WORKLIST, scope)
    assert snapshot(context) == before


def test_unused_native_worklist_filters_are_refused(context: Context) -> None:
    with pytest.raises(ValidationError):
        context.services().pqc.worklist(PqcFilter(buckets=(PqcReadinessBucket.READY,)))


def test_other_views_cannot_ignore_worklist_parameters_and_implicit_refresh_is_compatible(
    context: Context, fleet: Fleet
) -> None:
    insight = context.services().insight
    for scope in (ViewFilter(repository_ref_ids=()), ViewFilter(pqc_chokepoints=("gateway",))):
        with pytest.raises(ValidationError):
            insight.publish(ViewName.FINDINGS_ROLLUP, scope)
    refreshed = insight.refresh(None, ViewFilter(pqc_chokepoints=("gateway",)))
    assert set(refreshed.rendered) == {ViewName.PQC_WORKLIST} and refreshed.failed == {}
    only_worklist = InsightService([PqcWorklistView(context.services().pqc)], context.clock)
    assert set(only_worklist.refresh(None, ViewFilter()).rendered) == {ViewName.PQC_WORKLIST}


def test_hostile_priority_fragments_remain_data_in_the_model_and_human_reports(
    context: Context, fleet: Fleet
) -> None:
    hostile = "<img src=x onerror=alert(1)> [docs](javascript:alert(1))\n## forged | row"
    published = context.services().insight.publish(
        ViewName.PQC_WORKLIST, ViewFilter(pqc_chokepoints=(hostile,))
    )
    assert isinstance(published.model, PqcWorklist)
    assert published.model.chokepoints == (hostile,)
    assert published.model.entries[0].priority_tier == PqcWorklistTier.CRYPTO_CWE
    contracts.validate_view("pqc-worklist", published.model.model_dump(mode="json"))
    assert "<img" not in published.markdown and "<img" not in published.html
    assert "[docs](javascript:" not in published.markdown
    assert "\n## forged" not in published.markdown


def test_one_ref_worklist_does_not_enumerate_unrelated_inventory(
    context: Context, fleet: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    services = context.services()
    target = fleet.repositories["alpha"]
    ref = fleet.refs["alpha"]
    assert target.id is not None and ref.id is not None
    expected = next(
        row
        for row in services.portfolio.liveness(RepositoryFilter(), PageRequest()).items
        if row.repository_id == target.id
    )

    def no_fleet_enumeration(*args: object, **kwargs: object) -> None:
        raise AssertionError("a one-ref request enumerated the whole repository inventory")

    monkeypatch.setattr(services.portfolio, "list_repositories", no_fleet_enumeration)
    before = snapshot(context)
    (entry,) = services.pqc.worklist(PqcFilter(repository_ref_ids=(ref.id,)))
    assert (entry.repository_id, entry.repository_ref_id, entry.access) == (
        target.id,
        ref.id,
        expected,
    )
    assert snapshot(context) == before


@pytest.mark.parametrize(
    ("repository", "chokepoints", "cwes", "expected"),
    [
        (
            "https://github.com/example/oauth",
            (" OAUTH ",),
            ("CWE-327",),
            PqcWorklistTier.CHOKEPOINT,
        ),
        (
            "https://github.com/example/other",
            ("oauth",),
            ("cwe-327: legacy",),
            PqcWorklistTier.CRYPTO_CWE,
        ),
        ("https://github.com/example/other", (), (" CWE-1240 ",), PqcWorklistTier.CRYPTO_CWE),
        ("https://github.com/example/other", (), ("CWE-79",), PqcWorklistTier.TAIL),
        ("https://github.com/example/other", (), (), PqcWorklistTier.TAIL),
    ],
)
def test_priority_policy_preserves_precedence_and_legacy_cwe_normalization(
    repository: str,
    chokepoints: tuple[str, ...],
    cwes: tuple[str, ...],
    expected: PqcWorklistTier,
) -> None:
    assert WorklistPriorityPolicy(chokepoints).tier(repository, cwes) == expected
