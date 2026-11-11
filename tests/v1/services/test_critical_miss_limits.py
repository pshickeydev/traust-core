from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TypeVar

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_detection_quality_doors import Campaign, World
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import RecordBudget, TimeWindow
from traust_core.v1.models.detection_quality import MissReason
from traust_core.v1.models.findings import Finding, Occurrence
from traust_core.v1.models.insight import ViewFilter
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.repositories import InMemoryObjectStore, tables
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.tables import SqlTableRepository
from traust_core.v1.services import artifact_publishing, detection_quality
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpecs
from traust_core.v1.services.detection_quality import DetectionQualityService
from traust_core.v1.services.insight import CriticalMissesView

DAY = timedelta(days=1)
WINDOW = TimeWindow(start=T0 + 2 * DAY, end=T0 + 3 * DAY)
M = TypeVar("M", bound=Model)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def materialized(monkeypatch: pytest.MonkeyPatch) -> Counter[str]:
    counts: Counter[str] = Counter()
    original = SqlTableRepository._to_record

    def counted(repository: SqlTableRepository[M], row: Mapping[str, object] | M) -> M:
        counts[repository.spec.name] += 1
        return original(repository, row)

    monkeypatch.setattr(SqlTableRepository, "_to_record", counted)
    return counts


@dataclass
class Workload:
    uow: SqlTraustUnitOfWork
    seed: Seed
    repository: Repository
    ref: RepositoryRef
    audit: Assessment
    found: Assessment
    finding: Finding
    occurrence: Occurrence
    service: DetectionQualityService


@pytest.fixture
def workload(engine: Engine) -> Workload:
    uow = SqlTraustUnitOfWork(engine)
    seed = Seed(uow)
    with uow:
        repository = seed.repository()
        ref = seed.repository_ref(repository)
        audit = seed.assessment(ref, kind=AssessmentKind.SECURE_CODE, occurred_at=T0)
        found = seed.assessment(ref, kind=AssessmentKind.SCANNER, occurred_at=WINDOW.start)
        finding = seed.finding(repository)
        occurrence = seed.occurrence(finding, found, severity="critical")
        seed.location(occurrence, path="pkg/missed.go")
        uow.commit()
    publisher = ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow)
    return Workload(
        uow,
        seed,
        repository,
        ref,
        audit,
        found,
        finding,
        occurrence,
        DetectionQualityService(uow, finding_service(engine), publisher),
    )


def test_small_budget_preserves_canonical_population_order_and_native_provenance(
    engine: Engine,
) -> None:
    uow = SqlTraustUnitOfWork(engine)
    publisher = ArtifactPublisher(PublishSpecs(), InMemoryObjectStore(), uow)
    campaign = Campaign(World(engine, uow, publisher)).build()
    service = campaign.world.service()
    expected = service.critical_misses(WINDOW)
    actual = service.critical_misses(WINDOW, max_records=200)
    assert actual == expected
    assert {row.title: row.reason for row in actual} == {
        "area": MissReason.AREA_REPORTED,
        "missed": MissReason.MISSED,
        "benchmark-first": MissReason.MISSED,
    }
    assert {(row.found_by, row.missed_by, row.found_at) for row in actual} == {
        (campaign.ids["later"], campaign.ids["audit"], WINDOW.start)
    }
    assert {row.finding_id for row in actual} == {
        campaign.ids[name] for name in ("area", "missed", "benchmark-first")
    }


@pytest.mark.parametrize("max_records", [0, -1])
def test_invalid_budget_is_rejected_before_reading(
    workload: Workload, materialized: Counter[str], max_records: int
) -> None:
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=max_records)
    assert not materialized


def test_dense_window_stops_paged_assessments_before_occurrence_reads(
    workload: Workload, monkeypatch: pytest.MonkeyPatch, materialized: Counter[str]
) -> None:
    with workload.uow:
        for _ in range(12):
            workload.seed.assessment(workload.ref, occurred_at=WINDOW.start)
        workload.uow.commit()
    materialized.clear()
    monkeypatch.setattr(artifact_publishing, "_BATCH", 3)
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=8)
    assert materialized == {"assessment": 9}


def test_one_dense_assessment_stops_before_finding_context(
    workload: Workload, materialized: Counter[str]
) -> None:
    with workload.uow:
        for _ in range(20):
            workload.seed.occurrence(
                workload.seed.finding(workload.repository), workload.found, severity="critical"
            )
        workload.uow.commit()
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=8)
    assert materialized == {"assessment": 1, "occurrence": 8}


def test_historical_occurrences_stop_before_historical_assessments_or_rich_views(
    workload: Workload, materialized: Counter[str]
) -> None:
    with workload.uow:
        for n in range(20):
            historical = workload.seed.assessment(
                workload.ref, kind=AssessmentKind.BENCHMARK_AUDIT, occurred_at=T0 - n * DAY
            )
            workload.seed.occurrence(workload.finding, historical, severity="critical")
        workload.uow.commit()
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=8)
    assert materialized == {"assessment": 1, "occurrence": 8}


@pytest.mark.parametrize("related", ["decisions", "cwes", "labels", "refs", "locations"])
def test_dense_related_context_shares_the_input_budget_and_never_returns_partial_misses(
    workload: Workload, materialized: Counter[str], related: str
) -> None:
    with workload.uow:
        for n in range(20):
            if related == "decisions":
                workload.seed.decision(workload.finding, validity="confirmed")
            elif related == "cwes":
                workload.seed.finding_cwe(workload.finding)
            elif related == "labels":
                workload.seed.finding_label(workload.finding, label=f"T{n + 1000}")
            elif related == "refs":
                workload.seed.repository_ref(workload.repository, sha=f"{n + 1:040x}")
            else:
                workload.seed.location(workload.occurrence, path=f"pkg/{n}.go")
        workload.uow.commit()
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=10)
    assert sum(materialized.values()) == 11
    if related != "locations":
        assert materialized["location"] == 0
    if related == "cwes":
        assert materialized["cwe"] == 0
    assert materialized["finding"] == 1


def test_historical_baseline_assessments_are_bounded_before_inventory_or_locations(
    workload: Workload, materialized: Counter[str]
) -> None:
    with workload.uow:
        for n in range(8):
            baseline = workload.seed.assessment(
                workload.ref, kind=AssessmentKind.SECURE_CODE, occurred_at=T0 - (n + 1) * DAY
            )
            assessed = workload.seed.assessment(
                workload.ref,
                baseline_assessment_id=baseline.id,
                occurred_at=T0,
            )
            workload.seed.decision(
                workload.finding, assessment_id=assessed.id, actor=None, validity="confirmed"
            )
        workload.uow.commit()
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=25)
    assert sum(materialized.values()) == 26
    assert materialized["repository_ref"] == materialized["location"] == 0


def test_historical_audit_context_is_bounded_before_loading_its_reported_paths(
    workload: Workload, materialized: Counter[str]
) -> None:
    with workload.uow:
        for n in range(20):
            workload.seed.assessment(
                workload.ref, kind=AssessmentKind.SECURE_CODE, occurred_at=T0 - n * DAY
            )
        workload.uow.commit()
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=15)
    assert sum(materialized.values()) == 16
    assert materialized["occurrence"] == 3
    assert materialized["location"] == 1


def test_a_prior_audits_dense_path_context_is_bounded(
    workload: Workload, materialized: Counter[str]
) -> None:
    with workload.uow:
        occurrence = workload.seed.occurrence(
            workload.seed.finding(workload.repository), workload.audit
        )
        for n in range(20):
            workload.seed.location(occurrence, path=f"pkg/{n}.go")
        workload.uow.commit()
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=15)
    assert sum(materialized.values()) == 16
    assert materialized["occurrence"] == 4
    assert materialized["location"] == 5


def test_batches_consume_one_budget_instead_of_resetting_it(
    workload: Workload, materialized: Counter[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    with workload.uow:
        findings = [workload.seed.finding(workload.repository) for _ in range(8)]
        workload.uow.commit()
    ids = [finding.id for finding in findings if finding.id is not None]
    materialized.clear()
    monkeypatch.setattr(tables, "_BATCH", 3)
    with workload.uow as uow, pytest.raises(ValidationError):
        uow.findings.list_by_ids(ids, read_budget=RecordBudget(5, "critical misses"))
    assert materialized == {"finding": 6}


def test_exact_budget_returns_the_complete_native_result(
    workload: Workload, materialized: Counter[str]
) -> None:
    expected = workload.service.critical_misses(WINDOW)
    exact = sum(materialized.values())
    materialized.clear()
    assert workload.service.critical_misses(WINDOW, max_records=exact) == expected
    assert sum(materialized.values()) == exact
    materialized.clear()
    with pytest.raises(ValidationError):
        workload.service.critical_misses(WINDOW, max_records=exact - 1)
    assert sum(materialized.values()) == exact


def test_insight_propagates_native_overflow_without_returning_a_partial_model(
    workload: Workload, monkeypatch: pytest.MonkeyPatch, materialized: Counter[str]
) -> None:
    class SmallBudget(RecordBudget):
        def __init__(self, max_records: int, workload: str) -> None:
            super().__init__(min(max_records, 8), workload)

    with workload.uow:
        for _ in range(20):
            workload.seed.occurrence(workload.seed.finding(workload.repository), workload.found)
        workload.uow.commit()
    materialized.clear()
    monkeypatch.setattr(detection_quality, "RecordBudget", SmallBudget)
    with pytest.raises(ValidationError):
        CriticalMissesView(workload.service).build(ViewFilter(window=WINDOW))
    assert materialized == {"assessment": 1, "occurrence": 8}
