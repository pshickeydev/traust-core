from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from time import sleep

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from traust_core.v1.errors import ConflictError, RepositoryError
from traust_core.v1.models.records import (
    AdvisoryPackageRecord,
    AdvisoryRecord,
    ArtifactRecord,
    AssessmentRecord,
    ComponentRecord,
    CweRecord,
    DecisionRecord,
    DependencyRecord,
    EventRecord,
    FeedSnapshotRecord,
    FindingCweRecord,
    FindingRecord,
    LayerRecord,
    LocationRecord,
    OccurrenceRecord,
    OwnershipRecord,
    PackageRecord,
    ProductRecord,
    ReleaseRecord,
    RepositoryRecord,
    RepositoryRefRecord,
    ReviewItemRecord,
    RunOrderRecord,
    SbomRecord,
    SpendEventRecord,
    TeamRecord,
)
from traust_core.v1.repositories.traust.assessments import SqlAssessmentsUnitOfWork
from traust_core.v1.repositories.traust.dependencies import SqlDependenciesUnitOfWork
from traust_core.v1.repositories.traust.findings import SqlFindingsUnitOfWork
from traust_core.v1.repositories.traust.inventory import SqlInventoryUnitOfWork
from traust_core.v1.repositories.traust_ledger import SqlLedgerUnitOfWork
from traust_core.v1.repositories.traust_ops import SqlOpsUnitOfWork

T0 = datetime(2026, 10, 5, tzinfo=UTC)
SHA = "a" * 40


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@dataclass
class Scanned:
    repository: RepositoryRecord
    ref: RepositoryRefRecord
    assessment: AssessmentRecord
    finding: FindingRecord


@pytest.fixture
def scanned(engine: Engine) -> Scanned:
    with SqlInventoryUnitOfWork(engine) as inv:
        repo = inv.repositories.add(RepositoryRecord(url="https://github.com/o/r", public=True))
        assert repo.id is not None
        ref = inv.repository_refs.add(
            RepositoryRefRecord(
                repository_id=repo.id, name="main", kind="branch", is_default=True, sha=SHA
            )
        )
        inv.commit()
    assert ref.id is not None
    with SqlAssessmentsUnitOfWork(engine) as a:
        assessment = a.assessments.add(
            AssessmentRecord(
                repository_ref_id=ref.id,
                kind="audit",
                status="completed",
                assessor="skill:audit",
                assessor_version="1.0",
                occurred_at=T0,
            )
        )
        a.commit()
    with SqlFindingsUnitOfWork(engine) as f:
        finding = f.findings.add(
            FindingRecord(
                repository_id=repo.id, fingerprint_algo="v3", fingerprint="fp1", title="SQLi"
            )
        )
        f.commit()
    return Scanned(repo, ref, assessment, finding)


def test_inventory_round_trip_and_natural_keys(engine: Engine, scanned: Scanned) -> None:
    repo, ref = scanned.repository, scanned.ref
    assert repo.id is not None and ref.id is not None
    with SqlInventoryUnitOfWork(engine) as inv:
        product = inv.products.add(ProductRecord(slug="ocp", name="OpenShift"))
        assert product.id is not None
        release = inv.releases.add(ReleaseRecord(product_id=product.id, version="4.22"))
        assert release.id is not None
        component = inv.components.add(
            ComponentRecord(release_id=release.id, repository_ref_id=ref.id)
        )
        team = inv.teams.add(TeamRecord(name="core"))
        assert team.id is not None
        owned = inv.ownerships.add(
            OwnershipRecord(repository_id=repo.id, team_id=team.id, valid_from=T0)
        )
        inv.commit()

        assert inv.products.find_by_slug("ocp") == product
        assert inv.releases.find(product.id, "4.22") == release
        assert inv.components.list_for_ref(ref.id) == [component]
        assert inv.repositories.find_by_url("https://github.com/o/r") == repo
        assert inv.repository_refs.find(repo.id, "main", SHA) == ref
        assert inv.repository_refs.find(repo.id, None, SHA) is None
        assert inv.repository_refs.default(repo.id) == ref
        assert inv.teams.find_by_name("core") == team
        assert inv.ownerships.current(repo.id) == [owned]
        assert inv.ownerships.as_of(repo.id, T0 - timedelta(days=1)) == []


def test_closing_ownership_is_an_update_the_database_touches(
    engine: Engine, scanned: Scanned
) -> None:
    repo = scanned.repository
    assert repo.id is not None
    with SqlInventoryUnitOfWork(engine) as inv:
        team = inv.teams.add(TeamRecord(name="core"))
        assert team.id is not None
        owned = inv.ownerships.add(
            OwnershipRecord(repository_id=repo.id, team_id=team.id, valid_from=T0)
        )
        inv.commit()
    sleep(0.01)
    with SqlInventoryUnitOfWork(engine) as inv:
        closed = inv.ownerships.update(owned.model_copy(update={"valid_to": T0 + timedelta(1)}))
        inv.commit()
        assert inv.ownerships.current(repo.id) == []
        assert inv.ownerships.as_of(repo.id, T0) == [closed]
    assert closed.updated_at > owned.updated_at  # type: ignore[operator]


def test_duplicate_natural_key_is_a_conflict(engine: Engine, scanned: Scanned) -> None:
    with SqlInventoryUnitOfWork(engine) as inv, pytest.raises(ConflictError):
        inv.repositories.add(RepositoryRecord(url=scanned.repository.url, public=False))


def test_dependencies_trace_a_package_to_the_refs_that_ship_it(
    engine: Engine, scanned: Scanned
) -> None:
    with SqlDependenciesUnitOfWork(engine) as d:
        sbom = d.sboms.add(SbomRecord(digest="sha256:sbom"))
        package = d.packages.add(PackageRecord(ecosystem="go", name="golang.org/x/crypto"))
        assert sbom.id is not None and package.id is not None
        dep = d.dependencies.add(
            DependencyRecord(sbom_id=sbom.id, package_id=package.id, version="0.1.0", direct=True)
        )
        advisory = d.advisories.add(AdvisoryRecord(identifier="CVE-2026-0001"))
        assert advisory.id is not None
        alias = d.advisories.add(AdvisoryRecord(identifier="GHSA-x", alias_of_id=advisory.id))
        hit = d.advisory_packages.add(
            AdvisoryPackageRecord(advisory_id=advisory.id, package_id=package.id)
        )
        d.commit()

        assert d.sboms.find_by_digest("sha256:sbom") == sbom
        assert d.packages.find("go", "golang.org/x/crypto") == package
        assert d.dependencies.list_for_package(package.id) == [dep]
        assert d.advisories.list_aliases(advisory.id) == [alias]
        assert d.advisory_packages.list_for_package(package.id) == [hit]


def test_findings_chain_and_decisions_are_idempotent_by_statement(
    engine: Engine, scanned: Scanned
) -> None:
    finding, assessment = scanned.finding, scanned.assessment
    assert finding.id is not None and assessment.id is not None
    with SqlAssessmentsUnitOfWork(engine) as a:
        occurrence = a.occurrences.add(
            OccurrenceRecord(
                finding_id=finding.id,
                assessment_id=assessment.id,
                severity="high",
                cvss_score=Decimal("7.5"),
            )
        )
        assert occurrence.id is not None
        location = a.locations.add(
            LocationRecord(occurrence_id=occurrence.id, path="a.go", line_start=3, line_end=4)
        )
        artifact = a.artifacts.add(
            ArtifactRecord(assessment_id=assessment.id, digest="sha256:r", kind="report", uri="f")
        )
        a.commit()
        assert a.occurrences.list_for_assessment(assessment.id) == [occurrence]
        assert a.occurrences.find(finding.id, assessment.id) == occurrence
        assert a.locations.list_for_occurrence(occurrence.id) == [location]
        assert a.artifacts.find(assessment.id, "sha256:r") == artifact
        assert a.assessments.latest(scanned.ref.id, "audit") == assessment  # type: ignore[arg-type]

    with SqlFindingsUnitOfWork(engine) as f:
        cwe = f.cwes.add(CweRecord(identifier="CWE-89", abstraction="base"))
        assert cwe.id is not None
        f.finding_cwes.add(FindingCweRecord(finding_id=finding.id, cwe_id=cwe.id))
        decision = f.decisions.add(
            DecisionRecord(
                finding_id=finding.id,
                assessment_id=assessment.id,
                statement_key="k1",
                validity="true_positive",
                occurred_at=T0,
            )
        )
        review = f.review_items.add(
            ReviewItemRecord(finding_id=finding.id, decision_id=decision.id, status="pending")
        )
        f.commit()
        assert f.findings.find_by_fingerprint(finding.repository_id, "v3", "fp1") == finding
        assert f.finding_cwes.list_for_cwe(cwe.id) == f.finding_cwes.list_for_finding(finding.id)
        assert f.decisions.find_by_statement(finding.id, "k1") == decision
        assert f.decisions.list_since(T0 - timedelta(1), limit=10) == [decision]
        assert f.review_items.pending(limit=10) == [review]
        with pytest.raises(ConflictError):
            f.decisions.add(decision.model_copy(update={"id": None, "created_at": None}))


def test_append_only_rows_reject_mutation_in_the_database(engine: Engine, scanned: Scanned) -> None:
    with SqlAssessmentsUnitOfWork(engine) as a:
        table = a.assessments.table
        with pytest.raises((RepositoryError, ConflictError)):
            a.assessments._execute("raw update", sa.update(table).values(status="failed"))


def test_run_orders_claim_in_priority_order_and_leases_expire(
    engine: Engine, scanned: Scanned
) -> None:
    def order(priority: int) -> RunOrderRecord:
        return RunOrderRecord(
            repository_id=scanned.repository.id,
            lane="audit",
            state="queued",
            priority=priority,
            requested_by="user:me",
        )

    with SqlOpsUnitOfWork(engine) as ops:
        later = ops.run_orders.add(order(5))
        sooner = ops.run_orders.add(order(1))
        ops.commit()

        claimed = ops.run_orders.claim("w1", T0, timedelta(minutes=5))
        assert claimed is not None and claimed.id == sooner.id
        assert claimed.state == "leased" and claimed.lease_holder == "w1"
        next_claim = ops.run_orders.claim("w2", T0, timedelta(minutes=5))
        assert next_claim is not None and next_claim.id == later.id
        assert ops.run_orders.claim("w3", T0, timedelta(minutes=5)) is None

        assert ops.run_orders.release_expired(T0 + timedelta(minutes=10)) == 2
        assert ops.run_orders.claim("w4", T0, timedelta(minutes=5)).id == sooner.id  # type: ignore[union-attr]
        ops.commit()


def test_ops_spend_and_feed_snapshots(engine: Engine, scanned: Scanned) -> None:
    with SqlAssessmentsUnitOfWork(engine) as a:
        artifact = a.artifacts.add(ArtifactRecord(digest="sha256:osv", kind="feed", uri="f"))
        a.commit()
    assert artifact.id is not None
    with SqlOpsUnitOfWork(engine) as ops:
        spend = ops.spend_events.add(
            SpendEventRecord(
                provider="anthropic",
                model="m",
                tokens_in=10,
                tokens_out=5,
                cost_usd=Decimal("0.25"),
                occurred_at=T0,
            )
        )
        old = ops.feed_snapshots.add(
            FeedSnapshotRecord(artifact_id=artifact.id, feed="osv", retrieved_at=T0)
        )
        new = ops.feed_snapshots.add(
            FeedSnapshotRecord(artifact_id=artifact.id, feed="osv", retrieved_at=T0 + timedelta(1))
        )
        ops.commit()
        assert ops.spend_events.list_between(T0, T0 + timedelta(1)) == [spend]
        assert ops.feed_snapshots.latest("osv") == new != old


def test_ledger_events_prove_one_decision_each(engine: Engine, scanned: Scanned) -> None:
    finding = scanned.finding
    assert finding.id is not None and scanned.repository.id is not None
    with SqlFindingsUnitOfWork(engine) as f:
        decision = f.decisions.add(
            DecisionRecord(
                finding_id=finding.id, actor="user:me", statement_key="k", occurred_at=T0
            )
        )
        f.commit()
    assert decision.id is not None
    with SqlLedgerUnitOfWork(engine) as led:
        layer = led.layers.add(
            LayerRecord(repository_id=scanned.repository.id, merkle_signing_method="none")
        )
        assert layer.id is not None
        assert led.events.last_seq(layer.id) is None
        event = led.events.add(
            EventRecord(layer_id=layer.id, decision_id=decision.id, seq=0, event_payload=b"\x00")
        )
        led.commit()
        assert led.events.find_by_decision(decision.id) == event
        assert led.events.last_seq(layer.id) == 0
        assert led.layers.list_for_repository(scanned.repository.id) == [layer]
