"""Manifests the SBOM tool could not resolve: recorded beside the commit's manifest SBOM, and
read so a package missing from that SBOM is unknown rather than absent (plan 28, I8)."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_exposure_impact import LODASH, Lookup, engine
from tests.v1.services.test_exposure_sweep import FakeSbomTool
from traust_core.v1.errors import IntegrityError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    FixUptakeState,
    UnresolvedManifest,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem, ManifestCoverageReason
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import stored_bytes
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

__all__ = ["engine"]

NO_LODASH = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/left-pad@1.3.0"}],
     "metadata": {"tools": {"components": [{"name": "syft", "version": "1.51.1"}]}}}
).encode()  # fmt: skip


def exposure(
    engine: Engine, tool: FakeSbomTool | None = None, *records: AdvisoryRecord
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=Lookup(*(records or (LODASH,))),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        sbom_tool=tool or FakeSbomTool(raw=NO_LODASH),  # type: ignore[arg-type]
    )


def checkout(root: Path, *, locked: bool) -> Path:
    (root / "ui").mkdir(parents=True)
    (root / "ui" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4"}}))
    if locked:
        (root / "ui" / "package-lock.json").write_text('{"lockfileVersion": 3}')
    return root


def ref_id(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    return ref.id


def coverage_runs(engine: Engine, ref: UUID) -> int:
    with SqlTraustUnitOfWork(engine) as uow:
        runs = uow.assessments.list_for_ref(ref)
    assert not [a for a in runs if a.kind == AssessmentKind.TOOL_SCAN]  # code-facts' kind
    return sum(a.kind == AssessmentKind.MANIFEST_SBOM for a in runs)


def test_each_scan_records_its_coverage_bound_to_its_sbom_and_itself(
    engine: Engine, tmp_path: Path
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    first = service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    again = service.ingest_dependencies(ref, tmp_path)
    expected = (
        UnresolvedManifest(
            ecosystem=Ecosystem.NPM,
            path="ui/package.json",  # type: ignore[arg-type]
            reason=ManifestCoverageReason.NO_LOCKFILE,
        ),
    )
    assert first.unresolved == again.unresolved == expected
    assert first.sbom.id == again.sbom.id
    assert service.unresolved_manifests(ref) == expected
    assert coverage_runs(engine, ref) == 2
    with SqlTraustUnitOfWork(engine) as uow:
        current = uow.repository_refs.get(ref)
        scans = [a for a in uow.assessments.list_for_ref(ref)]
        [artifact] = uow.artifacts.list_for_assessment(current.manifest_sbom_assessment_id)
    assert current.manifest_sbom_assessment_id == max(scans, key=lambda a: a.created_at).id
    doc = json.loads(stored_bytes(service._objects, artifact))
    assert doc["sbom_id"] == str(first.sbom.id)
    assert doc["assessment_id"] == str(current.manifest_sbom_assessment_id)
    assert doc["unresolved"] == {"npm": {"ui/package.json": "no-lockfile"}}


def test_a_complete_read_records_no_unresolved_manifests(engine: Engine, tmp_path: Path) -> None:
    ref, service = ref_id(engine), exposure(engine)
    assert service.ingest_dependencies(ref, checkout(tmp_path, locked=True)).unresolved == ()
    assert service.unresolved_manifests(ref) == ()
    assert coverage_runs(engine, ref) == 1


def test_an_sbom_ingested_as_a_document_leaves_coverage_unknown(
    engine: Engine, tmp_path: Path
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    service.ingest_sbom(NO_LODASH, ref)
    assert service.unresolved_manifests(ref) is None
    assert coverage_runs(engine, ref) == 0
    service.ingest_dependencies(ref, checkout(tmp_path, locked=True))
    assert service.unresolved_manifests(ref) == ()
    service.ingest_sbom(NO_LODASH, ref)  # the same package list: the scan pointer still clears
    assert service.unresolved_manifests(ref) is None


def test_coverage_bound_to_another_sbom_or_scan_is_refused(engine: Engine, tmp_path: Path) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        mine = seed.repository_ref()
        theirs = seed.repository_ref(seed.repository(url="https://github.com/org/other"))
        uow.commit()
    assert mine.id is not None and theirs.id is not None
    ref, other, service = mine.id, theirs.id, exposure(engine)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=True))
    service.ingest_dependencies(other, tmp_path)
    with SqlTraustUnitOfWork(engine) as uow:
        current = uow.repository_refs.get(ref)
        stranger = uow.repository_refs.get(other).manifest_sbom_assessment_id
        uow.repository_refs.update(
            current.model_copy(update={"manifest_sbom_assessment_id": stranger})
        )
        uow.commit()
    with pytest.raises(IntegrityError, match="bound to"):
        service.unresolved_manifests(ref)


@pytest.mark.parametrize(
    ("locked", "depends", "classification", "uptake"),
    [
        (False, None, "inconclusive", FixUptakeState.NOT_OBSERVED),
        (True, False, "not_imported", FixUptakeState.MODULE_ABSENT),
    ],
)
def test_a_package_missing_beside_an_unresolved_manifest_is_unknown(
    engine: Engine,
    tmp_path: Path,
    locked: bool,
    depends: bool | None,
    classification: str,
    uptake: FixUptakeState,
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=locked))
    found = service.find_advisory(LODASH.identifier)
    assert found is not None and found.advisory_id is not None
    prepared = service.prepare(found.advisory_id, ref)
    assert prepared.evidence.l1_depends_on is depends
    assert prepared.document("1").repos[0].classification == classification
    assert ("ui/package.json" in (prepared.evidence.notes or "")) is not locked
    fix = service.consumes_fix(ref, Ecosystem.NPM, "lodash", Version("4.17.21"))
    assert fix.state == uptake


def test_a_failed_ingest_records_nothing_and_is_retried_whole(
    engine: Engine, tmp_path: Path
) -> None:
    ref, tool = ref_id(engine), FakeSbomTool(raw=b"not json")
    service = exposure(engine, tool)
    with pytest.raises(ValidationError):
        service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(ref).manifest_sbom_id is None
    tool.raw = NO_LODASH
    service.ingest_dependencies(ref, tmp_path)
    assert coverage_runs(engine, ref) == 1
    assert [m.path for m in service.unresolved_manifests(ref)] == ["ui/package.json"]


def test_coverage_that_changes_back_is_read_as_it_is_now(engine: Engine, tmp_path: Path) -> None:
    ref, service = ref_id(engine), exposure(engine)
    root = checkout(tmp_path, locked=False)
    service.ingest_dependencies(ref, root)
    lock = root / "ui" / "package-lock.json"
    lock.write_text('{"lockfileVersion": 3}')
    service.ingest_dependencies(ref, root)
    lock.unlink()
    service.ingest_dependencies(ref, root)
    assert [m.path for m in service.unresolved_manifests(ref)] == ["ui/package.json"]
    assert coverage_runs(engine, ref) == 3


def test_any_of_an_advisorys_ecosystems_left_unresolved_makes_it_unknown(
    engine: Engine, tmp_path: Path
) -> None:
    both = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GHSA-aaaa-bbbb-cccc"),
        source="osv",
        affected=tuple(
            AffectedPackage(
                ecosystem=e,
                name=n,
                spans=(AffectedSpan(introduced=Version("0"), fixed=Version("9.0.0")),),
            )
            for e, n in ((Ecosystem.PYPI, "requests"), (Ecosystem.NPM, "lodash"))
        ),
    )
    ref, service = ref_id(engine), exposure(engine, None, both)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    found = service.find_advisory(both.identifier)
    assert found is not None and found.advisory_id is not None
    assert service.prepare(found.advisory_id, ref).evidence.l1_depends_on is None


def test_the_fleet_sweep_keeps_an_sbom_given_as_a_document(engine: Engine) -> None:
    ref, service = ref_id(engine), exposure(engine)
    kept = service.ingest_sbom(NO_LODASH, ref)
    assert service.record_manifest_sbom(ref) == kept  # no checkout wired: nothing fetched
    assert service.unresolved_manifests(ref) is None
