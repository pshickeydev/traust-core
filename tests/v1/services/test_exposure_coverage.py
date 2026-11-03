"""Manifests the SBOM tool could not resolve: recorded beside the commit's manifest SBOM, and
read so a package missing from that SBOM is unknown rather than absent (plan 28, I8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_exposure_impact import LODASH, Lookup, engine
from tests.v1.services.test_exposure_sweep import FakeSbomTool
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.dependencies import FixUptakeState, UnresolvedManifest, Version
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

__all__ = ["engine"]

NO_LODASH = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/left-pad@1.3.0"}],
     "metadata": {"tools": {"components": [{"name": "syft", "version": "1.51.1"}]}}}
).encode()  # fmt: skip


def exposure(engine: Engine) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=Lookup(LODASH),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        sbom_tool=FakeSbomTool(raw=NO_LODASH),  # type: ignore[arg-type]
    )


def checkout(root: Path, *, locked: bool) -> Path:
    (root / "ui").mkdir(parents=True)
    (root / "ui" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4"}}))
    if locked:
        (root / "ui" / "package-lock.json").write_text("{}")
    return root


def ref_id(engine: Engine):
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    return ref.id


def tool_scans(engine: Engine, ref) -> int:
    with SqlTraustUnitOfWork(engine) as uow:
        return sum(a.kind == AssessmentKind.TOOL_SCAN for a in uow.assessments.list_for_ref(ref))


def test_unresolved_manifests_are_recorded_once_beside_the_sbom(
    engine: Engine, tmp_path: Path
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    first = service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    again = service.ingest_dependencies(ref, tmp_path)
    expected = (UnresolvedManifest(ecosystem=Ecosystem.NPM, path="ui/package.json"),)  # type: ignore[arg-type]
    assert first.unresolved == again.unresolved == expected
    assert service.unresolved_manifests(ref) == expected
    assert tool_scans(engine, ref) == 1


def test_a_complete_read_records_no_unresolved_manifests(engine: Engine, tmp_path: Path) -> None:
    ref, service = ref_id(engine), exposure(engine)
    assert service.ingest_dependencies(ref, checkout(tmp_path, locked=True)).unresolved == ()
    assert service.unresolved_manifests(ref) == ()
    assert tool_scans(engine, ref) == 1


def test_an_sbom_ingested_as_a_document_knows_no_unresolved_manifests(engine: Engine) -> None:
    ref, service = ref_id(engine), exposure(engine)
    service.ingest_sbom(NO_LODASH, ref)
    assert service.unresolved_manifests(ref) == ()
    assert tool_scans(engine, ref) == 0


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
