from __future__ import annotations

from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_pqc import CHECKOUT, URL, FakeScanner, World
from tests.v1.services.test_pqc import engine as engine
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.pqc import PqcService


def test_scan_states_include_unscanned_registered_commits_without_running_a_scanner(
    engine: Engine,
) -> None:
    scanner = FakeScanner()
    world = World(engine, scanner)
    scanned = world.ref()
    missing = world.ref(url=f"{URL}-missing", sbom=None)
    saved = world.pqc.prescan(scanned, CHECKOUT)
    states = {row.repository_ref_id: row for row in world.pqc.scan_states(PqcFilter())}
    assert set(states) == {scanned, missing}
    assert states[scanned].assessment_id == saved.assessment_id
    assert (states[scanned].basis, states[scanned].current) == ("source", True)
    assert (states[missing].assessment_id, states[missing].basis, states[missing].current) == (
        None,
        None,
        None,
    )
    assert scanner.scans == 1
    assert world.pqc.list_readiness(PqcFilter()) == []
    assert world.pqc.scan_states(PqcFilter(repository_ref_ids=())) == []


def test_scan_states_distinguish_stale_pack_from_unmeasured_freshness(engine: Engine) -> None:
    scanner = FakeScanner()
    world = World(engine, scanner)
    ref = world.ref()
    saved = world.pqc.prescan(ref, None)
    [current] = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert (current.assessment_id, current.basis, current.current) == (
        saved.assessment_id,
        "sbom-only",
        True,
    )
    scanner.pack = scanner.pack.model_copy(update={"rules_sha256": "cd" * 32})
    [stale] = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert stale.current is False
    without_scanner = PqcService(
        SqlTraustUnitOfWork(engine),
        world.code_facts,
        world.portfolio,
        world.publisher,
    )
    [unmeasured] = without_scanner.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert (unmeasured.assessment_id, unmeasured.basis, unmeasured.current) == (
        saved.assessment_id,
        "sbom-only",
        None,
    )
    assert scanner.scans == 0


def test_scan_states_intersect_product_membership_and_requested_commits(engine: Engine) -> None:
    world = World(engine, None)
    included = world.ref()
    excluded = world.ref(url=f"{URL}-other")
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product = seed.product()
        seed.component(seed.release(product), uow.repository_refs.get(included))
        uow.commit()
    assert product.id is not None
    assert [
        state.repository_ref_id for state in world.pqc.scan_states(PqcFilter(product_id=product.id))
    ] == [included]
    assert (
        world.pqc.scan_states(PqcFilter(product_id=product.id, repository_ref_ids=(excluded,)))
        == []
    )
