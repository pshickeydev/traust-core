"""PqcService.scan_states on SQLite and Postgres: each in-scope commit's newest facts scan."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.services.test_pqc import CHECKOUT, STAMPS, World, engine, world
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.pqc import PqcFilter, PqcScanState

__all__ = ["engine", "world"]


def test_an_unscanned_commit_has_a_state_without_a_scan(world: World) -> None:
    ref = world.ref()
    assert world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,))) == [
        PqcScanState(repository_ref_id=ref)
    ]


@pytest.mark.parametrize(
    ("field", "before", "after"),
    [
        ("rules_sha256", STAMPS.rules_sha256, "cd" * 32),
        ("pqc_scan_commit", STAMPS.pqc_scan_commit, "new-commit"),
        ("binary_sha256", "11" * 32, "22" * 32),
        ("binary_sha256", None, "22" * 32),
    ],
)
def test_a_source_scan_is_current_until_its_scanner_identity_changes(
    world: World, field: str, before: str | None, after: str
) -> None:
    assert world.scanner is not None
    world.scanner.pack = world.scanner.scanned_with = STAMPS.model_copy(update={field: before})
    ref = world.ref()
    done = world.pqc.prescan(ref, CHECKOUT)
    (state,) = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert (state.assessment_id, state.basis, state.current) == (done.assessment_id, "source", True)
    world.scanner.pack = world.scanner.pack.model_copy(update={field: after})
    (stale,) = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert (stale.assessment_id, stale.current) == (done.assessment_id, False)
    world.scanner.scanned_with = world.scanner.pack
    refreshed = world.pqc.prescan(ref, CHECKOUT)
    (current,) = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert refreshed.assessment_id != done.assessment_id
    assert (current.assessment_id, current.basis, current.current) == (
        refreshed.assessment_id,
        "source",
        True,
    )


@pytest.mark.parametrize("field", ["pqc_scan_commit", "binary_sha256"])
def test_sbom_currency_ignores_scanner_metadata_but_not_its_mapping_pack(
    world: World, field: str
) -> None:
    ref = world.ref()
    done = world.pqc.prescan(ref, None)
    assert world.scanner is not None
    world.scanner.pack = STAMPS.model_copy(update={field: "cd" * 32})
    (current,) = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert (current.assessment_id, current.basis, current.current) == (
        done.assessment_id,
        "sbom-only",
        True,
    )
    world.scanner.pack = world.scanner.pack.model_copy(update={"rules_sha256": "ef" * 32})
    (stale,) = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert (stale.assessment_id, stale.basis, stale.current) == (
        done.assessment_id,
        "sbom-only",
        False,
    )


def test_without_a_scanner_currency_is_unmeasured_not_false(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    ref = world.ref()
    world.pqc.prescan(ref, CHECKOUT)
    monkeypatch.setattr(world.pqc, "_scanner", None)
    (state,) = world.pqc.scan_states(PqcFilter(repository_ref_ids=(ref,)))
    assert state.assessment_id is not None and state.current is None


def test_a_fleet_filter_lists_every_registered_commit(world: World) -> None:
    first = world.ref()
    second = world.ref(url="https://github.com/acme/other")
    world.pqc.prescan(first, CHECKOUT)
    states = {s.repository_ref_id: s for s in world.pqc.scan_states(PqcFilter())}
    assert set(states) == {first, second}
    assert states[first].assessment_id is not None and states[second].assessment_id is None


def test_an_empty_scope_has_no_states_and_an_unknown_product_is_not_found(world: World) -> None:
    assert world.pqc.scan_states(PqcFilter(repository_ref_ids=())) == []
    assert world.pqc.scan_states(PqcFilter()) == []
    with pytest.raises(NotFoundError):
        world.pqc.scan_states(PqcFilter(product_id=uuid4()))
