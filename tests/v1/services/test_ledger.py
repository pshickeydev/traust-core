"""LedgerService on SQLite and Postgres: append in the decision's transaction, restamp and
sign like traust-ledger's write path, verify detects tampering."""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConflictError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.findings import Decision
from traust_core.v1.models.ledger import Event, Signing
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.ledger import LedgerConfig, LedgerService


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """A throwaway cosign keypair (cosign reads the empty password from the environment)."""
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    prefix = tmp_path / "ledger"
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
        check=True,
        capture_output=True,
    )
    return f"{prefix}.key", f"{prefix}.pub"


def ledger(uow: SqlTraustUnitOfWork, **config: object) -> LedgerService:
    return LedgerService(uow, LedgerConfig.model_validate(config))


def decisions(engine: Engine, n: int) -> tuple[UUID, list[Decision]]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo, made = seed.repository(), [seed.decision() for _ in range(n)]
        uow.commit()
    assert repo.id is not None
    return repo.id, made


def tamper(engine: Engine, change: Callable[[sa.Table, sa.Table], sa.Executable]) -> None:
    """Change ledger rows behind the app's back, append-only triggers off (this test's own db)."""
    with SqlTraustUnitOfWork(engine) as uow:
        conn = uow.connection
        if conn.dialect.name == "postgresql":
            conn.execute(sa.text("ALTER TABLE traust_ledger.events DISABLE TRIGGER USER"))
        else:
            conn.execute(sa.text("DROP TRIGGER IF EXISTS ledger_events_reject_update"))
            conn.execute(sa.text("DROP TRIGGER IF EXISTS ledger_events_reject_delete"))
        conn.execute(change(uow.events.table, uow.layers.table))
        uow.commit()


def test_first_append_opens_the_repository_layer_and_stamps_it(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    receipt = ledger(SqlTraustUnitOfWork(engine)).append_decision(decision, repo_id)
    layer = receipt.checkpoint.layer
    assert (layer.repository_id, layer.line, layer.merkle_signing_method) == (
        repo_id,
        None,
        "keypair",
    )
    assert (layer.merkle_size, layer.merkle_epoch, layer.merkle_root_signature) == (1, 0, None)
    assert receipt.event.seq == 0
    assert receipt.event.decision_id == decision.id
    assert (receipt.checkpoint.signing, receipt.checkpoint.warning) == (Signing.UNCONFIGURED, None)


def test_appends_take_the_next_seq_and_advance_the_root(engine: Engine) -> None:
    repo_id, made = decisions(engine, 3)
    service = ledger(SqlTraustUnitOfWork(engine))
    receipts = [service.append_decision(d, repo_id) for d in made]
    assert [r.event.seq for r in receipts] == [0, 1, 2]
    assert len({r.checkpoint.layer.merkle_root for r in receipts}) == 3
    assert len({r.checkpoint.layer.id for r in receipts}) == 1
    final = receipts[-1].checkpoint.layer
    assert final.merkle_size == 3
    assert final.id is not None
    assert service.verify(final.id).passed


def test_append_is_idempotent_per_decision(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    service = ledger(SqlTraustUnitOfWork(engine))
    first = service.append_decision(decision, repo_id)
    again = service.append_decision(decision, repo_id)
    assert again.event == first.event
    assert again.checkpoint.layer.merkle_root == first.checkpoint.layer.merkle_root
    assert again.checkpoint.layer.merkle_size == 1


def test_an_unsaved_decision_is_rejected(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    with pytest.raises(ValidationError, match="saved decision"):
        ledger(SqlTraustUnitOfWork(engine)).append_decision(
            decision.model_copy(update={"id": None}), repo_id
        )


@pytest.mark.parametrize("commit", [False, True])
def test_append_joins_the_callers_transaction(engine: Engine, commit: bool) -> None:
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        seed = Seed(uow)
        repo, decision = seed.repository(), seed.decision()
        assert repo.id is not None and decision.id is not None
        ledger(uow).append_decision(decision, repo.id)  # its commit waits for ours
        if commit:
            uow.commit()
    with SqlTraustUnitOfWork(engine) as check:
        proof = check.events.find_by_decision(decision.id)
        layer = check.layers.find_for_update(repo.id)
    assert (proof is not None, layer is not None) == (commit, commit)


def test_a_racing_first_append_is_rejected_not_a_second_chain(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite serialises writers; concurrency is a Postgres property")
    repo_id, (first, second) = decisions(engine, 2)
    outcome: list[object] = []

    def racer() -> None:
        try:
            outcome.append(ledger(SqlTraustUnitOfWork(engine)).append_decision(second, repo_id))
        except ConflictError as e:
            outcome.append(e)

    holder = SqlTraustUnitOfWork(engine)
    with holder:
        ledger(holder).append_decision(first, repo_id)  # layer created, not yet committed
        thread = threading.Thread(target=racer)
        thread.start()
        thread.join(timeout=0.3)  # the racer can't see our layer, so it inserts its own
        holder.commit()
    thread.join()
    assert isinstance(outcome[0], ConflictError)  # the layer key made it wait, then refused
    with SqlTraustUnitOfWork(engine) as uow:
        assert len(uow.layers.list_for_repository(repo_id)) == 1


def test_verify_detects_a_tampered_event(engine: Engine) -> None:
    repo_id, made = decisions(engine, 3)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = [service.append_decision(d, repo_id) for d in made][-1].checkpoint.layer
    assert layer.id is not None
    tamper(
        engine,
        lambda events, _: (
            sa.update(events)
            .where(events.c.seq == 1)
            .values(event_payload=b'{"validity":"false_positive"}')
        ),
    )
    result = service.verify(layer.id)
    assert not result.passed
    assert any("merkle_root mismatch" in e for e in result.errors)


def test_verify_detects_a_removed_event(engine: Engine) -> None:
    repo_id, made = decisions(engine, 2)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = [service.append_decision(d, repo_id) for d in made][-1].checkpoint.layer
    assert layer.id is not None
    tamper(engine, lambda events, _: sa.delete(events).where(events.c.seq == 0))
    errors = service.verify(layer.id).errors
    assert any("merkle_root mismatch" in e for e in errors)
    assert any("merkle_size mismatch" in e for e in errors)


def test_verify_detects_a_forged_event(engine: Engine) -> None:
    repo_id, (real, forged) = decisions(engine, 2)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = service.append_decision(real, repo_id).checkpoint.layer
    assert layer.id is not None
    with SqlTraustUnitOfWork(engine) as uow:  # append-only allows inserts; only the app restamps
        uow.events.add(Event(layer_id=layer.id, decision_id=forged.id, seq=1, event_payload=b"{}"))
        uow.commit()
    assert any("merkle_root mismatch" in e for e in service.verify(layer.id).errors)


def test_verify_detects_an_edited_root(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    service = ledger(SqlTraustUnitOfWork(engine))
    layer = service.append_decision(decision, repo_id).checkpoint.layer
    assert layer.id is not None
    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_root="00" * 32))
    assert any("merkle_root mismatch" in e for e in service.verify(layer.id).errors)


def test_an_unsigned_layer_fails_verify_when_signing_is_required(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    layer = ledger(SqlTraustUnitOfWork(engine)).append_decision(decision, repo_id).checkpoint.layer
    assert layer.id is not None
    result = ledger(SqlTraustUnitOfWork(engine), required=True).verify(layer.id)
    assert any("absent" in e for e in result.errors)


def test_verify_an_unknown_layer_raises(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        ledger(SqlTraustUnitOfWork(engine)).verify(uuid4())


def test_a_signed_root_verifies_with_the_public_key(engine: Engine, keys: tuple[str, str]) -> None:
    private, public = keys
    repo_id, made = decisions(engine, 2)
    service = ledger(
        SqlTraustUnitOfWork(engine),
        key_path=private,
        public_key_path=public,
    )
    checkpoint = [service.append_decision(d, repo_id) for d in made][-1].checkpoint
    layer = checkpoint.layer
    assert (checkpoint.signing, checkpoint.warning) == (Signing.SIGNED, None)
    assert layer.merkle_root_signature
    assert layer.merkle_signature_format == 4
    assert layer.id is not None
    assert service.verify(layer.id).passed

    tamper(engine, lambda _, layers: sa.update(layers).values(merkle_root_signature="AAAA"))
    assert service.verify(layer.id).errors  # the root still matches; the signature doesn't

    tamper(engine, lambda events, _: sa.update(events).values(event_payload=b"{}"))
    assert not service.verify(layer.id).passed


def test_a_signed_layer_without_the_public_key_does_not_pass(
    engine: Engine, keys: tuple[str, str]
) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    signer = ledger(SqlTraustUnitOfWork(engine), key_path=keys[0])
    layer = signer.append_decision(decision, repo_id).checkpoint.layer
    assert layer.id is not None
    result = signer.verify(layer.id)
    assert (result.errors, result.passed) == ((), False)
    assert any("no public key" in w for w in result.warnings)


def test_an_unsigned_append_drops_the_stale_signature(
    engine: Engine, keys: tuple[str, str]
) -> None:
    repo_id, (first, second) = decisions(engine, 2)
    signed = ledger(SqlTraustUnitOfWork(engine), key_path=keys[0])
    signed.append_decision(first, repo_id)
    checkpoint = ledger(SqlTraustUnitOfWork(engine)).append_decision(second, repo_id).checkpoint
    assert checkpoint.signing is Signing.UNCONFIGURED
    assert checkpoint.layer.merkle_root_signature is None
    assert checkpoint.warning is not None and "UNSIGNED" in checkpoint.warning


def test_required_signing_without_a_key_rolls_the_append_back(engine: Engine) -> None:
    repo_id, (decision,) = decisions(engine, 1)
    assert decision.id is not None
    with pytest.raises(ServiceError, match="not signed"):
        ledger(SqlTraustUnitOfWork(engine), required=True).append_decision(decision, repo_id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.events.find_by_decision(decision.id) is None
        assert uow.layers.find_for_update(repo_id) is None


def test_checkpoint_signs_an_existing_layer(engine: Engine, keys: tuple[str, str]) -> None:
    private, public = keys
    repo_id, (decision,) = decisions(engine, 1)
    unsigned = ledger(SqlTraustUnitOfWork(engine)).append_decision(decision, repo_id)
    signer = ledger(
        SqlTraustUnitOfWork(engine),
        key_path=private,
        public_key_path=public,
    )
    checkpoint = signer.checkpoint(repo_id)
    assert checkpoint.signing is Signing.SIGNED
    assert checkpoint.layer.merkle_root == unsigned.checkpoint.layer.merkle_root
    assert checkpoint.layer.id is not None
    assert signer.verify(checkpoint.layer.id).passed


def test_checkpoint_without_a_layer_raises(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        ledger(SqlTraustUnitOfWork(engine)).checkpoint(uuid4())
