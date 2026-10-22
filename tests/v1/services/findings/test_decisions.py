"""Restatement on SQLite and Postgres, ported from traust-ledger's restatement gates and tests."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.findings import Decision, Disposition, Restatement
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint

NOW = datetime(2026, 10, 23, 9, tzinfo=UTC)
ADMIN = Principal(
    identity="admin@example.com",
    kind=ActorKind.HUMAN,
    display="Admin",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN, Role.RESTATE}),
)
AUTHORITY: dict[str, Any] = {
    "reason": "data_error",
    "ticket": "SEC-42",
    "rationale": "the triage misread the sink",
}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(engine: Engine, approvers: int = 0, ledger: bool = False) -> FindingDecisions:
    uow = SqlTraustUnitOfWork(engine)
    chain = LedgerService(uow, LedgerConfig()) if ledger else None
    return FindingDecisions(
        uow, chain, Lint({}), clock=FixedClock(NOW), restatement_approvers=approvers
    )


def seeded(engine: Engine, **kw: Any) -> Decision:
    with SqlTraustUnitOfWork(engine) as uow:
        made = Seed(uow).decision(
            actor="human:analyst@example.com", validity="confirmed", severity="high", **kw
        )
        uow.commit()
    return made


def correct(decision: Decision, **kw: Any) -> Restatement:
    return Restatement(decision_id=decision.id, **{**AUTHORITY, "validity": "false_positive", **kw})


def history(engine: Engine, decision: Decision) -> list[Decision]:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.decisions.list_for_finding(decision.finding_id)


def test_a_restatement_replaces_the_decision_with_its_authority(engine: Engine) -> None:
    wrong = seeded(engine)
    fixed = service(engine).restate(correct(wrong), ADMIN)
    assert (fixed.restates_id, fixed.actor, fixed.ticket, fixed.reason, fixed.occurred_at) == (
        wrong.id,
        "human:admin@example.com",
        "SEC-42",
        "data_error",
        NOW,
    )
    assert (fixed.validity, fixed.severity) == ("false_positive", "high")
    assert history(engine, wrong) == [wrong, fixed]
    folded = Disposition.fold(wrong.finding_id, history(engine, wrong))
    assert (folded.validity, folded.conflict) == ("false_positive", False)


def test_restating_an_assessors_decision_judges_its_commit(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        assessment = seed.assessment()
        wrong = seed.decision(actor=None, assessment_id=assessment.id, validity="confirmed")
        uow.commit()
    fixed = service(engine).restate(correct(wrong), ADMIN)
    assert (fixed.assessment_id, fixed.repository_ref_id) == (None, assessment.repository_ref_id)


def test_named_approvers_are_kept_and_the_author_is_not_one(engine: Engine) -> None:
    wrong = seeded(engine)
    approvers = (" Bob@Example.com ", "admin@example.com", "carol@example.com", "")
    fixed = service(engine, approvers=2).restate(correct(wrong, approvers=approvers), ADMIN)
    with SqlTraustUnitOfWork(engine) as uow:
        kept = sorted(a.approver for a in uow.decision_approvers.list_for_decision(fixed.id))
    assert kept == ["human:bob@example.com", "human:carol@example.com"]


def test_too_few_independent_approvers_is_refused(engine: Engine) -> None:
    wrong = seeded(engine)
    restatement = correct(wrong, approvers=("admin@example.com", "bob@example.com"))
    with pytest.raises(ForbiddenError, match="needs 2 approvers besides its author; it names 1"):
        service(engine, approvers=2).restate(restatement, ADMIN)
    assert history(engine, wrong) == [wrong]


@pytest.mark.parametrize(
    ("who", "reason"),
    [
        (ADMIN.model_copy(update={"verified_by": None}), "verified human"),
        (ADMIN.model_copy(update={"roles": frozenset()}), "restate role"),
        (ADMIN.model_copy(update={"kind": ActorKind.MACHINE}), "verified human"),
    ],
    ids=["unverified", "not an admin", "a machine"],
)
def test_only_a_verified_admin_restates(engine: Engine, who: Principal, reason: str) -> None:
    wrong = seeded(engine)
    with pytest.raises(ForbiddenError, match=reason):
        service(engine).restate(correct(wrong), who)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"ticket": "  "}, "ticket"),
        ({"rationale": "too short"}, "10 characters"),
        ({"validity": None}, "corrects at least one"),
        ({"validity": "confirmed"}, "changes nothing"),
        ({"resolution": "resolved"}, "nothing to restate"),
    ],
    ids=["no ticket", "short rationale", "no change", "same value", "first value"],
)
def test_a_restatement_must_be_a_real_attributed_correction(
    engine: Engine, change: dict[str, Any], reason: str
) -> None:
    wrong = seeded(engine)
    with pytest.raises(ValidationError, match=reason):
        service(engine).restate(correct(wrong, **change), ADMIN)
    assert history(engine, wrong) == [wrong]


def test_a_stale_restatement_is_refused(engine: Engine) -> None:
    wrong = seeded(engine)
    fixed = service(engine).restate(correct(wrong), ADMIN)
    with pytest.raises(ConflictError, match="already restated"):
        service(engine).restate(correct(wrong, validity="hardening"), ADMIN)
    assert service(engine).restate(correct(fixed, validity="hardening"), ADMIN).restates_id == (
        fixed.id
    )


def test_a_restatement_never_restores_a_value_the_chain_retired(engine: Engine) -> None:
    wrong = seeded(engine)
    fixed = service(engine).restate(correct(wrong), ADMIN)
    with pytest.raises(ValidationError, match="already corrected away"):
        service(engine).restate(correct(fixed, validity="confirmed"), ADMIN)
    again = service(engine).restate(correct(fixed, validity="hardening", severity="low"), ADMIN)
    assert (again.validity, again.severity) == ("hardening", "low")


def test_restating_a_missing_decision_is_not_found(engine: Engine) -> None:
    wrong = seeded(engine)
    ghost = correct(wrong).model_copy(update={"decision_id": wrong.finding_id})
    with pytest.raises(NotFoundError):
        service(engine).restate(ghost, ADMIN)


def test_the_restatement_is_appended_to_the_ledger_in_its_transaction(engine: Engine) -> None:
    wrong = seeded(engine)
    fixed = service(engine, ledger=True).restate(correct(wrong), ADMIN)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.events.find_by_decision(fixed.id) is not None
        assert uow.events.find_by_decision(wrong.id) is None


def test_the_statement_key_is_the_judged_columns(engine: Engine) -> None:
    decisions = service(engine)
    wrong = seeded(engine)
    same = wrong.model_copy(update={"id": None, "created_at": None, "rationale": "different"})
    assert decisions.statement_key(same) == decisions.statement_key(wrong.model_copy())
    moved = wrong.model_copy(update={"severity": "low"})
    assert decisions.statement_key(moved) != decisions.statement_key(wrong)
