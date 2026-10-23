"""Restatement on SQLite and Postgres, ported from traust-ledger's restatement gates and tests."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.findings import Decision, Disposition, RecordDecision, Restatement
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
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
        uow,
        chain,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(NOW),
        restatement_approvers=approvers,
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


# decide: a person's direct statement
ALICE = ADMIN.model_copy(update={"identity": "alice@example.com", "roles": frozenset()})
BOB = ADMIN.model_copy(update={"identity": "bob@example.com", "roles": frozenset()})
UNVERIFIED = ALICE.model_copy(update={"verified_by": None})


def finding_id(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        made = Seed(uow).finding()
        uow.commit()
    assert made.id is not None
    return made.id


def say(finding: UUID, **kw: Any) -> RecordDecision:
    return RecordDecision(
        finding_id=finding, **{"validity": "confirmed", "rationale": "reproduced it", **kw}
    )


def test_a_statement_is_recorded_as_its_authors_decision(engine: Engine) -> None:
    finding = finding_id(engine)
    made = service(engine, ledger=True).decide(say(finding, source_channel="jira"), ALICE)
    assert (made.actor, made.validity, made.source_channel, made.occurred_at) == (
        "human:alice@example.com",
        "confirmed",
        "jira",
        NOW,
    )
    assert made.statement_key == service(engine).statement_key(made)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.events.find_by_decision(made.id) is not None


def test_a_retried_statement_is_the_same_decision(engine: Engine) -> None:
    finding = finding_id(engine)
    first = service(engine, ledger=True).decide(say(finding, occurred_at=NOW), ALICE)
    again = service(engine, ledger=True).decide(say(finding, occurred_at=NOW), ALICE)
    changed = service(engine).decide(say(finding, occurred_at=NOW, severity="low"), ALICE)
    assert again == first
    assert history(engine, first) == [first, changed]


@pytest.mark.parametrize(
    ("who", "change", "error"),
    [
        (ALICE, {"rationale": "short"}, ValidationError),
        (ALICE, {"occurred_at": NOW + timedelta(days=2)}, ValidationError),
        (ALICE.model_copy(update={"kind": ActorKind.MACHINE}), {}, ForbiddenError),
        (
            ALICE.model_copy(update={"verified_by": None}),
            {"validity": "false_positive"},
            ForbiddenError,
        ),
    ],
    ids=["short rationale", "dated ahead", "a machine", "unverified false positive"],
)
def test_the_statement_gates_refuse_and_write_nothing(
    engine: Engine, who: Principal, change: dict[str, Any], error: type[Exception]
) -> None:
    finding = finding_id(engine)
    with pytest.raises(error):
        service(engine).decide(say(finding, **change), who)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.decisions.list_for_finding(finding) == []


def test_after_a_validation_proves_it_the_same_person_cannot_reassert_alone(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        finding = seed.finding()
        proof = seed.assessment(kind="validation")
        seed.decision(finding, actor=None, assessment_id=proof.id, validity="confirmed")
        uow.commit()
    assert finding.id is not None
    first = say(finding.id, validity="false_positive")
    assert service(engine).decide(first, ALICE).validity == "false_positive"
    again = say(finding.id, validity="false_positive", reason="reasserted")
    with pytest.raises(ForbiddenError, match="second verified human"):
        service(engine).decide(again, ALICE)
    assert service(engine).decide(again, BOB).actor == "human:bob@example.com"
    assert service(engine).decide(first, ALICE).actor == "human:alice@example.com"


def test_a_statement_judges_a_commit_of_the_findings_repository(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        finding = seed.finding()
        own = seed.repository_ref(uow.repositories.get(finding.repository_id), name="dev")
        other = seed.repository_ref(seed.repository())
        uow.commit()
    assert finding.id is not None
    made = service(engine).decide(say(finding.id, repository_ref_id=own.id), ALICE)
    assert made.repository_ref_id == own.id
    with pytest.raises(ValidationError, match="not in finding"):
        service(engine).decide(say(finding.id, repository_ref_id=other.id), ALICE)


def test_a_statement_on_a_missing_finding_is_not_found(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).decide(say(uuid4()), ALICE)
