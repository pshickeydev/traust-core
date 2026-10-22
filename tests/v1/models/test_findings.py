"""Disposition rules, ported from traust-ledger's derive_disposition and gates at d1b589a."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest

from traust_core.v1.errors import ForbiddenError, ValidationError
from traust_core.v1.models.findings import Decision, Disposition
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.vocabulary import ActorKind, SourceType

T0 = datetime(2026, 10, 1, tzinfo=UTC)
LATER = T0 + timedelta(days=30)
FINDING = uuid4()
FP, CONFIRMED = "false_positive", "confirmed"


def person(verified: bool = True, kind: str = "human") -> Principal:
    return Principal(
        identity=f"{uuid4()}@example.com",
        kind=ActorKind(kind),
        display="p",
        verified_by=IdentitySource.OIDC if verified else None,
    )


ALICE, BOB = person(), person()


class History:
    """Decisions on one finding plus each assessment's report kind."""

    def __init__(self) -> None:
        self.decisions: list[Decision] = []
        self.sources: dict[UUID, SourceType] = {}

    def by(self, who: Principal, day: int, validity: str | None = None, **kw: Any) -> Decision:
        return self._add(actor=who.ref, day=day, validity=validity, **kw)

    def report(self, source: str, day: int, validity: str | None = None, **kw: Any) -> Decision:
        assessment = uuid4()
        self.sources[assessment] = SourceType(source)
        return self._add(assessment_id=assessment, day=day, validity=validity, **kw)

    def _add(self, day: int, **kw: Any) -> Decision:
        made = statement(day, id=uuid4(), created_at=T0 + timedelta(days=day), **kw)
        self.decisions.append(made)
        return made

    def fold(self) -> Disposition:
        return Disposition.fold(FINDING, self.decisions, self.sources)

    def admit(
        self, decision: Decision, actor: Principal | None, now: datetime = LATER
    ) -> Disposition:
        return Disposition.admit(self.decisions, decision, actor, now, self.sources)


def statement(day: int = 0, **kw: Any) -> Decision:
    return Decision(
        finding_id=FINDING, statement_key="k", occurred_at=T0 + timedelta(days=day), **kw
    )


def said(who: Principal, validity: str | None = FP, day: int = 9, **kw: Any) -> Decision:
    return statement(day, actor=who.ref, validity=validity, rationale="checked by hand", **kw)


# fold: evidence-class precedence
def test_nothing_decided_is_claimed_and_open() -> None:
    d = History().fold()
    assert (d.validity, d.resolution, d.assurance, d.last_decision_at) == (
        None,
        None,
        "claimed",
        None,
    )
    assert d.is_open()


def test_the_latest_human_beats_any_machine() -> None:
    h = History()
    h.report("triage_report", 1, CONFIRMED)
    h.by(ALICE, 2, "hardening")
    h.report("triage_report", 3, CONFIRMED)
    assert (h.fold().validity, h.fold().assurance) == ("hardening", "human_reviewed")


def test_a_machine_false_positive_waits_for_signoff_unless_auto_accepted() -> None:
    waiting = History()
    waiting.report("triage_report", 1, FP)
    d = waiting.fold()
    assert (d.validity, d.awaiting_signoff, d.assurance) == (None, True, "machine_verified")
    auto = History()
    auto.report("triage_report", 1, FP, auto_accept_tier=True)
    assert (auto.fold().validity, auto.fold().awaiting_signoff) == (FP, False)


def test_a_human_answer_ends_the_wait() -> None:
    h = History()
    h.report("triage_report", 1, FP)
    h.by(ALICE, 2, CONFIRMED)
    assert not h.fold().awaiting_signoff


def test_execution_proof_beats_an_earlier_human_false_positive() -> None:
    h = History()
    h.by(ALICE, 1, FP)
    h.report("validation_report", 2, CONFIRMED)
    d = h.fold()
    assert (d.validity, d.fp_overridden, d.assurance, d.conflict) == (
        CONFIRMED,
        True,
        "execution_proven",
        True,
    )


@pytest.mark.parametrize(
    ("signers", "validity", "blocked"),
    [((ALICE,), CONFIRMED, True), ((ALICE, ALICE), CONFIRMED, True), ((ALICE, BOB), FP, False)],
    ids=["one signer", "same signer twice", "two signers"],
)
def test_reasserting_a_false_positive_after_proof_takes_two_people(
    signers: tuple[Principal, ...], validity: str, blocked: bool
) -> None:
    h = History()
    h.report("verification_report", 1, CONFIRMED)
    for day, who in enumerate(signers, start=2):
        h.by(who, day, FP)
    d = h.fold()
    assert (d.validity, d.fp_reassertion_blocked, d.fp_overridden) == (validity, blocked, False)


def test_execution_proof_of_another_answer_decides_without_override() -> None:
    h = History()
    h.by(ALICE, 1, FP)
    h.report("validation_report", 2, "hardening")
    d = h.fold()
    assert (d.validity, d.fp_overridden, d.fp_reassertion_blocked) == ("hardening", False, False)


def test_an_execution_false_positive_is_not_decisive() -> None:
    h = History()
    h.by(ALICE, 1, "hardening")
    h.report("validation_report", 2, FP)
    assert (h.fold().validity, h.fold().assurance) == ("hardening", "execution_proven")


@pytest.mark.parametrize("grade", ["E2", "E3"])
def test_weak_evidence_demotes_an_execution_report_to_machine(grade: str) -> None:
    h = History()
    h.report("validation_report", 1, CONFIRMED, evidence_grade=grade)
    assert h.fold().assurance == "machine_verified"


def test_resolution_prefers_verification_then_jira_then_the_latest() -> None:
    h = History()
    h.report("triage_report", 1, resolution="fix_in_progress")
    assert h.fold().resolution == "fix_in_progress"
    h.by(ALICE, 2, resolution="risk_accepted", source_channel="jira")
    h.report("triage_report", 3, resolution="fix_in_progress")
    assert h.fold().resolution == "risk_accepted"
    h.report("verification_report", 4, resolution="resolved")
    h.by(BOB, 5, resolution="open", source_channel="jira")
    assert h.fold().resolution == "resolved"
    assert not h.fold().is_open()


def test_judgement_order_is_the_instant_then_the_insert() -> None:
    late_text = statement(actor=ALICE.ref, validity=FP)
    late_text = late_text.model_copy(
        update={"occurred_at": datetime(2026, 10, 1, 9, tzinfo=timezone(timedelta(hours=8)))}
    )
    early_text = statement(actor=BOB.ref, validity=CONFIRMED)
    early_text = early_text.model_copy(
        update={"occurred_at": datetime(2026, 10, 1, 2, tzinfo=timezone(timedelta(hours=-3)))}
    )
    assert Disposition.fold(FINDING, [early_text, late_text]).validity == CONFIRMED
    first = statement(actor=ALICE.ref, validity=FP, created_at=T0)
    second = statement(actor=BOB.ref, validity=CONFIRMED, created_at=T0 + timedelta(seconds=1))
    unsaved = statement(actor=ALICE.ref, validity="hardening")
    assert Disposition.fold(FINDING, [second, first]).validity == CONFIRMED
    assert Disposition.fold(FINDING, [unsaved, second, first]).validity == "hardening"


def test_a_restatement_replaces_the_decision_it_corrects() -> None:
    h = History()
    wrong = h.by(ALICE, 1, CONFIRMED)
    h.by(BOB, 2, FP, restates_id=wrong.id, ticket="T-1", reason="data_error")
    d = h.fold()
    assert (d.validity, d.conflict) == (FP, False)
    assert not d.is_open()


@pytest.mark.parametrize(
    ("validity", "resolution", "is_open"),
    [
        (None, None, True),
        (CONFIRMED, "fix_in_progress", True),
        (FP, None, False),
        (CONFIRMED, "resolved", False),
        (CONFIRMED, "risk_accepted", False),
    ],
)
def test_open_means_not_affirmatively_closed(
    validity: str | None, resolution: str | None, is_open: bool
) -> None:
    disposition = Disposition(
        finding_id=FINDING, validity=validity, resolution=resolution, assurance="claimed"
    )
    assert disposition.is_open() is is_open


# admit: the gates on a direct statement
def test_admit_returns_the_disposition_with_the_decision() -> None:
    h = History()
    h.report("triage_report", 1, FP)
    assert h.admit(said(ALICE, CONFIRMED, day=2), ALICE).validity == CONFIRMED


@pytest.mark.parametrize(
    ("actor", "author"),
    [(None, ALICE), (BOB, ALICE), (person(kind="machine"), None)],
    ids=["no caller", "someone else's name", "a machine"],
)
def test_a_statement_is_the_calling_humans_own(actor: Principal | None, author: Any) -> None:
    decision = said(author or actor, CONFIRMED)
    with pytest.raises(ForbiddenError):
        History().admit(decision, actor)


def test_a_statement_needs_a_rationale() -> None:
    with pytest.raises(ValidationError, match="10 characters"):
        History().admit(said(ALICE, CONFIRMED).model_copy(update={"rationale": "short"}), ALICE)


def test_a_statement_cannot_be_dated_more_than_a_day_ahead() -> None:
    History().admit(said(ALICE, CONFIRMED, day=1), ALICE, now=T0)
    with pytest.raises(ValidationError, match="ahead"):
        History().admit(said(ALICE, CONFIRMED, day=2), ALICE, now=T0)


def test_only_a_verified_human_says_false_positive() -> None:
    unverified = person(verified=False)
    History().admit(said(unverified, CONFIRMED), unverified)
    with pytest.raises(ForbiddenError, match="verified human"):
        History().admit(said(unverified), unverified)
    assert History().admit(said(ALICE), ALICE).validity == FP


def test_an_assessors_decision_skips_the_statement_gates() -> None:
    h = History()
    decision = statement(9, assessment_id=uuid4(), validity=FP)
    assert h.admit(decision, None).awaiting_signoff


@pytest.mark.parametrize("proof", ["validation_report", "verification_report"])
def test_after_execution_proof_the_same_person_cannot_reassert(proof: str) -> None:
    h = History()
    h.by(ALICE, 1, FP)
    h.report(proof, 2, CONFIRMED)
    with pytest.raises(ForbiddenError, match="second verified human"):
        h.admit(said(ALICE), ALICE)
    assert h.admit(said(BOB), BOB).validity == CONFIRMED  # admitted; one signer after proof


def test_the_first_signer_after_proof_is_admitted() -> None:
    h = History()
    h.report("validation_report", 1, CONFIRMED)
    assert h.admit(said(ALICE), ALICE).fp_reassertion_blocked


def test_without_execution_proof_the_same_person_may_repeat() -> None:
    h = History()
    h.by(ALICE, 1, FP)
    assert h.admit(said(ALICE), ALICE).validity == FP


def test_a_machine_false_positive_is_not_a_first_signer() -> None:
    h = History()
    h.report("triage_report", 1, FP)
    h.report("validation_report", 2, CONFIRMED)
    assert h.admit(said(ALICE), ALICE).fp_reassertion_blocked
