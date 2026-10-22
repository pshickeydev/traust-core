"""3b · Restatement at a year's volume: an administrator corrects one decision."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from perf.harness import Explained, Profile
from perf.queries.test_ledger import fast
from perf.seed import DECISIONS, REPOSITORIES
from traust_core.v1.models.findings import Restatement
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.lint import Lint

ADMIN = Principal(
    identity="admin@example.com",
    kind=ActorKind.HUMAN,
    display="admin",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.RESTATE}),
)


N = DECISIONS // 2 + 1  # a typical repository's finding (every 25th is the hot one's)


def _decision(uow: SqlTraustUnitOfWork) -> UUID:
    repo = uow.repositories.find_by_url(f"https://forge.example/org/r{1 + N % REPOSITORIES}")
    assert repo is not None and repo.id is not None
    finding = uow.findings.find_by_fingerprint(repo.id, "v2", f"fp-{N}")
    assert finding is not None and finding.id is not None
    decision = uow.decisions.find_by_statement(finding.id, f"sk-fp-{N}")
    assert decision is not None and decision.id is not None
    return decision.id


def restate(uow: SqlTraustUnitOfWork) -> None:
    decisions = FindingDecisions(uow, None, Lint({}), clock=FixedClock(datetime.now(UTC)))
    restatement = Restatement(
        decision_id=_decision(uow),
        validity="confirmed",
        reason="data_error",
        ticket="SEC-1",
        rationale="the triage misread the sink",
    )
    decisions.restate(restatement, ADMIN)


def reads(statements: list[Explained]) -> list[Explained]:
    return [e for e in statements if e.sql.lstrip().upper().startswith("SELECT")]


def test_restate_reads_the_decision_and_its_history_by_index(explained: Profile) -> None:
    *_, decision, history = reads(explained(restate))
    fast(decision, "decision_pkey", 1)
    fast(history, "idx_decision_finding_occurred", 5)


def test_approvers_of_a_decision_read_by_index(explained: Profile) -> None:
    *_, approvers = explained(lambda uow: uow.decision_approvers.list_for_decision(_decision(uow)))
    fast(approvers, "decision_approver_decision_id_approver_key", 1)
