"""The contracts' cross-column and referential rules hold on both backends.

Each case is a row the DDL must refuse (plan Appendix B, plus the DDL's own
CHECKs); the repository surfaces the refusal as ConflictError.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import T0, Seed, repository_for
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.base import Model

Case = Callable[[Seed], tuple[str, Model]]

INVALID: dict[str, Case] = {
    # 1 · Inventory
    "default ref must be a branch": lambda s: (
        "repository_ref",
        s.new_repository_ref(kind="tag", is_default=True),
    ),
    "named ref needs a kind": lambda s: ("repository_ref", s.new_repository_ref(kind=None)),
    "bare commit has no kind": lambda s: ("repository_ref", s.new_repository_ref(name=None)),
    "ownership ends after it starts": lambda s: (
        "ownership",
        s.new_ownership(valid_to=T0 - timedelta(days=1)),
    ),
    # 3a · Assessments
    "location range starts at line 1": lambda s: (
        "location",
        s.new_location(line_start=0, line_end=1),
    ),
    "location range is ordered": lambda s: ("location", s.new_location(line_start=9, line_end=3)),
    "location lines are both set or both null": lambda s: (
        "location",
        s.new_location(line_start=None, line_end=4),
    ),
    "cvss score is 0-10": lambda s: ("occurrence", s.new_occurrence(cvss_score=Decimal("10.5"))),
    # 3b · Findings
    "advisory match only with an advisory": lambda s: (
        "finding",
        s.new_finding(advisory_match="confirmed"),
    ),
    "advisory needs a match grade": lambda s: (
        "finding",
        s.new_finding(advisory_id=s.advisory().id),
    ),
    "decision has a who": lambda s: ("decision", s.new_decision(actor=None)),
    "decision has one who": lambda s: (
        "decision",
        s.new_decision(assessment_id=s.assessment().id),
    ),
    "assessed decision takes the assessment's commit": lambda s: (
        "decision",
        s.new_decision(
            actor=None, assessment_id=s.assessment().id, repository_ref_id=s.repository_ref().id
        ),
    ),
    # 4 · Operations
    "routed or injected, never both": lambda s: (
        "run_order",
        s.new_run_order(rule="r1", event_source="push"),
    ),
    "leased exactly when a holder is set": lambda s: ("run_order", s.new_run_order(state="leased")),
    "lease holder and expiry go together": lambda s: (
        "run_order",
        s.new_run_order(state="leased", lease_holder="w1"),
    ),
    "finished after started": lambda s: (
        "run_order",
        s.new_run_order(started_at=T0, finished_at=T0 - timedelta(minutes=1)),
    ),
    "spend is never negative": lambda s: ("spend_event", s.new_spend_event(tokens_in=-1)),
    # 5 · Ledger
    "event seq starts at 0": lambda s: ("events", s.new_events(seq=-1)),
    # referential integrity
    "release needs a product": lambda s: (
        "release",
        s.new_release().model_copy(update={"product_id": uuid4()}),
    ),
    "occurrence needs its assessment": lambda s: (
        "occurrence",
        s.new_occurrence().model_copy(update={"assessment_id": uuid4()}),
    ),
    "event proves a real decision": lambda s: (
        "events",
        s.new_events().model_copy(update={"decision_id": uuid4()}),
    ),
}


@pytest.mark.parametrize("case", list(INVALID), ids=list(INVALID))
def test_database_refuses(seed: Seed, case: str) -> None:
    table, row = INVALID[case](seed)
    with pytest.raises(ConflictError):
        repository_for(seed.uow, table).add(row)


def test_one_open_ownership_per_repository_and_team(seed: Seed) -> None:
    repo, team = seed.repository(), seed.team()
    closed = seed.ownership(repo, team, valid_to=T0 + timedelta(days=1))
    seed.ownership(repo, team, valid_from=T0 + timedelta(days=1))  # reopened after closing
    assert closed.valid_to is not None
    with pytest.raises(ConflictError):
        seed.ownership(repo, team, valid_from=T0 + timedelta(days=2))


def test_bare_commits_are_unique_per_repository(seed: Seed) -> None:
    repo = seed.repository()
    seed.repository_ref(repo, name=None, kind=None)
    seed.repository_ref(repo, name="main")  # same sha on a branch is a different ref
    with pytest.raises(ConflictError):
        seed.repository_ref(repo, name=None, kind=None)


def test_imported_artifacts_are_unique_by_digest(seed: Seed) -> None:
    seed.artifact(assessment_id=None, digest="sha256:same")
    seed.artifact(digest="sha256:same")  # produced by an assessment: its own key
    with pytest.raises(ConflictError):
        seed.artifact(assessment_id=None, digest="sha256:same")


def test_parent_rows_cannot_be_deleted_while_referenced(seed: Seed) -> None:
    product = seed.product()
    seed.release(product)
    repository = repository_for(seed.uow, "product")
    stmt = sa.delete(repository.table).where(repository.table.c.id == product.id)
    with pytest.raises(ConflictError):
        repository._execute("raw delete", stmt)
