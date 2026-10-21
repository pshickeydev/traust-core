"""observation_target and open counts over the contract tables (SQLite + Postgres)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.observation import ObservationTarget
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService


def service(engine: Engine) -> AssessmentService:
    """A service over its own unit of work, as the context door builds it."""
    return AssessmentService(SqlTraustUnitOfWork(engine))


def test_resolves_latest_audit_and_pinned_commit(uow, seed: Seed, engine: Engine):
    repo = seed.repository(url="https://github.com/org/audited")
    old_ref = seed.repository_ref(repository=repo, sha="a" * 40)
    new_ref = seed.repository_ref(repository=repo, sha="b" * 40)
    seed.assessment(
        ref=old_ref,
        kind=AssessmentKind.SECURE_CODE,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    seed.assessment(
        ref=new_ref,
        kind=AssessmentKind.SECURE_CODE,
        occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    # a non-audit assessment on a newer ref must not win
    seed.assessment(
        ref=new_ref,
        kind=AssessmentKind.THREAT_MODEL,
        occurred_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    uow.commit()

    target = service(engine).observation_target(repo_url="https://github.com/org/audited")
    assert target == ObservationTarget(
        repository_id=repo.id,
        repo_url="https://github.com/org/audited",
        has_audit=True,
        audit_date="2026-09-01",
        pinned_sha="b" * 40,
        repository_ref_id=new_ref.id,
    )
    by_id = service(engine).observation_target(repository_id=repo.id)
    assert by_id == target


def test_observation_target_without_an_audit_is_never_audited(uow, seed: Seed, engine: Engine):
    repo = seed.repository(url="https://github.com/org/never-audited")
    uow.commit()

    target = service(engine).observation_target(repo_url="https://github.com/org/never-audited")
    assert target.has_audit is False
    assert target.repository_id == repo.id


def test_observation_target_requires_inventory_membership(uow, seed: Seed, engine: Engine):
    with pytest.raises(NotFoundError):
        service(engine).observation_target(repo_url="https://github.com/org/unknown")


def test_observation_target_takes_exactly_one_selector(engine: Engine):
    with pytest.raises(ValidationError):
        service(engine).observation_target()
    with pytest.raises(ValidationError):
        service(engine).observation_target(
            repository_id=UUID(int=1), repo_url="https://github.com/org/x"
        )


def test_open_counts_read_the_finding_status_view(uow, seed: Seed, engine: Engine):
    from traust_core.v1.models.vocabulary import Severity

    repo = seed.repository()
    counts = uow.open_counts
    assert counts.open_count(repo.id, (Severity.CRITICAL, Severity.HIGH)) == 0
    critical, high, medium = (
        seed.finding(repository=repo),
        seed.finding(repository=repo),
        seed.finding(repository=repo),
    )
    # severity rides on the occurrence (the finding row is identity only)
    seed.occurrence(finding=critical, severity="critical")
    seed.occurrence(finding=high, severity="high")
    seed.occurrence(finding=medium, severity="medium")
    # decisions close two of the three: one false_positive, one resolved
    seed.decision(finding=critical, validity="false_positive")
    seed.decision(finding=medium, resolution="resolved")
    assert counts.open_count(repo.id, (Severity.CRITICAL, Severity.HIGH)) == 1
    assert counts.open_count(repo.id, ()) == 0
