"""3b · The scheduled-remediation repositories (`remediation`, `remediation_finding`): every
query, matching and empty, on SQLite and Postgres."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.repositories.tables.conftest import Seed, apart
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_remediations_by_assessment_id_status_and_all(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    work_item = seed.assessment()
    linked = seed.remediation(assessment_id=work_item.id)
    apart()
    other = seed.remediation(status="patched")
    repo = uow.remediations

    assert repo.find_by_assessment(work_item.id) == linked  # type: ignore[arg-type]
    assert repo.find_by_assessment(uuid4()) is None
    assert repo.find_by_assessment_for_update(work_item.id) == linked  # type: ignore[arg-type]
    assert repo.find_by_assessment_for_update(uuid4()) is None
    assert repo.get_for_update(linked.id) == linked  # type: ignore[arg-type]
    with pytest.raises(NotFoundError, match="remediation"):
        repo.get_for_update(uuid4())
    assert repo.list_by_ids({linked.id, other.id}) == [linked, other]  # type: ignore[arg-type]
    assert repo.list_by_ids(set()) == []
    assert repo.list_by_status(RemediationStatus("patched")) == [other]
    assert repo.list_by_status(RemediationStatus("merged")) == []
    assert repo.list_all() == [linked, other]


def test_search_applies_every_filter_and_pages_oldest_first(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    finding = seed.finding()
    elsewhere = seed.finding()
    first = seed.remediation()
    apart()
    second = seed.remediation(status="patched")
    apart()
    third = seed.remediation()
    seed.remediation_finding(first, finding)
    seed.remediation_finding(second, finding)
    seed.remediation_finding(third, elsewhere)
    repo = uow.remediations

    def search(**kw: object) -> list[object]:
        filters = {"status": None, "repository_id": None, "finding_id": None, **kw}
        return repo.search(**filters, limit=10, after=None)  # type: ignore[arg-type]

    assert search() == [first, second, third]
    assert search(finding_id=finding.id) == [first, second]
    assert search(repository_id=elsewhere.repository_id) == [third]
    assert search(finding_id=finding.id, status=RemediationStatus("patched")) == [second]
    assert search(finding_id=finding.id, repository_id=elsewhere.repository_id) == []
    assert search(status=RemediationStatus("merged")) == []
    page = repo.search(status=None, repository_id=None, finding_id=None, limit=2, after=None)
    assert page == [first, second]
    after = (second.created_at, second.id)
    rest = repo.search(status=None, repository_id=None, finding_id=None, limit=2, after=after)  # type: ignore[arg-type]
    assert rest == [third]


def test_remediation_findings_by_effort_finding_and_repository(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    finding = seed.finding()
    effort = seed.remediation()
    link = seed.remediation_finding(effort, finding)
    repo = uow.remediation_findings

    assert repo.list_for_remediation(effort.id) == [link]  # type: ignore[arg-type]
    assert repo.list_for_remediation(uuid4()) == []
    assert repo.list_for_finding(finding.id) == [link]  # type: ignore[arg-type]
    assert repo.list_for_finding(uuid4()) == []
    assert repo.list_for_findings({finding.id, uuid4()}) == [link]  # type: ignore[arg-type]
    assert repo.list_for_findings(set()) == []
    assert repo.list_for_repository(finding.repository_id) == [link]
    assert repo.list_for_repository(uuid4()) == []
