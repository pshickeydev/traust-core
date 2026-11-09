from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings.conftest import ANALYST
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest, TimeBucket
from traust_core.v1.models.findings import Finding, FindingDimension, FindingFilter
from traust_core.v1.models.inventory import Repository
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed_reported(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        assessment = s.assessment(s.repository_ref(repo))
        for _ in range(3):
            s.occurrence(s.finding(repo), assessment)
        uow.commit()
    return repo


def fingerprinted(context: Context) -> tuple[Repository, Finding]:
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        finding = s.finding(repo, fingerprint=" legacy:/A+B?x=%2F &Ω ")
        s.occurrence(finding, s.assessment(s.repository_ref(repo)), severity="critical")
        s.finding(s.repository(), fingerprint=finding.fingerprint)
        s.finding(repo, fingerprint=finding.fingerprint.strip())
        s.finding(repo, fingerprint=finding.fingerprint.lower())
        uow.commit()
    return repo, finding


@pytest.mark.parametrize("with_algorithm", [False, True])
def test_finding_by_fingerprint_preserves_exact_identity_and_matches_in_process(
    context: Context, client: TestClient, with_algorithm: bool
) -> None:
    repo, finding = fingerprinted(context)
    params = {"fingerprint": finding.fingerprint}
    if with_algorithm:
        params["fingerprint_algo"] = finding.fingerprint_algo
    response = client.get(
        f"/v1/repositories/{repo.id}/findings/by-fingerprint",
        params=params,
        headers=bearer(context, ANALYST),
    )
    assert response.status_code == 200
    assert response.json()["finding"]["id"] == str(finding.id)
    assert response.json()["finding"]["fingerprint"] == finding.fingerprint
    same_as_in_process(
        response.json(),
        context.services().findings.get_by_fingerprint(repo.id, **params),
    )
    same_as_in_process(response.json(), context.services().findings.get(finding.id))


def test_finding_by_fingerprint_refuses_ambiguity_without_an_algorithm(
    context: Context, client: TestClient
) -> None:
    repo, finding = fingerprinted(context)
    with SqlTraustUnitOfWork(context.database) as uow:
        other = Seed(uow).finding(repo, fingerprint=finding.fingerprint, fingerprint_algo="other")
        uow.commit()
    url = f"/v1/repositories/{repo.id}/findings/by-fingerprint"
    response = client.get(
        url, params={"fingerprint": finding.fingerprint}, headers=bearer(context, ANALYST)
    )
    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"
    for match in (finding, other):
        response = client.get(
            url,
            params={"fingerprint": match.fingerprint, "fingerprint_algo": match.fingerprint_algo},
            headers=bearer(context, ANALYST),
        )
        assert response.status_code == 200
        assert response.json()["finding"]["id"] == str(match.id)
        same_as_in_process(response.json(), context.services().findings.get(match.id))


@pytest.mark.parametrize("missing", ["repository", "fingerprint", "algorithm", "other-repository"])
def test_finding_by_fingerprint_reports_a_missing_exact_match(
    context: Context, client: TestClient, missing: str
) -> None:
    repo, finding = fingerprinted(context)
    with SqlTraustUnitOfWork(context.database) as uow:
        empty = Seed(uow).repository(url="https://forge.example/empty-fingerprint-repository")
        uow.commit()
    repository_id = repo.id
    if missing == "repository":
        repository_id = uuid4()
    elif missing == "other-repository":
        repository_id = empty.id
    params = {"fingerprint": "missing" if missing == "fingerprint" else finding.fingerprint}
    if missing == "algorithm":
        params["fingerprint_algo"] = "missing"
    response = client.get(
        f"/v1/repositories/{repository_id}/findings/by-fingerprint",
        params=params,
        headers=bearer(context, ANALYST),
    )
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


def test_finding_by_fingerprint_requires_the_fingerprint(
    context: Context, client: TestClient
) -> None:
    response = client.get(
        f"/v1/repositories/{uuid4()}/findings/by-fingerprint",
        headers=bearer(context, ANALYST),
    )
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_finding_by_fingerprint_requires_a_caller(client: TestClient) -> None:
    response = client.get(
        f"/v1/repositories/{uuid4()}/findings/by-fingerprint",
        params={"fingerprint": "opaque"},
    )
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


def test_finding_by_fingerprint_requires_a_uuid_repository(
    context: Context, client: TestClient
) -> None:
    response = client.get(
        "/v1/repositories/not-a-uuid/findings/by-fingerprint",
        params={"fingerprint": "opaque"},
        headers=bearer(context, ANALYST),
    )
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_a_repositorys_findings_page_like_in_process(context: Context, client: TestClient) -> None:
    repo = seed_reported(context)
    url = f"/v1/repositories/{repo.id}/findings"
    first = client.get(url, params={"limit": 2}, headers=bearer(context, ANALYST)).json()
    svc = context.services().findings
    same_as_in_process(first, svc.list(FindingFilter(repository_id=repo.id), PageRequest(limit=2)))
    assert len(first["items"]) == 2 and first["next"]
    rest = client.get(
        url, params={"limit": 2, "cursor": first["next"]}, headers=bearer(context, ANALYST)
    ).json()
    assert len(rest["items"]) == 1 and rest["next"] is None


def test_a_repositorys_finding_summary_and_timeline(context: Context, client: TestClient) -> None:
    repo = seed_reported(context)
    svc, scope = context.services().findings, FindingFilter(repository_id=repo.id)
    base = f"/v1/repositories/{repo.id}/findings"
    summary = client.get(
        f"{base}/summary", params={"group_by": "severity"}, headers=bearer(context, ANALYST)
    ).json()
    assert summary == [
        r.model_dump(mode="json") for r in svc.summary(scope, FindingDimension.SEVERITY)
    ]
    assert sum(r["findings"] for r in summary) == 3
    series = client.get(
        f"{base}/timeline", params={"bucket": "week"}, headers=bearer(context, ANALYST)
    ).json()
    assert series == [p.model_dump(mode="json") for p in svc.timeline(scope, TimeBucket.WEEK)]


def test_an_empty_repository_has_no_findings(context: Context, client: TestClient) -> None:
    url = f"/v1/repositories/{uuid4()}/findings"
    assert client.get(url, headers=bearer(context, ANALYST)).json() == {"items": [], "next": None}


@pytest.mark.parametrize(
    ("suffix", "params"),
    [("/summary", {}), ("/summary", {"group_by": "nonsense"}), ("", {"validity": "nonsense"})],
)
def test_finding_reads_reject_bad_parameters(
    context: Context, client: TestClient, suffix: str, params: dict[str, str]
) -> None:
    url = f"/v1/repositories/{uuid4()}/findings{suffix}"
    assert client.get(url, params=params, headers=bearer(context, ANALYST)).status_code == 422


def test_finding_reads_need_a_token(client: TestClient) -> None:
    assert client.get(f"/v1/repositories/{uuid4()}/findings").status_code == 401
