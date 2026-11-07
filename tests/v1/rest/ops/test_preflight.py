"""The preflight route: allow, each deny code, auth, and the problem envelope's typed codes."""

from __future__ import annotations

from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.models.identity import Credential
from traust_core.v1.models.operations import PreflightRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seeded_repository(context: Context, *, with_scan: bool = False) -> UUID:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        # Onboarded: a default line, so the subject gate sees an imported repository.
        seed.repository_ref(repo, is_default=True)
        if with_scan:
            seed.run_order(asset="assessment", repository_id=repo.id, state="succeeded")
        uow.commit()
    return repo.id


def staged(context: Context) -> None:
    """Declare the deployment's stage assets so the ordering gate applies."""
    context.config = context.config.model_copy(
        update={"recording": RecordingConfig(assessment=("assessment",), triage=("triage",))}
    )


def test_an_allowed_stage_matches_the_in_process_answer(
    context: Context, client: TestClient
) -> None:
    staged(context)
    repo = seeded_repository(context, with_scan=True)
    grant = context.local_issuer.mint("alice@example.com")
    body = {"asset": "triage", "repository_id": str(repo), "config_generation": "g7"}
    response = client.post(
        "/v1/preflight",
        json=body,
        headers={"Authorization": f"Bearer {grant.token.get_secret_value()}"},
    )
    principal = context.identity.authenticate(Credential(token=grant.token))
    expected = context.services().ops.preflight(PreflightRequest(**body), principal)
    assert response.status_code == 200
    same_as_in_process(response.json(), expected)


def test_preflight_requires_a_bearer_token(context: Context, client: TestClient) -> None:
    response = client.post("/v1/preflight", json={"asset": "triage", "repository_id": str(uuid4())})
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")


def test_a_denial_carries_the_typed_codes(context: Context, client: TestClient) -> None:
    response = client.post(
        "/v1/preflight",
        json={"asset": "triage", "repository_id": str(uuid4())},
        headers=bearer(context),
    )
    assert response.status_code == 403
    problem = response.json()
    assert problem["code"] == "subject_unknown"
    assert [issue["code"] for issue in problem["issues"]] == ["subject_unknown"]
    assert problem["detail"]


def test_a_machine_caller_is_denied_the_role(context: Context, client: TestClient) -> None:
    repo = seeded_repository(context, with_scan=True)
    response = client.post(
        "/v1/preflight",
        json={"asset": "triage", "repository_id": str(repo)},
        headers=runner(context),
    )
    assert response.status_code == 403
    problem = response.json()
    assert problem["code"] == "role_denied"
    # The denial is the whole answer: no other gate's codes, no spend figures in any detail.
    assert [issue["code"] for issue in problem["issues"]] == ["role_denied"]
    assert all("$" not in issue["detail"] for issue in problem["issues"])


def test_a_stage_without_its_prior_record_is_denied(context: Context, client: TestClient) -> None:
    staged(context)
    repo = seeded_repository(context)
    response = client.post(
        "/v1/preflight",
        json={"asset": "triage", "repository_id": str(repo)},
        headers=bearer(context),
    )
    assert response.status_code == 403
    assert response.json()["code"] == "ordering_violated"
