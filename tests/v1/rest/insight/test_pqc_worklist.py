from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from tests.v1.services.test_pqc_worklist import snapshot
from traust_core.v1 import contracts
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

URL = "/v1/insights/pqc-worklist"


def test_http_worklist_retains_native_scope_order_nullable_state_and_no_writes(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        gateway = seed.repository(url="https://github.com/example/oauth-gateway")
        registered = seed.repository_ref(gateway, sha="a" * 40, is_default=True)
        empty = seed.repository(url="https://github.com/example/empty")
        product = seed.product()
        seed.component(seed.release(product), registered)
        uow.commit()
    headers = bearer(context)
    before = snapshot(context)
    response = client.get(URL, params={"chokepoint": " OAuth-Gateway "}, headers=headers)
    assert response.status_code == 200, response.text
    document = response.json()
    contracts.validate_view("pqc-worklist", document)
    assert document["product_id"] is None and document["repository_ref_ids"] is None
    assert document["chokepoints"] == ["OAuth-Gateway"]
    assert [row["repository_id"] for row in document["entries"]] == [str(gateway.id), str(empty.id)]
    first, second = document["entries"]
    assert (first["priority_tier"], first["route"], first["cursor"]) == (
        "chokepoint",
        "source",
        "0|https://github.com/example/oauth-gateway",
    )
    assert first["repository_ref_id"] == str(registered.id)
    assert first["scan"] == {
        "repository_ref_id": str(registered.id),
        "assessment_id": None,
        "basis": None,
        "current": None,
    }
    assert first["access"]["observed_at"] is None and first["access"]["archived"] is None
    assert (second["repository_ref_id"], second["sha"], second["scan"]) == (None, None, None)
    assert (second["route"], second["reason"]) == ("access-request", "no-registered-commit")
    scoped = client.get(
        URL,
        params={"product_id": str(product.id), "repository_ref_id": str(registered.id)},
        headers=headers,
    )
    assert scoped.status_code == 200, scoped.text
    assert [row["repository_id"] for row in scoped.json()["entries"]] == [str(gateway.id)]
    assert scoped.json()["repository_ref_ids"] == [str(registered.id)]
    assert snapshot(context) == before
    assert client.get(URL).status_code == 401


@pytest.mark.parametrize(
    "parameters",
    [
        {"product_id": [str(uuid4()), str(uuid4())]},
        {"chokepoint": "  "},
        {"repository_ref_id": "not-a-uuid"},
        {"repository_id": str(uuid4())},
        {"team_id": str(uuid4())},
        {"category": "crypto"},
        {"as_of": "2026-10-05T00:00:00Z"},
        {"bucket": "day"},
        {"artifact_id": str(uuid4())},
        {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-05T00:00:00Z"},
    ],
)
def test_http_worklist_refuses_invalid_or_unsupported_scope_without_writes(
    context: Context, client: TestClient, parameters: dict[str, str | list[str]]
) -> None:
    before = snapshot(context)
    response = client.get(URL, params=parameters, headers=bearer(context))
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context) == before


def test_unknown_ref_selection_does_not_become_global_inventory(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository_ref()
        uow.commit()
    response = client.get(URL, params={"repository_ref_id": str(uuid4())}, headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json()["entries"] == []


def test_other_http_views_do_not_ignore_worklist_parameters(
    context: Context, client: TestClient
) -> None:
    response = client.get(
        "/v1/insights/findings-rollup", params={"chokepoint": "gateway"}, headers=bearer(context)
    )
    assert response.status_code == 422, response.text


def test_empty_inventory_is_a_valid_empty_worklist(context: Context, client: TestClient) -> None:
    response = client.get(URL, headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "product_id": None,
        "repository_ref_ids": None,
        "chokepoints": [],
        "entries": [],
    }
