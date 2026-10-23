from __future__ import annotations

import logging
from http import HTTPStatus

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from traust_core.v1.context import Context
from traust_core.v1.errors import (
    AuthenticationError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.rest import deps
from traust_core.v1.rest.app import create_app

TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def test_healthz_answers_without_auth_and_carries_a_request_id(client: TestClient) -> None:
    response = client.get("/v1/healthz")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    assert len(response.headers["X-Request-ID"]) == 32


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"X-Request-ID": "req-123"}, "req-123"),
        ({"traceparent": TRACE}, "4bf92f3577b34da6a3ce929d0e0e4736"),
        ({"X-Request-ID": "req-1", "traceparent": TRACE}, "req-1"),
    ],
    ids=["caller's request id", "traceparent's trace id", "request id wins"],
)
def test_the_request_id_comes_from_the_caller(
    client: TestClient, headers: dict[str, str], expected: str
) -> None:
    assert client.get("/v1/healthz", headers=headers).headers["X-Request-ID"] == expected


@pytest.mark.parametrize("given", ["has space", "x" * 200, "new\nline"])
def test_an_unsafe_request_id_is_replaced(client: TestClient, given: str) -> None:
    assert (
        client.get("/v1/healthz", headers={"X-Request-ID": given}).headers["X-Request-ID"] != given
    )


def failing(context: Context) -> FastAPI:
    app = create_app(context)
    router = APIRouter()
    errors = {
        "authentication": AuthenticationError("who are you"),
        "forbidden": ForbiddenError("not you"),
        "not-found": NotFoundError("no such thing"),
        "conflict": ConflictError("already done"),
        "validation": ValidationError("bad value"),
        "service": ServiceError("upstream broke"),
        "bug": RuntimeError("secret internals"),
    }

    @router.get("/raise/{kind}")
    def raise_it(kind: str) -> None:
        raise errors[kind]

    @router.get("/typed/{number}")
    def typed(number: int) -> int:
        return number

    app.include_router(router)
    return app


@pytest.mark.parametrize(
    ("kind", "status", "detail"),
    [
        ("authentication", 401, "who are you"),
        ("forbidden", 403, "not you"),
        ("not-found", 404, "no such thing"),
        ("conflict", 409, "already done"),
        ("validation", 422, "bad value"),
        ("service", 500, "upstream broke"),
        ("bug", 500, "Internal Server Error"),
    ],
)
def test_a_typed_error_is_one_problem_shape(
    context: Context, kind: str, status: int, detail: str
) -> None:
    with TestClient(failing(context), raise_server_exceptions=False) as client:
        response = client.get(f"/raise/{kind}", headers={"X-Request-ID": "r1"})
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
        "detail": detail,
        "instance": f"/raise/{kind}",
        "request_id": "r1",
    }
    assert (response.headers.get("WWW-Authenticate") == "Bearer") is (status == 401)


def test_a_malformed_request_is_a_422_problem(context: Context) -> None:
    with TestClient(failing(context)) as client:
        response = client.get("/typed/not-a-number")
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"].startswith("path.number:")


def test_a_bug_is_logged_once_and_its_internals_stay_inside(
    context: Context, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.ERROR, logger="traust_core.v1.rest.problems"),
        TestClient(failing(context), raise_server_exceptions=False) as client,
    ):
        response = client.get("/raise/bug")
    assert "secret internals" not in response.text
    assert [r.getMessage() for r in caplog.records] == ["GET /raise/bug failed"]


def test_every_request_gets_one_access_line(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="traust_core.rest.access"):
        client.get("/v1/healthz", headers={"X-Request-ID": "r9"})
    (line,) = [r.getMessage() for r in caplog.records if r.name == "traust_core.rest.access"]
    assert line.startswith("GET /v1/healthz 200 ") and line.endswith("request_id=r9")


def test_each_request_gets_its_own_unit_of_work(context: Context) -> None:
    first, second = deps.services(context), deps.services(context)
    assert first.findings._uow is not second.findings._uow


def test_openapi_documents_the_routes_and_their_problems(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert {"/v1/healthz", "/v1/whoami"} <= set(spec["paths"])
    unauthorized = spec["paths"]["/v1/whoami"]["get"]["responses"]["401"]
    assert "application/problem+json" in unauthorized["content"]
