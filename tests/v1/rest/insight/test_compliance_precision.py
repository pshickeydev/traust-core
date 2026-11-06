from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer
from tests.v1.services.test_insight_compliance_precision import HOSTILE, seed_calibration, snapshot
from traust_core.v1 import contracts
from traust_core.v1.context import Context

URL = "/v1/insights/compliance-precision"
FRAMEWORK = "nist-800-53-rev5"


def test_native_http_model_preserves_counts_gate_and_raw_check_ids_without_writes(
    context: Context, client: TestClient
) -> None:
    seed_calibration(context)
    before = snapshot(context)
    response = client.get(
        URL,
        params={"framework": FRAMEWORK, "precision_gate": 0.49},
        headers=bearer(context),
    )
    assert response.status_code == 200, response.text
    document = response.json()
    contracts.validate_view("compliance-precision", document)
    assert document == {
        "calibration": {
            "framework": FRAMEWORK,
            "assessments": 1,
            "gate": 0.49,
            "checks": [
                {
                    "check_id": HOSTILE,
                    "fired": 2,
                    "dismissed": 1,
                    "gate": 0.49,
                    "precision": 0.5,
                    "flagged": False,
                },
                {
                    "check_id": "mfa",
                    "fired": 1,
                    "dismissed": 0,
                    "gate": 0.49,
                    "precision": 1.0,
                    "flagged": False,
                },
            ],
        }
    }
    assert snapshot(context) == before
    assert client.get(URL, params={"framework": FRAMEWORK}).status_code == 401


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {"precision_gate": 0.4},
        {"framework": "not-a-framework"},
        {"framework": FRAMEWORK, "precision_gate": -0.1},
        {"framework": FRAMEWORK, "precision_gate": 1.1},
        {"framework": FRAMEWORK, "precision_gate": "nan"},
        {"framework": FRAMEWORK, "precision_gate": "inf"},
        {"framework": FRAMEWORK, "repository_id": str(uuid4())},
        {"framework": FRAMEWORK, "product_id": str(uuid4())},
        {"framework": FRAMEWORK, "team_id": str(uuid4())},
        {"framework": FRAMEWORK, "category": "authorization"},
        {"framework": FRAMEWORK, "as_of": "2026-10-05T00:00:00Z"},
        {"framework": FRAMEWORK, "bucket": "day"},
        {
            "framework": FRAMEWORK,
            "window_start": "2026-10-01T00:00:00Z",
            "window_end": "2026-10-05T00:00:00Z",
        },
    ],
)
def test_invalid_parameters_and_ignored_scope_are_refused_without_writes(
    context: Context, client: TestClient, parameters: dict[str, str | float]
) -> None:
    before = snapshot(context)
    response = client.get(URL, params=parameters, headers=bearer(context))
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context) == before


def test_other_http_views_refuse_inapplicable_calibration_parameters(
    context: Context, client: TestClient
) -> None:
    response = client.get(
        "/v1/insights/findings-rollup",
        params={"framework": FRAMEWORK, "precision_gate": 0.5},
        headers=bearer(context),
    )
    assert response.status_code == 422, response.text


def test_empty_http_calibration_is_not_a_zero_precision_claim(
    context: Context, client: TestClient
) -> None:
    response = client.get(URL, params={"framework": FRAMEWORK}, headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "calibration": {"framework": FRAMEWORK, "assessments": 0, "checks": [], "gate": 0.5}
    }
