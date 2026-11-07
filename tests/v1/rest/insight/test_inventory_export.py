from __future__ import annotations

import json
import shutil
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed, apart
from tests.v1.rest.conftest import bearer
from tests.v1.services.test_inventory_export import COLUMNS, FIXTURE
from tests.v1.services.test_portfolio_product_map import PROVENANCE
from tests.v1.services.test_pqc_worklist import snapshot
from traust_core.v1.context import Config, Context
from traust_core.v1.models.artifacts import ProductDefinitionsMapArtifact
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.identity import IdentityConfig

URL = "/v1/insights/inventory-export"


@pytest.fixture
def context(tmp_path: Path) -> Context:
    cache = Path(shutil.copytree(FIXTURE, tmp_path / "feeds"))
    config = Config(home=tmp_path / "home", identity=IdentityConfig(trust_local=True))
    config = config.model_copy(
        update={
            "locations": config.locations.model_copy(update={"feeds_cache": str(cache)}),
        }
    )
    return Context(config)


def test_http_export_is_the_canonical_native_inventory_with_real_contacts_and_no_writes(
    context: Context,
    client: TestClient,
) -> None:
    hostile = '=SUM(1,2)\r\n| forged | <script>alert("x")</script>'
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/acme/widget-api")
        seed.ownership(repository, seed.team(name=hostile))
        seed.ownership(repository, seed.team(name="future"), valid_from=T0 + timedelta(days=90))
        seed.ownership(repository, seed.team(name="closed"), valid_to=T0 + timedelta(days=1))
        main = seed.repository_ref(repository)
        tag = seed.repository_ref(repository, name="v1", kind="tag", sha="b" * 40)
        product = seed.product(slug="shipping-product")
        release = seed.release(product)
        seed.component(release, main)
        seed.component(release, tag)
        apart()
        empty = seed.repository(url="https://example.com/aaa/empty")
        uow.commit()
    context.services().portfolio.record_product_map(
        ProductDefinitionsMapArtifact.from_document(
            {
                "mappings": {"repos": {"github.com/acme/widget-api": "relic"}},
            }
        ),
        PROVENANCE,
    )
    headers = bearer(context)
    before = snapshot(context)
    response = client.get(URL, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert tuple(body) == ("rows",)
    assert all(tuple(row) == COLUMNS for row in body["rows"])
    assert body == {
        "rows": [
            {
                "Repository": "aaa/empty",
                "URL": empty.url,
                "Host": "example.com",
                "Organization/Group": "aaa",
                "Repo Name": "empty",
                "Owner Team": [],
                "Products": [],
                "Accountable Contacts": [],
            },
            {
                "Repository": "acme/widget-api",
                "URL": repository.url,
                "Host": "github.com",
                "Organization/Group": "acme",
                "Repo Name": "widget-api",
                "Owner Team": [hostile, "future"],
                "Products": ["shipping-product"],
                "Accountable Contacts": ["relicperson (default_cc; embargo_cleared=False)"],
            },
        ]
    }
    expected = context.services().insight.build(ViewName.INVENTORY_EXPORT, ViewFilter())
    assert body == expected.model_dump(mode="json")
    assert snapshot(context) == before
    assert client.get(URL).status_code == 401


@pytest.mark.parametrize(
    "parameters",
    [
        {"product_id": str(uuid4())},
        {"team_id": str(uuid4())},
        {"category": "crypto"},
        {"as_of": T0.isoformat()},
        {"bucket": "day"},
        {"artifact_id": str(uuid4())},
        {"repository_id": str(uuid4())},
        {"repository_ref_id": str(uuid4())},
        {"chokepoint": "gateway"},
        {"framework": next(iter(ComplianceFramework)).value},
        {"precision_gate": "0.5"},
        {"window_start": T0.isoformat(), "window_end": (T0 + timedelta(days=1)).isoformat()},
        {"window_start": T0.isoformat()},
    ],
)
def test_http_export_refuses_scoped_requests_without_changing_native_state(
    context: Context,
    client: TestClient,
    parameters: dict[str, str],
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository()
        uow.commit()
    headers = bearer(context)
    before = snapshot(context)
    response = client.get(URL, params=parameters, headers=headers)
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert "rows" not in response.json()
    assert snapshot(context) == before


def test_http_empty_export_keeps_the_canonical_wrapper(
    context: Context, client: TestClient
) -> None:
    headers = bearer(context)
    before = snapshot(context)
    response = client.get(URL, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == {"rows": []}
    assert snapshot(context) == before


def test_http_budget_refusal_returns_a_problem_not_partial_inventory(
    context: Context,
    client: TestClient,
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/acme/widget-api")
        uow.commit()
    cache = context.config.locations.feeds_cache_dir()
    assert cache is not None
    path = cache / "product_definitions.json"
    document = json.loads(path.read_text())
    document["ps_modules"]["widget-1"]["default_cc"] = [
        f"contact{number}" for number in range(10_001)
    ]
    path.write_text(json.dumps(document))
    headers = bearer(context)
    before = snapshot(context)
    response = client.get(URL, headers=headers)
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert "rows" not in response.json()
    assert snapshot(context) == before
