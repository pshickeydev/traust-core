from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services import test_inventory_export as inventory_fixtures
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.product_definitions import CONTACT_FIELDS, ProductSourceStatus
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

engine = inventory_fixtures.engine
context = inventory_fixtures.context
cache = inventory_fixtures.cache
CONTACTS = (
    "embargoperson (private_tracker_cc; embargo_cleared=True)",
    "componentperson (component_cc; embargo_cleared=False)",
    "publicperson (default_cc; embargo_cleared=False)",
)


@pytest.fixture
def native_repository(context: Context) -> Repository:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/acme/widget-api")
        seed.ownership(repository, seed.team(name="native-team"))
        release = seed.release(seed.product(slug="native-product"))
        seed.component(release, seed.repository_ref(repository))
        uow.commit()
    return repository


def replace(cache: Path, path: tuple[str, ...], value: object) -> None:
    source = cache / "product_definitions.json"
    document = json.loads(source.read_text())
    if path:
        node = document
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    else:
        document = value
    source.write_text(json.dumps(document))


@pytest.mark.parametrize(
    "metadata",
    [
        [],
        ["product-definitions"],
        None,
        "metadata",
        42,
        False,
        {},
        *({"product-definitions": entry} for entry in ([], ["entry"], None, "entry", 42, True)),
        *({"product-definitions": {"retrieved_at": value}} for value in (None, [], {}, 42, True)),
        {"product-definitions": {}},
    ],
)
def test_malformed_freshness_keeps_valid_definitions_and_native_inventory(
    context: Context, cache: Path, native_repository: Repository, metadata: object
) -> None:
    (cache / "feeds-meta.json").write_text(json.dumps(metadata))
    snapshot = context.product_definitions().read()
    assert snapshot.status == ProductSourceStatus.STALE
    assert snapshot.source.retrieved_at is None
    assert snapshot.source.age_hours is None
    assert snapshot.document is not None
    (row,) = context.services().portfolio.inventory_export()
    assert row.url == native_repository.url
    assert row.owner_teams == ("native-team",)
    assert row.products == ("native-product",)
    assert row.accountable_contacts == CONTACTS


@pytest.mark.parametrize("text", ["not json", ""])
def test_unreadable_freshness_keeps_valid_contacts(
    context: Context, cache: Path, native_repository: Repository, text: str
) -> None:
    (cache / "feeds-meta.json").write_text(text)
    snapshot = context.product_definitions().read()
    assert snapshot.status == ProductSourceStatus.STALE
    assert snapshot.source.retrieved_at is snapshot.source.age_hours is None
    (row,) = context.services().portfolio.inventory_export()
    assert row.url == native_repository.url
    assert row.accountable_contacts == CONTACTS


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ((), []),
        ((), None),
        (("ps_products",), []),
        (("ps_modules",), []),
        (("ps_update_streams",), []),
        *((("ps_products", "widget"), value) for value in ([], None, "product", 1)),
        *((("ps_modules", "widget-1"), value) for value in ([], None, "module", 1)),
        *((("ps_update_streams", "widget-1-default"), value) for value in ([], None, "stream", 1)),
        (("ps_products", "widget", "name"), []),
        (("ps_products", "widget", "ps_modules"), "widget-1"),
        (("ps_products", "widget", "ps_modules"), {}),
        (("ps_products", "widget", "ps_modules"), [[]]),
        (("ps_products", "widget", "ps_modules"), [None]),
        (("ps_modules", "widget-1", "ps_update_streams"), "widget-1-default"),
        (("ps_modules", "widget-1", "ps_update_streams"), {}),
        (("ps_modules", "widget-1", "ps_update_streams"), [{}]),
        (("ps_modules", "widget-1", "ps_update_streams"), [1]),
        (("ps_modules", "widget-1", "lifecycle"), []),
        (("ps_modules", "widget-1", "lifecycle"), "supported"),
        (("ps_modules", "widget-1", "lifecycle"), {"supported_from": 1}),
        (("ps_modules", "widget-1", "lifecycle"), {"supported_until": ["2027-01-01"]}),
        *(
            (("ps_modules", "widget-1", field), {"widget-core": members})
            for field, _, _ in CONTACT_FIELDS
            for members in (1, "person", {"person": []})
        ),
        (("ps_update_streams", "widget-1-default", "managed_service_components"), {}),
        (("ps_update_streams", "widget-1-default", "managed_service_components"), "component"),
        (("ps_update_streams", "widget-1-default", "managed_service_components"), [None]),
        (("ps_update_streams", "widget-1-default", "managed_service_components"), [[]]),
        (
            ("ps_update_streams", "widget-1-default", "managed_service_components"),
            [{"git_repo_url": ["https://github.com/acme/widget-api"]}],
        ),
        (
            ("ps_update_streams", "widget-1-default", "managed_service_components"),
            [{"name": {}, "git_repo_url": "https://github.com/acme/widget-api"}],
        ),
    ],
)
def test_malformed_consumed_shapes_make_only_optional_contacts_unknown(
    context: Context,
    cache: Path,
    native_repository: Repository,
    path: tuple[str, ...],
    value: object,
) -> None:
    replace(cache, path, value)
    snapshot = context.product_definitions().read()
    assert snapshot.status == ProductSourceStatus.UNAVAILABLE
    assert snapshot.document is None
    assert snapshot.source.detail
    services = context.services()
    (row,) = services.portfolio.inventory_export()
    assert row.url == native_repository.url
    assert row.owner_teams == ("native-team",)
    assert row.products == ("native-product",)
    assert row.accountable_contacts is None
    rendered = services.insight.publish(ViewName.INVENTORY_EXPORT, ViewFilter())
    assert rendered.model.model_dump(mode="json")["rows"][0]["Accountable Contacts"] == []
    assert rendered.csv is not None
    (record,) = csv.DictReader(io.StringIO(rendered.csv))
    assert record["Accountable Contacts"] == "—"


@pytest.mark.parametrize(
    ("path", "value", "contacts"),
    [
        (("ps_products", "widget", "name"), None, CONTACTS),
        (("ps_products", "widget", "ps_modules"), None, CONTACTS),
        (("ps_modules", "widget-1", "ps_update_streams"), None, ()),
        (("ps_modules", "widget-1", "lifecycle"), None, CONTACTS),
        (
            ("ps_update_streams", "widget-1-default", "managed_service_components"),
            [{"name": None, "git_repo_url": "https://github.com/acme/widget-api"}],
            CONTACTS,
        ),
        (
            ("ps_update_streams", "widget-1-default", "managed_service_components"),
            [{"name": "widget-api", "git_repo_url": None}],
            None,
        ),
        (
            ("ps_update_streams", "widget-1-default", "managed_service_components"),
            None,
            None,
        ),
    ],
)
def test_nullable_consumed_fields_keep_existing_resolution_semantics(
    context: Context,
    cache: Path,
    native_repository: Repository,
    path: tuple[str, ...],
    value: object,
    contacts: tuple[str, ...] | None,
) -> None:
    replace(cache, path, value)
    assert context.product_definitions().read().status == ProductSourceStatus.OK
    (row,) = context.services().portfolio.inventory_export()
    assert row.url == native_repository.url
    assert row.accountable_contacts == contacts


def test_unknown_fields_and_dropped_contact_values_keep_source_semantics(
    context: Context, cache: Path, native_repository: Repository
) -> None:
    source = cache / "product_definitions.json"
    document = json.loads(source.read_text())
    document["future_registry_field"] = [None, {"future": 1}]
    document["ps_products"]["widget"]["future"] = [False]
    module = document["ps_modules"]["widget-1"]
    module["future"] = "ignored"
    module["default_cc"].extend([None, 42, {}, [], "Not Kerberos"])
    module["component_cc"]["widget-core"].extend([None, 42, {}, []])
    module["component_cc"]["empty"] = None
    module["private_tracker_cc_component_override"] = 42
    document["ps_update_streams"]["widget-1-default"]["future"] = {}
    source.write_text(json.dumps(document))
    snapshot = context.product_definitions().read()
    assert snapshot.status == ProductSourceStatus.OK
    assert snapshot.document == document
    portfolio = context.services().portfolio
    (row,) = portfolio.inventory_export()
    assert row.url == native_repository.url
    assert row.accountable_contacts == CONTACTS
    resolution = portfolio.resolve_products(
        snapshot, portfolio.product_mappings(), repo_urls=[native_repository.url]
    )
    (match,) = resolution.results
    assert [contact.value for contact in match.dropped_contacts] == ["+unexpanded", "Not Kerberos"]
    assert match.lifecycle.state == "supported"


@pytest.mark.parametrize("section", ["contacts", "components", "links"])
def test_valid_registry_work_still_refuses_exhausted_record_budget(
    context: Context, cache: Path, native_repository: Repository, section: str
) -> None:
    if section == "contacts":
        path = ("ps_modules", "widget-1", "default_cc")
        value = [f"person{index}" for index in range(101)]
    elif section == "components":
        path = ("ps_update_streams", "widget-1-default", "managed_service_components")
        value = [
            {"name": f"component{index}", "git_repo_url": native_repository.url}
            for index in range(101)
        ]
    else:
        path = ("ps_products", "widget", "ps_modules")
        value = ["widget-1"] * 101
    replace(cache, path, value)
    assert context.product_definitions().read().status == ProductSourceStatus.OK
    portfolio = context.services().portfolio
    with pytest.raises(ValidationError):
        portfolio.inventory_export(max_records=100)
    (row,) = portfolio.inventory_export(max_records=10_000)
    assert row.url == native_repository.url
    assert row.owner_teams == ("native-team",)
    assert row.products == ("native-product",)
