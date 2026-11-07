from __future__ import annotations

import pytest
from pydantic import ValidationError

from traust_core.v1.models.insight import InventoryExport
from traust_core.v1.models.inventory import InventoryExportRow

COLUMNS = (
    "Repository",
    "URL",
    "Host",
    "Organization/Group",
    "Repo Name",
    "Owner Team",
    "Products",
    "Accountable Contacts",
)


def test_canonical_wrapper_has_exact_ordered_aliases_and_preserves_raw_text() -> None:
    hostile = '=SUM(1,2)\r\n| forged | <script>alert("x")</script>\x00'
    row = InventoryExportRow(
        repository=hostile,
        url="not a URL\n" + hostile,
        host="",
        organization=hostile,
        repo_name="",
        owner_teams=(hostile, ""),
        products=("", hostile),
        accountable_contacts=(hostile,),
    )
    exported = InventoryExport(rows=(row,))
    document = exported.model_dump(mode="json")
    assert tuple(document) == ("rows",)
    assert tuple(document["rows"][0]) == COLUMNS
    assert document == {
        "rows": [
            {
                "Repository": hostile,
                "URL": "not a URL\n" + hostile,
                "Host": "",
                "Organization/Group": hostile,
                "Repo Name": "",
                "Owner Team": [hostile, ""],
                "Products": ["", hostile],
                "Accountable Contacts": [hostile],
            }
        ]
    }
    assert InventoryExport.model_validate_json(exported.model_dump_json()) == exported


def test_empty_values_and_empty_lists_remain_representable() -> None:
    document = {label: [] if label in COLUMNS[5:] else "" for label in COLUMNS}
    row = InventoryExportRow.model_validate(document)
    assert row.model_dump(mode="json") == document
    assert InventoryExport(rows=()).model_dump(mode="json") == {"rows": []}


@pytest.mark.parametrize("label", COLUMNS)
def test_every_canonical_row_property_is_required(label: str) -> None:
    document = {key: [] if key in COLUMNS[5:] else "" for key in COLUMNS}
    del document[label]
    with pytest.raises(ValidationError):
        InventoryExportRow.model_validate(document)


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("Repository", 123),
        ("Owner Team", None),
        ("Products", [123]),
        ("Accountable Contacts", "contact"),
        ("id", "unexpected"),
    ],
)
def test_row_refuses_wrong_types_null_lists_and_extra_identity(label: str, value: object) -> None:
    document = {key: [] if key in COLUMNS[5:] else "" for key in COLUMNS}
    document[label] = value
    with pytest.raises(ValidationError):
        InventoryExportRow.model_validate(document)


def test_canonical_wrapper_refuses_missing_rows_and_extra_storage_metadata() -> None:
    with pytest.raises(ValidationError):
        InventoryExport.model_validate({})
    with pytest.raises(ValidationError):
        InventoryExport.model_validate({"rows": [], "artifact_id": "not persisted"})


def test_a_row_cannot_be_mutated_after_validation() -> None:
    row = InventoryExportRow.model_validate(
        {key: [] if key in COLUMNS[5:] else "" for key in COLUMNS}
    )
    with pytest.raises(ValidationError):
        row.repository = "changed"
