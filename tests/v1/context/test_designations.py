import json

from traust_core.v1.context.designations import load_designations
from traust_core.v1.models.observation import Designation, DesignationRecord


def test_designations_preserve_order(tmp_path):
    rows = (
        DesignationRecord(match="https://github.com/o/", designation=Designation.EXTERNAL),
        DesignationRecord(match="https://github.com/o/r", designation=Designation.INTERNAL_TOOLING),
    )
    path = tmp_path / "designations.json"
    path.write_text(
        json.dumps(
            {"designations": [{"match": row.match, "exposure": row.designation} for row in rows]}
        )
    )
    assert load_designations(path) == rows


def test_missing_or_invalid_designations_do_not_invent_exposure(tmp_path):
    path = tmp_path / "designations.json"
    assert load_designations(path) == ()
    path.write_text("{invalid")
    assert load_designations(path) == ()
    path.write_text('{"designations": [{"match": "x", "exposure": "not-a-designation"}]}')
    assert load_designations(path) == ()
