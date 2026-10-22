"""Repository designations: adopter data (an extension in the data model), read once by Context."""

from __future__ import annotations

from pathlib import Path

from traust_core.v1.models.base import Dto
from traust_core.v1.models.observation import Designation, DesignationRecord


class _Entry(Dto):
    match: str | None = None
    exposure: str | None = None


class _File(Dto):
    designations: tuple[_Entry, ...] = ()


def load_designations(path: Path) -> tuple[DesignationRecord, ...]:
    try:
        document = _File.model_validate_json(path.read_bytes())
    except (OSError, ValueError):
        return ()
    return tuple(
        DesignationRecord(match=row.match, designation=Designation(row.exposure))
        for row in document.designations
        if row.match and row.exposure in set(Designation)
    )
