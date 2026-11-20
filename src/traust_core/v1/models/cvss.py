"""A CVSS vector's qualitative rating — FIRST's bands, Red Hat's `cvss`.

main's hotfix carries only the rating a vector computes; development's module holds
the full advisory-source scoring this file is a strict subset of.
"""

from __future__ import annotations

import re
from typing import Literal

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

from traust_core.v1.models.vocabulary import Severity

CvssVersion = Literal["3.0", "3.1", "4.0"]

_VECTOR: dict[CvssVersion, re.Pattern[str]] = {
    "3.0": re.compile(r"CVSS:3\.0(/[A-Z]{1,3}:[A-Z])+"),
    "3.1": re.compile(r"CVSS:3\.1(/[A-Z]{1,3}:[A-Z])+"),
    "4.0": re.compile(r"CVSS:4\.0(/[A-Z]{1,3}:[A-Za-z]{1,5})+"),
}
# The spec's 4.0 metric order, which the library doesn't check; it refuses every other malformation.
_V4_ORDER = (
    *("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "E", "CR", "IR", "AR"),
    *("MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"),
    *("S", "AU", "R", "V", "RE", "U"),
)


def severity_of(vector: str | None) -> Severity | None:
    """A vector's qualitative rating — FIRST's bands, Red Hat's `cvss` — or None when the
    vector doesn't parse: never a guess at a malformed one. CVSS "None" reads informational."""
    if not isinstance(vector, str) or (version := _version(vector)) is None:
        return None
    # the spec's 4.0 metric order — a vector the scoring path rejects as malformed never
    # supplies a computed label either
    if version == "4.0" and not _in_spec_order(vector, version):
        return None
    try:
        parsed = CVSS4(vector) if version == "4.0" else CVSS3(vector)
        label = parsed.severities()[0]
    except CVSSError:
        return None
    return Severity.INFORMATIONAL if label == "None" else Severity(label.lower())


def _version(vector: str) -> CvssVersion | None:
    return next((v for v, pattern in _VECTOR.items() if pattern.fullmatch(vector)), None)


def _in_spec_order(vector: str, version: CvssVersion) -> bool:
    """4.0 requires the spec's metric order; 3.x allows any."""
    if version != "4.0":
        return True
    keys = [pair.split(":", 1)[0] for pair in vector.split("/")[1:]]
    if not set(keys) <= set(_V4_ORDER):
        return False
    positions = [_V4_ORDER.index(key) for key in keys]
    return positions == sorted(positions)
