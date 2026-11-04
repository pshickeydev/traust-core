"""Every array of findings a contracts schema carries, and what becomes of it. A recorded document
whose findings no door admits is the gap traust-core#356 closed for secure-code audits: the audit
was stored and nothing downstream ever saw a finding. A new findings array fails here until it is
admitted or listed with the reason it isn't (connectivity audit 2026-11-03)."""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from traust_core.v1 import contracts
from traust_core.v1.models.assessment import RECORDED_SCHEMAS, REPORTED_FINDINGS, AssessmentKind

# Arrays a kind recorded through `AssessmentService.record` admits (REPORTED_FINDINGS).
REPORTED = {("report", "findings"), ("vuln-findings", "findings"), ("fuzz-report", "crashers")}

# Arrays another door admits, named so the test can check the door still exists.
ADMITTED_ELSEWHERE = {
    ("cloud-config-audit", "findings"): "traust_core.v1.models.cloud_config:audit_candidates",
}

# Arrays that are not new findings, and why.
NOT_ADMITTED = {
    ("triage", "findings"): "verdicts on recorded findings (`traust triage record`)",
    ("validation", "validated_findings"): "verdicts on explicitly bound recorded findings",
    ("verification", "verified_findings"): "verification of recorded findings' fixes",
    ("remediation", "source_findings"): "references to the recorded findings it fixes",
    ("vuln-findings", "known_findings"): "the baseline's findings, carried for the diff",
    ("cloud-config-findings-current", "findings"): "a derived view over recorded findings",
    ("pqc-blockers", "findings"): "a derived projection of readiness remediations",
    ("compliance-assessment", "results"): "control results, not findings",
    ("adapter-result", "findings"): "tool hits `run_tools` hands to the auditing session",
}

# Arrays of new findings no door admits yet: each is an open gap with its tracking note.
GAPS = {
    ("validation", "novel_findings"): "connectivity audit 2026-11-03 #6",
}

# Kinds recorded with a findings-bearing schema that admit none, and why.
UNREPORTED_KINDS = {
    AssessmentKind.BENCHMARK_AUDIT: "scored against the answer key, never admitted",
    AssessmentKind.CLOUD_CONFIG_CANONICAL: "recorded through record_audit (ADMITTED_ELSEWHERE)",
}


def _arrays() -> set[tuple[str, str]]:
    found = set()
    for name in contracts.schema_names():
        props: dict[str, Any] = contracts.schema(name).get("properties", {})
        found |= {
            (name, key)
            for key, node in props.items()
            if isinstance(node, dict)
            and node.get("type") == "array"
            and ("finding" in key or key in ("crashers", "results"))
            and key != "findings_summary"
        }
    return found


def test_every_findings_array_is_classified() -> None:
    classified = REPORTED | ADMITTED_ELSEWHERE.keys() | NOT_ADMITTED.keys() | GAPS.keys()
    assert _arrays() == classified


def test_classes_do_not_overlap() -> None:
    groups = [REPORTED, set(ADMITTED_ELSEWHERE), set(NOT_ADMITTED), set(GAPS)]
    assert sum(map(len, groups)) == len(set().union(*groups))


def test_a_recorded_kind_with_a_reported_array_admits_it() -> None:
    schemas = {schema for schema, _ in REPORTED}
    for kind, schema in RECORDED_SCHEMAS.items():
        if schema in schemas:
            assert kind in REPORTED_FINDINGS or kind in UNREPORTED_KINDS, kind
    assert {RECORDED_SCHEMAS[k] for k in REPORTED_FINDINGS} == schemas


@pytest.mark.parametrize("door", sorted(ADMITTED_ELSEWHERE.values()))
def test_each_named_door_exists(door: str) -> None:
    module, name = door.split(":")
    assert callable(getattr(importlib.import_module(module), name))
