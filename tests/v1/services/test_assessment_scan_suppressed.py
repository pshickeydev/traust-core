from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services.test_assessment_scan import SCANNERS, a_ref, provenance
from tests.v1.services.test_assessment_scan import context as context
from tests.v1.services.test_assessment_scan import engine as engine
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.findings import CandidateFormat, FindingCandidate
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def suppressed_sarif() -> bytes:
    body = json.loads((SCANNERS / "codeql.sarif").read_bytes())
    first = body["runs"][0]["results"][0]
    first["suppressions"] = [{"kind": "external", "status": "accepted"}]
    body["runs"][0]["results"] = [first]
    return json.dumps(body).encode()


def test_suppressed_scanner_claims_are_opt_in_without_turning_suppression_into_a_verdict(
    context: Context,
    engine: Engine,
) -> None:
    service = context.services().assessment
    ref, raw, prov = a_ref(engine), suppressed_sarif(), provenance()
    first, skipped = service.record_scan(ref, raw, CandidateFormat.SARIF, prov)
    assert skipped.findings == {}
    same, admitted = service.record_scan(
        ref,
        raw,
        CandidateFormat.SARIF,
        prov,
        include_suppressed=True,
    )
    assert same.id == first.id and len(admitted.created) == 1
    [finding_id] = admitted.created
    found = context.services().findings.get(finding_id)
    assert found.disposition is None and found.is_open()
    with SqlTraustUnitOfWork(engine) as uow:
        [occurrence] = uow.occurrences.list_for_assessment(first.id)
    assert occurrence.finding_id == finding_id
    repeated, replay = service.record_scan(
        ref,
        raw,
        CandidateFormat.SARIF,
        prov,
        include_suppressed=True,
    )
    assert repeated.id == first.id and replay.created == ()
    assert replay.findings == admitted.findings


def test_candidate_boundary_preserves_default_suppression_and_can_include_it() -> None:
    raw, repository_id = suppressed_sarif(), uuid4()
    assert FindingCandidate.parse_many(raw, CandidateFormat.SARIF, repository_id) == []
    [candidate] = FindingCandidate.parse_many(
        raw,
        CandidateFormat.SARIF,
        repository_id,
        include_suppressed=True,
    )
    assert candidate.repository_id == repository_id
    assert candidate.rule == "go/log-injection" and candidate.reported_severity == "high"


@pytest.mark.parametrize("format", [CandidateFormat.DEPENDABOT, CandidateFormat.GOVULNCHECK])
def test_suppression_option_is_refused_for_formats_without_sarif_suppression(
    format: CandidateFormat,
) -> None:
    with pytest.raises(ValidationError, match="only to SARIF"):
        FindingCandidate.parse_many(b"[]", format, uuid4(), include_suppressed=True)
