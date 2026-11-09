from __future__ import annotations

import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from tests.v1.providers.test_cve_replay import NOW, SHA, advisory
from traust_core.v1.models.cve_replay import (
    CveReplayAudit,
    CveReplayCandidate,
    CveReplayState,
    CveReplayVerdict,
)
from traust_core.v1.models.identity import IdentitySource
from traust_core.v1.providers.osv import parse_osv

AUDIT = CveReplayAudit(
    repository_id=UUID(int=1),
    repository_ref_id=UUID(int=2),
    repository="https://example.test/project",
    audited_commit=SHA,
    audit_id=UUID(int=3),
    report_artifact_id=UUID(int=4),
    audited_at=NOW.replace(month=10, day=1),
)
PRESENCE = {
    "present_at_audit": True,
    "reviewer": "human:reviewer",
    "presence_identity_source": IdentitySource.LOCAL_USER,
    "presence_evidence": "git show audited-sha:pkg/archive/extract.go; unsafe extraction verified",
}


def classify(text: str = "", **kwargs: object) -> CveReplayCandidate:
    return CveReplayCandidate.classify(
        AUDIT, text, parse_osv(json.dumps(advisory()).encode(), "fixture:osv"), NOW, **kwargs
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CVE-2026-99901 affects the extraction handler", CveReplayVerdict.DETECTED),
        ("ghsa-2345-6789-cfgh affects extraction", CveReplayVerdict.DETECTED),
        ("The pkg/archive handler was examined", CveReplayVerdict.UNCLEAR),
        ("Extractor.Extract joins untrusted paths", CveReplayVerdict.UNCLEAR),
        ("Unauthenticated job routing middleware", CveReplayVerdict.MISSED),
        ("CVE-2026-999010 is a different advisory", CveReplayVerdict.MISSED),
        ("example.test/project is the module root", CveReplayVerdict.MISSED),
    ],
)
def test_identifier_matches_are_distinct_from_area_only_coverage(
    text: str, expected: CveReplayVerdict
) -> None:
    check = classify(text, **PRESENCE)
    assert check.audit_verdict == expected
    assert check.trend_eligible is (expected == CveReplayVerdict.MISSED)
    assert check.requires_human_review is True


def test_missing_report_evidence_never_establishes_presence_or_a_miss() -> None:
    check = classify()
    assert check.present_at_audit is None
    assert check.audit_verdict == CveReplayVerdict.UNCLEAR
    state = CveReplayState(checks=(check,))
    assert state.candidates().candidates == (check,)
    assert state.trends().rows == ()


@pytest.mark.parametrize("presence", [True, False])
def test_presence_verdict_requires_both_human_identity_and_evidence(presence: bool) -> None:
    for fields in ({}, {"reviewer": "human:reviewer"}, {"presence_evidence": "source evidence"}):
        with pytest.raises((ValidationError, ValueError)):
            classify(present_at_audit=presence, **fields)


def test_human_absence_and_withdrawn_advisories_never_enter_queue_or_trends() -> None:
    absent = classify(**{**PRESENCE, "present_at_audit": False})
    withdrawn = CveReplayCandidate.classify(
        AUDIT,
        "",
        parse_osv(json.dumps(advisory(withdrawn="2026-11-03T00:00:00Z")).encode(), "osv"),
        NOW,
        **PRESENCE,
    )
    state = CveReplayState(checks=(absent, withdrawn))
    assert absent.audit_verdict == withdrawn.audit_verdict == CveReplayVerdict.NOT_APPLICABLE
    assert state.candidates().candidates == state.trends().rows == ()


def test_alias_republication_is_idempotent_and_human_adjudication_can_correct_presence() -> None:
    unknown = classify()
    confirmed = classify(**PRESENCE)
    alias = confirmed.model_copy(
        update={"advisory_id": "GO-2026-99903", "aliases": ("CVE-2026-99901",)}
    )
    state = CveReplayState().merged((unknown, confirmed, alias, unknown))
    assert len(state.checks) == 1
    assert state.trends().rows == (alias,)
    corrected = classify(**{**PRESENCE, "present_at_audit": False})
    state = state.merged((corrected,))
    assert state.checks == (corrected,)
    assert state.candidates().candidates == state.trends().rows == ()


def test_same_advisory_on_another_recorded_audit_has_independent_evidence() -> None:
    first = classify(**PRESENCE)
    other = first.model_copy(update={"audit_id": UUID(int=9), "audited_commit": "b" * 40})
    state = CveReplayState().merged((first, other))
    assert len(state.trends().rows) == 2


def test_unconfirmed_raw_candidate_cannot_claim_a_miss() -> None:
    values = classify().model_dump()
    values["audit_verdict"] = CveReplayVerdict.MISSED
    with pytest.raises(ValidationError, match="human-confirmed"):
        CveReplayCandidate.model_validate(values)


def test_snapshot_rejects_a_check_bound_to_another_original_report() -> None:
    from traust_core.v1.models.cve_replay import CveReplaySnapshot

    check = classify().model_copy(update={"report_artifact_id": UUID(int=99)})
    with pytest.raises(ValidationError, match="exact recorded audit"):
        CveReplaySnapshot(audit=AUDIT, revision=1, watermark=None, checks=(check,))
