from __future__ import annotations

from fastapi import APIRouter
from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import OccurrenceClaim, OccurrenceClaimReport
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()

# A page's worth of declared claims per request, the batch doors' own bound: the
# estate-scale batch discipline (identity resolution in one call, claims by
# fingerprint set), never a per-claim fan-out and never an unbounded statement.
MAX_OCCURRENCE_CLAIMS = 500


class OccurrenceClaimsBody(Model):
    """A batch of declared CVSS claims under one authority: a ticket and a rationale
    naming why the claims are recorded (the claim-audit discipline — a verified
    person's statement, never a machine's)."""

    ticket: str = Field(min_length=1, max_length=200)
    rationale: str = Field(min_length=10, max_length=20_000)
    claims: tuple[OccurrenceClaim, ...]


@router.post("/v1/occurrence-claims", responses=PROBLEMS(401, 403, 422))
def record_occurrence_claims(
    body: OccurrenceClaimsBody, findings: Findings, caller: Caller
) -> OccurrenceClaimReport:
    """Record CVSS claims occurrences' reports stated (the occurrence-claim door,
    foundry#97): each claim declares the finding by its fingerprint — the identity both
    sides share — the assessment that reported it, and the CVSS itself, and is answered
    honestly: recorded (the governed statement appended), already recorded (idempotent),
    already carried (the occurrence's own columns state it — the fixed intake's write),
    conflicting (the occurrence carries a different claim: the review list, never an
    overwrite), or refused (an unknown fingerprint, an assessment that did not report
    the finding, a claim that fails core's CVSS discipline — never a guess).

    The write is append-only: the claim lands as a person's data-error decision under
    the named ticket, never a column mutation — occurrence rows keep what they said,
    and the append-only guard trigger stays armed. A verified person records (the
    claim-audit authority: a machine principal is refused)."""
    if not body.claims:
        raise ValidationError("record named occurrence claims; the set is required")
    if len(body.claims) > MAX_OCCURRENCE_CLAIMS:
        raise ValidationError(
            f"record at most {MAX_OCCURRENCE_CLAIMS} occurrence claims per request"
        )
    return findings.record_occurrence_claims(
        body.claims,
        ticket=body.ticket,
        rationale=body.rationale,
        principal=caller,
    )
