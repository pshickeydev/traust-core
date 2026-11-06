from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.remediation_scheduling import (
    Remediation,
    RemediationDetail,
    RemediationRequest,
)
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.remediation.service import Scheduling

router = APIRouter()


@router.post("/v1/remediations", responses=PROBLEMS(401, 403, 404, 409, 422))
def create_remediation(
    body: RemediationRequest, scheduling: Scheduling, caller: Caller
) -> Remediation:
    """Schedule a remediation — the fork the fix lands on and the findings to fix — opening
    the work item and the order that runs it. The entry point for SCI's automated trigger
    and the console's manual button: a verified person, or a machine granted
    `remediate_finding` on the repository in `recording.start`."""
    return scheduling.create(str(body.fork_url), body.fork_branch, body.findings, caller)


@router.get("/v1/remediations", responses=PROBLEMS(401, 422))
def list_remediations(
    scheduling: Scheduling,
    _: Caller,
    status: RemediationStatus | None = None,
    repository_id: UUID | None = None,
    finding_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Remediation]:
    """Scheduled remediations, oldest first, a page at a time: at a status, on a repository,
    on a finding (every filter given applies)."""
    return scheduling.list(
        PageRequest(limit=limit, cursor=cursor),
        status=status,
        repository_id=repository_id,
        finding_id=finding_id,
    )


@router.get("/v1/remediations/{remediation_id}", responses=PROBLEMS(401, 404))
def get_remediation(remediation_id: UUID, scheduling: Scheduling, _: Caller) -> RemediationDetail:
    """One scheduled remediation with its findings and the work item it opened."""
    return scheduling.get(remediation_id)
