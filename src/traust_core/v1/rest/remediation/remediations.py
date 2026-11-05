from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

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


@router.post("/v1/remediations", responses=PROBLEMS(401, 404, 409, 422))
def create_remediation(
    body: RemediationRequest, scheduling: Scheduling, caller: Caller
) -> Remediation:
    """Schedule a remediation — the fork the fix lands on and the findings to fix — opening
    the work item and the order that runs it. The entry point for SCI's automated trigger
    and the console's manual button; a machine or a person may call it."""
    return scheduling.create(str(body.fork_url), body.fork_branch, body.findings, caller)


@router.get("/v1/remediations", responses=PROBLEMS(401, 422))
def list_remediations(
    scheduling: Scheduling,
    _: Caller,
    status: RemediationStatus | None = None,
    repository_id: UUID | None = None,
    finding_id: UUID | None = None,
) -> list[Remediation]:
    """Scheduled remediations, oldest first: one status', one repository's or one finding's."""
    return scheduling.list(status=status, repository_id=repository_id, finding_id=finding_id)


@router.get("/v1/remediations/{remediation_id}", responses=PROBLEMS(401, 404))
def get_remediation(remediation_id: UUID, scheduling: Scheduling, _: Caller) -> RemediationDetail:
    """One scheduled remediation with its findings and the work item it opened."""
    return scheduling.get(remediation_id)
