"""The preflight REST resource: may this stage run on this subject, now."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.models.operations import PreflightRequest, PreflightResult
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.ops.service import Ops

router = APIRouter()


@router.post("/v1/preflight", responses=PROBLEMS(401, 403, 422))
def preflight(body: PreflightRequest, ops: Ops, caller: Caller) -> PreflightResult:
    """Fail fast before a run spends money; denials carry typed `code` and `issues[].code`."""
    return ops.preflight(body, caller)
