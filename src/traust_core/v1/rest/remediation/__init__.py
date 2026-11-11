from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.remediation import (
    remediation_records,
    remediations,
    verification_records,
    work_items,
)

router = APIRouter(tags=["remediation"])
router.include_router(remediation_records.router)
router.include_router(remediations.router)
router.include_router(verification_records.router)
router.include_router(work_items.router)

__all__ = ["router"]
