"""The operations REST resources: the run-order queue (claim, lease, complete, reads), feed and
preflight."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.ops import feed, orders, preflight

router = APIRouter(tags=["ops"])
router.include_router(orders.router)
router.include_router(feed.router)
router.include_router(preflight.router)

__all__ = ["router"]
