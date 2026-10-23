"""One router per domain; app.py includes every router listed here."""

from __future__ import annotations

from traust_core.v1.rest.routes import health, identity

ROUTERS = (health.router, identity.router)
