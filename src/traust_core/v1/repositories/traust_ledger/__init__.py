"""5 · Ledger (traust_ledger) - app-owned proof tables; traust-ledger (library) computes.

One repository per table. SQLite carries the namespace as the `ledger_` prefix.
"""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.traust_ledger.events import (
    EVENTS,
    EventRepository,
    SqlEventRepository,
)
from traust_core.v1.repositories.traust_ledger.layers import (
    LAYERS,
    LayerRepository,
    SqlLayerRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (LAYERS, EVENTS)


class LedgerUnitOfWork(UnitOfWork, Protocol):
    layers: LayerRepository
    events: EventRepository


__all__ = [
    "TABLES",
    "EventRepository",
    "LayerRepository",
    "LedgerUnitOfWork",
    "SqlEventRepository",
    "SqlLayerRepository",
]
