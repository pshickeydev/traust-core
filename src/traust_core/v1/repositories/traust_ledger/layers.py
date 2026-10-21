from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.ledger import Layer
from traust_core.v1.repositories.tables import (
    TRAUST_LEDGER,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

LAYERS = TableSpec(
    TRAUST_LEDGER,
    "layers",
    lambda: (
        uuid_column("repository_id"),
        text_column("line", nullable=True),
        text_column("merkle_root", nullable=True),
        sa.Column("merkle_epoch", sa.Integer, nullable=True),
        sa.Column("merkle_size", sa.Integer, nullable=True),
        text_column("merkle_root_signature", nullable=True),
        text_column("merkle_signing_method"),
        sa.Column("merkle_signature_format", sa.Integer, nullable=True),
    ),
)


class LayerRepository(MutableRecordRepository[Layer], Protocol):
    def list_for_repository(self, repository_id: UUID) -> list[Layer]: ...


class SqlLayerRepository(SqlMutableRepository[Layer]):
    spec = LAYERS
    record = Layer

    def list_for_repository(self, repository_id: UUID) -> list[Layer]:
        return self._many(f"list for {repository_id}", self.table.c.repository_id == repository_id)
