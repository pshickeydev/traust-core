"""Open counts over the finding_status view: the one definition of "open".

The view is part of the contracts DDL (findings domain); severity is the latest
re-rating, is_open encodes the closed-set exclusions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.sql import SqlRepository
from traust_core.v1.repositories.tables import TRAUST, Dialect, RecordUuid


def _view(dialect: Dialect) -> sa.TableClause:
    schema, name = TRAUST.locate("finding_status", dialect)
    return sa.table(
        name,
        sa.column("repository_id", RecordUuid),
        sa.column("severity", sa.Text),
        sa.column("is_open", sa.Boolean),
        schema=schema,
    )


class OpenCounts(Protocol):
    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int: ...


class SqlOpenCounts(SqlRepository):
    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        view = _view(Dialect.of(self._connection))
        stmt = (
            sa.select(sa.func.count())
            .select_from(view)
            .where(
                view.c.repository_id == repository_id,
                view.c.is_open,
                view.c.severity.in_([str(s) for s in severities]),
            )
        )
        return int(self._execute(f"count open findings for {repository_id}", stmt).scalar_one())
