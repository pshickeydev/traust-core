"""The dashboard facts read: the measured SQL, every fact a lookup, state
from the stamped fold. Values are bound, identifiers come from the service's
catalog."""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from traust_core.v1.models.dashboard import Subject

# The estate join: a repository ships in any number of products (release
# components name refs), so a finding fans out to one row per product that
# ships its repository, NULL when none does. The count measures go distinct
# in that mode (the catalog's call), so a shared repository's findings count
# once per product row and once under a multi-product filter.
_ESTATE = """
        LEFT JOIN (
            SELECT DISTINCT rr.repository_id AS repository_id, p.slug AS product
            FROM repository_ref rr
            JOIN component c ON c.repository_ref_id = rr.id
            JOIN "release" rel ON rel.id = c.release_id
            JOIN product p ON p.id = rel.product_id
        ) estate ON estate.repository_id = f.repository_id
"""

# The findings subject's facts: one indexed row per finding, read as stored. State,
# severity and decided are the finding's current answer, stamped by core's write doors
# from the fold; category is its first category label. NULL severity is unrated.
_FINDING_SELECT = """
    SELECT f.id, f.repository_id, f.created_at,
        f.current_state AS state,
        f.current_severity AS severity,
        coalesce(f.category, '<none>') AS category,
        f.current_decided AS decided
"""

# The review_items subject's facts: one row per review item, with its finding's
# repository and current answer (state, severity) - one join, no fold.
_REVIEW_SELECT = """
    SELECT r.id, f.repository_id, r.reason, r.status,
        f.current_state AS state, f.current_severity AS severity
"""

_SELECTS = {Subject.FINDINGS: _FINDING_SELECT, Subject.REVIEW_ITEMS: _REVIEW_SELECT}
_SOURCES = {
    Subject.FINDINGS: "FROM finding f",
    Subject.REVIEW_ITEMS: "FROM review_item r JOIN finding f ON f.id = r.finding_id",
}


def _facts_sql(subject: Subject, products: bool) -> str:
    """The subject's facts CTE; `products` adds the estate join and a `product`
    column (the shipped product's slug)."""
    select = _SELECTS[subject]
    source = _SOURCES[subject]
    if products:
        select += ",\n            estate.product AS product"
        source += _ESTATE
    return f"WITH facts AS (\n{select}\n    {source}\n    )\n"


_ROW_CAP = 1000


class SqlDashboardFacts:
    """The measured SQL through the house connection. Table names are the
    contract tables' unprefixed spellings (schema-qualified by the search path
    the unit of work sets); values are bound, identifiers come from the catalog."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def aggregate(
        self,
        subject: Subject,
        repository_ids: frozenset[UUID] | None,
        columns: list[str],
        aggregates: list[str],
        predicates: list[tuple[str, tuple[str, ...]]],
        order: list[str],
        limit: int,
        products: bool = False,
    ) -> list[tuple[object, ...]]:
        facts = _facts_sql(subject, products)  # require() refused the rest
        selected = [*columns, *aggregates]
        stmt = facts + f"SELECT {', '.join(selected)} FROM facts"
        conditions: list[str] = []
        binds: dict[str, object] = {}
        if repository_ids is not None:
            conditions.append("repository_id IN :repository_ids")
            binds["repository_ids"] = [str(identifier) for identifier in repository_ids]
        for index, (column, values) in enumerate(predicates):
            conditions.append(f"{column} IN :w_{index}")
            binds[f"w_{index}"] = list(values)
        if conditions:
            stmt += " WHERE " + " AND ".join(conditions)
        if columns:
            stmt += " GROUP BY " + ", ".join(columns)
        if order:
            stmt += " ORDER BY " + ", ".join(order)
        stmt += f" LIMIT {min(limit, _ROW_CAP)}"
        statement = sa.text(stmt)
        for name in binds:
            statement = statement.bindparams(sa.bindparam(name, expanding=True))
        return [tuple(row) for row in self._connection.execute(statement, binds).all()]
