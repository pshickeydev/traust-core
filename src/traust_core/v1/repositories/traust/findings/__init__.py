"""3b · Findings & decisions - what was found and judged. One repository per table."""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.tables import SqlTablesUnitOfWork
from traust_core.v1.repositories.traust.findings.cwe import CWE, CweRepository, SqlCweRepository
from traust_core.v1.repositories.traust.findings.decision import (
    DECISION,
    DecisionRepository,
    SqlDecisionRepository,
)
from traust_core.v1.repositories.traust.findings.finding import (
    FINDING,
    FindingRepository,
    SqlFindingRepository,
)
from traust_core.v1.repositories.traust.findings.finding_cwe import (
    FINDING_CWE,
    FindingCweRepository,
    SqlFindingCweRepository,
)
from traust_core.v1.repositories.traust.findings.finding_external_ref import (
    FINDING_EXTERNAL_REF,
    FindingExternalRefRepository,
    SqlFindingExternalRefRepository,
)
from traust_core.v1.repositories.traust.findings.finding_label import (
    FINDING_LABEL,
    FindingLabelRepository,
    SqlFindingLabelRepository,
)
from traust_core.v1.repositories.traust.findings.review_item import (
    REVIEW_ITEM,
    ReviewItemRepository,
    SqlReviewItemRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (
    FINDING,
    CWE,
    FINDING_CWE,
    FINDING_LABEL,
    FINDING_EXTERNAL_REF,
    DECISION,
    REVIEW_ITEM,
)


class FindingsUnitOfWork(UnitOfWork, Protocol):
    findings: FindingRepository
    cwes: CweRepository
    finding_cwes: FindingCweRepository
    finding_labels: FindingLabelRepository
    finding_external_refs: FindingExternalRefRepository
    decisions: DecisionRepository
    review_items: ReviewItemRepository


class SqlFindingsUnitOfWork(SqlTablesUnitOfWork):
    def _open_repositories(self) -> None:
        conn, tables = self.connection, self.tables
        self.findings = SqlFindingRepository(conn, tables)
        self.cwes = SqlCweRepository(conn, tables)
        self.finding_cwes = SqlFindingCweRepository(conn, tables)
        self.finding_labels = SqlFindingLabelRepository(conn, tables)
        self.finding_external_refs = SqlFindingExternalRefRepository(conn, tables)
        self.decisions = SqlDecisionRepository(conn, tables)
        self.review_items = SqlReviewItemRepository(conn, tables)


__all__ = [
    "TABLES",
    "CweRepository",
    "DecisionRepository",
    "FindingCweRepository",
    "FindingExternalRefRepository",
    "FindingLabelRepository",
    "FindingRepository",
    "FindingsUnitOfWork",
    "ReviewItemRepository",
    "SqlCweRepository",
    "SqlDecisionRepository",
    "SqlFindingCweRepository",
    "SqlFindingExternalRefRepository",
    "SqlFindingLabelRepository",
    "SqlFindingRepository",
    "SqlFindingsUnitOfWork",
    "SqlReviewItemRepository",
]
