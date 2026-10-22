from __future__ import annotations

from pathlib import Path
from uuid import UUID

from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    RecordDecision,
    StatementKey,
    TriageInput,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import RestatementReason
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.lint import Lint, LintContext, LintReport


class FindingDecisions:
    """Decisions are the only writes to a finding's state; every read is a view over them."""

    def __init__(self, uow: TraustUnitOfWork, ledger: LedgerService | None, lint: Lint) -> None:
        self._uow = uow
        self._ledger = ledger
        self._lint = lint

    def decide(self, command: RecordDecision) -> Disposition:
        raise NotImplementedError("stub: replaces emit_*_ledger_events.py, ledger event_handler")

    def statement_key(self, decision: Decision) -> StatementKey:
        raise NotImplementedError("stub: replaces ledger compute_event_id (classifier steps 9/12)")

    def restate(
        self, decision_id: UUID, reason: RestatementReason, principal: Principal
    ) -> Disposition:
        raise NotImplementedError("stub: replaces ledger events/builders.build_restatement_event")

    def prepare(self, assessment_id: UUID) -> TriageInput:
        raise NotImplementedError("stub: replaces the triage skill's query_index / precedent CLIs")

    def check(self, doc: TriageArtifact, checkout: Path) -> LintReport:
        """Lint the triage against the target checkout: after the votes, before `record`."""
        return self._lint.run(doc, LintContext(files=WorkspaceFiles(checkout)))

    def record(self, doc: TriageArtifact, provenance: Provenance) -> list[Decision]:
        """A triage is an assessment (kind triage) and one decision per verdict, one transaction."""
        raise NotImplementedError("stub: replaces record_triage, emit_triage_ledger_events")
