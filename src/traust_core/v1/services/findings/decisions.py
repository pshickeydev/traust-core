from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import (
    RATIONALE_MIN_LENGTH,
    RESTATABLE,
    Decision,
    DecisionApprover,
    Disposition,
    FindingContext,
    Location,
    RecordDecision,
    Restatement,
    StatementKey,
    SubjectRef,
    TriageInput,
    TriageItem,
    report_sources,
)
from traust_core.v1.models.identity import Principal, Role
from traust_core.v1.models.integrity import canonical_json, sha256_hex
from traust_core.v1.models.vocabulary import ActorKind, SourceType
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.lint import Lint, LintContext, LintReport

log = logging.getLogger(__name__)

PRECEDENTS_PER_FINDING = 3


_JUDGED = (
    "finding_id",
    "assessment_id",
    "actor",
    "repository_ref_id",
    "restates_id",
    "validity",
    "resolution",
    "evidence_grade",
    "reason",
    "severity",
    "fixed_repository_ref_id",
)


class FindingDecisions:
    """Decisions are the only writes to a finding's state; every read is a view over them."""

    def __init__(
        self,
        uow: TraustUnitOfWork,
        ledger: LedgerService | None,
        lint: Lint,
        precedents: FindingPrecedents,
        *,
        clock: Clock,
        restatement_approvers: int = 0,
    ) -> None:
        self._uow = uow
        self._ledger = ledger
        self._lint = lint
        self._precedents = precedents
        self._clock = clock
        self._restatement_approvers = restatement_approvers

    def decide(self, command: RecordDecision, principal: Principal) -> Decision:
        """A person's statement, if they may make it; a retried statement is the same decision."""
        with self._uow as uow:
            finding = uow.findings.get(command.finding_id)
            if command.repository_ref_id is not None:
                judged = uow.repository_refs.get(command.repository_ref_id)
                if judged.repository_id != finding.repository_id:
                    raise ValidationError(
                        f"commit {judged.id} is not in finding {finding.id}'s repository"
                    )
            now = self._clock.now()
            draft = Decision(
                **command.model_dump(exclude={"occurred_at"}),
                actor=principal.ref,
                occurred_at=command.occurred_at or now,
                statement_key="pending",
            )
            draft = draft.model_copy(update={"statement_key": self.statement_key(draft)})
            same = uow.decisions.find_by_statement(finding.id, draft.statement_key)
            if same is not None:
                return same
            history = uow.decisions.list_for_finding(finding.id)
            Disposition.admit(history, draft, principal, now, self._sources(history))
            saved = uow.decisions.add(draft)
            if self._ledger is not None:
                self._ledger.append_decision(saved, finding.repository_id)
            uow.commit()
        log.info("decision %s on finding %s by %s", saved.id, finding.id, principal.ref)
        return saved

    def _sources(self, history: Sequence[Decision]) -> dict[UUID, SourceType]:
        ids = {d.assessment_id for d in history if d.assessment_id}
        return report_sources(self._uow.assessments.list_by_ids(ids))

    def statement_key(self, decision: Decision) -> StatementKey:
        """The hash of every judged column: a retried statement is the same decision."""
        judged = {k: str(v) for k in _JUDGED if (v := getattr(decision, k)) is not None}
        return StatementKey(sha256_hex(canonical_json(judged)))

    def restate(self, restatement: Restatement, principal: Principal) -> Decision:
        """An administrator's correction: a new decision that replaces the one it restates."""
        approvers = self._authorize(restatement, principal)
        with self._uow as uow:
            restated = uow.decisions.get(restatement.decision_id)
            history = uow.decisions.list_for_finding(restated.finding_id)
            _check_correction(restatement, restated, history)
            commit = restated.repository_ref_id
            if restated.assessment_id is not None:
                commit = uow.assessments.get(restated.assessment_id).repository_ref_id
            draft = restated.model_copy(
                update={
                    **restatement.changes(),
                    "id": None,
                    "created_at": None,
                    "assessment_id": None,
                    "repository_ref_id": commit,
                    "restates_id": restated.id,
                    "auto_accept_tier": False,
                    "actor": principal.ref,
                    "reason": restatement.reason,
                    "ticket": restatement.ticket.strip(),
                    "rationale": restatement.rationale,
                    "occurred_at": self._clock.now(),
                }
            )
            saved = uow.decisions.add(
                draft.model_copy(update={"statement_key": self.statement_key(draft)})
            )
            for approver in sorted(approvers):
                ref = f"{ActorKind.HUMAN}:{approver}"
                uow.decision_approvers.add(DecisionApprover(decision_id=saved.id, approver=ref))
            if self._ledger is not None:
                repository_id = uow.findings.get(saved.finding_id).repository_id
                self._ledger.append_decision(saved, repository_id)
            uow.commit()
        log.info("decision %s restated as %s by %s", restated.id, saved.id, principal.ref)
        return saved

    def _authorize(self, restatement: Restatement, principal: Principal) -> set[str]:
        """Who may restate, and on whose authority (traust-ledger's restatement gates)."""
        if not principal.is_verified_human():
            raise ForbiddenError(f"{principal.ref}: a restatement is a verified human's correction")
        if not principal.has_role(Role.RESTATE):
            raise ForbiddenError(f"{principal.ref}: restating needs the restate role")
        if not restatement.ticket.strip():
            raise ValidationError("a restatement names its authority: a ticket")
        if len(restatement.rationale) < RATIONALE_MIN_LENGTH:
            raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
        approvers = {a.strip().lower() for a in restatement.approvers if a.strip()}
        approvers.discard(principal.identity)
        if len(approvers) < self._restatement_approvers:
            raise ForbiddenError(
                f"a restatement needs {self._restatement_approvers} approvers besides its author;"
                f" it names {len(approvers)}"
            )
        return approvers

    def prepare(self, assessment_id: UUID) -> TriageInput:
        """What a triage of one assessment judges: its findings as reported, where, precedents."""
        with self._uow as uow:
            assessment = uow.assessments.get(assessment_id)
            ref = uow.repository_refs.get(assessment.repository_ref_id)
            repository = uow.repositories.get(ref.repository_id)
            occurrences = uow.occurrences.list_for_assessment(assessment_id)
            findings = {
                f.id: f for f in uow.findings.list_by_ids({o.finding_id for o in occurrences})
            }
            where: dict[UUID, list[Location]] = defaultdict(list)
            for loc in uow.locations.list_for_occurrences([o.id for o in occurrences]):
                where[loc.occurrence_id].append(loc)
            precedents = self._precedents.for_findings(
                {o.finding_id: where[o.id] for o in occurrences}, PRECEDENTS_PER_FINDING
            )
        return TriageInput(
            subject=SubjectRef(
                repository_id=repository.id,
                repository_url=repository.url,
                repository_ref_id=ref.id,
                sha=ref.sha,
                assessment_id=assessment_id,
            ),
            findings=FindingContext(),
            prepared_at=self._clock.now(),
            assessor=assessment.assessor,
            items=tuple(
                TriageItem(
                    finding=findings[o.finding_id],
                    occurrence=o,
                    locations=tuple(where[o.id]),
                    precedents=tuple(precedents.get(o.finding_id, ())),
                )
                for o in occurrences
            ),
        )

    def check(self, doc: TriageArtifact, checkout: Path) -> LintReport:
        """Lint the triage against the target checkout: after the votes, before `record`."""
        return self._lint.run(doc, LintContext(files=WorkspaceFiles(checkout)))

    def record(self, doc: TriageArtifact, provenance: Provenance) -> list[Decision]:
        """A triage is an assessment (kind triage) and one decision per verdict, one transaction."""
        raise NotImplementedError("stub: replaces record_triage, emit_triage_ledger_events")


def _check_correction(
    restatement: Restatement, restated: Decision, history: list[Decision]
) -> None:
    """The change is real, replaces a value, restates the latest record and restores nothing."""
    if any(d.restates_id == restated.id for d in history):
        raise ConflictError(f"decision {restated.id} was already restated: restate the correction")
    changes = restatement.changes()
    if not changes:
        raise ValidationError("a restatement corrects at least one of " + ", ".join(RESTATABLE))
    by_id = {d.id: d for d in history}
    earlier, step = [], restated
    while step.restates_id is not None and (step := by_id.get(step.restates_id)) is not None:
        earlier.append(step)
    for field, value in changes.items():
        current = getattr(restated, field)
        if current is None:
            raise ValidationError(
                f"nothing to restate: {field} has no value yet; record it instead"
            )
        if value == current:
            raise ValidationError(f"the restatement changes nothing: {field} is already {value}")
        if value in {getattr(d, field) for d in earlier} - {current}:
            raise ValidationError(
                f"{field} {value} was already corrected away from; record why anew"
            )
