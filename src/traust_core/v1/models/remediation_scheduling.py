"""Scheduling remediation: the mutable remediation row, its findings and the door's shapes."""

from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.remediation import WorkItem, furthest
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import RemediationStatus

_REVALIDATED = frozenset({"revalidated_fixed", "revalidated_still_vulnerable"})


class Remediation(Entity):
    """The current state of one remediation effort: where the fix lives (the fork and its
    branch) and where the effort stands. Decisions stay the source of truth; the services
    that write them keep this row in the same transaction."""

    fork_url: str
    fork_branch: str
    status: RemediationStatus
    assessment_id: UUID | None = None

    def moved_on(self, status: RemediationStatus) -> Remediation | None:
        """The effort at `status` when that stands at or beyond where it is; None when it
        would step back (the row never rewinds a status sync). Between the two revalidated
        verdicts, which rank alike, the latest verification wins (a re-patch, a regression)."""
        if status != self.status and {status, self.status} <= _REVALIDATED:
            return self.model_copy(update={"status": status})
        reached = furthest((self.status, status))
        return None if reached == self.status else self.model_copy(update={"status": reached})


class RemediationFinding(Entity):
    """One finding a remediation resolves, on the repository it belongs to."""

    remediation_id: UUID
    finding_id: UUID
    repository_id: UUID


class RemediationFindingRequest(Model):
    """A finding to schedule, named with the repository it belongs to."""

    finding_id: UUID
    repository_id: UUID


class RemediationRequest(Model):
    """What the scheduling door takes: the fork the fix lands on and the findings to fix."""

    fork_url: HttpsRepoUrl
    fork_branch: str
    findings: tuple[RemediationFindingRequest, ...]


class RemediationDetail(Model):
    """A scheduled remediation with its findings and the work item it opened."""

    remediation: Remediation
    findings: tuple[RemediationFinding, ...]
    assessment: WorkItem | None = None
