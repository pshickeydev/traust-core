"""Scheduling remediation: the door that starts the pipeline (SCI's trigger, the console's
button). One call writes the remediation row, its findings, the work item they open and the
order that runs the fix, in one transaction — nothing before it started remediation alone."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import AssetName, OrderRequest
from traust_core.v1.models.remediation_scheduling import (
    Remediation,
    RemediationDetail,
    RemediationFinding,
    RemediationFindingRequest,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.portfolio import Inventory
from traust_core.v1.services.remediation import RemediationService

if TYPE_CHECKING:
    from traust_core.v1.services.operations import OpsService

log = logging.getLogger(__name__)

REMEDIATE_FINDING = AssetName("remediate_finding")
# A scheduled fix is asked for now, like onboarding's baseline orders.
_ASKED_NOW = 0


class RemediationSchedulingService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        findings: FindingService,
        remediation: RemediationService,
        ops: OpsService,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._findings = findings
        self._remediation = remediation
        self._ops = ops

    def create(
        self,
        fork_url: str,
        fork_branch: str,
        findings: Sequence[RemediationFindingRequest],
        principal: Principal,
    ) -> Remediation:
        """Schedule one remediation effort: its row, its findings, the work item they open
        (candidate decisions, one per finding) and the order that runs the fix — one
        transaction. Scheduling the same findings again returns the effort already covering
        them; overlapping findings are a conflict (`RemediationService.open`)."""
        wanted = tuple(dict.fromkeys((f.finding_id, f.repository_id) for f in findings))
        if not wanted:
            raise ValidationError("a remediation needs at least one finding")
        url = _https(fork_url)
        _branch(fork_branch)
        with self._uow as uow:
            views = {v.finding.id: v for v in self._findings.list_by_ids([f for f, _ in wanted])}
            for finding_id, repository_id in wanted:
                view = views[finding_id]
                if view.finding.repository_id != repository_id:
                    raise ValidationError(
                        f"finding {finding_id} is not in repository {repository_id}"
                    )
                if not view.is_open():
                    raise ValidationError(f"finding {finding_id} is closed")
            repositories = {v.finding.repository_id for v in views.values()}
            if len(repositories) != 1:
                # a fork branches from one upstream: the effort patches that repository
                listed = ", ".join(sorted(map(str, repositories)))
                raise ValidationError(
                    f"a remediation schedules one repository's findings, not {listed}"
                )
            (repository_id,) = repositories
            patch = self._patch_ref(repository_id)
            assert patch.id is not None
            item = self._remediation.open([f for f, _ in wanted], patch.id)
            if (existing := uow.remediations.find_by_assessment(item.work_item_id)) is not None:
                return existing
            scheduled = uow.remediations.add(
                Remediation(
                    fork_url=str(url),
                    fork_branch=fork_branch,
                    status=item.status,
                    assessment_id=item.work_item_id,
                )
            )
            assert scheduled.id is not None
            for finding_id, repository in wanted:
                uow.remediation_findings.add(
                    RemediationFinding(
                        remediation_id=scheduled.id,
                        finding_id=finding_id,
                        repository_id=repository,
                    )
                )
            order = self._ops.submit(
                OrderRequest(
                    asset=REMEDIATE_FINDING, priority=_ASKED_NOW, repository_id=repository_id
                ),
                principal,
            )
            uow.commit()
        self._uow.after_commit(
            lambda: log.info(
                "remediation %s scheduled for %d findings, order %s",
                scheduled.id,
                len(wanted),
                order.id,
            )
        )
        return scheduled

    def get(self, remediation_id: UUID) -> RemediationDetail:
        """One scheduled remediation with its findings and the work item it opened."""
        with self._uow as uow:
            scheduled = uow.remediations.get(remediation_id)
            findings = tuple(uow.remediation_findings.list_for_remediation(remediation_id))
        assessment = None
        if scheduled.assessment_id is not None:
            with contextlib.suppress(NotFoundError):  # the link is severable (ON DELETE SET NULL)
                assessment = self._remediation.get(scheduled.assessment_id)
        return RemediationDetail(remediation=scheduled, findings=findings, assessment=assessment)

    def list(
        self,
        *,
        status: RemediationStatus | None = None,
        repository_id: UUID | None = None,
        finding_id: UUID | None = None,
    ) -> list[Remediation]:
        """Scheduled remediations, oldest first: one status', one repository's or one
        finding's."""
        with self._uow as uow:
            if repository_id is not None:
                linked = uow.remediation_findings.list_for_repository(repository_id)
                found = uow.remediations.list_by_ids({r.remediation_id for r in linked})
            elif finding_id is not None:
                linked = uow.remediation_findings.list_for_finding(finding_id)
                found = uow.remediations.list_by_ids({r.remediation_id for r in linked})
            elif status is not None:
                found = uow.remediations.list_by_status(status)
            else:
                found = uow.remediations.list_all()
            return [r for r in found if status is None or r.status == status]

    def _patch_ref(self, repository_id: UUID) -> RepositoryRef:
        """The commit the work item patches: the repository's default line."""
        refs = [r for r in self._inventory.list_refs(repository_id) if r.is_default]
        if len(refs) != 1:
            raise ValidationError(
                f"repository {repository_id} has no single default ref: a fix needs the "
                "commit to patch"
            )
        return refs[0]


def _https(raw: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(raw.rstrip("/"), [urlsplit(raw).hostname or ""])


def _branch(name: str) -> None:
    """Reject what git's check-ref-format rejects (the parts a caller could trip on)."""
    bad = (
        not name
        or name == "@"
        or "@{" in name
        or name.startswith("-")
        or name.endswith(".lock")
        or ".." in name
        or "//" in name
        or name.startswith("/")
        or name.endswith("/")
        or any(c in name for c in " ~^:?*[\\")
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
    )
    if bad:
        raise ValidationError(f"fork_branch is not a branch name: {name!r}")
