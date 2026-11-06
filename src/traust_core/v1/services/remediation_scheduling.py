"""Scheduling remediation: the door that starts the pipeline (SCI's trigger, the console's
button). One call writes the remediation row, its findings, the work item they open and the
order that runs the fix, in one transaction — nothing before it started remediation alone."""

from __future__ import annotations

import contextlib
import logging
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import AssetName, OrderRequest
from traust_core.v1.models.remediation import OVER
from traust_core.v1.models.remediation_scheduling import (
    Remediation,
    RemediationDetail,
    RemediationFindingRequest,
)
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
# The remediation report's `fork.fix_branch` (traust-contracts remediation schema): a branch
# scheduled here becomes that field, so it must pass it as well as git's rules.
_FIX_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}")


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
        transaction. The fork must be the repository's remediation fork (`ForkPolicy`: never a
        public repository). Scheduling the same findings again returns the live effort covering
        them; another target for them, or an overlap, is a conflict."""
        wanted = tuple(dict.fromkeys((f.finding_id, f.repository_id) for f in findings))
        if not wanted:
            raise ValidationError("a remediation needs at least one finding")
        _branch(fork_branch)
        finding_ids = {f for f, _ in wanted}
        with self._uow.write():
            # a second request for any of these findings waits here, then finds this effort
            self._findings.scheduled.lock_findings(finding_ids)
            views = {v.finding.id: v for v in self._findings.list_by_ids(list(finding_ids))}
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
            self._ops.authorize_request(REMEDIATE_FINDING, repository_id, principal)
            fork = self._remediation.resolve_fork(repository_id)
            if fork_url.rstrip("/").removesuffix(".git") != str(fork.url):
                raise ValidationError(
                    f"fork_url must be the repository's remediation fork, {fork.url}"
                )
            if (existing := self._live(finding_ids, str(fork.url), fork_branch)) is not None:
                return existing
            patch = self._patch_ref(repository_id)
            assert patch.id is not None
            item = self._remediation.open(list(finding_ids), patch.id)
            scheduled = self._findings.scheduled.add(
                Remediation(
                    fork_url=str(fork.url),
                    fork_branch=fork_branch,
                    status=item.status,
                    assessment_id=item.work_item_id,
                ),
                wanted,
            )
            # the order names the work item it runs: the runner prepares that one, never the
            # repository's oldest pending item
            order = self._ops.submit(
                OrderRequest(
                    asset=REMEDIATE_FINDING,
                    priority=_ASKED_NOW,
                    repository_id=repository_id,
                    work_item_id=item.work_item_id,
                ),
                principal,
            )
            self._uow.commit()
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
        scheduled, findings = self._findings.scheduled.get(remediation_id)
        assessment = None
        if scheduled.assessment_id is not None:
            with contextlib.suppress(NotFoundError):  # the link is severable (ON DELETE SET NULL)
                assessment = self._remediation.get(scheduled.assessment_id)
        return RemediationDetail(remediation=scheduled, findings=findings, assessment=assessment)

    def list(
        self,
        page: PageRequest,
        *,
        status: RemediationStatus | None = None,
        repository_id: UUID | None = None,
        finding_id: UUID | None = None,
    ) -> Page[Remediation]:
        """Scheduled remediations, oldest first, a page at a time: at a status, on a
        repository, on a finding (every filter given applies)."""
        return self._findings.scheduled.page(
            page, status=status, repository_id=repository_id, finding_id=finding_id
        )

    def _live(self, finding_ids: set[UUID], fork_url: str, fork_branch: str) -> Remediation | None:
        """The live effort covering exactly these findings for this target (a retry, a report
        recorded since); the same findings for another target, or an overlap, conflict."""
        for effort, covers in self._findings.scheduled.efforts_covering(finding_ids):
            if effort.status in OVER:
                continue
            if covers != finding_ids:
                listed = ", ".join(sorted(map(str, covers & finding_ids)))
                raise ConflictError(f"remediation {effort.id} already covers {listed}")
            if (effort.fork_url, effort.fork_branch) != (fork_url, fork_branch):
                raise ConflictError(
                    f"remediation {effort.id} already schedules these findings on "
                    f"{effort.fork_url} {effort.fork_branch}"
                )
            return effort
        return None

    def _patch_ref(self, repository_id: UUID) -> RepositoryRef:
        """The commit the work item patches: the repository's default line."""
        refs = [r for r in self._inventory.list_refs(repository_id) if r.is_default]
        if len(refs) != 1:
            raise ValidationError(
                f"repository {repository_id} has no single default ref: a fix needs the "
                "commit to patch"
            )
        return refs[0]


def _branch(name: str) -> None:
    """Reject what `git check-ref-format --branch` rejects, and what the remediation report's
    `fork.fix_branch` pattern does."""
    parts = name.split("/")
    bad = (
        not _FIX_BRANCH.fullmatch(name)
        or name == "@"
        or name.startswith("-")
        or ".." in name
        or name.endswith(".")
        # per component: not empty (no leading, trailing or doubled /), no leading dot,
        # no .lock ending
        or any(not p or p.startswith(".") or p.endswith(".lock") for p in parts)
    )
    if bad:
        raise ValidationError(f"fork_branch is not a branch name: {name!r}")
