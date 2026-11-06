"""The scheduled-remediation rows (`remediation`, `remediation_finding`): findings-owned tables,
read and written only here, on the caller's unit of work so a row lands or rolls back with the
decisions beside it."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.remediation_scheduling import Remediation, RemediationFinding
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.repositories.contract import TraustUnitOfWork


class ScheduledRemediations:
    def __init__(self, uow: TraustUnitOfWork) -> None:
        self._uow = uow

    def lock_findings(self, finding_ids: Collection[UUID]) -> None:
        """Lock the findings' rows in one order until the transaction ends, so two requests
        scheduling any of them run one after the other."""
        with self._uow as uow:
            for finding_id in sorted(set(finding_ids), key=str):
                uow.findings.get_for_update(finding_id)

    def efforts_covering(
        self, finding_ids: Collection[UUID]
    ) -> list[tuple[Remediation, frozenset[UUID]]]:
        """Every effort scheduled on any of these findings, with all the findings it covers."""
        with self._uow as uow:
            rows = uow.remediation_findings.list_for_findings(finding_ids)
            efforts = uow.remediations.list_by_ids({r.remediation_id for r in rows})
            return [
                (
                    effort,
                    frozenset(
                        r.finding_id
                        for r in uow.remediation_findings.list_for_remediation(effort.id)  # type: ignore[arg-type]
                    ),
                )
                for effort in efforts
            ]

    def add(self, effort: Remediation, findings: Sequence[tuple[UUID, UUID]]) -> Remediation:
        """The effort's row and one junction row per (finding, repository)."""
        with self._uow as uow:
            saved = uow.remediations.add(effort)
            assert saved.id is not None
            for finding_id, repository_id in findings:
                uow.remediation_findings.add(
                    RemediationFinding(
                        remediation_id=saved.id, finding_id=finding_id, repository_id=repository_id
                    )
                )
            return saved

    def get(self, remediation_id: UUID) -> tuple[Remediation, tuple[RemediationFinding, ...]]:
        with self._uow as uow:
            effort = uow.remediations.get(remediation_id)
            return effort, tuple(uow.remediation_findings.list_for_remediation(remediation_id))

    def find_by_work_item(self, work_item_id: UUID) -> Remediation | None:
        with self._uow as uow:
            return uow.remediations.find_by_assessment(work_item_id)

    def page(
        self,
        page: PageRequest,
        *,
        status: RemediationStatus | None = None,
        repository_id: UUID | None = None,
        finding_id: UUID | None = None,
    ) -> Page[Remediation]:
        """Scheduled efforts, oldest first, a page at a time; every filter given applies."""
        with self._uow as uow:
            rows = uow.remediations.search(
                status=status,
                repository_id=repository_id,
                finding_id=finding_id,
                limit=page.limit + 1,
                after=page.position(),
            )
        return Page.of(rows, page.limit, lambda r: (r.created_at, r.id))  # type: ignore[arg-type,return-value]

    def follow(self, work_item_id: UUID, status: RemediationStatus) -> None:
        """The effort scheduled on a work item follows it, never stepping back; its row is
        locked for the read-modify-write so two syncs can't interleave."""
        with self._uow as uow:
            linked = uow.remediations.find_by_assessment_for_update(work_item_id)
            if linked is not None and (moved := linked.moved_on(status)) is not None:
                uow.remediations.update(moved)

    def move(self, remediation_id: UUID, status: RemediationStatus) -> None:
        """A verification's verdict for one effort (`Remediation.moved_on`), its row locked."""
        with self._uow as uow:
            effort = uow.remediations.get_for_update(remediation_id)
            if (moved := effort.moved_on(status)) is not None:
                uow.remediations.update(moved)
