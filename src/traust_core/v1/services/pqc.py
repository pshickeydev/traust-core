from __future__ import annotations

from typing import overload
from uuid import UUID

from traust_core.v1.models.artifacts import PqcArtifact, PqcBlockersArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.pqc import (
    PqcBlocker,
    PqcDimension,
    PqcFilter,
    PqcReadiness,
    PqcReadinessInput,
    PqcRollup,
)
from traust_core.v1.repositories.assessment import PqcUnitOfWork
from traust_core.v1.services.code_facts import CodeFactsService


class PqcService:
    def __init__(self, uow: PqcUnitOfWork, code_facts: CodeFactsService) -> None:
        self._uow = uow
        self._code_facts = code_facts

    def prescan(self, revision_id: UUID) -> PqcReadiness:
        raise NotImplementedError("stub: replaces bulk_prescan, l2_prepass, scan_xcrypto_usage")

    def prepare(self, revision_id: UUID) -> PqcReadinessInput:
        raise NotImplementedError("stub: replaces pqc-readiness skill inputs")

    @overload
    def record(self, doc: PqcArtifact, provenance: Provenance) -> PqcReadiness: ...
    @overload
    def record(self, doc: PqcBlockersArtifact, provenance: Provenance) -> list[PqcBlocker]: ...
    def record(
        self, doc: PqcArtifact | PqcBlockersArtifact, provenance: Provenance
    ) -> PqcReadiness | list[PqcBlocker]:
        raise NotImplementedError("stub: replaces pqc_facts.py, build_pqc_blockers.py")

    def find(self, component_id: UUID) -> PqcReadiness | None:
        raise NotImplementedError("stub: replaces pqc_readiness reads")

    def summary(self, filter: PqcFilter, group_by: PqcDimension) -> list[PqcRollup]:
        raise NotImplementedError("stub: replaces build_pqc_rollup, pqc_posture, trackers")

    def blockers(self, filter: PqcFilter) -> list[PqcBlocker]:
        raise NotImplementedError("stub: replaces build_pqc_worklist, vendor tracker")
