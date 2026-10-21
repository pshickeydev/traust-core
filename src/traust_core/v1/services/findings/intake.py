from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import Finding, FindingCandidate, IdentityMove, IntakeResult
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy


class FindingIntake:
    def __init__(
        self, uow: TraustUnitOfWork, identity: IdentityPolicy, taxonomy: TaxonomyPolicy
    ) -> None:
        self._uow = uow
        self._identity = identity
        self._taxonomy = taxonomy

    def accept(
        self,
        assessment_id: UUID,
        candidates: Sequence[FindingCandidate],
        provenance: Provenance,
    ) -> IntakeResult:
        raise NotImplementedError(
            "stub: replaces route_impact_findings, route_regressions, emit_fuzz_events"
        )

    def rebaseline(self, moves: Sequence[IdentityMove], decision_id: UUID) -> list[Finding]:
        raise NotImplementedError("stub: replaces finding_identity.rebaseline")
