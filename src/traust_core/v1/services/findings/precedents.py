from __future__ import annotations

from traust_core.v1.models.findings import FindingCandidate, Precedent
from traust_core.v1.repositories.findings import FindingUnitOfWork


class FindingPrecedents:
    def __init__(self, uow: FindingUnitOfWork) -> None:
        self._uow = uow

    def for_candidate(self, candidate: FindingCandidate, limit: int) -> list[Precedent]:
        raise NotImplementedError(
            "stub: replaces corpus/precedent.py, ops/compile_precedent_cards.py"
        )

    def refresh(self) -> int:
        raise NotImplementedError("stub: replaces ops/compile_precedent_cards.py")
