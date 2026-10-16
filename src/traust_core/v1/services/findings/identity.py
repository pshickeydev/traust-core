from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1.models.findings import Finding, FindingCandidate, IdentityMove
from traust_core.v1.models.integrity import Fingerprint


class IdentityPolicy:
    def match_key(self, candidate: FindingCandidate) -> Fingerprint:
        raise NotImplementedError(
            "stub: replaces _util/finding_identity.py, ledger _internal/identity.py"
        )

    def moves(
        self, previous: Sequence[Finding], candidates: Sequence[FindingCandidate]
    ) -> list[IdentityMove]:
        raise NotImplementedError("stub: replaces finding_identity.identity_moves")
