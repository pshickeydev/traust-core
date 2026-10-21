from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1.models.findings import CweId, WeaknessLabels


class TaxonomyPolicy:
    def labels(self, cwes: Sequence[CweId]) -> WeaknessLabels:
        raise NotImplementedError(
            "stub: replaces asvs_for, classify_axis, infer_techniques, ATT&CK mapping"
        )
