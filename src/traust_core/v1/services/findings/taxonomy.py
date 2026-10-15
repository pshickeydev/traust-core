from __future__ import annotations

from collections.abc import Sequence

from traust_core.v1.models.findings import Cwe, WeaknessLabels


class TaxonomyPolicy:
    def labels(self, cwes: Sequence[Cwe]) -> WeaknessLabels:
        raise NotImplementedError(
            "stub: replaces asvs_for, classify_axis, infer_techniques, ATT&CK mapping"
        )
