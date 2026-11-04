from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.remediation import SweepTier, VerifySweep
from traust_core.v1.rendering.markdown import Report, Section, Table


def verification_sweep(
    sweep: VerifySweep, repositories: Mapping[UUID, str], generated_at: datetime
) -> Report:
    """The classified verification worklist, including every skipped target and its reason."""
    tiers = Counter(e.tier for e in sweep.queued)
    return Report(
        title="Remediation verification worklist",
        generated_at=generated_at,
        sections=(
            Section(
                heading="Summary",
                body=f"{len(sweep.queued)} queued; {len(sweep.skipped)} skipped. "
                "Routing is not verification evidence; no work-item status is changed.",
                table=Table(
                    columns=("Tier", "Targets"),
                    rows=tuple((tier.value, str(tiers[tier])) for tier in SweepTier),
                ),
            ),
            Section(
                heading="Targets",
                table=Table(
                    columns=(
                        "Tier / skip",
                        "Repository",
                        "Ref",
                        "Head source",
                        "Pinned SHA",
                        "Head SHA",
                        "Open",
                        "Critical",
                        "High",
                        "Claims",
                        "Archived",
                    ),
                    rows=tuple(
                        (
                            str(e.tier or e.skip),
                            repositories[e.repository_id],
                            e.ref_name or "(default)",
                            e.head_source.value,
                            e.pinned_sha or "unknown",
                            e.head_sha or "unobserved",
                            str(e.open_findings),
                            str(e.criticals),
                            str(e.highs),
                            str(e.claims),
                            "unknown" if e.archived is None else str(e.archived).lower(),
                        )
                        for e in (*sweep.queued, *sweep.skipped)
                    ),
                ),
            ),
        ),
        sources=("Registered inventory, completed assessments and finding decisions",),
    )
