from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.code_facts import CryptoFact
from traust_core.v1.models.dependencies import Package
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.vocabulary import (
    PqcBlastRadius,
    PqcClassification,
    PqcReadinessBucket,
    PqcRemediationCategory,
)


class PqcFilter(Model): ...


class PqcDimension(Model): ...


class PqcRollup(Model): ...


class PqcReadinessInput(SkillInput): ...


class PqcBlocker(Model):
    package: Package
    category: PqcRemediationCategory
    vendor: str | None = None


class PqcReadiness(Model):
    assessment_id: UUID
    bucket: PqcReadinessBucket
    classification: PqcClassification
    blast_radius: PqcBlastRadius
    facts: tuple[CryptoFact, ...] = ()
    blockers: tuple[PqcBlocker, ...] = ()

    def is_blocked(self) -> bool:
        raise NotImplementedError("stub: replaces build_pqc_blockers.build_findings_doc")
