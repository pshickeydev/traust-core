from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.portfolio import BusinessUnit, TeamName


class ViewName(StrEnum):
    FINDINGS_ROLLUP = "findings-rollup"
    FINDINGS_TREND = "findings-trend"
    COVERAGE = "coverage"
    LOC = "loc"
    ATTACK_COVERAGE = "attack-coverage"
    THREAT_REGISTER = "threat-register"
    EXPOSURE = "exposure"
    VALIDATION_FUZZ = "validation-fuzz"
    PQC = "pqc"
    COMPLIANCE = "compliance"
    PROGRAM = "program"
    EXECUTIVE_SUMMARY = "executive-summary"
    REVIEW_CARD = "review-card"
    TRIAGE = "triage"
    SARIF = "sarif"
    OSCAL = "oscal"


# Each view's model is a contracts JSON schema (I4); shapes land with the view's slice.
class ViewModel(Model): ...


class ViewFilter(Model):
    product_ids: tuple[UUID, ...] = ()
    business_units: tuple[BusinessUnit, ...] = ()
    teams: tuple[TeamName, ...] = ()
    as_of: datetime | None = None
    window: TimeWindow | None = None
