from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.assessment import Threat
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import Disposition, Occurrence, RatingInputs, RiskRating
from traust_core.v1.models.vocabulary import RiskRatingBand, Severity


class RatingConfig(Model): ...


class RatingPolicy:
    def __init__(self, config: RatingConfig) -> None:
        self._config = config

    def rate(self, inputs: RatingInputs) -> RiskRating:
        raise NotImplementedError("stub: replaces contracts risk_rating.py, build_trends ratings")

    def effective_severity(self, occurrence: Occurrence, disposition: Disposition) -> Severity:
        raise NotImplementedError("stub: replaces build_trends.cvss_effective, effective_severity")

    def sla_due(self, severity: Severity, opened_at: datetime, product_id: UUID) -> datetime:
        raise NotImplementedError("stub: replaces metrics/sla.py")

    def threat_rating(self, threat: Threat) -> RiskRatingBand:
        raise NotImplementedError("stub: replaces reporting/threat_rating.py")
