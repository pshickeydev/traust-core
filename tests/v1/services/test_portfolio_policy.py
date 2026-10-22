from __future__ import annotations

from datetime import date

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.inventory import ExposureClass, RiskTier
from traust_core.v1.models.observation import Designation
from traust_core.v1.services.portfolio import PortfolioPolicy

POLICY = PortfolioPolicy(p0_min_live=5, dormant_days=365)
TODAY = date(2026, 10, 22)


@pytest.mark.parametrize(
    ("designation", "public", "public_upstream", "exposure"),
    [
        (None, True, False, ExposureClass.PUBLIC_EXTERNAL),
        (Designation.INTERNAL_TOOLING, True, False, ExposureClass.PUBLIC_INTERNAL),
        (Designation.EXTERNAL, False, True, ExposureClass.PUBLIC_EXTERNAL),
        (Designation.EXTERNAL, False, False, ExposureClass.PRIVATE_EXTERNAL),
        (None, False, True, ExposureClass.PUBLIC_INTERNAL),
        (None, False, False, ExposureClass.PRIVATE_INTERNAL),
        (None, None, None, ExposureClass.PRIVATE_INTERNAL),
    ],
    ids=[
        "public",
        "public internal tooling",
        "private fork of a public external upstream",
        "private external",
        "private fork of a public upstream",
        "private",
        "never observed",
    ],
)
def test_exposure_class(
    designation: Designation | None,
    public: bool | None,
    public_upstream: bool | None,
    exposure: ExposureClass,
) -> None:
    assert POLICY.exposure_class(designation, public, public_upstream) is exposure


@pytest.mark.parametrize(
    ("open_critical_high", "archived", "dormant", "tier"),
    [
        (5, True, True, RiskTier.P0),
        (4, False, False, RiskTier.P1),
        (1, True, False, RiskTier.P1),
        (0, False, False, RiskTier.P2),
        (0, True, False, RiskTier.P3),
        (0, False, True, RiskTier.P3),
    ],
    ids=["live findings beat archived", "below p0", "one live", "quiet", "archived", "dormant"],
)
def test_risk_tier(open_critical_high: int, archived: bool, dormant: bool, tier: RiskTier) -> None:
    assert POLICY.risk_tier(open_critical_high, archived, dormant) is tier


@pytest.mark.parametrize(
    ("pushed", "dormant"),
    [
        (date(2025, 10, 22), False),
        (date(2025, 10, 21), True),
        (TODAY, False),
        (None, False),
    ],
    ids=["exactly the threshold", "a day past it", "pushed today", "push date unknown"],
)
def test_is_dormant(pushed: date | None, dormant: bool) -> None:
    assert POLICY.is_dormant(pushed, TODAY) is dormant


@pytest.mark.parametrize(("p0_min_live", "dormant_days"), [(0, 365), (5, -1)])
def test_thresholds_must_be_positive(p0_min_live: int, dormant_days: int) -> None:
    with pytest.raises(ValidationError):
        PortfolioPolicy(p0_min_live=p0_min_live, dormant_days=dormant_days)
