from __future__ import annotations

from decimal import Decimal

import pytest

from traust_core.v1.models.operations import Budget, BudgetStatus, LaneName
from traust_core.v1.models.vocabulary import BudgetEnforcement

LANE = LaneName("full-audit")


def budget(enforcement: str, monthly: str = "100") -> Budget:
    return Budget(
        lane=LANE, monthly_usd=Decimal(monthly), enforcement=BudgetEnforcement(enforcement)
    )


@pytest.mark.parametrize(
    ("spent", "estimate", "status"),
    [
        ("0", "0", BudgetStatus.WITHIN),
        ("90", "10", BudgetStatus.WITHIN),
        ("90", "10.01", BudgetStatus.OVER),
        ("100", None, BudgetStatus.WITHIN),
        ("100.01", None, BudgetStatus.OVER),
    ],
    ids=["nothing", "exactly at budget", "a cent over", "unknown cost", "already over"],
)
def test_verdict_judges_spent_plus_a_known_estimate(
    spent: str, estimate: str | None, status: BudgetStatus
) -> None:
    cost = None if estimate is None else Decimal(estimate)
    verdict = budget("observe").verdict(Decimal(spent), cost)
    assert (verdict.status, verdict.spent_usd, verdict.estimate_usd, verdict.budget_usd) == (
        status,
        Decimal(spent),
        cost,
        Decimal("100"),
    )


@pytest.mark.parametrize(
    ("enforcement", "binding"),
    [("none", False), ("observe", False), ("advisory", True), ("enforced", True)],
)
def test_only_an_enforcing_budget_over_its_limit_binds(enforcement: str, binding: bool) -> None:
    assert budget(enforcement).verdict(Decimal("100"), Decimal("1")).binding is binding
    assert budget(enforcement).verdict(Decimal("1"), Decimal("1")).binding is False


def test_unknown_cost_never_binds_even_when_over() -> None:
    verdict = budget("enforced").verdict(Decimal("500"), None)
    assert (verdict.status, verdict.binding) == (BudgetStatus.OVER, False)
