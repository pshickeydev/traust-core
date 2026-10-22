from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from traust_core.v1.models.common import IdentitySource, Principal, Role, TimeWindow
from traust_core.v1.models.vocabulary import ActorKind


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)  # type: ignore[misc]


@pytest.mark.parametrize(
    ("at", "start", "end"),
    [
        (utc(2026, 10, 5, 12), utc(2026, 10, 1), utc(2026, 11, 1)),
        (utc(2026, 10, 1), utc(2026, 10, 1), utc(2026, 11, 1)),
        (utc(2026, 12, 31, 23, 59), utc(2026, 12, 1), utc(2027, 1, 1)),
        (utc(2028, 2, 29), utc(2028, 2, 1), utc(2028, 3, 1)),
        (
            datetime(2026, 11, 1, 1, tzinfo=timezone(timedelta(hours=3))),
            utc(2026, 10, 1),
            utc(2026, 11, 1),
        ),
    ],
    ids=["mid-month", "first instant", "december rolls the year", "leap day", "offset to utc"],
)
def test_month_of_is_the_utc_calendar_month(at: datetime, start: datetime, end: datetime) -> None:
    assert TimeWindow.month_of(at) == TimeWindow(start=start, end=end)


def principal(
    kind: str = "human", verified: bool = True, roles: tuple[Role, ...] = ()
) -> Principal:
    return Principal(
        id=uuid4(),
        kind=ActorKind(kind),
        display="someone",
        verified_by=IdentitySource.OIDC if verified else None,
        roles=frozenset(roles),
    )


@pytest.mark.parametrize(
    ("kind", "verified", "expected"),
    [("human", True, True), ("human", False, False), ("machine", True, False)],
)
def test_a_verified_human_is_a_person_a_trusted_source_proved(
    kind: str, verified: bool, expected: bool
) -> None:
    assert principal(kind, verified).is_verified_human() is expected


def test_a_role_counts_only_for_a_verified_human() -> None:
    assert principal(roles=(Role.RESTATE,)).has_role(Role.RESTATE)
    assert not principal(roles=(Role.RESTATE,)).has_role(Role.ADMIN)
    assert not principal(verified=False, roles=(Role.RESTATE,)).has_role(Role.RESTATE)
    assert not principal("machine", roles=(Role.ADMIN,)).has_role(Role.ADMIN)
