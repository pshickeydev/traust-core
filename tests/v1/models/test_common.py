from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from traust_core.v1.models.common import TimeWindow


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
