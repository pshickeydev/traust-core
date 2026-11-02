"""A query datetime without a UTC offset is refused at parse time (422), never
reaching a TypeError in Python-side comparisons against aware DB timestamps (500)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from traust_core.v1.rest.common.aware_datetime import UtcDatetime


def test_an_aware_datetime_passes() -> None:
    assert UtcDatetime._validate(datetime(2026, 10, 23, tzinfo=UTC)) == datetime(
        2026, 10, 23, tzinfo=UTC
    )


def test_a_naive_datetime_is_refused() -> None:
    from traust_core.v1.errors import ValidationError

    with pytest.raises(ValidationError, match="timezone-aware"):
        UtcDatetime._validate(datetime(2026, 10, 23))
