"""A query datetime that must carry a UTC offset.

The database's timestamps are always timezone-aware (`UtcTimestamp`); a naive
`as_of` reaches Python-side comparisons and raises a bare TypeError (HTTP 500,
not a 422). Every REST door that takes an `as_of` uses this type so the
refusal happens at parse time, where it belongs.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema


class UtcDatetime(datetime):
    """A datetime that requires a UTC offset; naive values are refused at parse."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: type[datetime], handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls._validate,
            core_schema.datetime_schema(),
        )

    @classmethod
    def _validate(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            from traust_core.v1.errors import ValidationError

            raise ValidationError("must be a timezone-aware datetime (include a UTC offset)")
        return value
