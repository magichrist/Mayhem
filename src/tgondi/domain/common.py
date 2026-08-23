"""Shared scalar types and small pure helpers used across the domain.

Duration parsing accepts the DSL grammar documented in
``docs/reference/experiment-dsl.md``: ``30s | 5m | 1h`` (plus plain seconds).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator, PlainSerializer

from tgondi.domain.errors import SchemaValidationError

_DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>s|m|h)$")


def parse_duration(raw: str) -> float:
    """Parse a duration string into seconds.

    Raises:
        SchemaValidationError: If the string does not match the grammar.
    """
    match = _DURATION_RE.fullmatch(raw.strip())
    if match is None:
        raise SchemaValidationError("duration", f"expected '<n>s|<n>m|<n|h' format, got {raw!r}")
    value = float(match.group("value"))
    unit = match.group("unit")
    multiplier = {"s": 1.0, "m": 60.0, "h": 3600.0}[unit]
    return value * multiplier


def _coerce_duration(v: object) -> object:
    return parse_duration(v) if isinstance(v, str) else v


def _check_non_negative(v: float) -> float:
    if v < 0:
        raise SchemaValidationError("duration", f"must be >= 0, got {v}")
    return v


Duration = Annotated[
    Annotated[float, AfterValidator(_check_non_negative)],
    BeforeValidator(_coerce_duration),
    PlainSerializer(lambda v: f"{v:g}s", return_type=str),
]
"""Seconds as float; accepts and emits DSL duration strings."""


def utc_now() -> datetime:
    """Timezone-aware UTC now (DTZ discipline: never naive datetimes)."""
    return datetime.now(UTC)


def iso_utc(dt: datetime) -> str:
    """Render a datetime as ISO-8601 UTC text, as persisted in storage."""
    if dt.tzinfo is None:
        raise SchemaValidationError("timestamp", "naive datetime refused; require tz-aware")
    return dt.astimezone(UTC).isoformat()
