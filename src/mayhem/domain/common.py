"""Shared scalar types and small pure helpers used across the domain.

Duration parsing accepts the DSL grammar documented in
``docs/reference/experiment-dsl.md``: ``30s | 5m | 1h`` (plus plain seconds).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator, PlainSerializer

from mayhem.domain.errors import SchemaValidationError

_DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>s|m|h)$")

_BYTES_RE = re.compile(
    r"^(?P<value>\d+(?:\.\d+)?)"
    r"(?P<unit>TiB|GiB|MiB|KiB|TB|GB|MB|KB|Ti|Gi|Mi|Ki|T|G|M|K|B)?$"
)


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


def parse_bytes(raw: str) -> float:
    """Parse a byte quantity string (e.g. ``256M``, ``1.5GiB``, ``128Mi``) into bytes.

    Grammar accepts ``<n>`` followed by an optional unit: ``B``,
    ``K``/``Ki``/``KiB``, ``M``/``Mi``/``MiB``, ``G``/``Gi``/``GiB``,
    ``T``/``Ti``/``TiB`` computed in powers of 1024, or
    ``KB``/``MB``/``GB``/``TB`` computed in powers of 1000. A bare number is
    plain bytes. The ``Ki``/``Mi``/… forms match the Kubernetes quantity
    suffixes (k8s manifests author ``128Mi`` where the single-letter ``M``
    stays the project's existing 1024-based reading).

    Raises:
        SchemaValidationError: If the string does not match the grammar.
    """
    match = _BYTES_RE.fullmatch(raw.strip())
    if match is None:
        raise SchemaValidationError(
            "bytes",
            f"expected '<n>[B|K|KB|Ki|KiB|M|MB|Mi|MiB|G|GB|Gi|GiB|T|TB|Ti|TiB]', got {raw!r}",
        )
    value = float(match.group("value"))
    unit = match.group("unit") or "B"
    base = 1024.0 if unit.endswith("iB") or unit.endswith("i") or len(unit) == 1 else 1000.0
    power = {"B": 0, "K": 1, "M": 2, "G": 3, "T": 4}[unit[0]]
    return value * base**power


def _coerce_duration(v: object) -> object:
    return parse_duration(v) if isinstance(v, str) else v


def _check_non_negative(v: float | str) -> float:
    seconds = parse_duration(v) if isinstance(v, str) else float(v)
    if seconds < 0:
        raise SchemaValidationError("duration", f"must be >= 0, got {v}")
    return seconds


def _serialize_duration(v: float | str) -> str:
    seconds = parse_duration(v) if isinstance(v, str) else float(v)
    return f"{seconds:g}s"


Duration = Annotated[
    float | str,
    BeforeValidator(_coerce_duration),
    AfterValidator(_check_non_negative),
    PlainSerializer(_serialize_duration, return_type=str),
]
"""Seconds; accepts DSL duration strings (``"30s"``/``"5m"``/``"1h"``) or a
plain ``float`` of seconds, and emits a seconds string on serialization.

The declared type is ``float | str`` because an unpassed class default is
returned by Pydantic v2 *without* running the validator (see
``tests/unit/test_drill_spec.py`` asserting ``DrillConfig().timeout == "30m"``),
so a string default must be type-valid. Explicitly supplied values are coerced
to ``float`` seconds at validation time.
"""


def utc_now() -> datetime:
    """Timezone-aware UTC now (DTZ discipline: never naive datetimes)."""
    return datetime.now(UTC)


def iso_utc(dt: datetime) -> str:
    """Render a datetime as ISO-8601 UTC text, as persisted in storage."""
    if dt.tzinfo is None:
        raise SchemaValidationError("timestamp", "naive datetime refused; require tz-aware")
    return dt.astimezone(UTC).isoformat()
