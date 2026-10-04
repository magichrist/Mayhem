"""Schedule, fairness, and concurrency model (plan 13, Phase 1).

Three vocabularies, one discipline: **every function here is a pure function of
its arguments, including the clock.** ``now`` / ``fire_at`` is always an
argument and never a ``datetime.now()`` call, so a scheduling decision can be
replayed from evidence and is bit-for-bit reproducible -- the same property
:mod:`mayhem.domain.policy` earned for policy evaluation.

The three vocabularies:

``Schedule``
    When a run *may* fire. Three recurrence kinds (cron, interval, explicit
    calendar windows) plus the gates a fire time must clear: business hours,
    maintenance windows, blackout dates, jitter, a creation instant, and a
    horizon. The cron dialect is five fields, evaluated on the schedule's own
    wall clock, with Vixie-style day-of-month/day-of-week OR semantics.

``FairnessPolicy``
    Which team gets the *next* slot when more than one is asking. Weighted
    shares, with an absolute-priority rule for any team that has been skipped
    for ``starvation_window`` consecutive windows. The starvation guarantee is a
    property of :meth:`FairnessPolicy.simulate_fairness`, not a promise in a
    docstring.

``ConcurrencyClass``
    Whether two runs *may overlap* on a shared resource -- the experiment
    concurrency model of gap 85. The lock-compatibility matrix is a table of
    pure booleans; :func:`evaluate_concurrency` combines it with the 07
    resource locks so the refusal names the run that holds the resource.

Nothing here schedules anything: there is no store, no dispatch, no clock read.
This is the vocabulary Phase 2's scheduler engine is written against, and it
extends the campaign core (:mod:`mayhem.domain.campaigns`,
:mod:`mayhem.domain.campaign_checkpoint`) rather than replacing it.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, date, datetime, time, timedelta
from enum import StrEnum
from functools import cache
from typing import TYPE_CHECKING, Any, Final, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import Duration
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.policy import ResourceLock, acquire_lock

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

SCHEDULING_SCHEMA_VERSION: Final[str] = "1.0"

#: Minute-resolution ceiling on how far a cron search walks before giving up
#: ("no such occurrence within a year"). Bounded so a pathological dialect such
#: as ``0 0 30 2 *`` (February 30th) answers "never fires" instead of hanging.
CRON_SEARCH_LIMIT_MINUTES: Final[int] = 366 * 24 * 60

#: Buckets used to spread a jitter offset across its declared range. Fixed so a
#: jitter draw is a pure function of ``(seed, nominal)`` rather than of any RNG
#: state, which is what lets a replay reproduce a fire time exactly.
JITTER_BUCKETS: Final[int] = 1_000_000

#: Decimal places a jitter offset is rounded to, so repeated float arithmetic on
#: the same nominal time cannot drift the last binary digit.
JITTER_PRECISION: Final[int] = 6

#: Decimal places a fairness deficit is rounded to before comparison, so two
#: teams whose entitlements differ only below float noise resolve by name rather
#: than by whichever way the last bit happened to fall.
DEFICIT_PRECISION: Final[int] = 9


def _as_utc(value: datetime, *, rule: str, subject: str) -> datetime:
    """Normalize an aware datetime to UTC, refusing a naive one.

    DTZ discipline enforced rather than assumed: a naive datetime here would
    silently mean "somewhere", which is exactly the ambiguity a scheduler
    cannot carry into a fire decision.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        msg = f"{subject} must be timezone-aware; got naive {value.isoformat()}"
        raise InvariantViolationError(rule, msg)
    return value.astimezone(UTC)


@cache
def resolve_zone(name: str) -> ZoneInfo:
    """Resolve an IANA timezone name, refusing an unknown one by name.

    Raises:
        InvariantViolationError: If the name is not a known IANA zone.
    """
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        msg = f"unknown timezone {name!r}: {exc}"
        raise InvariantViolationError("schedule.unknown_timezone", msg) from exc


# =============================================================================
# Windows: maintenance, business hours, blackout dates
# =============================================================================


def windows_overlap(
    first_start: datetime,
    first_end: datetime,
    second_start: datetime,
    second_end: datetime,
) -> bool:
    """True when two half-open windows ``[start, end)`` share any instant.

    Half-open because a maintenance window ending at 09:00 and one starting at
    09:00 do not overlap, and back-to-back windows are the normal way to say
    "change freeze until nine, then work may resume". Touching is not
    overlapping; both comparisons are strict.
    """
    return first_start < second_end and second_start < first_end


class MaintenanceWindow(BaseModel):
    """An absolute interval during which nothing may fire."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    window_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    starts_at: datetime
    ends_at: datetime
    reason: str = ""

    @model_validator(mode="after")
    def _check_window(self) -> Self:
        _as_utc(self.starts_at, rule="schedule.window_naive", subject="maintenance start")
        _as_utc(self.ends_at, rule="schedule.window_naive", subject="maintenance end")
        if self.ends_at <= self.starts_at:
            msg = (
                f"maintenance window {self.window_id!r} ends "
                f"({self.ends_at.isoformat()}) at or before it starts "
                f"({self.starts_at.isoformat()})"
            )
            raise InvariantViolationError("schedule.window_empty", msg)
        return self

    def contains(self, now: datetime) -> bool:
        """True inside the window; half-open, so ``ends_at`` itself is clear."""
        return self.starts_at <= now < self.ends_at

    def overlaps(self, other: MaintenanceWindow) -> bool:
        """True when the two windows share at least one instant."""
        return windows_overlap(self.starts_at, self.ends_at, other.starts_at, other.ends_at)

    def describe(self) -> str:
        reason = f" - {self.reason}" if self.reason else ""
        span = f"{self.starts_at.isoformat()} to {self.ends_at.isoformat()}"
        return f"{self.window_id} ({span}){reason}"


class DailyWindow(BaseModel):
    """A recurring local-time band, e.g. "Mon-Fri 09:00-17:00".

    ``start_time`` / ``end_time`` are wall-clock times in the schedule's own
    timezone, so they follow DST: 09:00 is 09:00 local on both sides of a
    transition. A window whose end is *not* after its start runs overnight, and
    :meth:`contains` then also answers for the tail of the following morning.

    ``days`` is Python weekday numbering: 0 = Monday through 6 = Sunday.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = ""
    days: frozenset[int] = Field(default_factory=lambda: frozenset({0, 1, 2, 3, 4}))
    start_time: time
    end_time: time
    #: Weekdays (same numbering as ``days``) on which this band does *not* apply.
    excluded_days: frozenset[int] = Field(default_factory=frozenset)

    @model_validator(mode="after")
    def _check_days(self) -> Self:
        unknown = {day for day in (*self.days, *self.excluded_days) if not 0 <= day <= 6}
        if unknown:
            msg = f"daily window {self.label!r} names out-of-range weekdays {sorted(unknown)}"
            raise InvariantViolationError("schedule.weekday_range", msg)
        contradiction = self.days & self.excluded_days
        if contradiction:
            msg = (
                f"daily window {self.label!r} excludes weekdays it also includes: "
                f"{sorted(contradiction)}"
            )
            raise InvariantViolationError("schedule.weekday_excluded", msg)
        return self

    @property
    def overnight(self) -> bool:
        """True when the band runs past local midnight."""
        return self.end_time <= self.start_time

    def applies(self, weekday: int) -> bool:
        """True when this band is in force on ``weekday`` (0 = Monday)."""
        return weekday in self.days and weekday not in self.excluded_days

    def contains(self, local: datetime) -> bool:
        """True when ``local`` is inside the band.

        ``local`` may be aware (its fields are read as the schedule's wall clock)
        or a naive wall clock. An overnight band is open from ``start_time`` to
        local midnight on its own day *and* from midnight to ``end_time`` on the
        following day, so a Mon 22:00-02:00 band is open at Mon 23:00 and at Tue
        01:00, and shut at Tue 02:00.
        """
        wall = local.replace(tzinfo=None)
        clock = wall.time()
        weekday = wall.weekday()
        if self.applies(weekday) and self._covers_same_day(clock):
            return True
        if not self.overnight:
            return False
        return self.applies((weekday - 1) % 7) and clock < self.end_time

    def _covers_same_day(self, clock: time) -> bool:
        """True when ``clock`` is in this band's own-day portion.

        For a same-day band that is ``start <= clock < end``. For an overnight
        band there is no same-day end -- the band simply runs from ``start`` to
        local midnight, and :meth:`contains` credits the tail to the next day.
        """
        if self.overnight:
            return clock >= self.start_time
        return self.start_time <= clock < self.end_time

    def describe(self) -> str:
        names = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        shown = ",".join(names[day] for day in sorted(self.days)) or "never"
        return f"{shown} {self.start_time:%H:%M}-{self.end_time:%H:%M}"


class BusinessHours(BaseModel):
    """The union of :class:`DailyWindow` bands a fire time must fall inside."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    windows: tuple[DailyWindow, ...] = ()

    @model_validator(mode="after")
    def _check_windows(self) -> Self:
        if not self.windows:
            msg = "business hours must declare at least one window; empty means never open"
            raise InvariantViolationError("schedule.business_hours_empty", msg)
        return self

    def contains(self, local: datetime) -> bool:
        """True when any declared band covers ``local``."""
        return any(window.contains(local) for window in self.windows)

    def window_for(self, local: datetime) -> DailyWindow | None:
        """The band ``local`` falls in, or ``None`` when closed."""
        for window in self.windows:
            if window.contains(local):
                return window
        return None

    def closed_reason(self, local: datetime) -> str:
        """One line naming the bands that were open and were missed."""
        bands = ", ".join(window.describe() for window in self.windows)
        stamp = (
            local.astimezone(UTC).isoformat()
            if local.tzinfo is not None
            else local.isoformat()
        )
        return f"{stamp} is outside business hours ({bands})"

    def describe(self) -> str:
        return " | ".join(window.describe() for window in self.windows)


class BlackoutDates(BaseModel):
    """Named calendar dates on which nothing fires, in the schedule's timezone."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dates: frozenset[date] = Field(default_factory=frozenset)
    reason: str = ""

    def hits(self, local: datetime) -> date | None:
        """The blacked-out local date ``local`` falls on, else ``None``.

        ``local`` is read as a wall clock: "the 4th is blacked out" means the
        4th where the schedule runs, not the 4th in UTC.
        """
        day = local.date()
        return day if day in self.dates else None

    def describe(self) -> str:
        days = ",".join(day.isoformat() for day in sorted(self.dates))
        return f"blackout on {days}" if days else "blackout on no dates"


class Jitter(BaseModel):
    """A bounded, deterministic, symmetric offset applied to a nominal fire time.

    Jitter exists so that N schedules authored with the same cron expression do
    not stampede a shared target. It is bounded (``[-max_offset_s, +max_offset_s]``)
    and *deterministic*: the offset is a hash of ``(seed, nominal)``, not a draw
    from a global RNG, so replaying a schedule reproduces the same fire time and
    the declared bound is a guarantee rather than a hope.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_offset_s: Duration = 0.0

    @property
    def max_offset_seconds(self) -> float:
        return float(self.max_offset_s)

    @property
    def enabled(self) -> bool:
        return self.max_offset_seconds > 0.0

    def offset_s(self, *, seed: str, nominal: datetime) -> float:
        """The signed offset for one nominal fire time, inside the declared bound."""
        bound = self.max_offset_seconds
        if bound <= 0.0:
            return 0.0
        moment = _as_utc(nominal, rule="schedule.jitter_naive", subject="nominal fire time")
        bucket = int(digest({"seed": seed, "nominal": moment.isoformat()})[:16], 16)
        fraction = (bucket % JITTER_BUCKETS) / JITTER_BUCKETS
        return round(-bound + fraction * (2.0 * bound), JITTER_PRECISION)

    def apply(self, nominal: datetime, *, seed: str) -> datetime:
        """``nominal`` shifted by :meth:`offset_s`; the identity when disabled."""
        if not self.enabled:
            return nominal
        return nominal + timedelta(seconds=self.offset_s(seed=seed, nominal=nominal))

    def describe(self) -> str:
        return f"jitter within {self.max_offset_seconds:g}s either side"


# =============================================================================
# Cron - the Mayhem dialect
# =============================================================================


class ScheduleKind(StrEnum):
    """The three recurrence vocabularies a schedule may be authored in."""

    CRON = "cron"
    INTERVAL = "interval"
    CALENDAR = "calendar"


_MONTH_ALIASES: Final[dict[str, int]] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

_WEEKDAY_ALIASES: Final[dict[str, int]] = {
    "sun": 0,
    "mon": 1,
    "tue": 2,
    "wed": 3,
    "thu": 4,
    "fri": 5,
    "sat": 6,
}

#: ``field -> (label, minimum, maximum, aliases)``, in cron field order. Day-of-week
#: accepts 7 as Sunday, as Vixie cron does; it is folded onto 0 after parsing so
#: downstream code only ever sees 0-6.
_CRON_FIELD_BOUNDS: Final[dict[str, tuple[str, int, int, dict[str, int] | None]]] = {
    "minute": ("minute", 0, 59, None),
    "hour": ("hour", 0, 23, None),
    "day-of-month": ("day of month", 1, 31, None),
    "month": ("month", 1, 12, _MONTH_ALIASES),
    "day-of-week": ("day of week", 0, 7, _WEEKDAY_ALIASES),
}

_CRON_FIELDS: Final[tuple[str, ...]] = tuple(_CRON_FIELD_BOUNDS)

_CRON_NICKNAMES: Final[dict[str, str]] = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}

_CRON_DISALLOWED: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9*,\-/#]+")


def _cron_value(token: str, *, aliases: dict[str, int] | None, field: str) -> int:
    """One bare cron atom: a number, or an alias such as ``MON``."""
    text = token.strip()
    if not text.isdigit():
        if aliases is not None and text.lower() in aliases:
            return aliases[text.lower()]
        msg = f"cron {field} field does not understand {token!r}"
        raise InvariantViolationError("schedule.cron_token", msg)
    return int(text)


def _parse_cron_field(raw: str, field: str) -> frozenset[int]:
    """Parse one cron field into the set of values it admits.

    Grammar: a comma-separated list of ``*``, ``n``, or ``a-b``, each optionally
    suffixed with ``/step``. Out-of-range values, reversed ranges, and a zero or
    non-numeric step are refused rather than clamped, because a silently clamped
    cron is a schedule that fires at a time its author did not write.

    Raises:
        InvariantViolationError: On any out-of-dialect atom.
    """
    label, minimum, maximum, aliases = _CRON_FIELD_BOUNDS[field]
    values: set[int] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            msg = f"cron {field} field {raw!r} has an empty list element"
            raise InvariantViolationError("schedule.cron_field", msg)
        step = 1
        if "/" in token:
            token, _, step_text = token.partition("/")
            if not step_text.isdigit():
                msg = f"cron {field} field {raw!r} has a non-numeric step {step_text!r}"
                raise InvariantViolationError("schedule.cron_step", msg)
            step = int(step_text)
            if step < 1:
                msg = f"cron {field} field {raw!r} has a step of {step}; steps start at 1"
                raise InvariantViolationError("schedule.cron_step", msg)
        if token.strip() == "*":
            low, high = minimum, maximum
        elif "-" in token:
            low_text, _, high_text = token.partition("-")
            low = _cron_value(low_text, aliases=aliases, field=label)
            high = _cron_value(high_text, aliases=aliases, field=label)
            if low > high:
                msg = f"cron {field} field {raw!r} has the reversed range {low}-{high}"
                raise InvariantViolationError("schedule.cron_range", msg)
        else:
            low = high = _cron_value(token, aliases=aliases, field=label)
        if low < minimum or high > maximum:
            msg = f"cron {field} field {raw!r} is outside {minimum}-{maximum}"
            raise InvariantViolationError("schedule.cron_range", msg)
        values.update(range(low, high + 1, step))
    if not values:
        msg = f"cron {field} field {raw!r} admits no values"
        raise InvariantViolationError("schedule.cron_field", msg)
    if field == "day-of-week" and 7 in values:
        values.discard(7)
        values.add(0)
    return frozenset(values)


def local_time_exists(local: datetime, tz: ZoneInfo) -> bool:
    """False for a wall clock the zone skipped (the spring-forward gap).

    Round-tripping through UTC is the only portable test: ``02:30`` on a
    spring-forward day in ``America/New_York`` is a legal ``time`` that no
    instant of the year ever names.
    """
    aware = local.replace(tzinfo=tz, fold=0)
    return aware.astimezone(UTC).astimezone(tz).replace(tzinfo=None) == local


def local_time_is_ambiguous(local: datetime, tz: ZoneInfo) -> bool:
    """True for a wall clock that happens twice (the fall-back hour)."""
    first = local.replace(tzinfo=tz, fold=0).utcoffset()
    second = local.replace(tzinfo=tz, fold=1).utcoffset()
    return first != second


def _resolve_local(local: datetime, tz: ZoneInfo) -> datetime | None:
    """Attach ``tz`` to a naive wall clock, or ``None`` if it never happened.

    An ambiguous wall clock resolves to its *first* occurrence (``fold=0``), so a
    cron that would fire during a fall-back hour fires once, not twice. That is
    the honest reading of "at 01:30 local", and it is asserted by the DST tests
    rather than left to a reader's trust.
    """
    if not local_time_exists(local, tz):
        return None
    return local.replace(tzinfo=tz, fold=0)


class CronSpec(BaseModel):
    """A parsed Mayhem cron expression: five fields, wall-clock, no seconds.

    The dialect is deliberately small:

    * exactly five whitespace-separated fields --
      ``minute hour day-of-month month day-of-week``;
    * each field is ``*``, ``n``, ``a-b``, a comma-separated list of those, and
      any of them may carry ``/step``;
    * ``@hourly`` / ``@daily`` / ``@weekly`` / ``@monthly`` / ``@yearly``
      nicknames;
    * three-letter aliases for months (``JAN``) and weekdays (``MON``);
    * day-of-week is 0-6 with Sunday = 0, and 7 accepted as Sunday.

    When both day-of-month and day-of-week are restricted the match is a
    **union**, matching Vixie cron: ``0 0 1 * MON`` fires on the first of the
    month *or* on any Monday, not on the intersection.

    Six- and seven-field expressions are **rejected**. Accepting them and
    guessing whether field six is a year or a second would make a silent
    wrong-time fire, which is the one failure a scheduler must not have.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    expression: str
    minutes: frozenset[int] = Field(default_factory=frozenset)
    hours: frozenset[int] = Field(default_factory=frozenset)
    days_of_month: frozenset[int] = Field(default_factory=frozenset)
    months: frozenset[int] = Field(default_factory=frozenset)
    days_of_week: frozenset[int] = Field(default_factory=frozenset)
    day_of_month_restricted: bool = False
    day_of_week_restricted: bool = False

    @model_validator(mode="before")
    @classmethod
    def _derive_from_expression(cls, data: Any) -> Any:
        """Parse ``expression`` into the value sets unless they were supplied."""
        if not isinstance(data, dict) or "expression" not in data:
            return data
        derived = {"minutes", "hours", "days_of_month", "months", "days_of_week"}
        if derived & set(data):
            return data
        return {**data, **cls._parse_expression(str(data["expression"]))}

    @classmethod
    def _parse_expression(cls, expression: str) -> dict[str, Any]:
        """Parse an expression into the field sets, or refuse it.

        Raises:
            InvariantViolationError: If the expression is outside the dialect.
        """
        raw = expression.strip()
        if raw.startswith("@"):
            # Checked before the character filter, which would otherwise eat the
            # "@" and turn an unsupported shorthand into a field-count error.
            nickname = _CRON_NICKNAMES.get(raw.lower())
            if nickname is None:
                supported = ", ".join(sorted(_CRON_NICKNAMES))
                msg = f"unsupported cron shorthand {raw!r}; supported: {supported}"
                raise InvariantViolationError("schedule.cron_shorthand", msg)
            text = nickname
        else:
            text = _CRON_DISALLOWED.sub(" ", raw).strip()
        parts = text.split()
        if len(parts) != 5:
            msg = (
                f"cron expression {expression!r} has {len(parts)} field(s); the Mayhem "
                f"dialect has 5 ({' '.join(_CRON_FIELDS)}). Six- and seven-field cron "
                "expressions are not supported"
            )
            raise InvariantViolationError("schedule.cron_field_count", msg)
        pairs = zip(parts, _CRON_FIELDS, strict=True)
        values = [_parse_cron_field(part, field) for part, field in pairs]
        return {
            "expression": expression.strip(),
            "minutes": values[0],
            "hours": values[1],
            "days_of_month": values[2],
            "months": values[3],
            "days_of_week": values[4],
            "day_of_month_restricted": parts[2].strip() != "*",
            "day_of_week_restricted": parts[4].strip() != "*",
        }

    @classmethod
    def parse(cls, expression: str) -> CronSpec:
        """Parse ``expression`` into a :class:`CronSpec`."""
        return cls(**cls._parse_expression(expression))

    def matches(self, local: datetime) -> bool:
        """True when the naive wall clock ``local`` is one of this cron's minutes.

        ``local`` must be a **naive** wall clock. Attaching a zone here would be
        ambiguous about which of two instants an ambiguous wall clock means;
        :meth:`next_after` is the API that resolves a zone, and it always takes
        the first occurrence.

        Raises:
            InvariantViolationError: If ``local`` is timezone-aware.
        """
        if local.tzinfo is not None:
            msg = (
                "cron matching reads wall-clock fields; pass a naive local datetime, "
                f"got {local.isoformat()}"
            )
            raise InvariantViolationError("schedule.cron_naive", msg)
        if local.minute not in self.minutes or local.hour not in self.hours:
            return False
        if local.month not in self.months:
            return False
        day_of_month_hit = local.day in self.days_of_month
        day_of_week_hit = (local.weekday() + 1) % 7 in self.days_of_week
        if self.day_of_month_restricted and self.day_of_week_restricted:
            return day_of_month_hit or day_of_week_hit
        return day_of_month_hit and day_of_week_hit

    def next_after(
        self,
        after: datetime,
        *,
        tz: ZoneInfo,
        max_steps: int = CRON_SEARCH_LIMIT_MINUTES,
    ) -> datetime | None:
        """The first matching instant strictly after ``after``, in UTC.

        Walks the schedule's own wall clock minute by minute, so a fire time is
        "09:00 local, wherever and whenever that is". Local wall clocks the zone
        skipped are stepped over, and an ambiguous one contributes only its first
        occurrence. ``None`` means the expression admits no occurrence within
        ``max_steps`` -- the answer for an impossible calendar such as
        February 30th, which is bounded rather than hung.
        """
        floor = _as_utc(after, rule="schedule.cron_naive", subject="cron search floor")
        start = floor.astimezone(tz).replace(second=0, microsecond=0, tzinfo=None)
        candidate = start + timedelta(minutes=1)
        for _ in range(max_steps):
            if self.matches(candidate):
                aware = _resolve_local(candidate, tz)
                if aware is not None and aware.astimezone(UTC) > floor:
                    return aware.astimezone(UTC)
            candidate += timedelta(minutes=1)
        return None

    def describe(self) -> str:
        return f"cron {self.expression!r}"


class IntervalSpec(BaseModel):
    """A fixed-period recurrence anchored to an instant.

    Arithmetic is absolute, not wall-clock: occurrences are
    ``anchor + n * every_s``, so an interval schedule keeps its period across a
    DST transition instead of drifting by an hour twice a year.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    every_s: float = Field(gt=0.0)
    anchor_at: datetime
    #: Optional ceiling on the recurrence, as a count of occurrences.
    max_occurrences: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check_anchor(self) -> Self:
        _as_utc(self.anchor_at, rule="schedule.interval_naive", subject="interval anchor")
        return self

    @property
    def period(self) -> timedelta:
        return timedelta(seconds=self.every_s)

    def occurrence_at(self, index: int) -> datetime:
        """The ``index``-th occurrence (0 = the anchor).

        Raises:
            InvariantViolationError: If ``index`` is negative.
        """
        if index < 0:
            msg = f"occurrence index must be >= 0, got {index}"
            raise InvariantViolationError("schedule.interval_index", msg)
        return self.anchor_at + self.period * index

    def index_of(self, moment: datetime) -> int:
        """Which occurrence slot ``moment`` falls in; negative before the anchor."""
        instant = _as_utc(moment, rule="schedule.interval_naive", subject="interval probe")
        return math.floor((instant - self.anchor_at).total_seconds() / self.every_s)

    def exhausted_at(self, index: int) -> bool:
        """True when ``index`` is past the declared occurrence ceiling."""
        return self.max_occurrences is not None and index >= self.max_occurrences

    def next_after(self, after: datetime) -> datetime | None:
        """The first occurrence strictly after ``after``; ``None`` past the cap."""
        instant = _as_utc(after, rule="schedule.interval_naive", subject="interval probe")
        if instant < self.anchor_at:
            return self.anchor_at
        index = self.index_of(instant) + 1
        if self.exhausted_at(index):
            return None
        return self.occurrence_at(index)

    def describe(self) -> str:
        return f"every {self.every_s:g}s from {self.anchor_at.isoformat()}"


class CalendarWindow(BaseModel):
    """One explicit, one-off fire window in absolute time."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = ""
    starts_at: datetime
    ends_at: datetime

    @model_validator(mode="after")
    def _check_window(self) -> Self:
        _as_utc(self.starts_at, rule="schedule.window_naive", subject="calendar start")
        _as_utc(self.ends_at, rule="schedule.window_naive", subject="calendar end")
        if self.ends_at <= self.starts_at:
            msg = (
                f"calendar window {self.name!r} ends ({self.ends_at.isoformat()}) at or "
                f"before it starts ({self.starts_at.isoformat()})"
            )
            raise InvariantViolationError("schedule.window_empty", msg)
        return self

    def contains(self, now: datetime) -> bool:
        """True inside the window; half-open."""
        return self.starts_at <= now < self.ends_at

    def describe(self) -> str:
        label = f"{self.name} " if self.name else ""
        span = f"{self.starts_at.isoformat()} to {self.ends_at.isoformat()}"
        return f"{label}({span})"


# =============================================================================
# Schedule - recurrence plus the gates a fire time must clear
# =============================================================================


class FireCode(StrEnum):
    """Why a fire attempt did or did not happen. Recorded, never inferred."""

    FIRED = "schedule.fired"
    NOT_DUE = "schedule.not_due"
    MISSED = "schedule.missed"
    PREMATURE = "schedule.premature"
    EXPIRED = "schedule.expired"
    EXHAUSTED = "schedule.exhausted"
    OUTSIDE_BUSINESS_HOURS = "schedule.outside_business_hours"
    MAINTENANCE = "schedule.maintenance"
    BLACKOUT = "schedule.blackout"

    @property
    def is_non_fire(self) -> bool:
        """True for every code that is not :attr:`FIRED`.

        A convenience for callers that iterate the vocabulary and need the
        "nothing ran" test; reading it off the enum keeps every such test from
        re-spelling ``code is not FireCode.FIRED`` and possibly getting it wrong
        for one member.
        """
        return self is not FireCode.FIRED


class FireDecision(BaseModel):
    """The recorded outcome of asking one schedule to fire at one instant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fired: bool
    code: FireCode
    reason: str
    schedule_id: str
    now: datetime
    #: The slot being answered. For a cron or interval that is a point; for a
    #: calendar it is the *opening* of the window this evaluation fell inside,
    #: which is also what the claim ledger keys on -- a window must not mint a
    #: fresh key per poll inside it.
    slot_start: datetime | None = None
    #: The instant the schedule's effective time is measured from: the slot for
    #: cron and interval, the evaluation instant itself for a calendar window.
    #: Jitter is applied to *this*, and :attr:`lateness_s` is measured against
    #: it, so jitter and poller lateness are two separable facts.
    nominal_at: datetime | None = None
    effective_at: datetime | None = None
    #: How wide this schedule's slot stays open, copied in so a reader of a
    #: persisted decision can judge :attr:`lateness_s` without going back to the
    #: schedule body -- which may since have been edited to a different
    #: resolution, in which case the body would answer a question about a
    #: schedule that no longer exists.
    resolution_s: float = 60.0
    blocked_by: tuple[str, ...] = ()

    @property
    def jittered(self) -> bool:
        """True when jitter actually moved the effective time off the nominal.

        Measured against :attr:`nominal_at` -- the instant jitter was applied to
        -- and not against ``effective_at != slot_start``. The second reading is
        a lie twice over: an *unjittered* schedule polled 45s into a one-minute
        cron slot would report itself as jittered, dressing a late poller up as
        a deliberate offset; and a *calendar* schedule's slot is its whole
        window, so every evaluation inside the window would look jittered too.
        Comparing against the nominal says what it means: the offset is non-zero
        exactly when a declared jitter bound produced one. (A declared jitter
        whose hash happens to draw 0.0s reports ``False``, which is the truth --
        it moved nothing.)
        """
        return (
            self.effective_at is not None
            and self.nominal_at is not None
            and self.effective_at != self.nominal_at
        )

    @property
    def lateness_s(self) -> float:
        """How long after the nominal fire instant the evaluation happened.

        **The poller's lateness, and nothing else.** ``now - nominal_at``, not
        ``effective_at - slot_start``: after jitter is applied the difference
        between the effective instant and the slot *is the jitter offset*, so
        reading lateness off it would report a declared ±60s spread as a poller
        that was up to a minute late, which is a different fact about a
        different subsystem.

        Zero for a non-fire, for a refusal, and for an evaluation that landed
        exactly on its nominal instant. Zero for a *calendar* schedule, where the
        nominal **is** the evaluation instant by construction: a one-off window
        has no deadline to be late against, and the window's age is a fact about
        the window rather than about the poller.

        Non-zero for a cron or interval fire means the poller was late, and it is
        reported rather than absorbed -- a run that fires 45s into a one-minute
        cron slot is a different fact from one that fires on the slot, and the
        difference belongs in the record. Negative means the evaluation preceded
        its nominal instant, which the fire decision does not currently allow;
        the property is written so a future change that permitted it would be
        visible rather than silently negative.
        """
        if not self.fired or self.nominal_at is None:
            return 0.0
        return round((self.now - self.nominal_at).total_seconds(), JITTER_PRECISION)

    @property
    def missed_window(self) -> bool:
        """True when this evaluation is reporting a recurrence that was let go.

        Read off :attr:`code`, not recomputed from :attr:`lateness_s` and
        :attr:`resolution_s`, for a reason worth stating: a *fired* decision can
        be arbitrarily late and is not a missed window -- the poller answered
        inside the slot -- while a *missed* one is by construction not a fire at
        all. Asking "is this decision about a window nobody answered?" is one
        comparison against the vocabulary; deriving it from two numbers is four
        cases (fired/late, fired/late-enough, not-fired/on-time, not-fired/late)
        of which three are wrong.

        The related distinction is deliberately *not* folded in: a fire that is
        late enough to worry a human is still a fire, and :attr:`lateness_s` is
        where that fact lives.
        """
        return self.code is FireCode.MISSED

    def describe(self) -> str:
        verdict = "FIRED" if self.fired else "HELD"
        return (
            f"{self.schedule_id}: {verdict} at {self.now.isoformat()} "
            f"[{self.code.value}] {self.reason}"
        )


class Schedule(BaseModel):
    """One recurring or one-off run trigger with its safety gates.

    Exactly one recurrence source is set, and the two *recurring* kinds
    (``cron``, ``interval``) must also carry a **horizon** -- ``ends_at``,
    ``max_runs``, or ``interval.max_occurrences``. An unbounded recurrence is
    refused at construction: a schedule that can fire forever is a schedule that
    can outlive its reason, and the refusal is cheaper than the cleanup.

    Every gate is evaluated against an injected instant. ``created_at`` is part
    of the model, so a fire time that predates creation is a *recorded
    non-event* (:attr:`FireCode.PREMATURE`) rather than a run nobody approved.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schedule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    name: str = ""
    team: str = ""
    kind: ScheduleKind
    cron: CronSpec | None = None
    interval: IntervalSpec | None = None
    calendar: tuple[CalendarWindow, ...] = ()
    timezone_name: str = "UTC"
    business_hours: BusinessHours | None = None
    maintenance_windows: tuple[MaintenanceWindow, ...] = ()
    blackout_dates: BlackoutDates | None = None
    jitter: Jitter | None = None
    created_at: datetime
    ends_at: datetime | None = None
    max_runs: int | None = Field(default=None, ge=1)
    #: How wide a fire slot stays open. A cron slot is one minute wide; an
    #: interval slot is this wide after each occurrence, so a poller that is a
    #: few seconds late does not silently miss a recurrence.
    poll_resolution_s: float = Field(default=60.0, gt=0.0)
    schema_version: str = SCHEDULING_SCHEMA_VERSION

    # -- invariants -----------------------------------------------------------

    @model_validator(mode="after")
    def _check_schedule(self) -> Self:
        _as_utc(self.created_at, rule="schedule.created_naive", subject="schedule created_at")
        if self.ends_at is not None:
            _as_utc(self.ends_at, rule="schedule.ends_naive", subject="schedule ends_at")
            if self.ends_at <= self.created_at:
                msg = (
                    f"schedule {self.schedule_id!r} ends ({self.ends_at.isoformat()}) "
                    f"at or before it was created ({self.created_at.isoformat()})"
                )
                raise InvariantViolationError("schedule.horizon", msg)
        resolve_zone(self.timezone_name)
        self._check_recurrence()
        self._check_horizon()
        seen: set[str] = set()
        for window in self.maintenance_windows:
            if window.window_id in seen:
                msg = (
                    f"schedule {self.schedule_id!r} declares two windows named "
                    f"{window.window_id!r}"
                )
                raise InvariantViolationError("schedule.window_duplicate", msg)
            seen.add(window.window_id)
        return self

    def _check_recurrence(self) -> None:
        """Exactly one of cron / interval / calendar, and it must be ``kind``'s.

        ``sources`` is ordered so that element 0 is the source ``kind`` expects;
        the other two must be absent. Checking "exactly one is present" without
        that ordering would accept a schedule that declared both a cron and an
        interval, which is precisely the ambiguity the type is meant to remove.
        """
        expected, *others = {
            ScheduleKind.CRON: (self.cron is not None, bool(self.interval), bool(self.calendar)),
            ScheduleKind.INTERVAL: (
                self.interval is not None,
                bool(self.cron),
                bool(self.calendar),
            ),
            ScheduleKind.CALENDAR: (
                bool(self.calendar),
                bool(self.cron),
                bool(self.interval),
            ),
        }[self.kind]
        if expected and not any(others):
            return
        labels = ("cron", "interval", "calendar")
        present = (expected, *others)
        named = [label for label, seen in zip(labels, present, strict=True) if seen]
        msg = (
            f"schedule {self.schedule_id!r} is {self.kind.value} but carries "
            f"{named or 'no'} recurrence source; exactly one of "
            "cron/interval/calendar is required"
        )
        raise InvariantViolationError("schedule.recurrence_source", msg)

    def _check_horizon(self) -> None:
        """A recurring schedule must be able to retire."""
        if self.kind is ScheduleKind.CALENDAR:
            return
        capped = self.interval is not None and self.interval.max_occurrences is not None
        if self.ends_at is None and self.max_runs is None and not capped:
            msg = (
                f"schedule {self.schedule_id!r} is an unbounded {self.kind.value} "
                "recurrence; declare ends_at, max_runs, or interval.max_occurrences "
                "so the schedule can retire"
            )
            raise InvariantViolationError("schedule.unbounded_recurrence", msg)

    # -- reads ----------------------------------------------------------------

    @property
    def zone(self) -> ZoneInfo:
        """The schedule's timezone, resolved from ``timezone_name``."""
        return resolve_zone(self.timezone_name)

    def recurrence_description(self) -> str:
        if self.kind is ScheduleKind.CRON and self.cron is not None:
            return self.cron.describe()
        if self.kind is ScheduleKind.INTERVAL and self.interval is not None:
            return self.interval.describe()
        windows = ", ".join(window.describe() for window in self.calendar)
        return f"calendar [{windows}]"

    def blocking_maintenance(self, now: datetime) -> tuple[MaintenanceWindow, ...]:
        """Live maintenance windows covering ``now``, id-sorted."""
        return tuple(
            sorted(
                (window for window in self.maintenance_windows if window.contains(now)),
                key=lambda window: window.window_id,
            )
        )

    def blacked_out_on(self, local: datetime) -> date | None:
        """The blacked-out local date ``local`` falls on, else ``None``."""
        return None if self.blackout_dates is None else self.blackout_dates.hits(local)

    def slot_start(self, now: datetime) -> datetime | None:
        """Start of the fire slot containing ``now``, or ``None`` if there is none.

        A *slot*, not an instant: cron slots are one minute wide and an interval
        schedule's slot is ``poll_resolution_s`` wide, so "is it due" survives a
        poller that runs a few seconds late without turning every recurrence
        into a race.
        """
        moment = _as_utc(now, rule="schedule.slot_naive", subject="schedule probe")
        if self.ends_at is not None and moment > self.ends_at:
            return None
        if self.kind is ScheduleKind.CALENDAR:
            return self._calendar_slot(moment)
        if self.kind is ScheduleKind.CRON:
            return self._cron_slot(moment)
        return self._interval_slot(moment)

    def _calendar_slot(self, moment: datetime) -> datetime | None:
        for window in self.calendar:
            if window.contains(moment):
                return window.starts_at
        return None

    def _cron_slot(self, moment: datetime) -> datetime | None:
        if self.cron is None:  # pragma: no cover - guarded by _check_recurrence
            return None
        zone = self.zone
        wall = moment.astimezone(zone).replace(second=0, microsecond=0, tzinfo=None)
        if not self.cron.matches(wall):
            return None
        aware = _resolve_local(wall, zone)
        return None if aware is None else aware.astimezone(UTC)

    def _interval_slot(self, moment: datetime) -> datetime | None:
        interval = self.interval
        if interval is None:  # pragma: no cover - guarded by _check_recurrence
            return None
        anchor = interval.anchor_at.astimezone(UTC)
        if moment < anchor:
            return None
        index = interval.index_of(moment)
        if interval.exhausted_at(index):
            return None
        start = interval.occurrence_at(index)
        return start if (moment - start).total_seconds() < self.poll_resolution_s else None

    def _interval_missed(self, moment: datetime) -> datetime | None:
        """The occurrence a poller arriving at ``moment`` has already let go.

        ``None`` unless every one of these holds, which is why the predicate is
        a function rather than a flag:

        * the schedule is an interval one -- only an interval has a slot width a
          poller can be late past, since a cron slot is one minute wide and a
          calendar window stays open for as long as its author made it;
        * ``moment`` is at or after the anchor, so there is an occurrence to
          have missed;
        * the occurrence containing ``moment`` is *not* exhausted and its slot is
          *not* still open -- if it were, the poller is merely late and
          :meth:`_interval_slot` already answered;
        * that occurrence is inside the declared horizon.

        This is Phase 4's acceptance criterion made *distinguishable*: "a
        schedule whose window closed between creation and fire time does not fire,
        with the non-fire recorded". Reporting it as :attr:`FireCode.NOT_DUE`
        would record the non-fire and lose the reason -- and an operator reading
        the record at 09:05 could not then tell a quiet night from a recurrence
        that was slept through.
        """
        interval = self.interval
        if interval is None or self.kind is not ScheduleKind.INTERVAL:
            return None
        anchor = interval.anchor_at.astimezone(UTC)
        if moment < anchor:
            return None
        index = interval.index_of(moment)
        if interval.exhausted_at(index):
            return None
        # Called only when `_interval_slot` returned None, so the occurrence's
        # slot has already closed; recomputed here rather than assumed, because
        # "already closed" is the property being reported and reading it off the
        # caller would be a claim about the caller instead.
        missed = interval.occurrence_at(index)
        if (moment - missed).total_seconds() < self.poll_resolution_s:
            return None
        if self.ends_at is not None and missed > self.ends_at.astimezone(UTC):
            return None
        return missed

    def is_due(self, now: datetime, *, run_count: int = 0) -> bool:
        """True when a fire slot covers ``now`` and the run budget allows it."""
        if self.max_runs is not None and run_count >= self.max_runs:
            return False
        return self.slot_start(now) is not None

    def next_fire_time(self, after: datetime) -> datetime | None:
        """The next nominal fire instant strictly after ``after``, in UTC.

        ``None`` means the recurrence is finished: the horizon closed, the
        occurrence ceiling was reached, or the expression admits no future
        occurrence at all.
        """
        instant = _as_utc(after, rule="schedule.next_naive", subject="schedule search floor")
        if self.kind is ScheduleKind.CALENDAR:
            upcoming = [window.starts_at for window in self.calendar if window.starts_at > instant]
            candidate: datetime | None = min(upcoming) if upcoming else None
        elif self.kind is ScheduleKind.CRON and self.cron is not None:
            candidate = self.cron.next_after(instant, tz=self.zone)
        elif self.interval is not None:
            candidate = self.interval.next_after(instant)
        else:  # pragma: no cover - guarded by _check_recurrence
            candidate = None
        if candidate is None:
            return None
        return None if self.ends_at is not None and candidate > self.ends_at else candidate

    # -- the decision ---------------------------------------------------------

    def evaluate(self, *, now: datetime, run_count: int = 0) -> FireDecision:
        """Decide whether this schedule fires at ``now``, and record why.

        ``now`` is the *fire* instant -- the scheduler passes the moment it is
        about to dispatch, not the moment the schedule was created. That is the
        Phase 4 requirement ("windows are evaluated live") expressed as a
        signature: there is no second, stale copy of "is it allowed" anywhere in
        this module.

        Every refusal carries a :class:`FireCode` and a reason, so a non-fire is
        an evidence object rather than a silence.

        Raises:
            InvariantViolationError: If ``now`` is naive.
        """
        moment = _as_utc(now, rule="schedule.evaluate_naive", subject="schedule fire attempt")
        refusal = self._budget_refusal(moment, run_count=run_count)
        if refusal is None:
            refusal = self._calendar_refusal(moment)
        if refusal is not None:
            return refusal
        slot = self.slot_start(moment)
        # Jitter is applied to the *nominal*, not to the evaluation instant, so
        # the declared bound is a bound on how far the fire time may move from
        # the slot -- which is the thing a late poller would otherwise be free to
        # add on top of it, unbounded by anything the author wrote. With no
        # jitter declared the effective instant *is* the nominal, which is what
        # makes ``jittered`` and ``lateness_s`` separable.
        #
        # A calendar window's nominal is the evaluation instant rather than the
        # window's opening. A one-off window is open for however long its author
        # made it, so there is no deadline to be late against and no stampede to
        # spread -- measuring against the window's start would report a run
        # scheduled for a 09:00-12:00 window as "three hours late" at 12:00.
        nominal = moment if self.kind is ScheduleKind.CALENDAR else (slot or moment)
        jitter = self.jitter
        effective = nominal if jitter is None else jitter.apply(nominal, seed=self.schedule_id)
        return FireDecision(
            fired=True,
            code=FireCode.FIRED,
            reason=f"fire slot is open and every gate cleared for {self.schedule_id}",
            schedule_id=self.schedule_id,
            now=moment,
            slot_start=slot,
            nominal_at=nominal,
            effective_at=effective,
            resolution_s=self.poll_resolution_s,
        )

    def _budget_refusal(self, moment: datetime, *, run_count: int) -> FireDecision | None:
        """Refuse a fire that predates creation or overran the run budget."""
        if moment < self.created_at.astimezone(UTC):
            return self._hold(
                FireCode.PREMATURE,
                f"fire time {moment.isoformat()} predates schedule creation "
                f"({self.created_at.isoformat()})",
                moment,
                blocked_by=("created_at",),
            )
        if self.max_runs is not None and run_count >= self.max_runs:
            return self._hold(
                FireCode.EXHAUSTED,
                f"schedule already ran its budget of {self.max_runs} run(s)",
                moment,
                blocked_by=("max_runs",),
            )
        return None

    def _no_slot_refusal(self, moment: datetime) -> FireDecision:
        """The recorded non-event for an instant no fire slot covers.

        Three codes, and the distinction between them is the point:
        :attr:`FireCode.EXPIRED` when the horizon closed,
        :attr:`FireCode.MISSED` when a recurrence's slot opened and closed with no
        poller in it, and :attr:`FireCode.NOT_DUE` for an ordinary quiet instant.
        Collapsing the middle one into ``NOT_DUE`` would make "nothing was
        scheduled at this minute" and "we slept through the 09:00 run" the same
        record, and an operator reading that record at 09:05 could not tell a
        quiet night from a missed recurrence.

        Only an *interval* schedule can miss this way, because only an interval
        has a slot width the poller can be late past: a cron slot is one minute
        wide and a calendar window stays open for as long as its author made it,
        so for both of them "no slot covers this instant" is genuinely
        :attr:`FireCode.NOT_DUE`.
        """
        if self.ends_at is not None and moment > self.ends_at.astimezone(UTC):
            return self._hold(
                FireCode.EXPIRED,
                f"schedule horizon closed at {self.ends_at.isoformat()}",
                moment,
                blocked_by=("ends_at",),
            )
        missed = self._interval_missed(moment)
        if missed is not None:
            gap = round((moment - missed).total_seconds(), JITTER_PRECISION)
            return self._hold(
                FireCode.MISSED,
                (
                    f"recurrence due at {missed.isoformat()} was missed: its slot stayed "
                    f"open for {self.poll_resolution_s:g}s and this evaluation arrived "
                    f"{gap:g}s after it closed. The next fire answers a *different* slot "
                    "with a different idempotency key, so this occurrence is not retried"
                ),
                moment,
                slot=missed,
                blocked_by=("poll_resolution_s",),
            )
        return self._hold(
            FireCode.NOT_DUE,
            f"no fire slot covers {moment.isoformat()}",
            moment,
        )

    def _calendar_refusal(self, moment: datetime) -> FireDecision | None:
        """Refuse a fire the recurrence, the calendar, or the live gates deny."""
        slot = self.slot_start(moment)
        if slot is None:
            return self._no_slot_refusal(moment)
        local = moment.astimezone(self.zone)
        day = self.blacked_out_on(local)
        if day is not None:
            return self._hold(
                FireCode.BLACKOUT,
                f"{day.isoformat()} is a blackout date",
                moment,
                slot=slot,
                blocked_by=(f"blackout:{day.isoformat()}",),
            )
        windows = self.blocking_maintenance(moment)
        if windows:
            return self._hold(
                FireCode.MAINTENANCE,
                f"maintenance window {windows[0].describe()} is in force",
                moment,
                slot=slot,
                blocked_by=tuple(f"maintenance:{window.window_id}" for window in windows),
            )
        hours = self.business_hours
        if hours is not None and not hours.contains(local):
            return self._hold(
                FireCode.OUTSIDE_BUSINESS_HOURS,
                hours.closed_reason(local),
                moment,
                slot=slot,
                blocked_by=("business_hours",),
            )
        return None

    def _hold(
        self,
        code: FireCode,
        reason: str,
        moment: datetime,
        *,
        slot: datetime | None = None,
        blocked_by: tuple[str, ...] = (),
    ) -> FireDecision:
        """Build the recorded non-event for one refused gate."""
        return FireDecision(
            fired=False,
            code=code,
            reason=reason,
            schedule_id=self.schedule_id,
            now=moment,
            slot_start=slot,
            resolution_s=self.poll_resolution_s,
            blocked_by=blocked_by,
        )

    def describe(self) -> str:
        horizon = self.ends_at.isoformat() if self.ends_at else f"max {self.max_runs} run(s)"
        return (
            f"{self.schedule_id} [{self.timezone_name}] {self.recurrence_description()}; "
            f"created {self.created_at.isoformat()}, horizon {horizon}"
        )


# =============================================================================
# Fairness - per-team shares with starvation prevention (gap 84)
# =============================================================================


class GrantRecord(BaseModel):
    """One slot granted to one team in one window. This is the whole history."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    window_index: int = Field(ge=0)
    team: str = Field(min_length=1)
    schedule_id: str = ""


def grant_counts(history: Iterable[GrantRecord]) -> dict[str, int]:
    """How many grants each team received, id-sorted."""
    counts: dict[str, int] = {}
    for record in history:
        counts[record.team] = counts.get(record.team, 0) + 1
    return {team: counts[team] for team in sorted(counts)}


def longest_skip_runs(
    history: Iterable[GrantRecord], *, teams: Sequence[str], windows: int
) -> dict[str, int]:
    """Longest run of consecutive un-granted windows per team.

    Both the gap *between* two grants and the trailing gap after the last one
    count: a team served in window 0 and then never again has gone without a
    grant for every window since, and reporting only interior gaps would hide
    exactly the case the guarantee is about.
    """
    records = tuple(history)
    result: dict[str, int] = {}
    for team in sorted(teams):
        granted = sorted(record.window_index for record in records if record.team == team)
        longest = 0
        previous = -1
        for index in granted:
            longest = max(longest, index - previous - 1)
            previous = index
        result[team] = max(longest, windows - 1 - previous)
    return result


class FairnessSimulation(BaseModel):
    """The recorded result of a fairness simulation, and its verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str
    windows: int
    grants: tuple[tuple[str, ...], ...] = ()
    counts: dict[str, int] = Field(default_factory=dict)
    max_consecutive_skips: dict[str, int] = Field(default_factory=dict)

    def starvation_bound(self, policy: FairnessPolicy) -> int:
        """The longest starvation a demanding team may experience, in windows.

        ``starvation_window + demanding_teams - 1``, and the argument is short.
        A team is served in the first window where it has the *largest* skip
        count among the starving, because that tier is ordered longest-wait
        first. So its count can only grow while a peer holding an equal or
        larger count is served instead -- and there are at most
        ``demanding_teams - 1`` of those before it is the only one left. The
        bound is tight at ``starvation_window`` whenever at most one team is
        starving at a time (an evenly weighted policy, or a lightly loaded one).
        """
        return policy.starvation_window + max(0, len(self.max_consecutive_skips) - 1)

    def honours_policy(self, policy: FairnessPolicy) -> bool:
        """True when no demanding team was starved beyond :meth:`starvation_bound`."""
        return all(
            skips <= self.starvation_bound(policy) for skips in self.max_consecutive_skips.values()
        )

    def starved_teams(self, policy: FairnessPolicy) -> tuple[str, ...]:
        """Teams the simulation starved past the bound, id-sorted."""
        bound = self.starvation_bound(policy)
        offenders = (team for team, skips in self.max_consecutive_skips.items() if skips > bound)
        return tuple(sorted(offenders))

    def describe(self) -> str:
        served = ", ".join(f"{team}={count}" for team, count in sorted(self.counts.items()))
        return f"{self.policy_id} over {self.windows} windows: {served}"


class FairnessPolicy(BaseModel):
    """Weighted per-team shares with an absolute anti-starvation rule.

    ``shares`` are relative weights, not fractions: they need not sum to one. A
    team absent from ``shares`` still gets ``default_share``.

    Starvation prevention is not "weight everyone up over time" -- it is a
    priority rule. Once a team has been skipped for ``starvation_window``
    consecutive windows it outranks every team that has not, regardless of
    weight, and inside that tier the longest-waiting team is served first. That
    makes the guarantee a property of :meth:`select_team`; the exact worst case a
    demanding team can suffer is :meth:`FairnessSimulation.starvation_bound`, and
    :meth:`simulate_fairness` is how it is checked rather than asserted.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    shares: dict[str, float] = Field(default_factory=dict)
    default_share: float = Field(default=1.0, ge=0.0)
    #: Consecutive skipped windows after which a demanding team jumps the queue.
    starvation_window: int = Field(default=3, ge=1)
    #: Slots issuable in one window. Bounds any single team's share in practice.
    max_grants_per_window: int = Field(default=1, ge=1)
    description: str = ""

    @model_validator(mode="after")
    def _check_shares(self) -> Self:
        if not self.shares:
            msg = f"fairness policy {self.policy_id!r} names no teams"
            raise InvariantViolationError("fairness.no_shares", msg)
        for team, weight in sorted(self.shares.items()):
            if not team:
                msg = f"fairness policy {self.policy_id!r} has an empty team name"
                raise InvariantViolationError("fairness.empty_team", msg)
            if not math.isfinite(weight) or weight < 0.0:
                msg = f"fairness policy {self.policy_id!r} gives team {team!r} share {weight}"
                raise InvariantViolationError("fairness.share_range", msg)
        if math.fsum(self.shares.values()) <= 0.0:
            msg = f"fairness policy {self.policy_id!r} gives every team a zero share"
            raise InvariantViolationError("fairness.share_total", msg)
        return self

    def share_of(self, team: str) -> float:
        """``team``'s weight, falling back to ``default_share``."""
        return self.shares.get(team, self.default_share)

    def teams(self) -> tuple[str, ...]:
        """Every team the policy names, id-sorted."""
        return tuple(sorted(self.shares))

    def normalised_deficit(
        self, team: str, pending: Sequence[str], history: Sequence[GrantRecord]
    ) -> float:
        """How far ``team`` is behind its entitlement, as a fraction in (-1, 1).

        Two normalisations, both against the *currently demanding* set: the
        team's share over the shares of everyone in ``pending``, minus the share
        of all grants it has already received. A team with weight 9 among two
        teams starts at +0.8 and falls below zero once it has been served more
        than its share of the slots.

        This is weighted deficit round robin, and it is what makes ``shares``
        mean something: "longest wait" on its own would collapse every policy to
        round robin regardless of the weights the author wrote.
        """
        total_share = math.fsum(self.share_of(candidate) for candidate in pending)
        if total_share <= 0.0:
            return 0.0
        granted = sum(1 for record in history if record.team == team)
        served = granted / len(history) if history else 0.0
        return self.share_of(team) / total_share - served

    def consecutive_skips(
        self, team: str, history: Sequence[GrantRecord], *, window_index: int
    ) -> int:
        """How many windows in a row ``team`` has gone without a grant."""
        skipped = 0
        for index in range(window_index - 1, -1, -1):
            if any(record.team == team and record.window_index == index for record in history):
                break
            skipped += 1
        return skipped

    def is_starving(self, team: str, history: Sequence[GrantRecord], *, window_index: int) -> bool:
        """True once ``team`` has been skipped for ``starvation_window`` windows."""
        waits = self.consecutive_skips(team, history, window_index=window_index)
        return waits >= self.starvation_window

    def select_team(
        self,
        pending: Sequence[str],
        history: Sequence[GrantRecord],
        *,
        window_index: int,
    ) -> str | None:
        """The team to grant next, or ``None`` when nobody is asking.

        Ordering, highest priority first:

        1. starving teams -- skipped ``starvation_window`` windows or more,
           regardless of weight. This is the guarantee, stated as a rule;
        2. inside that tier, the team that has gone without a grant for *longest*
           (FIFO), so simultaneous starvation does not compound;
        3. then the largest :meth:`normalised_deficit`, which is how the
           author's weights actually take effect;
        4. then team name, so the choice is total and reproducible.

        The final tiebreak is what makes a fairness decision replayable: two
        teams with equal deficit always resolve the same way, whatever order
        they arrived in. Note that "longest wait" is *not* a rule that applies to
        every team -- a team that has waited longer has a lower served fraction
        and therefore a larger deficit, which is the same preference expressed in
        units comparable across teams of different weights.
        """
        candidates = sorted(
            pending,
            key=lambda team: (
                0 if self.is_starving(team, history, window_index=window_index) else 1,
                -self.consecutive_skips(team, history, window_index=window_index)
                if self.is_starving(team, history, window_index=window_index)
                else 0,
                -round(self.normalised_deficit(team, pending, history), DEFICIT_PRECISION),
                team,
            ),
        )
        return candidates[0] if candidates else None

    def simulate_fairness(self, teams: Sequence[str], *, windows: int) -> FairnessSimulation:
        """Run ``windows`` windows in which every team always demands a slot.

        Constant demand is the deliberate assumption: a team that stops asking
        cannot be starved by definition, so simulating unconditional demand is
        the strongest reading of the guarantee. Pure -- the same inputs always
        produce the same grant sequence.

        Raises:
            InvariantViolationError: If there are no teams or no windows.
        """
        demanding = tuple(sorted(set(teams)))
        if not demanding:
            msg = "fairness simulation needs at least one demanding team"
            raise InvariantViolationError("fairness.no_teams", msg)
        if windows < 1:
            msg = f"fairness simulation needs at least one window, got {windows}"
            raise InvariantViolationError("fairness.window_count", msg)
        history: list[GrantRecord] = []
        per_window: list[tuple[str, ...]] = []
        for index in range(windows):
            available = list(demanding)
            granted: list[str] = []
            for _ in range(self.max_grants_per_window):
                pick = self.select_team(tuple(available), history, window_index=index)
                if pick is None:
                    break
                available.remove(pick)
                history.append(GrantRecord(window_index=index, team=pick))
                granted.append(pick)
            per_window.append(tuple(granted))
        return FairnessSimulation(
            policy_id=self.policy_id,
            windows=windows,
            grants=tuple(per_window),
            counts=grant_counts(history),
            max_consecutive_skips=longest_skip_runs(history, teams=demanding, windows=windows),
        )

    def describe(self) -> str:
        teams = ", ".join(f"{team}={weight:g}" for team, weight in sorted(self.shares.items()))
        return (
            f"{self.policy_id}: {teams} (default {self.default_share:g}, "
            f"starvation window {self.starvation_window}, "
            f"{self.max_grants_per_window} grant(s)/window)"
        )


# =============================================================================
# Concurrency - the experiment concurrency model (gap 85)
# =============================================================================


class ConcurrencyClass(StrEnum):
    """How a run relates to other runs on the resources it names.

    ``PARALLEL``
        Takes no resource locks. May overlap anything. This is the strongest
        claim an author can make and the only class under which a run can share a
        resource without naming it -- which is why a ``PARALLEL`` request that
        names a resource is refused at construction.
    ``EXCLUSIVE``
        Needs a resource to itself, serializing against every other class on it.
        This is the "one experiment owns the database" case.
    ``SHARED_RESOURCE``
        Uses a resource many runs may hold at once, up to whatever capacity the
        resource itself declares. Coexists with ``SHARED_RESOURCE`` and
        ``PREEMPTIBLE`` runs; yields to ``EXCLUSIVE``.
    ``CONFLICTING``
        Statically incompatible with every other class on any shared resource
        (fault families that must never co-occur). Not overridable by weight or
        by an expiry: only a free resource satisfies it.
    ``PREEMPTIBLE``
        May be interrupted to yield a resource to an ``EXCLUSIVE`` run. Coexists
        with ``SHARED_RESOURCE`` and other ``PREEMPTIBLE`` runs.
    """

    PARALLEL = "parallel"
    EXCLUSIVE = "exclusive"
    SHARED_RESOURCE = "shared_resource"
    CONFLICTING = "conflicting"
    PREEMPTIBLE = "preemptible"


LOCK_COMPATIBILITY: Final[dict[ConcurrencyClass, frozenset[ConcurrencyClass]]] = {
    ConcurrencyClass.PARALLEL: frozenset(ConcurrencyClass),
    ConcurrencyClass.EXCLUSIVE: frozenset({ConcurrencyClass.PARALLEL}),
    ConcurrencyClass.SHARED_RESOURCE: frozenset(
        {
            ConcurrencyClass.PARALLEL,
            ConcurrencyClass.SHARED_RESOURCE,
            ConcurrencyClass.PREEMPTIBLE,
        }
    ),
    ConcurrencyClass.CONFLICTING: frozenset({ConcurrencyClass.PARALLEL}),
    ConcurrencyClass.PREEMPTIBLE: frozenset(
        {
            ConcurrencyClass.PARALLEL,
            ConcurrencyClass.SHARED_RESOURCE,
            ConcurrencyClass.PREEMPTIBLE,
        }
    ),
}
"""Which class a run of each kind may overlap.

Symmetric by construction and checked as such by the tests: a class appears in
its own row only when it may run alongside itself. ``EXCLUSIVE`` and
``CONFLICTING`` appear in nobody's row except ``PARALLEL``'s, and ``PARALLEL``
names no resources, so the two entries pointing at it are unreachable in
practice rather than a loophole -- the conservative reading is kept so that a
misdeclared request is refused rather than admitted.
"""


def classes_compatible(left: ConcurrencyClass, right: ConcurrencyClass) -> bool:
    """True when a run of ``left`` may overlap a run of ``right``.

    Symmetric and pure. This is the whole of gap 85's vocabulary; resource
    overlap and lock state are layered on top by :func:`evaluate_concurrency`.
    """
    return right in LOCK_COMPATIBILITY[left] and left in LOCK_COMPATIBILITY[right]


def _lock_id(run_id: str, resource: str) -> str:
    """A 07-legal lock id built from a run id and a resource name.

    The resource is lowercased and every run of characters outside 07's
    ``[a-z0-9._:-]`` set collapses to a single hyphen, so ``"Data/Primary DB"``
    and ``"data/primary db"`` produce the same id -- two spellings of one
    resource must not become two locks.
    """
    cleaned = re.sub(r"[^a-z0-9._:-]+", "-", resource.lower()).strip("-") or "resource"
    return f"{run_id}--{cleaned}"[:128]


class ConcurrencyRequest(BaseModel):
    """One run asking for a place in the concurrency model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    experiment_id: str = Field(min_length=1)
    team: str = ""
    concurrency_class: ConcurrencyClass
    resources: tuple[str, ...] = ()
    acquired_at: datetime
    expires_at: datetime
    priority: int = 0

    @model_validator(mode="after")
    def _check_request(self) -> Self:
        _as_utc(self.acquired_at, rule="concurrency.naive", subject="acquired_at")
        _as_utc(self.expires_at, rule="concurrency.naive", subject="expires_at")
        if self.expires_at <= self.acquired_at:
            msg = (
                f"concurrency request {self.run_id!r} expires "
                f"({self.expires_at.isoformat()}) at or before it acquires "
                f"({self.acquired_at.isoformat()})"
            )
            raise InvariantViolationError("concurrency.window", msg)
        if len(set(self.resources)) != len(self.resources):
            msg = f"concurrency request {self.run_id!r} names a resource twice"
            raise InvariantViolationError("concurrency.resource_duplicate", msg)
        if self.concurrency_class is ConcurrencyClass.PARALLEL and self.resources:
            msg = (
                f"concurrency request {self.run_id!r} is PARALLEL but names "
                f"{list(self.resources)}; a parallel run takes no resource locks, so "
                "it cannot also reserve one"
            )
            raise InvariantViolationError("concurrency.parallel_resources", msg)
        return self

    def is_live(self, now: datetime) -> bool:
        """True before ``expires_at``; an abandoned request fences nothing."""
        return now < self.expires_at

    def shares_resource_with(self, other: ConcurrencyRequest) -> bool:
        """True when the two requests name at least one common resource."""
        return bool(set(self.resources) & set(other.resources))

    def lock_for(self, resource: str) -> ResourceLock:
        """The 07 :class:`ResourceLock` this request implies on ``resource``.

        The lock id is derived from the run and the resource, so re-acquiring the
        same resource within one run stays re-entrant under 07's rules, exactly as
        ``lock_conflicts`` intends.
        """
        return ResourceLock(
            lock_id=_lock_id(self.run_id, resource),
            resource=resource,
            experiment_id=self.experiment_id,
            owner_run_id=self.run_id,
            acquired_at=self.acquired_at,
            expires_at=self.expires_at,
            reason=f"{self.concurrency_class.value} concurrency request",
        )

    def describe(self) -> str:
        held = ", ".join(self.resources) or "no resources"
        return (
            f"{self.run_id} ({self.concurrency_class.value}, experiment "
            f"{self.experiment_id}) holding {held} until {self.expires_at.isoformat()}"
        )


class ConcurrencyVerdict(BaseModel):
    """Whether a request may start now, and which run is in the way if not."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    runnable: bool
    run_id: str
    concurrency_class: ConcurrencyClass
    requested_by: str = ""
    blocking_run_id: str = ""
    blocking_experiment_id: str = ""
    blocking_resource: str = ""
    blocking_reason: str = ""
    blockers: tuple[str, ...] = ()
    reason: str = ""

    def queued_behind(self) -> str:
        """The run to name in a refusal; empty when nothing is blocking."""
        return self.blocking_run_id

    def describe(self) -> str:
        verdict = "runnable" if self.runnable else f"queued behind {self.queued_behind()}"
        return f"{self.run_id} ({self.concurrency_class.value}) {verdict}: {self.reason}"


def conflicting_runs(
    active: Iterable[ConcurrencyRequest],
    requested: ConcurrencyRequest,
    *,
    now: datetime,
) -> tuple[ConcurrencyRequest, ...]:
    """Live requests whose class forbids overlapping ``requested``, id-sorted.

    Two liveness tests, and both are needed. ``now`` drops requests that have
    already been abandoned -- the reason a dead run cannot fence a resource
    forever -- and the candidate's own ``acquired_at`` drops requests whose
    window ends before the candidate ever starts, which is how two sequential
    uses of one resource are told apart from two overlapping ones.

    A request never conflicts with itself: one run taking a second step on a
    resource it already holds is re-entrant, the same rule 07's ``lock_conflicts``
    applies to resource locks.
    """
    conflicts = [
        other
        for other in active
        if other.run_id != requested.run_id
        and other.is_live(now)
        and other.is_live(requested.acquired_at)
        and other.shares_resource_with(requested)
        and not classes_compatible(other.concurrency_class, requested.concurrency_class)
    ]
    return tuple(sorted(conflicts, key=lambda other: other.run_id))


def _first_shared_resource(left: ConcurrencyRequest, right: ConcurrencyRequest) -> str:
    for resource in sorted(set(left.resources) & set(right.resources)):
        return resource
    return ""


def evaluate_concurrency(
    active: Iterable[ConcurrencyRequest],
    requested: ConcurrencyRequest,
    locks: Iterable[ResourceLock] = (),
    *,
    now: datetime,
) -> ConcurrencyVerdict:
    """Decide whether ``requested`` may start, naming the run that blocks it.

    Two layers, in order:

    1. the :data:`LOCK_COMPATIBILITY` matrix, which refuses a class pair that may
       never overlap; then
    2. 07's :func:`~mayhem.domain.policy.acquire_lock`, which refuses a resource
       already reserved by a live lock.

    Both name the blocking run, so the refusal a caller records reads the same
    way in either case: "queued behind run-2, which holds db-primary". Expired
    requests and expired locks are dropped first, which is what keeps a dead run
    from fencing a resource forever.

    Raises:
        InvariantViolationError: If ``now`` is naive.
    """
    moment = _as_utc(now, rule="concurrency.naive", subject="concurrency probe")
    conflicts = conflicting_runs(active, requested, now=moment)
    if conflicts:
        return _class_conflict_verdict(requested, conflicts)
    for resource in requested.resources:
        verdict = acquire_lock(locks, requested.lock_for(resource), now=moment)
        if not verdict.granted:
            return ConcurrencyVerdict(
                runnable=False,
                run_id=requested.run_id,
                concurrency_class=requested.concurrency_class,
                requested_by=requested.run_id,
                blocking_run_id=verdict.queued_behind(),
                blocking_experiment_id=verdict.holder_experiment_id,
                blocking_resource=resource,
                blocking_reason="resource reserved by a live lock",
                blockers=verdict.blockers,
                reason=verdict.reason,
            )
    held = ", ".join(requested.resources) or "no resources"
    return ConcurrencyVerdict(
        runnable=True,
        run_id=requested.run_id,
        concurrency_class=requested.concurrency_class,
        requested_by=requested.run_id,
        reason=f"no live {requested.concurrency_class.value} run conflicts; {held} available",
    )


def _class_conflict_verdict(
    requested: ConcurrencyRequest, conflicts: tuple[ConcurrencyRequest, ...]
) -> ConcurrencyVerdict:
    """The refusal for a class pair that may never overlap, naming the holder."""
    first = conflicts[0]
    resource = _first_shared_resource(requested, first)
    return ConcurrencyVerdict(
        runnable=False,
        run_id=requested.run_id,
        concurrency_class=requested.concurrency_class,
        requested_by=requested.run_id,
        blocking_run_id=first.run_id,
        blocking_experiment_id=first.experiment_id,
        blocking_resource=resource,
        blocking_reason=(
            f"{first.concurrency_class.value} and {requested.concurrency_class.value} "
            f"runs may not share {resource}"
        ),
        blockers=tuple(other.run_id for other in conflicts),
        reason=(
            f"queued behind run {first.run_id} (experiment {first.experiment_id}), "
            f"which holds {resource} under concurrency class "
            f"{first.concurrency_class.value} until {first.expires_at.isoformat()}"
        ),
    )


def admit(
    active: Sequence[ConcurrencyRequest],
    candidate: ConcurrencyRequest,
    *,
    now: datetime,
    locks: Iterable[ResourceLock] = (),
) -> tuple[ConcurrencyVerdict, tuple[ConcurrencyRequest, ...]]:
    """Admit ``candidate`` if the model allows, returning the updated active set.

    A pure queue step: the same helper drives a one-at-a-time drain and a
    parallel-admission sweep, and it never mutates ``active``. A refused
    candidate leaves the set byte-for-byte identical, which is what "the second
    queues and names the first" means as a fact about state rather than as a
    message someone chose to write.
    """
    verdict = evaluate_concurrency(active, candidate, locks, now=now)
    if not verdict.runnable:
        return verdict, tuple(active)
    return verdict, (*active, candidate)
