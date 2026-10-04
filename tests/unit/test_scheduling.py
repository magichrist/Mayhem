"""Plan 13 Phase 1: schedule evaluation, fairness, and concurrency.

Three things are being defended here, and they are deliberately kept apart:

* a schedule's decision is a **pure function of an injected instant** -- DST
  boundaries, business hours, blackouts, and jitter are computed, not slept
  through;
* the fairness rule **provably** prevents starvation, checked by simulation
  over hundreds of windows rather than asserted in a docstring;
* two experiments that may not overlap **serialize, naming the holder**, which
  is a state fact and not a message someone remembered to write.

The negative controls at the end are the ones that would let a scheduler
misbehave quietly: a window that closed after the schedule was created, an
unbounded recurrence, and a fire time that predates creation.
"""

from __future__ import annotations

import ast
from datetime import UTC, date, datetime, time, timedelta
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.policy import ResourceLock

if TYPE_CHECKING:
    from collections.abc import Callable
from mayhem.domain.scheduling import (
    LOCK_COMPATIBILITY,
    BlackoutDates,
    BusinessHours,
    CalendarWindow,
    ConcurrencyClass,
    ConcurrencyRequest,
    CronSpec,
    DailyWindow,
    FairnessPolicy,
    FireCode,
    GrantRecord,
    IntervalSpec,
    Jitter,
    MaintenanceWindow,
    Schedule,
    ScheduleKind,
    admit,
    classes_compatible,
    conflicting_runs,
    evaluate_concurrency,
    grant_counts,
    local_time_exists,
    local_time_is_ambiguous,
    longest_skip_runs,
    resolve_zone,
    windows_overlap,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DOMAIN_MODULE = REPO_ROOT / "src" / "mayhem" / "domain" / "scheduling.py"

NY = ZoneInfo("America/New_York")
UTC_ZONE = ZoneInfo("UTC")

#: 2026-03-08 is the US spring-forward date; 2026-11-01 the fall-back date.
SPRING_FORWARD = date(2026, 3, 8)
FALL_BACK = date(2026, 11, 1)

CREATED = datetime(2026, 1, 1, tzinfo=UTC)
HORIZON = datetime(2027, 1, 1, tzinfo=UTC)


def _utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def _wall(*args: int) -> datetime:
    """A deliberately naive wall clock.

    Every use below is one of the two things this module is about: a cron
    ``matches()`` call takes a naive local datetime, or a test is handing the
    domain a naive instant precisely to watch it refuse. Those are the only
    reasons to build one, so the reason is named at the definition rather than
    silenced at twenty call sites.
    """
    return datetime(*args)  # noqa: DTZ001


def _rule(candidate: Callable[[], object]) -> str:
    """Run ``candidate`` and return the rule id of the invariant it violated."""
    with pytest.raises(InvariantViolationError) as excinfo:
        candidate()
    return excinfo.value.rule


# --- cron dialect -------------------------------------------------------------


def test_cron_parses_every_atom_of_the_dialect() -> None:
    spec = CronSpec.parse("0,30 9-17/4 1,15 JAN,JUN MON-FRI")

    assert spec.minutes == frozenset({0, 30})
    assert spec.hours == frozenset({9, 13, 17})
    assert spec.days_of_month == frozenset({1, 15})
    assert spec.months == frozenset({1, 6})
    assert spec.days_of_week == frozenset({1, 2, 3, 4, 5})


@pytest.mark.parametrize(
    ("shorthand", "expanded"),
    [
        ("@hourly", "0 * * * *"),
        ("@daily", "0 0 * * *"),
        ("@midnight", "0 0 * * *"),
        ("@weekly", "0 0 * * 0"),
        ("@monthly", "0 0 1 * *"),
        ("@yearly", "0 0 1 1 *"),
        ("@annually", "0 0 1 1 *"),
    ],
)
def test_cron_shorthand_expands_to_its_documented_expression(
    shorthand: str, expanded: str
) -> None:
    reference = CronSpec.parse(expanded)
    spec = CronSpec.parse(shorthand)

    assert spec.hours == reference.hours
    assert spec.minutes == reference.minutes
    assert spec.days_of_month == reference.days_of_month
    assert spec.days_of_week == reference.days_of_week
    assert spec.expression == shorthand


def test_cron_hourly_fires_on_every_hour_but_midnight_only() -> None:
    """@hourly is "0 * * * *" -- every hour, on the hour, not just midnight."""
    hourly = CronSpec.parse("@hourly")
    daily = CronSpec.parse("@daily")

    assert hourly.hours == frozenset(range(24))
    assert daily.hours == frozenset({0})


def test_cron_shorthand_is_case_insensitive() -> None:
    assert CronSpec.parse("@DAILY").hours == CronSpec.parse("@daily").hours


def test_cron_day_of_week_seven_folds_onto_sunday() -> None:
    assert CronSpec.parse("0 0 * * 7").days_of_week == CronSpec.parse("0 0 * * 0").days_of_week


def test_cron_day_and_weekday_restrictions_union_like_vixie() -> None:
    """Both restricted means OR, so the first-of-month *or* any Monday fires."""
    spec = CronSpec.parse("0 0 1 * MON")
    assert spec.day_of_month_restricted is True
    assert spec.day_of_week_restricted is True

    assert spec.matches(_wall(2026, 6, 1, 0, 0)) is True  # Monday, and the 1st
    assert spec.matches(_wall(2026, 6, 8, 0, 0)) is True  # Monday, not the 1st
    assert spec.matches(_wall(2026, 6, 2, 0, 0)) is False  # neither the 1st nor a Monday
    assert spec.matches(_wall(2026, 6, 3, 0, 0)) is False  # neither


def test_cron_day_and_weekday_union_covers_both_axes_of_a_whole_month() -> None:
    """The union reading is not a curiosity: it is most of the month firing."""
    spec = CronSpec.parse("0 0 1 * MON")

    firing_days = [day for day in range(1, 31) if spec.matches(_wall(2026, 6, day, 0, 0))]

    # June 2026 opens on a Monday, so the 1st is on both axes and the union is
    # the 1st plus the four remaining Mondays -- not the intersection, which
    # would be the 1st alone, and not "every day", which is what an accidental
    # AND would not be either.
    assert firing_days == [1, 8, 15, 22, 29]
    assert all(_wall(2026, 6, day).weekday() == 0 for day in firing_days)


def test_cron_unrestricted_day_fields_conjoin() -> None:
    spec = CronSpec.parse("0 9 15 * *")
    assert spec.matches(_wall(2026, 6, 15, 9, 0)) is True
    assert spec.matches(_wall(2026, 6, 16, 9, 0)) is False
    assert spec.matches(_wall(2026, 6, 15, 10, 0)) is False


def test_cron_matches_refuses_an_aware_datetime() -> None:
    """Wall-clock matching cannot decide an ambiguous instant, so it refuses.

    During a fall-back hour the naive wall clock 01:30 names two instants. If
    ``matches`` accepted an aware datetime it would be silently choosing one, so
    it refuses and leaves the choice to :meth:`CronSpec.next_after`.
    """
    spec = CronSpec.parse("30 1 * * *")

    assert _rule(lambda: spec.matches(_utc(2026, 11, 1, 5, 30))) == "schedule.cron_naive"
    assert _rule(lambda: spec.matches(_utc(2026, 1, 1, 9, 30))) == "schedule.cron_naive"
    # The naive wall clock is the accepted form, and it matches.
    assert spec.matches(_wall(2026, 11, 1, 1, 30)) is True


@pytest.mark.parametrize(
    ("expression", "rule"),
    [
        ("*/0 * * * *", "schedule.cron_step"),
        ("*/x * * * *", "schedule.cron_step"),
        ("70 * * * *", "schedule.cron_range"),
        ("* 24 * * *", "schedule.cron_range"),
        ("* * 32 * *", "schedule.cron_range"),
        ("* * 0 * *", "schedule.cron_range"),
        ("5-1 * * * *", "schedule.cron_range"),
        ("* * * FOO *", "schedule.cron_token"),
        ("1,,2 * * * *", "schedule.cron_field"),
        ("@reboot", "schedule.cron_shorthand"),
    ],
)
def test_cron_refuses_out_of_dialect_expressions(expression: str, rule: str) -> None:
    assert _rule(lambda: CronSpec.parse(expression)) == rule


@pytest.mark.parametrize(
    "expression",
    ["0 0 9 * * *", "0 0 0 9 * * *", "* * * *", "* * * * * *"],
)
def test_cron_six_and_seven_field_expressions_are_rejected(expression: str) -> None:
    """A field count we cannot interpret is refused, never guessed at."""
    assert _rule(lambda: CronSpec.parse(expression)) == "schedule.cron_field_count"


def test_cron_next_after_returns_a_time_strictly_after_the_floor() -> None:
    spec = CronSpec.parse("0 9 * * *")
    floor = _utc(2026, 6, 1, 9, 0, 0)

    assert spec.next_after(floor, tz=UTC_ZONE) == _utc(2026, 6, 2, 9, 0)


def test_cron_next_after_returns_none_for_an_impossible_calendar() -> None:
    """February 30th does not exist, and the search is bounded rather than hung."""
    spec = CronSpec.parse("0 0 30 2 *")

    assert spec.next_after(_utc(2026, 1, 1), tz=UTC_ZONE, max_steps=40 * 24 * 60) is None


def test_cron_next_after_stays_within_its_search_budget() -> None:
    spec = CronSpec.parse("0 0 1 1 *")

    assert spec.next_after(_utc(2026, 6, 1), tz=UTC_ZONE, max_steps=5) is None


# --- timezone and DST boundaries ---------------------------------------------


def test_local_time_in_the_spring_forward_gap_does_not_exist() -> None:
    assert local_time_exists(_wall(2026, 3, 8, 2, 30), NY) is False
    assert local_time_exists(_wall(2026, 3, 8, 3, 30), NY) is True


def test_local_time_in_the_fall_back_hour_is_ambiguous() -> None:
    assert local_time_is_ambiguous(_wall(2026, 11, 1, 1, 30), NY) is True
    assert local_time_is_ambiguous(_wall(2026, 11, 1, 3, 30), NY) is False


def test_cron_fire_time_follows_the_spring_forward_offset() -> None:
    """09:00 local is 14:00Z under EST and 13:00Z under EDT."""
    spec = CronSpec.parse("0 9 * * *")

    before = spec.next_after(_utc(2026, 3, 6, 12), tz=NY)
    after = spec.next_after(_utc(2026, 3, 8, 12), tz=NY)

    assert before == _utc(2026, 3, 6, 14, 0)  # 2026-03-06, still EST
    assert after == _utc(2026, 3, 8, 13, 0)  # 2026-03-08, already EDT
    assert before.astimezone(NY).strftime("%H:%M") == "09:00"
    assert after.astimezone(NY).strftime("%H:%M") == "09:00"


def test_cron_in_the_spring_forward_gap_does_not_fire_that_day() -> None:
    """02:30 local never happens on 2026-03-08 in New York, so it is skipped."""
    spec = CronSpec.parse("30 2 * * *")

    assert spec.next_after(_utc(2026, 3, 7, 12), tz=NY) == _utc(2026, 3, 9, 6, 30)


def test_cron_in_the_fall_back_hour_fires_once_not_twice() -> None:
    """01:30 local names two instants; the schedule commits to the first."""
    spec = CronSpec.parse("30 1 * * *")
    first = spec.next_after(_utc(2026, 10, 31, 12), tz=NY)

    assert first == _utc(2026, 11, 1, 5, 30)
    assert spec.next_after(first, tz=NY) == _utc(2026, 11, 2, 6, 30)


def test_cron_next_after_returns_utc_not_the_local_zone() -> None:
    spec = CronSpec.parse("0 9 * * *")

    assert spec.next_after(_utc(2026, 6, 1), tz=NY).tzinfo is UTC


def test_resolve_zone_refuses_an_unknown_timezone() -> None:
    assert _rule(lambda: resolve_zone("Mars/Olympus")) == "schedule.unknown_timezone"


def test_resolve_zone_agrees_with_the_schedule_zone_property() -> None:
    schedule = _cron_schedule(timezone_name="America/New_York")

    assert schedule.zone is resolve_zone("America/New_York")


# --- interval arithmetic -----------------------------------------------------


def test_interval_occurrences_are_anchor_aligned() -> None:
    interval = IntervalSpec(every_s=900.0, anchor_at=_utc(2026, 1, 1, 0, 7))

    assert interval.occurrence_at(0) == _utc(2026, 1, 1, 0, 7)
    assert interval.occurrence_at(1) == _utc(2026, 1, 1, 0, 22)
    assert interval.occurrence_at(4) == _utc(2026, 1, 1, 1, 7)


def test_interval_next_after_snaps_to_the_next_occurrence_not_the_probe() -> None:
    interval = IntervalSpec(every_s=900.0, anchor_at=_utc(2026, 1, 1))

    assert interval.next_after(_utc(2026, 1, 1, 0, 10)) == _utc(2026, 1, 1, 0, 15)
    assert interval.next_after(_utc(2026, 1, 1, 0, 15)) == _utc(2026, 1, 1, 0, 30)


def test_interval_before_the_anchor_fires_at_the_anchor() -> None:
    interval = IntervalSpec(every_s=60.0, anchor_at=_utc(2026, 1, 1))

    assert interval.next_after(_utc(2025, 12, 31, 23, 0)) == _utc(2026, 1, 1)


def test_interval_period_is_absolute_and_survives_a_dst_transition() -> None:
    """Every 3600s stays every 3600s; the wall clock is what shifts, not the period."""
    interval = IntervalSpec(every_s=3600.0, anchor_at=_utc(2026, 3, 8, 6, 30))
    occurrences = [interval.occurrence_at(index) for index in range(4)]

    gaps = {later - earlier for earlier, later in pairwise(occurrences)}
    assert gaps == {timedelta(hours=1)}
    local = [moment.astimezone(NY).strftime("%H:%M") for moment in occurrences]
    assert local == ["01:30", "03:30", "04:30", "05:30"]


def test_interval_respects_its_occurrence_ceiling() -> None:
    interval = IntervalSpec(every_s=60.0, anchor_at=_utc(2026, 1, 1), max_occurrences=3)

    # max_occurrences=3 permits indices 0, 1, 2 and no further.
    assert [interval.occurrence_at(index) for index in range(3)] == [
        _utc(2026, 1, 1, 0, 0),
        _utc(2026, 1, 1, 0, 1),
        _utc(2026, 1, 1, 0, 2),
    ]
    assert interval.next_after(_utc(2026, 1, 1, 0, 1)) == _utc(2026, 1, 1, 0, 2)
    assert interval.next_after(_utc(2026, 1, 1, 0, 2)) is None
    assert interval.exhausted_at(2) is False
    assert interval.exhausted_at(3) is True


def test_interval_slot_is_only_open_inside_the_poll_resolution() -> None:
    schedule = _interval_schedule(every_s=900.0, anchor_at=_utc(2026, 1, 1, 0, 0))

    assert schedule.is_due(_utc(2026, 1, 1, 0, 15, 0)) is True
    assert schedule.is_due(_utc(2026, 1, 1, 0, 15, 59)) is True
    assert schedule.is_due(_utc(2026, 1, 1, 0, 16, 0)) is False


def test_interval_schedule_never_fires_before_its_anchor() -> None:
    schedule = _interval_schedule(every_s=900.0, anchor_at=_utc(2026, 6, 1))

    assert schedule.is_due(_utc(2026, 5, 31, 23, 59)) is False
    assert schedule.is_due(_utc(2026, 6, 1, 0, 0)) is True


# --- window overlap, business hours, blackout ---------------------------------


def test_touching_windows_do_not_overlap() -> None:
    """Half-open windows: a freeze ending at 09:00 and work starting at 09:00."""
    assert windows_overlap(
        _utc(2026, 6, 1, 8), _utc(2026, 6, 1, 9), _utc(2026, 6, 1, 9), _utc(2026, 6, 1, 11)
    ) is False


def test_windows_overlap_when_they_share_an_instant() -> None:
    assert windows_overlap(
        _utc(2026, 6, 1, 8), _utc(2026, 6, 1, 10), _utc(2026, 6, 1, 9), _utc(2026, 6, 1, 11)
    ) is True


def test_a_window_contains_only_its_interior() -> None:
    window = MaintenanceWindow(
        window_id="freeze", starts_at=_utc(2026, 6, 1, 8), ends_at=_utc(2026, 6, 1, 10)
    )

    assert window.contains(_utc(2026, 6, 1, 8)) is True
    assert window.contains(_utc(2026, 6, 1, 9, 59)) is True
    assert window.contains(_utc(2026, 6, 1, 10)) is False


def test_business_hours_reject_the_weekend() -> None:
    hours = _office_hours()
    saturday = datetime(2026, 6, 6, 10, tzinfo=NY)

    assert hours.contains(saturday) is False
    assert hours.window_for(saturday) is None
    assert "Mon,Tue,Wed,Thu,Fri 09:00-17:00" in hours.closed_reason(saturday)


def test_business_hours_accept_the_working_day() -> None:
    hours = _office_hours()

    assert hours.contains(datetime(2026, 6, 1, 9, 0, tzinfo=NY)) is True
    assert hours.contains(datetime(2026, 6, 1, 16, 59, tzinfo=NY)) is True
    assert hours.contains(datetime(2026, 6, 1, 17, 0, tzinfo=NY)) is False


def test_an_overnight_window_credits_the_following_morning() -> None:
    night = DailyWindow(
        label="nightly batch", days=frozenset({0}), start_time=time(22, 0), end_time=time(2, 0)
    )

    assert night.overnight is True
    assert night.contains(_wall(2026, 6, 1, 21, 0)) is False  # Monday, before the band
    assert night.contains(_wall(2026, 6, 1, 22, 0)) is True  # Monday evening
    assert night.contains(_wall(2026, 6, 1, 23, 59)) is True  # Monday night
    assert night.contains(_wall(2026, 6, 2, 0, 0)) is True  # Tuesday, tail of Monday
    assert night.contains(_wall(2026, 6, 2, 1, 59)) is True  # Tuesday, just inside
    assert night.contains(_wall(2026, 6, 2, 2, 0)) is False  # band is over
    assert night.contains(_wall(2026, 6, 2, 12, 0)) is False  # Tuesday daytime
    assert night.contains(_wall(2026, 6, 3, 1, 0)) is False  # Wednesday is not the tail


def test_business_hours_must_declare_at_least_one_window() -> None:
    assert _rule(lambda: BusinessHours(windows=())) == "schedule.business_hours_empty"


def test_daily_window_rejects_a_weekday_it_both_includes_and_excludes() -> None:
    assert _rule(lambda: DailyWindow(days=frozenset({0, 1}), excluded_days=frozenset({1}),
                                      start_time=time(9), end_time=time(17))) == (
        "schedule.weekday_excluded"
    )


def test_daily_window_rejects_an_out_of_range_weekday() -> None:
    assert _rule(lambda: DailyWindow(days=frozenset({9}), start_time=time(9),
                                      end_time=time(17))) == "schedule.weekday_range"


def test_blackout_matches_a_local_date_not_a_utc_one() -> None:
    """The 4th is blacked out where the schedule runs, not in UTC."""
    blackouts = BlackoutDates(dates=frozenset({date(2026, 6, 4)}), reason="freeze")
    schedule = _cron_schedule(
        expression="0 9 * * *", timezone_name="America/New_York", blackout_dates=blackouts
    )

    # 2026-06-04 09:00 New York is 13:00Z; both spellings are the same local day.
    assert schedule.blacked_out_on(datetime(2026, 6, 4, 13, tzinfo=UTC)) == date(2026, 6, 4)
    assert schedule.evaluate(now=_utc(2026, 6, 4, 13)).code is FireCode.BLACKOUT
    assert schedule.evaluate(now=_utc(2026, 6, 5, 13)).code is FireCode.FIRED


def test_maintenance_and_blackout_together_name_every_blocker() -> None:
    window = MaintenanceWindow(
        window_id="deploy", starts_at=_utc(2026, 6, 1, 8), ends_at=_utc(2026, 6, 1, 10),
        reason="release freeze",
    )
    schedule = _cron_schedule(
        expression="0 9 * * *",
        maintenance_windows=(window,),
        blackout_dates=BlackoutDates(dates=frozenset({date(2026, 6, 1)})),
    )

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9))

    assert decision.code is FireCode.BLACKOUT
    assert decision.blocked_by == ("blackout:2026-06-01",)
    assert schedule.blocking_maintenance(_utc(2026, 6, 1, 9)) == (window,)


def test_schedule_refuses_two_windows_with_the_same_id() -> None:
    window = MaintenanceWindow(
        window_id="deploy", starts_at=_utc(2026, 6, 1, 8), ends_at=_utc(2026, 6, 1, 10)
    )
    other = MaintenanceWindow(
        window_id="deploy", starts_at=_utc(2026, 6, 2, 8), ends_at=_utc(2026, 6, 2, 10)
    )

    assert _rule(lambda: _cron_schedule(maintenance_windows=(window, other))) == (
        "schedule.window_duplicate"
    )


# --- jitter ------------------------------------------------------------------


def test_jitter_stays_inside_its_declared_bound() -> None:
    jitter = Jitter(max_offset_s="90s")
    nominal = _utc(2026, 6, 1, 9, 0)

    offsets = [jitter.offset_s(seed=f"schedule-{index}", nominal=nominal) for index in range(500)]

    assert all(-90.0 <= offset <= 90.0 for offset in offsets)
    assert min(offsets) < -45.0
    assert max(offsets) > 45.0


def test_jitter_is_deterministic_for_the_same_seed_and_nominal() -> None:
    jitter = Jitter(max_offset_s="5m")
    nominal = _utc(2026, 6, 1, 9, 0)

    first = jitter.offset_s(seed="nightly", nominal=nominal)
    second = jitter.offset_s(seed="nightly", nominal=nominal)

    assert first == second
    assert jitter.apply(nominal, seed="nightly") == nominal + timedelta(seconds=first)


def test_jitter_varies_by_seed_so_schedules_do_not_stampede_together() -> None:
    jitter = Jitter(max_offset_s="5m")
    nominal = _utc(2026, 6, 1, 9, 0)

    offsets = {jitter.offset_s(seed=f"schedule-{index}", nominal=nominal) for index in range(50)}

    assert len(offsets) == 50


def test_jitter_is_the_identity_when_disabled() -> None:
    jitter = Jitter()
    nominal = _utc(2026, 6, 1, 9, 0)

    assert jitter.enabled is False
    assert jitter.apply(nominal, seed="anything") == nominal


def test_a_jittered_fire_stays_within_bound_of_its_slot() -> None:
    schedule = _cron_schedule(expression="0 9 * * *", jitter=Jitter(max_offset_s="2m"))

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0))
    drift = abs((decision.effective_at - decision.nominal_at).total_seconds())

    assert decision.fired is True
    assert decision.jittered is True
    assert drift <= 120.0


# --- honesty about time: jitter and lateness are two different facts ----------


def test_jitter_is_applied_to_the_slot_not_to_the_pollers_instant() -> None:
    """The declared bound bounds the *offset*, not the poller's slack.

    A late poller reading the same slot twice -- once on time, once 45s late --
    gets the same jittered effective instant. If jitter were applied to ``now``,
    the second reading would move the fire time by 45s *plus* the offset, and a
    schedule evaluated a minute late could land outside its own declared bound.
    """
    schedule = _cron_schedule(expression="0 9 * * *", jitter=Jitter(max_offset_s="2m"))

    on_time = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0, 0))
    late = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0, 45))

    assert on_time.fired and late.fired
    assert on_time.effective_at == late.effective_at
    assert on_time.lateness_s == 0.0
    assert late.lateness_s == 45.0


def test_lateness_reports_the_poller_and_nothing_else() -> None:
    """A declared jitter spread is not a poller that was late.

    The negative control that matters: a schedule with a +/-2m jitter evaluated
    exactly on its slot is on time, and reading lateness off ``effective_at``
    would report up to two minutes of delay that never happened.
    """
    schedule = _cron_schedule(expression="0 9 * * *", jitter=Jitter(max_offset_s="2m"))

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0, 0))

    assert decision.jittered is True
    assert abs(decision.effective_at - decision.nominal_at).total_seconds() > 0
    assert decision.lateness_s == 0.0
    # And the two fields really do disagree, which is the whole point.
    assert decision.effective_at != decision.nominal_at
    assert decision.nominal_at == decision.slot_start


def test_an_unjittered_late_poll_is_not_reported_as_jittered() -> None:
    """``jittered`` is about the declared jitter, not about "differs from slot".

    Before the fix this was the same lie from the other side: an unjittered
    schedule polled 45s into its one-minute cron slot reported ``jittered``,
    dressing a late poller up as a deliberate offset.
    """
    schedule = _cron_schedule(expression="0 9 * * *")

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0, 45))

    assert decision.fired is True
    assert decision.jittered is False
    assert decision.effective_at == decision.slot_start == decision.nominal_at
    assert decision.lateness_s == 45.0


def test_a_calendar_window_is_never_reported_as_late_or_jittered() -> None:
    """A one-off window has no deadline to be late against.

    Its slot is the whole window, so measuring lateness against the window's
    *opening* would report a run scheduled for a 09:00-17:00 window as "eight
    hours late" whenever the poller got to it at 17:00.
    """
    schedule = _calendar_schedule()

    early = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0))
    late_in_window = schedule.evaluate(now=_utc(2026, 6, 1, 16, 59))

    assert early.fired and late_in_window.fired
    assert early.lateness_s == 0.0
    assert late_in_window.lateness_s == 0.0
    assert early.jittered is False and late_in_window.jittered is False
    # The slot the ledger keys on is still the window's opening, so two polls
    # inside one window cannot mint two idempotency keys.
    assert early.slot_start == late_in_window.slot_start == _utc(2026, 6, 1, 9, 0)
    assert early.nominal_at == _utc(2026, 6, 1, 9, 0)
    assert late_in_window.nominal_at == _utc(2026, 6, 1, 16, 59)


def test_a_refusal_reports_no_lateness_and_no_jitter() -> None:
    """A non-fire is not a late fire. Both fields read zero on a refusal."""
    schedule = _cron_schedule(
        expression="0 9 * * *", jitter=Jitter(max_offset_s="2m"), blackout_dates=BlackoutDates(
            dates=frozenset({date(2026, 6, 1)})
        )
    )

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9, 0, 30))

    assert decision.fired is False
    assert decision.lateness_s == 0.0
    assert decision.jittered is False
    assert decision.missed_window is False


def test_a_recurrence_the_poller_slept_through_is_reported_as_missed() -> None:
    """A window that closed with nobody in it says so, and says it is not a fire.

    The interval slot is ``poll_resolution_s`` wide. Past that the recurrence the
    poller was answering has gone and the next occurrence is a *different* slot
    with a different idempotency key, so the occurrence is not retried and never
    runs. Reporting that as ``NOT_DUE`` would record the non-fire and lose the
    reason -- and a reader at 09:05 could not then tell a quiet minute from a
    skipped run.
    """
    schedule = _interval_schedule(every_s=3600.0, anchor_at=_utc(2026, 6, 1, 9, 0))
    tight = schedule.model_copy(update={"poll_resolution_s": 60.0})

    inside = tight.evaluate(now=_utc(2026, 6, 1, 9, 0, 30))
    after = tight.evaluate(now=_utc(2026, 6, 1, 9, 1, 30))

    assert inside.fired is True
    assert inside.code is FireCode.FIRED
    assert inside.missed_window is False

    assert after.fired is False
    assert after.code is FireCode.MISSED
    assert after.missed_window is True
    # The missed occurrence is named, and so is the reason it cannot be retried.
    assert after.slot_start == _utc(2026, 6, 1, 9, 0)
    assert "2026-06-01T09:00:00+00:00" in after.reason
    assert "idempotency key" in after.reason
    assert after.blocked_by == ("poll_resolution_s",)
    # A miss is not a late fire, and does not pretend to be one: the recurrence
    # did not run late, it did not run.
    assert after.lateness_s == 0.0
    assert "HELD" in after.describe()


def test_a_quiet_interval_instant_is_not_dressed_up_as_a_missed_window() -> None:
    """The negative control on the miss predicate: nothing due, nothing missed.

    Before the anchor there is no occurrence to have missed, so the predicate must
    answer ``None`` rather than naming the occurrence at or after the probe.
    Without the ``moment < anchor`` guard the earliest occurrence would be
    reported as missed by every poll before it existed, which would open a
    freshly started controller with an invented incident.
    """
    schedule = _interval_schedule(every_s=3600.0, anchor_at=_utc(2026, 6, 1, 9, 0))
    tight = schedule.model_copy(update={"poll_resolution_s": 60.0})

    well_before = tight.evaluate(now=_utc(2026, 6, 1, 8, 30))

    assert well_before.code is FireCode.NOT_DUE
    assert well_before.missed_window is False
    assert well_before.fired is False
    assert "no fire slot covers" in well_before.reason


def test_a_missed_recurrence_stays_missed_until_the_next_one_answers() -> None:
    """A miss persists for the whole gap, and clears the moment the next slot opens.

    Reported here because it is the honest consequence of the design and a reader
    deserves to be told about it: every poll between the missed occurrence and the
    next one reports the *same* miss, naming the same ``slot_start``. That is
    correct -- the recurrence is still unrun and still unreported -- and it is why
    :attr:`FireDecision.missed_window` is a boolean a consumer can latch rather
    than a counter it should try to sum.
    """
    schedule = _interval_schedule(every_s=3600.0, anchor_at=_utc(2026, 6, 1, 9, 0))
    tight = schedule.model_copy(update={"poll_resolution_s": 60.0})

    first_poll = tight.evaluate(now=_utc(2026, 6, 1, 9, 1, 30))
    later_poll = tight.evaluate(now=_utc(2026, 6, 1, 9, 59))
    next_slot = tight.evaluate(now=_utc(2026, 6, 1, 10, 0, 10))

    assert first_poll.code is FireCode.MISSED
    assert later_poll.code is FireCode.MISSED
    assert first_poll.slot_start == later_poll.slot_start == _utc(2026, 6, 1, 9, 0)
    # And the next occurrence is a different slot, which is what makes the miss
    # permanent rather than merely delayed.
    assert next_slot.fired is True
    assert next_slot.slot_start == _utc(2026, 6, 1, 10, 0)


def test_a_cron_slot_never_reports_a_missed_window() -> None:
    """A cron slot is one minute wide, so a cron poller can be late but not miss.

    The predicate is scoped to intervals deliberately. Two minutes past a
    ``0 9 * * *`` slot there is no recurrence pending and no open window -- it is
    a minute in which nothing was ever due, and calling it a miss would train an
    operator to ignore the word.
    """
    schedule = _cron_schedule(expression="0 9 * * *")

    two_minutes_late = schedule.evaluate(now=_utc(2026, 6, 1, 9, 2))

    assert two_minutes_late.code is FireCode.NOT_DUE
    assert two_minutes_late.missed_window is False


def test_a_closed_horizon_reports_expiry_rather_than_a_miss() -> None:
    """The horizon closing outranks the miss predicate.

    Past ``ends_at`` the schedule is retired, and a retired schedule is not
    accused of having slept through anything: the operator closed it.
    """
    schedule = _interval_schedule(every_s=3600.0, anchor_at=_utc(2026, 6, 1, 9, 0))
    retired = schedule.model_copy(
        update={"poll_resolution_s": 60.0, "ends_at": _utc(2026, 6, 1, 9, 30)}
    )

    decision = retired.evaluate(now=_utc(2026, 6, 1, 10, 0))

    assert decision.code is FireCode.EXPIRED
    assert decision.missed_window is False
    assert "horizon closed" in decision.reason


def test_a_calendar_window_can_never_report_a_missed_window() -> None:
    """Structurally unreachable, not merely unlikely.

    A calendar window stays open for as long as its author made it, so there is
    no resolution past which it has "closed". The predicate reads off
    :attr:`FireCode`, and :meth:`Schedule._interval_missed` refuses a non-interval
    schedule outright, so the two together make the claim structural.
    """
    schedule = _calendar_schedule()

    for hour in (9, 12, 16, 59):
        decision = schedule.evaluate(now=_utc(2026, 6, 1, hour if hour != 59 else 16))
        assert decision.fired is True
        assert decision.missed_window is False

    after_window = schedule.evaluate(now=_utc(2026, 6, 1, 17, 30))
    assert after_window.code is FireCode.NOT_DUE
    assert after_window.missed_window is False


def test_the_fire_code_vocabulary_can_be_asked_which_side_of_the_split_it_is_on() -> None:
    """``is_non_fire`` so a caller iterating codes does not re-spell the test."""
    codes = list(FireCode)

    assert FireCode.FIRED.is_non_fire is False
    assert {code.value for code in codes if code.is_non_fire} == {
        code.value for code in codes if code is not FireCode.FIRED
    }
    assert FireCode.MISSED.is_non_fire is True


def test_the_fire_decision_carries_the_resolution_a_reader_needs() -> None:
    """``resolution_s`` travels with the decision so a lateness figure is readable.

    A consumer reading a persisted decision otherwise has to go back to the
    schedule body to learn how wide the slot was, and a schedule edited since the
    decision was recorded would give it the answer for a schedule that no longer
    exists.
    """
    schedule = _interval_schedule(every_s=3600.0, anchor_at=_utc(2026, 6, 1, 9, 0))
    tight = schedule.model_copy(update={"poll_resolution_s": 90.0})

    decision = tight.evaluate(now=_utc(2026, 6, 1, 9, 0, 10))

    assert decision.resolution_s == 90.0
    assert decision.lateness_s == 10.0
    # And a reader can judge it without the body: 10s late is well inside a 90s
    # slot, which is why this one fired at all.
    assert decision.lateness_s < decision.resolution_s


def test_a_late_but_answered_fire_is_not_a_missed_window() -> None:
    """The distinction the miss predicate is careful about, asserted directly.

    A poller 30s into a 60s interval slot produced a *fire*, and it is late. It is
    not a missed window, because the recurrence did run. Reading lateness and
    missingness off the same number would have to choose, and either choice is
    wrong for one of these two records.
    """
    schedule = _interval_schedule(every_s=3600.0, anchor_at=_utc(2026, 6, 1, 9, 0))
    tight = schedule.model_copy(update={"poll_resolution_s": 60.0})

    decision = tight.evaluate(now=_utc(2026, 6, 1, 9, 0, 30))

    assert decision.fired is True
    assert decision.lateness_s == 30.0
    assert decision.missed_window is False


# --- schedule evaluation -----------------------------------------------------


def test_cron_schedule_fires_inside_its_slot() -> None:
    schedule = _cron_schedule(expression="0 9 * * *")

    assert schedule.is_due(_utc(2026, 6, 1, 9, 0, 30)) is True
    assert schedule.slot_start(_utc(2026, 6, 1, 9, 0, 30)) == _utc(2026, 6, 1, 9, 0)
    assert schedule.evaluate(now=_utc(2026, 6, 1, 9, 0, 30)).code is FireCode.FIRED


def test_cron_schedule_does_not_fire_outside_its_slot() -> None:
    schedule = _cron_schedule(expression="0 9 * * *")

    assert schedule.is_due(_utc(2026, 6, 1, 9, 1)) is False
    assert schedule.evaluate(now=_utc(2026, 6, 1, 9, 1)).code is FireCode.NOT_DUE


def test_calendar_schedule_needs_no_horizon_because_it_is_finite() -> None:
    schedule = _calendar_schedule()

    assert schedule.next_fire_time(_utc(2026, 1, 1)) == _utc(2026, 6, 1, 9, 0)
    assert schedule.next_fire_time(_utc(2026, 6, 1, 10, 0)) == _utc(2026, 7, 1, 9, 0)
    assert schedule.next_fire_time(_utc(2026, 8, 1)) is None
    assert schedule.evaluate(now=_utc(2026, 6, 1, 10)).code is FireCode.FIRED
    assert schedule.evaluate(now=_utc(2026, 6, 1, 18)).code is FireCode.NOT_DUE


def test_schedule_refuses_a_horizon_that_ends_before_it_is_created() -> None:
    assert _rule(lambda: _cron_schedule(ends_at=_utc(2025, 1, 1))) == "schedule.horizon"


def test_schedule_refuses_a_naive_created_at() -> None:
    assert _rule(lambda: _cron_schedule(created_at=_wall(2026, 1, 1))) == (
        "schedule.created_naive"
    )


def test_schedule_refuses_an_unknown_timezone() -> None:
    assert _rule(lambda: _cron_schedule(timezone_name="Mars/Olympus")) == (
        "schedule.unknown_timezone"
    )


def test_evaluation_refuses_a_naive_probe() -> None:
    schedule = _cron_schedule()

    assert _rule(lambda: schedule.evaluate(now=_wall(2026, 6, 1, 9))) == (
        "schedule.evaluate_naive"
    )


def test_schedule_describe_names_its_recurrence_and_horizon() -> None:
    described = _cron_schedule(expression="0 9 * * *", max_runs=3).describe()

    assert "0 9 * * *" in described
    assert "max 3 run(s)" in described


# --- negative controls --------------------------------------------------------


def test_negative_control_a_window_that_closed_after_creation_does_not_fire() -> None:
    """The Phase 4 acceptance criterion, as a Phase 1 predicate.

    The schedule is created at the top of a working window, when the office is
    open, and asked to fire on a Saturday. Nothing about the schedule changed;
    only the instant did. Windows are evaluated live, so the fire is refused and
    the refusal is recorded rather than silently dropped.
    """
    schedule = _cron_schedule(
        expression="0 9 * * *",
        timezone_name="America/New_York",
        business_hours=_office_hours(),
    )
    assert schedule.created_at.astimezone(NY).weekday() < 5  # created on a weekday

    saturday = _utc(2026, 6, 6, 13, 0)  # 09:00 New York on Saturday 2026-06-06
    assert saturday.astimezone(NY).strftime("%A") == "Saturday"

    decision = schedule.evaluate(now=saturday)

    assert decision.fired is False
    assert decision.code is FireCode.OUTSIDE_BUSINESS_HOURS
    assert decision.blocked_by == ("business_hours",)
    assert "business hours" in decision.reason
    assert decision.slot_start is not None  # the recurrence did match
    assert "HELD" in decision.describe()


def test_negative_control_a_maintenance_window_opened_after_creation_does_not_fire() -> None:
    window = MaintenanceWindow(
        window_id="emergency-freeze", starts_at=_utc(2026, 6, 1, 8), ends_at=_utc(2026, 6, 1, 10),
        reason="incident bridge",
    )
    schedule = _cron_schedule(expression="0 9 * * *", maintenance_windows=(window,))

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9))

    assert decision.fired is False
    assert decision.code is FireCode.MAINTENANCE
    assert decision.blocked_by == ("maintenance:emergency-freeze",)
    assert "emergency-freeze" in decision.reason


def test_negative_control_an_unbounded_cron_is_rejected() -> None:
    """A schedule that can fire forever is a schedule that can outlive its reason."""
    assert _rule(
        lambda: Schedule(
            schedule_id="forever",
            kind=ScheduleKind.CRON,
            cron=CronSpec.parse("* * * * *"),
            created_at=CREATED,
        )
    ) == "schedule.unbounded_recurrence"


def test_negative_control_an_unbounded_interval_is_rejected() -> None:
    assert _rule(
        lambda: Schedule(
            schedule_id="forever",
            kind=ScheduleKind.INTERVAL,
            interval=IntervalSpec(every_s=60.0, anchor_at=CREATED),
            created_at=CREATED,
        )
    ) == "schedule.unbounded_recurrence"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ends_at": HORIZON},
        {"max_runs": 5},
    ],
)
def test_any_declared_horizon_satisfies_the_unbounded_refusal(kwargs: dict[str, object]) -> None:
    schedule = Schedule(
        schedule_id="bounded", kind=ScheduleKind.CRON, cron=CronSpec.parse("* * * * *"),
        created_at=CREATED, **kwargs,
    )

    assert schedule.describe()


def test_interval_max_occurrences_alone_is_a_horizon() -> None:
    schedule = Schedule(
        schedule_id="bounded-interval",
        kind=ScheduleKind.INTERVAL,
        interval=IntervalSpec(every_s=60.0, anchor_at=CREATED, max_occurrences=3),
        created_at=CREATED,
    )

    assert schedule.next_fire_time(CREATED) is not None


def test_negative_control_a_pre_dating_fire_time_is_rejected() -> None:
    """A fire time before the schedule existed is a recorded non-event, not a run."""
    schedule = _cron_schedule(expression="0 9 * * *", created_at=_utc(2026, 6, 1))

    decision = schedule.evaluate(now=_utc(2026, 5, 1, 9, 0))

    assert decision.fired is False
    assert decision.code is FireCode.PREMATURE
    assert decision.blocked_by == ("created_at",)
    assert "predates schedule creation" in decision.reason


def test_next_fire_time_never_returns_a_past_instant() -> None:
    schedule = _cron_schedule(expression="0 9 * * *")
    floor = _utc(2026, 6, 1, 9, 0)

    assert schedule.next_fire_time(floor) > floor


def test_negative_control_the_run_budget_is_enforced_at_evaluation_time() -> None:
    schedule = _cron_schedule(expression="0 9 * * *", max_runs=2)

    assert schedule.evaluate(now=_utc(2026, 6, 1, 9), run_count=1).code is FireCode.FIRED
    exhausted = schedule.evaluate(now=_utc(2026, 6, 2, 9), run_count=2)

    assert exhausted.code is FireCode.EXHAUSTED
    assert exhausted.fired is False
    assert schedule.is_due(_utc(2026, 6, 2, 9), run_count=2) is False


def test_negative_control_a_closed_horizon_does_not_fire() -> None:
    schedule = _cron_schedule(expression="0 9 * * *", ends_at=_utc(2026, 5, 1))

    decision = schedule.evaluate(now=_utc(2026, 6, 1, 9))

    assert decision.code is FireCode.EXPIRED
    assert decision.blocked_by == ("ends_at",)
    # A fire time still inside the horizon is offered; one past it is not.
    assert schedule.next_fire_time(_utc(2026, 1, 2)) == _utc(2026, 1, 2, 9)
    assert schedule.next_fire_time(_utc(2026, 5, 1, 12)) is None


def test_schedule_refuses_two_recurrence_sources() -> None:
    assert _rule(
        lambda: Schedule(
            schedule_id="ambiguous",
            kind=ScheduleKind.CRON,
            cron=CronSpec.parse("0 9 * * *"),
            interval=IntervalSpec(every_s=60.0, anchor_at=CREATED),
            created_at=CREATED,
            max_runs=1,
        )
    ) == "schedule.recurrence_source"


def test_schedule_refuses_no_recurrence_source() -> None:
    assert _rule(
        lambda: Schedule(
            schedule_id="empty", kind=ScheduleKind.CRON, created_at=CREATED, max_runs=1
        )
    ) == "schedule.recurrence_source"


# --- fairness -----------------------------------------------------------------


def test_fairness_policy_refuses_an_empty_share_table() -> None:
    assert _rule(lambda: FairnessPolicy(policy_id="f", shares={})) == "fairness.no_shares"


def test_fairness_policy_refuses_an_all_zero_share_table() -> None:
    assert _rule(lambda: FairnessPolicy(policy_id="f", shares={"a": 0.0})) == (
        "fairness.share_total"
    )


def test_fairness_policy_refuses_a_negative_share() -> None:
    assert _rule(lambda: FairnessPolicy(policy_id="f", shares={"a": -1.0})) == (
        "fairness.share_range"
    )


def test_an_unlisted_team_falls_back_to_the_default_share() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0}, default_share=4.0)

    assert policy.share_of("a") == 1.0
    assert policy.share_of("newcomer") == 4.0
    assert policy.teams() == ("a",)


def test_shares_decide_the_order_when_nobody_is_starving() -> None:
    """A 9:1 policy serves the heavy team roughly nine times as often."""
    policy = FairnessPolicy(policy_id="f", shares={"a": 9.0, "b": 1.0}, starvation_window=3)

    simulation = policy.simulate_fairness(("a", "b"), windows=200)

    assert simulation.counts["a"] == 150
    assert simulation.counts["b"] == 50


def test_equal_shares_serve_every_team_evenly() -> None:
    policy = FairnessPolicy(
        policy_id="f", shares={"a": 1.0, "b": 1.0, "c": 1.0}, starvation_window=3
    )

    simulation = policy.simulate_fairness(("a", "b", "c"), windows=300)

    assert set(simulation.counts.values()) == {100}
    assert [grant[0] for grant in simulation.grants[:3]] == ["a", "b", "c"]


@pytest.mark.parametrize(
    ("shares", "starvation_window", "teams"),
    [
        ({"a": 1.0, "b": 1.0, "c": 1.0}, 3, ("a", "b", "c")),
        ({"a": 1.0, "b": 1.0, "c": 1.0, "d": 1.0}, 4, ("a", "b", "c", "d")),
        ({"a": 50.0, "b": 1.0, "c": 1.0, "d": 1.0}, 2, ("a", "b", "c", "d")),
        ({"a": 50.0, "b": 1.0, "c": 1.0, "d": 1.0}, 6, ("a", "b", "c", "d")),
        ({"a": 1000.0, "b": 1.0, "c": 1.0, "d": 1.0, "e": 1.0}, 2, ("a", "b", "c", "d", "e")),
    ],
)
def test_no_team_starves_over_many_windows(
    shares: dict[str, float], starvation_window: int, teams: tuple[str, ...]
) -> None:
    """Every demanding team is served inside the policy's declared bound."""
    policy = FairnessPolicy(
        policy_id="f", shares=shares, default_share=2.0, starvation_window=starvation_window
    )

    simulation = policy.simulate_fairness(teams, windows=400)

    assert simulation.honours_policy(policy) is True
    assert simulation.starved_teams(policy) == ()
    assert all(count > 0 for count in simulation.counts.values())
    assert sum(simulation.counts.values()) == 400


def test_the_anti_starvation_rule_floors_a_deliberately_skewed_policy() -> None:
    """A 50:1 policy still serves the small teams; the floor is the point.

    Without the starvation tier this policy would give the heavy team 50 windows
    out of every 53. With it, the light teams are still served on a bounded
    cadence, which is the trade a fair scheduler is *required* to make.
    """
    policy = FairnessPolicy(
        policy_id="skewed", shares={"a": 50.0, "b": 1.0, "c": 1.0, "d": 1.0}, starvation_window=6
    )

    simulation = policy.simulate_fairness(("a", "b", "c", "d"), windows=400)

    assert simulation.honours_policy(policy) is True
    # Each light team is served on a bounded cadence, and they are served
    # identically: the 50:1 skew is real but it is capped, not obeyed.
    assert min(simulation.counts.values()) > 20
    assert simulation.counts["b"] == simulation.counts["c"] == simulation.counts["d"]
    assert simulation.max_consecutive_skips["b"] <= policy.starvation_window
    # The skew survives as a preference, just not as an unbounded one.
    assert simulation.counts["a"] > 3 * min(simulation.counts.values())


def test_within_the_starving_tier_the_longest_waiting_team_goes_first() -> None:
    """Two teams starve at once; the one that has waited longer is served.

    Without the FIFO tiebreak the ordering falls through to weight, so a
    fifty-weight team that has waited 2 windows would jump a one-weight team
    that has waited 3. That inversion is what the tiebreak exists to prevent,
    and the window-by-window simulation does not reliably expose it, so it is
    pinned here against an explicit history.
    """
    policy = FairnessPolicy(policy_id="f", shares={"a": 50.0, "b": 1.0, "c": 1.0},
                            starvation_window=2)
    history = [
        GrantRecord(window_index=0, team="a"),
        GrantRecord(window_index=1, team="b"),
        GrantRecord(window_index=2, team="b"),
    ]

    # At window 3, 'a' last ran in window 0 and 'c' never has: both have cleared
    # the threshold of 2 and both are starving, but 'c' has waited longer -- and
    # 'a' carries fifty times its weight and has ten times the deficit.
    assert policy.is_starving("a", history, window_index=3) is True
    assert policy.is_starving("c", history, window_index=3) is True
    assert policy.consecutive_skips("a", history, window_index=3) == 2
    assert policy.consecutive_skips("c", history, window_index=3) == 3
    assert policy.normalised_deficit("a", ("a", "b", "c"), history) > (
        policy.normalised_deficit("c", ("a", "b", "c"), history)
    )

    assert policy.select_team(("a", "b", "c"), history, window_index=3) == "c"


def test_the_starving_tier_outranks_a_heavier_team_that_is_not_starving() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"heavy": 100.0, "light": 0.1},
                            starvation_window=2)
    history = [
        GrantRecord(window_index=0, team="heavy"),
        GrantRecord(window_index=1, team="heavy"),
    ]

    assert policy.is_starving("light", history, window_index=2) is True
    assert policy.is_starving("heavy", history, window_index=2) is False
    assert policy.select_team(("heavy", "light"), history, window_index=2) == "light"


def test_select_team_returns_none_when_nobody_is_demanding() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0})

    assert policy.select_team((), (), window_index=0) is None


def test_select_team_is_order_independent() -> None:
    """Two teams in the same state resolve the same way whichever way they arrive."""
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0, "b": 1.0, "c": 1.0})

    first = policy.select_team(("a", "b", "c"), (), window_index=0)
    reversed_order = policy.select_team(("c", "b", "a"), (), window_index=0)

    assert first == reversed_order == "a"


def test_consecutive_skips_counts_back_from_the_window_under_consideration() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0})
    history = [
        GrantRecord(window_index=0, team="a"),
        GrantRecord(window_index=1, team="a"),
    ]

    assert policy.consecutive_skips("a", history, window_index=1) == 0
    assert policy.consecutive_skips("a", history, window_index=2) == 0
    assert policy.consecutive_skips("a", history, window_index=5) == 3


def test_fairness_simulation_refuses_to_run_with_nothing_to_simulate() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0})

    assert _rule(lambda: policy.simulate_fairness((), windows=5)) == "fairness.no_teams"
    assert _rule(lambda: policy.simulate_fairness(("a",), windows=0)) == (
        "fairness.window_count"
    )


def test_longest_skip_runs_counts_the_trailing_gap_not_only_interior_gaps() -> None:
    """A team served once at the start and never again has starved ever since."""
    history = [GrantRecord(window_index=0, team="early")]

    runs = longest_skip_runs(history, teams=("early", "late"), windows=10)

    assert runs == {"early": 9, "late": 10}


def test_grant_counts_is_id_sorted() -> None:
    history = [GrantRecord(window_index=0, team="c"), GrantRecord(window_index=1, team="a")]

    assert grant_counts(history) == {"a": 1, "c": 1}


# --- concurrency --------------------------------------------------------------


def test_the_compatibility_matrix_is_symmetric() -> None:
    for left in ConcurrencyClass:
        for right in ConcurrencyClass:
            assert classes_compatible(left, right) == classes_compatible(right, left), (
                f"{left.value} vs {right.value} disagrees with itself"
            )


def test_the_matrix_row_agrees_with_the_symmetric_lookup() -> None:
    for left, permitted in LOCK_COMPATIBILITY.items():
        for right in ConcurrencyClass:
            assert classes_compatible(left, right) == (right in permitted)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (ConcurrencyClass.PARALLEL, ConcurrencyClass.EXCLUSIVE, True),
        (ConcurrencyClass.PARALLEL, ConcurrencyClass.CONFLICTING, True),
        (ConcurrencyClass.EXCLUSIVE, ConcurrencyClass.EXCLUSIVE, False),
        (ConcurrencyClass.EXCLUSIVE, ConcurrencyClass.SHARED_RESOURCE, False),
        (ConcurrencyClass.EXCLUSIVE, ConcurrencyClass.PREEMPTIBLE, False),
        (ConcurrencyClass.SHARED_RESOURCE, ConcurrencyClass.SHARED_RESOURCE, True),
        (ConcurrencyClass.SHARED_RESOURCE, ConcurrencyClass.PREEMPTIBLE, True),
        (ConcurrencyClass.SHARED_RESOURCE, ConcurrencyClass.EXCLUSIVE, False),
        (ConcurrencyClass.PREEMPTIBLE, ConcurrencyClass.PREEMPTIBLE, True),
        (ConcurrencyClass.CONFLICTING, ConcurrencyClass.CONFLICTING, False),
        (ConcurrencyClass.CONFLICTING, ConcurrencyClass.SHARED_RESOURCE, False),
    ],
)
def test_each_pair_of_concurrency_classes_has_a_decided_compatibility(
    left: ConcurrencyClass, right: ConcurrencyClass, expected: bool
) -> None:
    assert classes_compatible(left, right) is expected


def test_a_parallel_run_may_not_claim_a_resource() -> None:
    """``PARALLEL`` is the class that takes no locks, so it cannot hold one."""
    assert _rule(lambda: _request(run_id="r", experiment_id="e",
                                  concurrency_class=ConcurrencyClass.PARALLEL,
                                  resources=("db-primary",))) == (
        "concurrency.parallel_resources"
    )


def test_a_request_must_expire_after_it_acquires() -> None:
    assert _rule(lambda: _request(run_id="r", experiment_id="e",
                                  acquired_at=_utc(2026, 6, 1),
                                  expires_at=_utc(2026, 6, 1))) == "concurrency.window"


def test_a_request_may_not_name_a_resource_twice() -> None:
    assert _rule(lambda: _request(run_id="r", experiment_id="e",
                                  resources=("db", "db"))) == "concurrency.resource_duplicate"


def test_a_parallel_run_overlaps_everything_because_it_names_nothing() -> None:
    verdict, _ = admit((), _request(run_id="free", experiment_id="e"), now=_utc(2026, 6, 1))

    assert verdict.runnable is True
    assert verdict.queued_behind() == ""


def test_two_exclusive_experiments_on_one_database_serialize_naming_the_first() -> None:
    """The headline claim, as a pure predicate over state.

    "The second queues and names the first" is asserted three ways: the verdict
    refuses, the active set is left byte-for-byte identical, and the reason
    names both the run and the experiment holding the resource.
    """
    first = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    second = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1, 0, 1),
        expires_at=_utc(2026, 6, 1, 2),
    )

    granted, active = admit((), first, now=_utc(2026, 6, 1))
    assert granted.runnable is True
    assert active == (first,)

    refused, after_refusal = admit(active, second, now=_utc(2026, 6, 1, 0, 1))

    assert refused.runnable is False
    assert refused.queued_behind() == "run-1"
    assert refused.blocking_experiment_id == "exp-a"
    assert refused.blocking_resource == "db-primary"
    assert refused.blockers == ("run-1",)
    assert after_refusal == (first,)
    assert "run-1" in refused.reason
    assert "db-primary" in refused.reason


def test_a_queue_of_exclusive_requests_drains_one_at_a_time() -> None:
    """Four exclusive experiments on one database: one runs, three queue.

    The queue is the interesting part. Each candidate arrives while the previous
    one is still live, so it is refused and the *current holder* is named -- not
    the most recent request, and not the whole list.
    """
    moment = _utc(2026, 6, 1)
    holder: ConcurrencyRequest | None = None
    queued: list[str] = []

    for index in range(4):
        candidate = _request(
            run_id=f"run-{index}",
            experiment_id=f"exp-{index}",
            concurrency_class=ConcurrencyClass.EXCLUSIVE,
            resources=("db-primary",),
            acquired_at=moment + timedelta(minutes=index),
            expires_at=moment + timedelta(hours=2),
        )
        verdict, active = admit((holder,) if holder else (), candidate, now=candidate.acquired_at)
        if verdict.runnable:
            holder = candidate
        else:
            queued.append(verdict.queued_behind())

    assert holder is not None
    assert holder.run_id == "run-0"
    assert queued == ["run-0", "run-0", "run-0"]
    assert len(active) == 1  # a refused candidate never joins the active set


def test_only_the_holder_blocks_and_never_a_non_overlapping_request() -> None:
    """Two runs a day apart are two uses of a resource, not two claims on it."""
    holder = _request(
        run_id="run-0", experiment_id="exp-0", acquired_at=_utc(2026, 6, 1),
        expires_at=_utc(2026, 6, 1, 2),
    )
    same_window = _request(
        run_id="run-1", experiment_id="exp-1", acquired_at=_utc(2026, 6, 1, 1),
        expires_at=_utc(2026, 6, 1, 3),
    )
    next_day = _request(
        run_id="run-2", experiment_id="exp-2", acquired_at=_utc(2026, 6, 2),
        expires_at=_utc(2026, 6, 2, 1),
    )

    assert conflicting_runs((holder,), same_window, now=_utc(2026, 6, 1, 1)) == (holder,)
    assert conflicting_runs((holder,), next_day, now=_utc(2026, 6, 2)) == ()


def test_an_expired_holder_stops_fencing_the_resource() -> None:
    holder = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    latecomer = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1, 3),
        expires_at=_utc(2026, 6, 1, 4),
    )

    # Asked at 03:00 the resource is free, and the latecomer's own window never
    # overlaps the dead run's -- so it is runnable.
    assert evaluate_concurrency((holder,), latecomer, now=_utc(2026, 6, 1, 3)).runnable is True
    # Asked while the holder is still live, with an overlapping window, it is not.
    eager = latecomer.model_copy(
        update={"acquired_at": _utc(2026, 6, 1, 0, 30), "expires_at": _utc(2026, 6, 1, 0, 45)}
    )
    refused = evaluate_concurrency((holder,), eager, now=_utc(2026, 6, 1, 0, 30))

    assert refused.runnable is False
    assert refused.queued_behind() == "run-1"


def test_a_sequential_use_of_one_resource_is_not_a_conflict() -> None:
    """Non-overlapping windows are two uses of a resource, not two claims on it."""
    first = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    later = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1, 1),
        expires_at=_utc(2026, 6, 1, 2),
    )

    assert evaluate_concurrency((first,), later, now=_utc(2026, 6, 1, 1)).runnable is True


def test_one_run_may_reacquire_the_resource_it_already_holds() -> None:
    """Re-entrancy: a run taking a second step must not queue behind itself."""
    first = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    second_step = first.model_copy(update={"experiment_id": "exp-a-step-2"})

    assert evaluate_concurrency((first,), second_step, now=_utc(2026, 6, 1)).runnable is True


def test_shared_resource_runs_coexist_on_the_same_resource() -> None:
    reader = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    other_reader = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1),
        expires_at=_utc(2026, 6, 1, 1),
    )

    assert evaluate_concurrency((reader,), other_reader, now=_utc(2026, 6, 1)).runnable is True


def test_an_exclusive_run_preempts_a_shared_resource_run() -> None:
    reader = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    owner = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1),
        expires_at=_utc(2026, 6, 1, 1),
    )

    verdict = evaluate_concurrency((reader,), owner, now=_utc(2026, 6, 1))

    assert verdict.runnable is False
    assert verdict.queued_behind() == "run-1"


RESOURCE_HOLDING_CLASSES = [
    value for value in ConcurrencyClass if value is not ConcurrencyClass.PARALLEL
]


@pytest.mark.parametrize("other", RESOURCE_HOLDING_CLASSES)
def test_a_conflicting_run_coexists_with_nothing_it_names_a_resource_with(
    other: ConcurrencyClass,
) -> None:
    """``CONFLICTING`` is absolute: no other resource-holding class may overlap it.

    ``PARALLEL`` is excluded because it names no resources, so it never reaches
    this comparison at all -- and :class:`ConcurrencyRequest` refuses to let it
    claim one.
    """
    blocking = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.CONFLICTING,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    contender = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=other,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )

    verdict = evaluate_concurrency((blocking,), contender, now=_utc(2026, 6, 1))

    assert verdict.runnable is False, f"conflicting ran alongside {other.value}"
    assert verdict.queued_behind() == "run-1"


def test_runs_on_different_resources_never_conflict() -> None:
    left = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    right = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("cache-flush",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )

    assert evaluate_concurrency((left,), right, now=_utc(2026, 6, 1)).runnable is True


def test_the_policy_lock_layer_refuses_and_names_the_holder() -> None:
    """The 07 lock layer is consulted after the class matrix, and names its owner."""
    holder = _request(
        run_id="run-1", experiment_id="exp-a", concurrency_class=ConcurrencyClass.PARALLEL,
        resources=(), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )
    lock = holder.lock_for("db-primary")
    compatible = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 1),
    )

    verdict = evaluate_concurrency((), compatible, [lock], now=_utc(2026, 6, 1))

    assert verdict.runnable is False
    assert verdict.queued_behind() == "run-1"
    assert verdict.blocking_experiment_id == "exp-a"
    assert verdict.blocking_resource == "db-primary"
    assert "db-primary" in verdict.reason


def test_an_expired_lock_fences_nothing() -> None:
    lock = _lock("lock-1", owner="run-1", acquired_at=_utc(2026, 6, 1),
                 expires_at=_utc(2026, 6, 1, 1))
    candidate = _request(
        run_id="run-2", experiment_id="exp-b", concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
        resources=("db-primary",), acquired_at=_utc(2026, 6, 1), expires_at=_utc(2026, 6, 1, 2),
    )

    assert evaluate_concurrency((), candidate, [lock], now=_utc(2026, 6, 1)).runnable is False
    assert evaluate_concurrency((), candidate, [lock], now=_utc(2026, 6, 1, 2)).runnable is True


def test_a_request_derives_a_legal_lock_id_from_any_resource_name() -> None:
    request = _request(
        run_id="run-1", experiment_id="exp-a", resources=("Data/Primary DB (eu-west)",)
    )

    lock = request.lock_for("Data/Primary DB (eu-west)")

    assert lock.resource == "Data/Primary DB (eu-west)"
    # Lowercased, with every run of disallowed characters collapsed to one
    # hyphen. Case cannot fork the id, so "DB" and "db" cannot become two locks.
    assert lock.lock_id == "run-1--data-primary-db-eu-west"
    assert lock.owner_run_id == "run-1"
    assert request.lock_for("Data/Primary DB (eu-west)").lock_id == lock.lock_id


def test_evaluation_refuses_a_naive_concurrency_probe() -> None:
    request = _request(run_id="r", experiment_id="e")

    assert _rule(lambda: evaluate_concurrency((), request, now=_wall(2026, 6, 1))) == (
        "concurrency.naive"
    )


# --- domain law: this module must not reach outside the domain ----------------


def test_scheduling_imports_nothing_the_domain_layer_forbids() -> None:
    """The layering contract, checked on the module that was just added.

    The domain layer may not depend on IO, on the layers above it, or on the
    ambient clock. An import of ``os``, ``asyncio``, or ``mayhem.infra`` here
    would make every purity claim in the module docstring untrue, so the claim
    is machine-checked rather than trusted.
    """
    forbidden_roots = {
        "asyncio",
        "os",
        "socket",
        "sqlite3",
        "subprocess",
        "pathlib",
    }
    forbidden_project = ("mayhem.agents", "mayhem.controller", "mayhem.infra", "mayhem.toolkit")

    tree = ast.parse(DOMAIN_MODULE.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    offending = sorted(
        name
        for name in imported
        if name.split(".")[0] in forbidden_roots or name.startswith(forbidden_project)
    )

    assert offending == [], f"domain layer must not import {offending}"


def test_scheduling_never_reads_the_clock() -> None:
    """No ambient clock read: every instant is an argument.

    Scanned as *code*, not text -- the module docstring has to be able to say
    "never a ``datetime.now()`` call" without tripping its own guard, so the
    string literals and comments are stripped before the scan.
    """
    import io
    import tokenize

    code_only: list[str] = []
    with DOMAIN_MODULE.open("rb") as handle:
        for token in tokenize.tokenize(handle.readline):
            if token.type not in (tokenize.STRING, tokenize.COMMENT):
                code_only.append(token.string)
    body = " ".join(code_only)

    for forbidden in ("now", "today", "time"):
        assert f"datetime.{forbidden}(" not in body, (
            f"datetime.{forbidden}() makes a scheduling decision ambient"
        )
    assert "utc_now(" not in body
    assert "monotonic(" not in body
    assert io is not None  # keeps the import meaningful to a reader of the scan


# --- helpers ------------------------------------------------------------------


def _office_hours() -> BusinessHours:
    return BusinessHours(
        windows=(
            DailyWindow(
                label="office",
                days=frozenset({0, 1, 2, 3, 4}),
                start_time=time(9, 0),
                end_time=time(17, 0),
            ),
        )
    )


def _cron_schedule(
    *,
    expression: str = "0 9 * * *",
    schedule_id: str = "nightly-report",
    timezone_name: str = "UTC",
    business_hours: BusinessHours | None = None,
    maintenance_windows: tuple[MaintenanceWindow, ...] = (),
    blackout_dates: BlackoutDates | None = None,
    jitter: Jitter | None = None,
    created_at: datetime = CREATED,
    ends_at: datetime | None = None,
    max_runs: int | None = 100,
) -> Schedule:
    return Schedule(
        schedule_id=schedule_id,
        kind=ScheduleKind.CRON,
        cron=CronSpec.parse(expression),
        timezone_name=timezone_name,
        business_hours=business_hours,
        maintenance_windows=maintenance_windows,
        blackout_dates=blackout_dates,
        jitter=jitter,
        created_at=created_at,
        ends_at=ends_at,
        max_runs=max_runs,
    )


def _interval_schedule(*, every_s: float, anchor_at: datetime) -> Schedule:
    return Schedule(
        schedule_id="poller",
        kind=ScheduleKind.INTERVAL,
        interval=IntervalSpec(every_s=every_s, anchor_at=anchor_at),
        created_at=CREATED - timedelta(days=1),
        max_runs=10_000,
    )


def _calendar_schedule() -> Schedule:
    return Schedule(
        schedule_id="game-day",
        kind=ScheduleKind.CALENDAR,
        calendar=(
            CalendarWindow(
                name="june", starts_at=_utc(2026, 6, 1, 9), ends_at=_utc(2026, 6, 1, 17)
            ),
            CalendarWindow(
                name="july", starts_at=_utc(2026, 7, 1, 9), ends_at=_utc(2026, 7, 1, 17)
            ),
        ),
        created_at=CREATED,
    )


def _request(
    *,
    run_id: str = "run-1",
    experiment_id: str = "exp-a",
    concurrency_class: ConcurrencyClass = ConcurrencyClass.EXCLUSIVE,
    resources: tuple[str, ...] = ("db-primary",),
    acquired_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> ConcurrencyRequest:
    acquired = acquired_at or _utc(2026, 6, 1)
    return ConcurrencyRequest(
        run_id=run_id,
        experiment_id=experiment_id,
        concurrency_class=concurrency_class,
        resources=resources,
        acquired_at=acquired,
        expires_at=expires_at or _utc(2026, 6, 1, 1),
    )


def _lock(
    lock_id: str, *, owner: str, acquired_at: datetime, expires_at: datetime
) -> ResourceLock:
    return ResourceLock(
        lock_id=lock_id,
        resource="db-primary",
        experiment_id="exp-a",
        owner_run_id=owner,
        acquired_at=acquired_at,
        expires_at=expires_at,
    )
