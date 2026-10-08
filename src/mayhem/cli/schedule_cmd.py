"""``mayhem schedule`` — the scheduling surface the campaign CLI never had.

Plan 13 Phase 3. Before this module a schedule could be registered by calling
:meth:`mayhem.infra.schedule_store.ScheduleStore.save_schedule` from Python and
nowhere else: the campaign group had no sub-command that mentioned a recurrence,
a timezone, a blackout date, or a concurrency class. That absence is the gap this
group closes — a person who cannot author a schedule cannot review one either.

Two commitments shape what is here and, more importantly, what is not.

**Every command is plan-only except the two that mutate the registry.**
``add``, ``enable``, ``disable``, and ``delete`` write schedule *definitions*.
Everything else — ``list``, ``show``, ``next``, ``runs``, ``fairness``, and
``tick`` — reads and evaluates. There is deliberately **no** ``--execute``,
``--force``, or ``--ignore-windows`` on any of them, and the reason is not
taste: dispatch is not a thing this surface can do correctly. Firing a schedule
means running :meth:`mayhem.controller.scheduler.Scheduler.tick`, which means
compiling the drill through ``plan_drill``, compiling the safety proof through
``compile_safety_evidence``, and reading the policy verdict through
``simulate_plan_policy`` — and all three need a topology graph, a
:class:`~mayhem.controller.safety.SafetyContext`, and a runtime executor that
this command has no business assembling by hand. A CLI that dispatched on its
own would be a second dispatch path, and the second dispatch path is exactly
how a scheduled run ends up skipping a gate.

**So ``tick`` evaluates and reports; it never dispatches.** What it renders is
the honest answer to "would this have fired?", and it says which of the answers
it could not compute. :func:`build_tick_payload` is the whole of that: for each
registered schedule it records the :class:`~mayhem.domain.scheduling.FireCode`
the *live* gates produced at ``--now``, whether a game-day facilitator hold is
blocking the slot, and whether the claim ledger already holds the slot's
idempotency key. It then names the three gates it deliberately did **not**
evaluate — the safety gate, the approval gate, and the concurrency model — so a
reader cannot mistake "due" for "cleared". A missed slot is reported with its
reason; a slot already fired is reported as already fired, never as pending.

Time is injected everywhere. ``--now`` sets the instant every decision is made
against; without it the command reads the host clock *once*, stamps it, and says
so in ``clock`` — a single declared read whose value is reported in the payload
so a reader can reproduce it rather than re-derive it.

Invocations that resolve against this group::

    mayhem schedule --help
    mayhem schedule add --campaign-id camp-1 --experiment-id net-latency \\
        --team sre --cron "0 9 * * 1-5" --timezone America/New_York --max-runs 20
    mayhem schedule add --campaign-id camp-1 --experiment-id poller \\
        --team sre --interval-s 3600 --anchor-at 2026-06-01T09:00:00+00:00 --max-runs 50
    mayhem schedule list --json
    mayhem schedule show nightly
    mayhem schedule next --now 2026-06-01T12:00:00+00:00
    mayhem schedule tick --now 2026-06-01T09:00:00+00:00 --json
    mayhem schedule runs nightly
    mayhem schedule fairness --team sre --team payments --windows 12
    mayhem schedule disable nightly
    mayhem schedule delete nightly --yes

.. warning::

   **This group is not registered.** ``cli/app.py`` and
   ``cli/command_registry.py`` belong to other lanes, so the group is exported
   and exercised directly through ``CliRunner``. The integration pass has to add
   the row before ``mayhem schedule --help`` resolves from the root command. The
   same applies to :mod:`mayhem.cli.game_day_step_cmd`, which carries the
   game-day facilitation verbs this plan's Phase 3 also asks for.

What this surface deliberately does **not** claim:

* It does not predict a run's outcome. It says a slot is *due*; it cannot say
  the drill will be admitted, and it prints that it cannot.
* It does not enforce a wall-clock precision. ``--jitter-s`` moves a fire time
  by a bounded, hash-derived offset, and the payload reports the effective
  instant that offset produced so the bound is visible rather than asserted.
* It performs no signature verification and contacts no cluster. Every value it
  prints comes from the local SQLite registry.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time
from typing import Any, NoReturn

import click

from mayhem.cli import style
from mayhem.cli.context import DEFAULT_DB
from mayhem.cli.resolver import make_group
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.scheduling import (
    BlackoutDates,
    BusinessHours,
    CalendarWindow,
    ConcurrencyClass,
    CronSpec,
    DailyWindow,
    FairnessPolicy,
    IntervalSpec,
    Jitter,
    MaintenanceWindow,
    Schedule,
    ScheduleKind,
)
from mayhem.infra.schedule_store import DEFAULT_LOCK_WINDOW_S, ScheduleEntry
from mayhem.infra.store import Store

__all__ = [
    "DEFAULT_TEAM",
    "MONITORED_INVOCATIONS",
    "NOT_EVALUATED_HERE",
    "SCHEDULE_TICK_SCHEMA_VERSION",
    "build_tick_payload",
    "parse_business_hours",
    "parse_calendar_window",
    "parse_maintenance_window",
    "schedule",
]

DEFAULT_TEAM = "unassigned"

#: Version stamped on every ``tick`` payload. Bumped when the *shape* changes;
#: adding a row field is additive and does not need one.
SCHEDULE_TICK_SCHEMA_VERSION = "1.0"

#: The three gates ``tick`` refuses to pretend it ran. Named in the payload and
#: in the human rendering, because "the slot was due" and "the slot was cleared"
#: are different claims and only the second one is a safety statement.
NOT_EVALUATED_HERE: tuple[str, ...] = (
    "safety gate (controller.safety_proof.compile_safety_evidence)",
    "approval gate (controller.approval_gate.verify_approvals)",
    "concurrency model (domain.scheduling.evaluate_concurrency)",
)

#: The invocations this module's own suite resolves against the live Click tree.
#: Every spelling a document may use, kept here so the surface and the docs are
#: checked against the same list.
MONITORED_INVOCATIONS: tuple[tuple[str, ...], ...] = (
    ("schedule", "--help"),
    ("schedule", "add", "--help"),
    ("schedule", "list", "--help"),
    ("schedule", "show", "--help"),
    ("schedule", "next", "--help"),
    ("schedule", "tick", "--help"),
    ("schedule", "runs", "--help"),
    ("schedule", "fairness", "--help"),
    ("schedule", "enable", "--help"),
    ("schedule", "disable", "--help"),
    ("schedule", "delete", "--help"),
)

schedule = make_group("schedule", "Register, inspect, and evaluate scheduled campaign runs.")


# =============================================================================
# Parsing: every authorable field, refused loudly rather than coerced
# =============================================================================


def parse_business_hours(text: str) -> DailyWindow:
    """Parse ``"Mon-Fri 09:00-17:00"`` into a :class:`DailyWindow`.

    The grammar is deliberately the smallest one an operator can hold in their
    head: a weekday list, a space, and ``HH:MM-HH:MM``. Weekday names are
    three-letter and case-insensitive, and a hyphen inside the *weekday* span is
    what distinguishes ``Mon-Fri`` (a range) from the hyphen in ``09:00-17:00``
    (the band) by position — the band is always the last whitespace-separated
    token. A window whose end is not after its start runs overnight, which is
    how "22:00-02:00" is written rather than as two windows.

    Raises:
        click.UsageError: On any shape the grammar does not describe.
    """
    tokens = text.split()
    if len(tokens) != 2:
        raise click.UsageError(
            f"business-hours {text!r} is not '<weekdays> <HH:MM-HH:MM>'; "
            "e.g. 'Mon-Fri 09:00-17:00' or 'Mon-Fri 22:00-02:00' for overnight"
        )
    days_token, band = tokens
    days = _parse_weekdays(days_token)
    start_text, _, end_text = band.partition("-")
    return DailyWindow(
        label=days_token,
        days=days,
        start_time=_parse_clock(start_text, text),
        end_time=_parse_clock(end_text, text),
    )


def _parse_weekdays(token: str) -> frozenset[int]:
    """``Mon-Fri`` / ``Mon,Wed,Fri`` / ``*`` into Python weekday numbers."""
    names = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    if token.strip() == "*":
        return frozenset(range(7))
    days: set[int] = set()
    for part in token.split(","):
        span = part.strip().lower()
        if "-" in span:
            low_text, _, high_text = span.partition("-")
            low, high = _weekday_number(low_text, names), _weekday_number(high_text, names)
            days.update(day for day in range(7) if low <= day <= high)
        else:
            days.add(_weekday_number(span, names))
    if not days:
        raise click.UsageError(f"business-hours {token!r} names no weekday")
    return frozenset(days)


def _weekday_number(text: str, names: tuple[str, ...]) -> int:
    key = text.strip().lower()
    if key in names:
        return names.index(key)
    if key.isdigit() and 0 <= int(key) <= 6:
        return int(key)
    raise click.UsageError(f"{text!r} is not a weekday; use Mon..Sun or 0..6 with 0 = Monday")


def _parse_clock(text: str, whole: str) -> time:
    try:
        return time.fromisoformat(text.strip())
    except ValueError as exc:
        raise click.UsageError(f"{whole!r} has an unreadable time {text!r}") from exc


def parse_maintenance_window(text: str) -> MaintenanceWindow:
    """Parse ``"change-freeze=2026-06-01T00:00:00Z..2026-06-01T04:00:00Z"``.

    The window id is mandatory and must be unique across a schedule's windows,
    because a refusal names the window that blocked it — an unnamed window can
    only be reported as "a window", which is not actionable.

    Raises:
        click.UsageError: On any shape the grammar does not describe.
    """
    window_id, sep, span = text.partition("=")
    if not sep:
        raise click.UsageError(f"maintenance-window {text!r} is not '<id>=<start>..<end>'")
    start_text, sep, end_text = span.partition("..")
    if not sep:
        raise click.UsageError(
            f"maintenance-window {text!r} is missing the '..' between start and end"
        )
    return MaintenanceWindow(
        window_id=window_id.strip(),
        starts_at=parse_instant(start_text),
        ends_at=parse_instant(end_text),
        reason="",
    )


def parse_calendar_window(text: str) -> CalendarWindow:
    """Parse ``"2026-06-01T09:00:00Z..2026-06-01T12:00:00Z"`` with an optional name.

    A name may be given as ``"cutover=<start>..<end>"``; without it the window is
    still schedulable and simply reports no label.

    Raises:
        click.UsageError: On any shape the grammar does not describe.
    """
    name = ""
    span = text
    head, sep, tail = text.partition("=")
    if sep and ".." in tail:
        name, span = head.strip(), tail
    start_text, sep, end_text = span.partition("..")
    if not sep:
        raise click.UsageError(f"calendar-window {text!r} is not '[name=]<start>..<end>'")
    return CalendarWindow(
        name=name, starts_at=parse_instant(start_text), ends_at=parse_instant(end_text)
    )


def parse_instant(text: str) -> datetime:
    """Parse an ISO-8601 instant, refusing a naive one.

    Refusing naive input is the same discipline
    :func:`mayhem.domain.scheduling._as_utc` applies: a schedule whose anchor
    says "09:00" without a zone is a schedule whose fire time depends on which
    machine reads it.

    Raises:
        click.UsageError: If the text is not an aware ISO-8601 instant.
    """
    raw = text.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise click.UsageError(f"{text!r} is not an ISO-8601 instant") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise click.UsageError(
            f"{text!r} has no timezone offset; every scheduling instant must be aware "
            "(e.g. 2026-06-01T09:00:00+00:00)"
        )
    return parsed


def parse_day(text: str) -> date:
    """Parse an ISO ``YYYY-MM-DD`` blackout date."""
    try:
        return date.fromisoformat(text.strip())
    except ValueError as exc:
        raise click.UsageError(f"{text!r} is not a YYYY-MM-DD date") from exc


def _refuse(message: str) -> NoReturn:
    """Turn a domain refusal into a usage error with the domain's own words.

    Annotated :data:`typing.NoReturn` so every ``_refuse(...)`` call site reads as
    terminating -- to a reader and to ``mypy`` alike. The constructors below end
    with one: a body that can only raise has no other way to produce a value.
    """
    raise click.UsageError(message)


def _build_schedule(
    *,
    schedule_id: str,
    name: str,
    team: str,
    cron: str | None,
    interval_s: float | None,
    anchor_at: str | None,
    calendar: tuple[str, ...],
    timezone_name: str,
    business_hours: tuple[str, ...],
    maintenance_windows: tuple[str, ...],
    blackout_dates: tuple[str, ...],
    jitter_s: float | None,
    created_at: str,
    ends_at: str | None,
    max_runs: int | None,
) -> Schedule:
    """Assemble a :class:`Schedule` from parsed CLI inputs, refusing ambiguity.

    Exactly one recurrence source must be given, and every refusal is the
    *domain's* refusal re-raised verbatim rather than a CLI paraphrase — a
    schedule author debugging an unbounded cron should read the same sentence
    the engine will refuse with at fire time.
    """
    sources = sum(1 for given in (cron, interval_s is not None, calendar) if given)
    if sources != 1:
        raise click.UsageError(
            "give exactly one of --cron, --interval-s (with --anchor-at), or --calendar"
        )
    parsed_calendar = tuple(parse_calendar_window(text) for text in calendar)
    # Constructed only when asked for. ``BusinessHours`` refuses an empty union
    # on purpose -- empty means "never open" -- so building one unconditionally
    # would make "no --business-hours flag" mean "closed for ever".
    hours = (
        BusinessHours(windows=tuple(parse_business_hours(h) for h in business_hours))
        if business_hours
        else None
    )
    windows = tuple(parse_maintenance_window(text) for text in maintenance_windows)
    blackouts = (
        BlackoutDates(dates=frozenset(parse_day(text) for text in blackout_dates))
        if blackout_dates
        else None
    )
    spec_kind: ScheduleKind
    cron_spec: CronSpec | None = None
    interval_spec: IntervalSpec | None = None
    if cron:
        spec_kind = ScheduleKind.CRON
        cron_spec = CronSpec.parse(cron)
    elif interval_s is not None:
        spec_kind = ScheduleKind.INTERVAL
        if not anchor_at:
            raise click.UsageError("--interval-s requires --anchor-at")
        interval_spec = IntervalSpec(every_s=interval_s, anchor_at=parse_instant(anchor_at))
    else:
        spec_kind = ScheduleKind.CALENDAR
    body: dict[str, Any] = {
        "schedule_id": schedule_id,
        "name": name,
        "team": team,
        "kind": spec_kind,
        "timezone_name": timezone_name,
        "created_at": parse_instant(created_at),
        "business_hours": hours,
        "maintenance_windows": windows,
        "blackout_dates": blackouts,
        "jitter": Jitter(max_offset_s=jitter_s) if jitter_s is not None else None,
        "ends_at": parse_instant(ends_at) if ends_at else None,
        "max_runs": max_runs,
        "calendar": parsed_calendar,
    }
    if cron_spec is not None:
        body["cron"] = cron_spec
    if interval_spec is not None:
        body["interval"] = interval_spec
    try:
        return Schedule(**body)
    except InvariantViolationError as exc:
        _refuse(f"{exc.rule}: {exc}")


def _open_store(db_opt: str | None) -> Store:
    """Open (and migrate) the store this invocation reads and writes.

    ``--db`` wins; otherwise the root context's ``--db``. Read through
    ``getattr`` rather than an ``assert isinstance``, so the group is testable
    through ``CliRunner`` with a bare ``obj`` and a missing context never turns
    into an ``AttributeError`` at the wrong place.
    """
    if db_opt:
        return Store.open_migrated(db_opt)
    ctx = click.get_current_context(silent=True)
    obj = getattr(ctx, "obj", None)
    return Store.open_migrated(getattr(obj, "db", "") or DEFAULT_DB)


def _now_arg(value: str | None) -> datetime:
    """The instant this invocation decides against.

    ``--now`` when given; otherwise the host clock read exactly once, here, so
    there is a single read to point at rather than a clock consulted inside a
    loop of evaluations.
    """
    return parse_instant(value) if value else datetime.now(UTC)


def _entry_payload(entry: ScheduleEntry, *, now: datetime | None) -> dict[str, Any]:
    """The JSON-able view of one registered schedule."""
    payload: dict[str, Any] = {
        "schedule_id": entry.schedule_id,
        "name": entry.schedule.name,
        "team": entry.team,
        "campaign_id": entry.campaign_id,
        "experiment_id": entry.experiment_id,
        "enabled": entry.enabled,
        "kind": entry.schedule.kind.value,
        "timezone_name": entry.schedule.timezone_name,
        "recurrence": entry.schedule.recurrence_description(),
        "concurrency_class": entry.concurrency_class.value,
        "resources": list(entry.resources),
        "lock_window_s": entry.lock_window_s,
        "run_count": entry.run_count,
        "window_index": entry.window_index,
        "body_digest": entry.body_digest,
        "max_runs": entry.schedule.max_runs,
        "ends_at": entry.schedule.ends_at.isoformat() if entry.schedule.ends_at else "",
        "jitter_s": entry.schedule.jitter.max_offset_seconds if entry.schedule.jitter else 0.0,
        "business_hours": (
            entry.schedule.business_hours.describe() if entry.schedule.business_hours else ""
        ),
        "maintenance_windows": [w.window_id for w in entry.schedule.maintenance_windows],
        "blackout_dates": sorted(
            day.isoformat()
            for day in (
                entry.schedule.blackout_dates.dates
                if entry.schedule.blackout_dates
                else frozenset()
            )
        ),
        "created_at": entry.schedule.created_at.isoformat(),
    }
    if now is not None:
        upcoming = entry.schedule.next_fire_time(now)
        payload["next_fire_at"] = upcoming.isoformat() if upcoming else ""
        payload["retired"] = upcoming is None
    return payload


# =============================================================================
# The commands
# =============================================================================


@schedule.command("add")
@click.argument("schedule_id")
@click.option("--name", default="", help="Human-readable name for this schedule.")
@click.option(
    "--team", default=DEFAULT_TEAM, show_default=True, help="Owning team (fairness is by team)."
)
@click.option("--campaign-id", required=True, help="Campaign this schedule fires into.")
@click.option("--experiment-id", required=True, help="Experiment this schedule runs.")
@click.option("--cron", default=None, help="Five-field Mayhem cron expression.")
@click.option("--interval-s", type=float, default=None, help="Fixed period in seconds.")
@click.option("--anchor-at", default=None, help="ISO-8601 instant the interval counts from.")
@click.option(
    "--calendar",
    "calendar",
    multiple=True,
    help="One-off window '[name=]<start>..<end>' (repeatable).",
)
@click.option("--timezone", "timezone_name", default="UTC", show_default=True, help="IANA zone.")
@click.option(
    "--business-hours",
    multiple=True,
    help="Recurring band 'Mon-Fri 09:00-17:00' (repeatable; implies the union).",
)
@click.option(
    "--maintenance-window",
    multiple=True,
    help="Absolute window 'id=<start>..<end>' (repeatable).",
)
@click.option(
    "--blackout-date", multiple=True, help="Local date on which nothing fires (repeatable)."
)
@click.option("--jitter-s", type=float, default=None, help="Bounded jitter, +/- seconds.")
@click.option("--created-at", default="", help="Creation instant (defaults to the host clock).")
@click.option("--ends-at", default=None, help="Horizon instant; required with --cron/--interval-s.")
@click.option(
    "--max-runs",
    type=int,
    default=None,
    help="Run budget; required with --cron/--interval-s.",
)
@click.option(
    "--concurrency-class",
    type=click.Choice([member.value for member in ConcurrencyClass]),
    default=ConcurrencyClass.EXCLUSIVE.value,
    show_default=True,
    help="How this run relates to other runs on its resources.",
)
@click.option(
    "--resource", "resources", multiple=True, help="Resource this run holds (repeatable)."
)
@click.option(
    "--lock-window-s",
    type=float,
    default=DEFAULT_LOCK_WINDOW_S,
    show_default=True,
    help="How long the run holds its resources.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def add(
    schedule_id: str,
    name: str,
    team: str,
    campaign_id: str,
    experiment_id: str,
    cron: str | None,
    interval_s: float | None,
    anchor_at: str | None,
    calendar: tuple[str, ...],
    timezone_name: str,
    business_hours: tuple[str, ...],
    maintenance_window: tuple[str, ...],
    blackout_date: tuple[str, ...],
    jitter_s: float | None,
    created_at: str,
    ends_at: str | None,
    max_runs: int | None,
    concurrency_class: str,
    resources: tuple[str, ...],
    lock_window_s: float,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Register a schedule. Writes the definition; never fires anything."""
    body = _build_schedule(
        schedule_id=schedule_id,
        name=name,
        team=team,
        cron=cron,
        interval_s=interval_s,
        anchor_at=anchor_at,
        calendar=calendar,
        timezone_name=timezone_name,
        business_hours=business_hours,
        maintenance_windows=maintenance_window,
        blackout_dates=blackout_date,
        jitter_s=jitter_s,
        created_at=created_at or datetime.now(UTC).isoformat(),
        ends_at=ends_at,
        max_runs=max_runs,
    )
    try:
        entry = ScheduleEntry(
            schedule=body,
            campaign_id=campaign_id,
            experiment_id=experiment_id,
            concurrency_class=ConcurrencyClass(concurrency_class),
            resources=tuple(sorted(resources)),
            lock_window_s=lock_window_s,
        )
    except InvariantViolationError as exc:
        # The binding has its own refusals -- an exclusive run that names no
        # resource, a parallel run that names one -- and they are as load-bearing
        # as the schedule's. Surfaced as a usage error with the domain's own
        # words rather than as a traceback, so an operator reads the reason.
        _refuse(f"{exc.rule}: {exc}")
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        stored = ScheduleStore(store).save_schedule(entry)
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    payload = _entry_payload(stored, now=None)
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(
        f"schedule {style.cyan(stored.schedule_id)} registered for team "
        f"{stored.team} -> {stored.campaign_id}/{stored.experiment_id}"
    )
    click.echo(f"  {stored.schedule.describe()}")
    click.echo(
        f"  concurrency {stored.concurrency_class.value} on "
        f"{', '.join(stored.resources) or 'no resources'}"
    )
    click.echo(f"  body digest {stored.body_digest[:16]}")


@schedule.command("list")
@click.option("--team", default=None, help="Only this team's schedules.")
@click.option("--enabled-only", is_flag=True, help="Only enabled schedules.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def list_schedules(team: str | None, enabled_only: bool, db_opt: str | None, as_json: bool) -> None:
    """List registered schedules."""
    now = datetime.now(UTC)
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        entries = ScheduleStore(store).list_schedules(enabled_only=enabled_only)
    finally:
        store.close()
    if team:
        entries = tuple(entry for entry in entries if entry.team == team)
    from mayhem.cli.output import echo_machine

    if echo_machine([_entry_payload(entry, now=now) for entry in entries], as_json=as_json):
        return
    if not entries:
        click.echo("no schedules registered")
        return
    for entry in entries:
        upcoming = entry.schedule.next_fire_time(now)
        when = upcoming.isoformat() if upcoming else style.state("retired")
        flag = "" if entry.enabled else style.state("disabled")
        click.echo(
            f"{entry.schedule_id:<24} {entry.team:<12} {flag:<10} "
            f"{entry.schedule.recurrence_description()} -> {when}"
        )


@schedule.command("show")
@click.argument("schedule_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def show(schedule_id: str, db_opt: str | None, as_json: bool) -> None:
    """Show one schedule, and the ledger of what it has actually done."""
    now = datetime.now(UTC)
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        repo = ScheduleStore(store)
        entry = repo.load_schedule(schedule_id)
        runs = repo.runs_for_schedule(schedule_id) if entry is not None else ()
    finally:
        store.close()
    if entry is None:
        click.echo(f"unknown schedule: {schedule_id}", err=True)
        raise SystemExit(1)
    from mayhem.cli.output import echo_machine

    payload = {
        **_entry_payload(entry, now=now),
        "runs": [
            {
                "idempotency_key": record.idempotency_key,
                "slot_start": record.slot_start.isoformat(),
                "effective_at": record.effective_at.isoformat(),
                "state": record.state.value,
                "code": record.code,
                "reason": record.reason,
                "run_id": record.run_id,
                "settled": record.settled,
            }
            for record in runs
        ],
    }
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(f"schedule {entry.schedule_id}: {entry.schedule.describe()}")
    click.echo(f"  team {entry.team} -> {entry.campaign_id}/{entry.experiment_id}")
    click.echo(f"  concurrency {entry.concurrency_class.value} on {', '.join(entry.resources)}")
    click.echo(f"  runs dispatched {entry.run_count}, window {entry.window_index}")
    if not runs:
        click.echo("  no fire has been attempted")
        return
    for record in runs:
        click.echo(f"  {record.slot_start.isoformat()} {record.state.value} {record.code}")


@schedule.command("next")
@click.option("--now", default=None, help="Instant to search from (defaults to the host clock).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def next_fires(now: str | None, db_opt: str | None, as_json: bool) -> None:
    """Report each schedule's next nominal fire instant, or that it has retired.

    A *nominal* instant, before jitter: the slot is what the claim ledger keys
    on and the effective instant is the slot shifted by the schedule's bounded
    offset. Both are reported so the bound is visible.
    """
    instant = _now_arg(now)
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        entries = ScheduleStore(store).list_schedules()
    finally:
        store.close()
    rows: list[dict[str, Any]] = []
    for entry in entries:
        upcoming = entry.schedule.next_fire_time(instant)
        jitter = entry.schedule.jitter
        shifted = upcoming
        if shifted is not None and jitter is not None:
            shifted = jitter.apply(shifted, seed=entry.schedule_id)
        rows.append(
            {
                "schedule_id": entry.schedule_id,
                "team": entry.team,
                "enabled": entry.enabled,
                "slot_start": upcoming.isoformat() if upcoming else "",
                "effective_at": shifted.isoformat() if shifted else "",
                "jitter_s": 0.0 if jitter is None else jitter.max_offset_seconds,
                "retired": upcoming is None,
            }
        )
    from mayhem.cli.output import echo_machine

    if echo_machine({"now": instant.isoformat(), "schedules": rows}, as_json=as_json):
        return
    if not rows:
        click.echo("no schedules registered")
        return
    for row in rows:
        if row["retired"]:
            click.echo(f"{row['schedule_id']:<24} retired (horizon closed)")
            continue
        shift = row["effective_at"] != row["slot_start"]
        click.echo(
            f"{row['schedule_id']:<24} {row['slot_start']}"
            + (f"  (jittered to {row['effective_at']})" if shift else "")
        )


@schedule.command("tick")
@click.option("--now", default=None, help="Instant to evaluate at (defaults to the host clock).")
@click.option(
    "--window-index", type=int, default=None, help="Fairness window this evaluation is in."
)
@click.option("--schedule-id", "only", default=None, help="Evaluate only this schedule.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def tick(
    now: str | None, window_index: int | None, only: str | None, db_opt: str | None, as_json: bool
) -> None:
    """Evaluate every schedule at ``--now`` and report. **Dispatches nothing.**

    Every row is one schedule's live answer: the ``FireCode`` the schedule's own
    gates produced, whether a facilitator hold is blocking it, and whether the
    claim ledger already holds this slot. A slot that was missed says so with its
    reason; a slot that already fired says ``already_dispatched`` rather than
    repeating as pending.
    """
    instant = _now_arg(now)
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        payload = build_tick_payload(
            ScheduleStore(store),
            now=instant,
            window_index=window_index,
            only=only,
        )
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        return
    click.echo(f"evaluated {len(payload['schedules'])} schedule(s) at {payload['now']}")
    for row in payload["schedules"]:
        click.echo(f"  {row['schedule_id']:<24} {row['code']:<28} {row['reason']}")
    for gate in payload["not_evaluated_here"]:
        click.echo(f"  not evaluated here: {gate}")


@schedule.command("runs")
@click.argument("schedule_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def runs(schedule_id: str, db_opt: str | None, as_json: bool) -> None:
    """Show the claim ledger: every slot this schedule attempted to fire."""
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        records = ScheduleStore(store).runs_for_schedule(schedule_id)
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    payload = {
        "schedule_id": schedule_id,
        "runs": [
            {
                "idempotency_key": record.idempotency_key,
                "window_index": record.window_index,
                "slot_start": record.slot_start.isoformat(),
                "effective_at": record.effective_at.isoformat(),
                "state": record.state.value,
                "settled": record.settled,
                "code": record.code,
                "reason": record.reason,
                "run_id": record.run_id,
                "controller_id": record.controller_id,
            }
            for record in records
        ],
    }
    if echo_machine(payload, as_json=as_json):
        return
    if not records:
        click.echo(f"no fire has been attempted for {schedule_id}")
        return
    for record in records:
        unsettled = "" if record.settled else style.danger(" UNKNOWN OUTCOME")
        click.echo(
            f"{record.slot_start.isoformat()} {record.state.value:<11} "
            f"{record.code or '-':<28} {record.run_id or '-'}{unsettled}"
        )


@schedule.command("fairness")
@click.option("--team", "teams", multiple=True, help="Demanding team (repeatable; required).")
@click.option(
    "--share", "shares", multiple=True, help="team=weight (repeatable; overrides --team)."
)
@click.option("--windows", type=int, default=12, show_default=True, help="Windows to simulate.")
@click.option(
    "--starvation-window",
    type=int,
    default=3,
    show_default=True,
    help="Consecutive skipped windows after which a team jumps the queue.",
)
@click.option(
    "--grants-per-window", type=int, default=1, show_default=True, help="Slots per window."
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def fairness(
    teams: tuple[str, ...],
    shares: tuple[str, ...],
    windows: int,
    starvation_window: int,
    grants_per_window: int,
    as_json: bool,
) -> None:
    """Simulate the anti-starvation guarantee over N windows.

    A simulation, not a promise: it runs the same
    :meth:`mayhem.domain.scheduling.FairnessPolicy.select_team` the scheduler
    orders dispatches with, over constant demand, and reports the longest run of
    windows any team went without a grant beside the bound it was promised.
    """
    weights: dict[str, float] = {}
    for team in teams:
        weights[team] = 1.0
    for pair in shares:
        name, sep, weight = pair.partition("=")
        if not sep:
            raise click.UsageError(f"--share {pair!r} is not 'team=weight'")
        weights[name.strip()] = float(weight)
    if not weights:
        raise click.UsageError("name at least one --team (or --share team=weight)")
    try:
        policy = FairnessPolicy(
            policy_id="cli-preview",
            shares=weights,
            starvation_window=starvation_window,
            max_grants_per_window=grants_per_window,
        )
        simulation = policy.simulate_fairness(tuple(weights), windows=windows)
    except InvariantViolationError as exc:
        _refuse(f"{exc.rule}: {exc}")
    from mayhem.cli.output import echo_machine

    payload = {
        "policy": policy.describe(),
        "windows": simulation.windows,
        "counts": simulation.counts,
        "max_consecutive_skips": simulation.max_consecutive_skips,
        "starvation_bound": simulation.starvation_bound(policy),
        "honours_policy": simulation.honours_policy(policy),
        "starved_teams": list(simulation.starved_teams(policy)),
        "grants": [list(window) for window in simulation.grants],
    }
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(simulation.describe())
    click.echo(f"  starvation bound {payload['starvation_bound']} window(s)")
    for team, skips in sorted(simulation.max_consecutive_skips.items()):
        click.echo(f"  {team:<16} longest without a grant: {skips}")
    click.echo("  honours policy: " + ("yes" if payload["honours_policy"] else "NO"))


def _set_enabled(schedule_id: str, enabled: bool, db_opt: str | None, as_json: bool) -> None:
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        updated = ScheduleStore(store).set_enabled(schedule_id, enabled=enabled)
    finally:
        store.close()
    if updated is None:
        click.echo(f"unknown schedule: {schedule_id}", err=True)
        raise SystemExit(1)
    from mayhem.cli.output import echo_machine

    payload = _entry_payload(updated, now=datetime.now(UTC))
    payload["enabled"] = enabled
    if echo_machine(payload, as_json=as_json):
        return
    verb = "enabled" if enabled else "disabled"
    click.echo(
        f"schedule {style.cyan(schedule_id)} {verb}"
        if enabled
        else f"schedule {style.cyan(schedule_id)} disabled — a tick reports it as held"
    )


@schedule.command("enable")
@click.argument("schedule_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def enable_cmd(schedule_id: str, db_opt: str | None, as_json: bool) -> None:
    """Re-enable a schedule. A disabled schedule is *held*, not skipped."""
    _set_enabled(schedule_id, True, db_opt, as_json)


@schedule.command("disable")
@click.argument("schedule_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def disable_cmd(schedule_id: str, db_opt: str | None, as_json: bool) -> None:
    """Disable a schedule. Its next tick is recorded as held, not as a fire."""
    _set_enabled(schedule_id, False, db_opt, as_json)


@schedule.command("delete")
@click.argument("schedule_id")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def delete_cmd(schedule_id: str, yes: bool, db_opt: str | None, as_json: bool) -> None:
    """Delete a schedule that has never dispatched anything.

    A schedule with claims cannot be deleted: the evidence that it ran outlives
    the trigger. The store refuses it, and this command reports that refusal
    rather than working around it.
    """
    store = _open_store(db_opt)
    try:
        from mayhem.infra.schedule_store import ScheduleStore

        repo = ScheduleStore(store)
        if repo.load_schedule(schedule_id) is None:
            click.echo(f"unknown schedule: {schedule_id}", err=True)
            raise SystemExit(1)
        if not yes:
            click.confirm(f"Delete schedule '{schedule_id}'?", abort=True)
        try:
            removed = repo.delete_schedule(schedule_id)
        except InvariantViolationError as exc:
            click.echo(f"refused: {exc}", err=True)
            raise SystemExit(1) from exc
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    if echo_machine({"deleted": schedule_id if removed else None}, as_json=as_json):
        return
    click.echo(style.ok(f"Schedule '{schedule_id}' deleted."))


# =============================================================================
# The tick payload — a view, and an explicitly partial one
# =============================================================================


def build_tick_payload(
    repo: Any,
    *,
    now: datetime,
    window_index: int | None = None,
    only: str | None = None,
) -> dict[str, Any]:
    """Evaluate every schedule at ``now`` and describe the answer.

    The payload is honest about its own reach. ``schedules`` carries what these
    gates decided; ``not_evaluated_here`` names the three that were not run and
    says, in one sentence, that a due slot is not an admitted one. That sentence
    is load-bearing: a scheduler that reported "due" without it would be the
    exact failure this plan exists to prevent, only with better manners.

    ``code`` is the schedule's own :class:`~mayhem.domain.scheduling.FireCode`,
    or ``schedule.already_dispatched`` when the claim ledger already holds this
    slot — a slot that fired is never reported as pending a second time.
    """
    from mayhem.controller.scheduler import slot_idempotency_key

    entries = repo.list_schedules()
    if only:
        entries = tuple(entry for entry in entries if entry.schedule_id == only)
    rows: list[dict[str, Any]] = []
    for entry in entries:
        fire = entry.schedule.evaluate(now=now, run_count=entry.run_count)
        slot = fire.slot_start
        held = tuple(step.key for step in repo.steps_for_schedule(entry.schedule_id) if step.held)
        already = ""
        if fire.fired and slot is not None:
            key = slot_idempotency_key(
                schedule_id=entry.schedule_id,
                campaign_id=entry.campaign_id,
                experiment_id=entry.experiment_id,
                slot_start=slot,
            )
            record = repo.load_run(key)
            if record is not None:
                already = (
                    "already_dispatched"
                    if record.state.value == "dispatched"
                    else "claim_in_flight"
                )
        if not entry.enabled:
            code, reason = "schedule.disabled", f"schedule {entry.schedule_id} is disabled"
        elif held:
            code, reason = (
                "schedule.facilitator_hold",
                f"game-day step(s) {', '.join(held)} hold this schedule's fire",
            )
        elif already:
            code = already
            reason = f"slot {slot.isoformat() if slot else ''} is already in the claim ledger"
        else:
            code, reason = fire.code.value, fire.reason
        rows.append(
            {
                "schedule_id": entry.schedule_id,
                "team": entry.team,
                "campaign_id": entry.campaign_id,
                "experiment_id": entry.experiment_id,
                "code": code,
                "reason": reason,
                # ``due`` is the *schedule's own* answer at ``--now`` and nothing
                # else: did every gate the schedule carries clear at this instant?
                # It is deliberately independent of whether the schedule is
                # enabled and of whether the slot is already spent, because both of
                # those are reported in their own fields. A row that folded them
                # together would say ``due: false`` for a schedule that is due,
                # which is the opposite of informative.
                "due": fire.fired,
                "slot_start": slot.isoformat() if slot else "",
                "nominal_at": fire.nominal_at.isoformat() if fire.nominal_at else "",
                "effective_at": fire.effective_at.isoformat() if fire.effective_at else "",
                "jittered": fire.jittered,
                "jitter_s": entry.schedule.jitter.max_offset_seconds
                if entry.schedule.jitter
                else 0.0,
                # ``lateness_s`` is the *poller's* lateness and nothing else --
                # the jitter offset is reported in its own two fields above, so a
                # declared +/-60s spread can never be misread as a poller that
                # was a minute late. ``missed_window`` is the boolean that says
                # the slot had already closed: a recurrence that was skipped is
                # reported as skipped, never as a fire that happened to be slow.
                "lateness_s": fire.lateness_s,
                "resolution_s": fire.resolution_s,
                "missed_window": fire.missed_window,
                "blocked_by": list(fire.blocked_by),
                "enabled": entry.enabled,
                "game_day_holds": list(held),
            }
        )
    return {
        "schema_version": SCHEDULE_TICK_SCHEMA_VERSION,
        "now": now.isoformat(),
        "window_index": window_index,
        "dispatches_performed": 0,
        "schedules": rows,
        "not_evaluated_here": list(NOT_EVALUATED_HERE),
        "notice": (
            "A due slot is not an admitted slot. The safety gate, the approval gate, and "
            "the concurrency model are evaluated by the controller at dispatch time, in "
            "the same order an authored drill faces them; this command reports only the "
            "gates it can evaluate locally."
        ),
    }
