"""``mayhem game-day-step`` — the facilitator's verbs on a scheduled dispatch.

Plan 13 Phase 3, game-day half. The existing ``mayhem game-day`` group
(:mod:`mayhem.cli.game_day`) owns a *session*: create it, approve it, start it,
pause it, complete it. It has no verb for the thing a game day actually does,
which is put a scheduled drill into the session and decide when it may run — and
that is exactly what the scheduler reads at fire time.

Four commands, and the shape of them is the argument:

``inject``
    Bind a registered schedule to a session step. The step is created **held**,
    and stays held until a facilitator releases it. There is no flag that stages
    a step already released, because a hold that exists only to be immediately
    bypassed is not a hold, and a drill that "was going to run anyway" is a drill
    nobody approved.
``steps``
    Read the session's steps and their hold states.
``hold``
    Re-hold a released step, naming the facilitator and the reason. A game day
    that changed its mind needs to say so, and the store records the re-hold
    rather than deleting the release.
``release``
    Release a held step, naming the facilitator and the reason. Delegates to
    :func:`mayhem.controller.scheduler.release_hold`, which refuses a blank
    actor, a blank reason, and a step that is not currently held.
``note``
    Record a game-day artifact — a decision, a note, or a graded finding — through
    :mod:`mayhem.controller.game_day_evidence`. The word is ``note`` because that
    is the common case; ``--kind decision`` and ``--kind finding`` reach the other
    two, and ``--severity`` is required for a finding and refused for anything
    else, by the artifact model rather than by this surface.

**Nothing here dispatches, and that is the load-bearing property.** There is no
``--execute``, no ``--force``, no ``--skip-hold``: releasing a hold changes a
*gate*, and the scheduler reads that gate at fire time. A surface that could
dispatch would be a second dispatch path, and the second dispatch path is how a
scheduled run ends up skipping admission.

Time is injected. ``--now`` sets the instant a decision is recorded against;
without it the host clock is read once, stamped, and reported in the payload, so
a reader can reproduce the invocation rather than re-derive it.

Invocations that resolve against this group::

    mayhem game-day-step --help
    mayhem game-day-step inject gd-1 --step-id net-latency \\
        --scenario regional-outage@1.0.0 --schedule-id nightly \\
        --hold-reason "wait for the bridge"
    mayhem game-day-step steps gd-1
    mayhem game-day-step release gd-1 net-latency --facilitator sre@example \\
        --reason "comms bridge open"
    mayhem game-day-step hold gd-1 net-latency --facilitator sre@example \\
        --reason "participant pushed back"
    mayhem game-day-step note gd-1 --kind finding --severity high \\
        --actor sre@example --text "runbook step 4 does not exist"

.. warning::

   **This group is not registered.** ``cli/app.py`` and
   ``cli/command_registry.py`` belong to other lanes, so the group is exported
   and exercised directly through ``CliRunner``. The integration pass has to add
   the row before ``mayhem game-day-step --help`` resolves from the root command;
   the same applies to :mod:`mayhem.cli.schedule_cmd`, which this plan's Phase 3
   also lands. See the Phase 3 entry in
   ``docs/v1.1.0/13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md``.

What this surface deliberately does **not** claim:

* It performs no signature verification and contacts no cluster. Every value it
  prints comes from the local SQLite registry.
* It does not promise that a released step *will* run. The hold is one gate among
  several: the scheduler still reads policy windows, blackouts, deployment and
  incident state, the concurrency model, the safety gate, and the approval gate at
  fire time. What releasing changes is one of those, and only one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, NoReturn

import click

from mayhem.cli import style
from mayhem.cli.context import DEFAULT_DB
from mayhem.cli.resolver import make_group
from mayhem.controller.game_day_evidence import (
    ArtifactKind,
    GameDayArtifact,
    Severity,
    default_artifact_id,
    record_artifact,
)
from mayhem.controller.scheduler import release_hold
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.game_day import OperatorAcknowledgement
from mayhem.domain.scenarios import SCENARIO_TEMPLATES
from mayhem.infra.game_day_repository import GameDayRepository
from mayhem.infra.schedule_store import GameDayStepRecord, HoldState, ScheduleStore
from mayhem.infra.store import Store

__all__ = [
    "MONITORED_INVOCATIONS",
    "game_day_step",
    "parse_instant",
    "resolve_scenario",
]

#: The invocations this module's own suite resolves against the live Click tree.
#: Every spelling a document may use, kept here so the surface and the docs are
#: checked against the same list.
MONITORED_INVOCATIONS: tuple[tuple[str, ...], ...] = (
    ("game-day-step", "--help"),
    ("game-day-step", "inject", "--help"),
    ("game-day-step", "steps", "--help"),
    ("game-day-step", "hold", "--help"),
    ("game-day-step", "release", "--help"),
    ("game-day-step", "note", "--help"),
)

game_day_step = make_group(
    "game-day-step",
    "Stage, hold, release, and annotate scheduled dispatches inside a game day.",
)


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
    loop.
    """
    return parse_instant(value) if value else datetime.now(UTC)


def parse_instant(text: str) -> datetime:
    """Parse an ISO-8601 instant, refusing a naive one.

    Refusing naive input is the same discipline
    :func:`mayhem.domain.scheduling._as_utc` applies: an acknowledgement stamped
    "10:00" without a zone cannot be ordered against the incident or the hold it
    authorises, and a store that accepted one would hold two records that disagree
    about when the same decision was made.

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
            f"{text!r} has no timezone offset; every recorded instant must be aware "
            "(e.g. 2026-06-01T09:00:00+00:00)"
        )
    return parsed


def _refuse(message: str) -> NoReturn:
    """Turn a domain refusal into a usage error with the domain's own words."""
    raise click.UsageError(message)


def _load_session(store: Store, session_id: str) -> Any:
    """Load a session or exit, so every command reads the same way."""
    session = GameDayRepository(store).load(session_id)
    if session is None:
        click.echo(f"unknown game-day session: {session_id}", err=True)
        raise SystemExit(1)
    return session


def resolve_scenario(reference: str) -> str:
    """Resolve a ``id@version`` scenario reference against plan 21's library.

    Returns the canonical reference, or the empty string for an empty input.
    Resolution rather than a free string: a step staged against a scenario
    nobody wrote down is an inject outside its scenario, and the after-action
    report would cite a claim that does not exist. Requiring the version is the
    same discipline :class:`~mayhem.domain.scenarios.ScenarioTemplate` documents
    for itself -- a revised scenario keeps its history instead of silently
    changing what a citation means.

    Raises:
        click.UsageError: If the reference is malformed or names no template.
    """
    if not reference.strip():
        return ""
    template_id, sep, version = reference.strip().partition("@")
    if not sep or not template_id or not version:
        _refuse(
            f"scenario {reference!r} is not 'id@version', e.g. "
            f"{SCENARIO_TEMPLATES[0].template_id}@{SCENARIO_TEMPLATES[0].version}"
        )
    match = next(
        (
            template
            for template in SCENARIO_TEMPLATES
            if template.template_id == template_id and template.version == version
        ),
        None,
    )
    if match is None:
        known = ", ".join(template.ref for template in SCENARIO_TEMPLATES[:3])
        _refuse(
            f"unknown scenario {reference!r}; mayhem ships {known} and "
            f"{len(SCENARIO_TEMPLATES) - 3} more in domain.scenarios.SCENARIO_TEMPLATES"
        )
    return match.ref


def _step_payload(step: GameDayStepRecord) -> dict[str, Any]:
    """The JSON-able view of one dispatch step."""
    return {
        "session_id": step.session_id,
        "step_id": step.step_id,
        "step_seq": step.step_seq,
        "scenario": step.scenario,
        "schedule_id": step.schedule_id,
        "hold_state": step.hold_state.value,
        "hold_reason": step.hold_reason,
        "released_by": step.released_by,
        "released_at": step.released_at,
        "dispatched_at": step.dispatched_at,
        "note": step.note,
    }


@game_day_step.command("inject")
@click.argument("session_id")
@click.option("--step-id", required=True, help="Step id within this session.")
@click.option("--schedule-id", required=True, help="Registered schedule this step dispatches.")
@click.option(
    "--scenario",
    default="",
    help=(
        "Plan 21 scenario this step belongs to, as 'id@version'. Must resolve "
        "against mayhem.domain.scenarios.SCENARIO_TEMPLATES when given."
    ),
)
@click.option(
    "--seq", "step_seq", type=int, default=0, show_default=True, help="Order within the session."
)
@click.option(
    "--hold-reason",
    default="",
    help="Why the facilitator hold is in force. Recorded verbatim on the step.",
)
@click.option("--now", default=None, help="Instant to stamp (defaults to the host clock).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def inject(
    session_id: str,
    step_id: str,
    schedule_id: str,
    scenario: str,
    step_seq: int,
    hold_reason: str,
    now: str | None,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Stage a scheduled dispatch as a **held** game-day step.

    Held on creation, with no flag to stage it released: the hold is the gate the
    scheduler reads at fire time, and a hold that exists only to be immediately
    bypassed is not one. Releasing it is :command:`release`, and it names the
    facilitator who did it.

    Two references must resolve, or nothing is written:

    * the ``--schedule-id`` must name a registered schedule, because a step bound
      to no schedule would hold a fire that can never happen and still read as a
      facilitator gate that was honoured;
    * the ``--scenario`` must resolve against plan 21's
      :data:`~mayhem.domain.scenarios.SCENARIO_TEMPLATES`, in the library's own
      ``id@version`` spelling. A step staged against a scenario nobody wrote down
      is an inject outside its scenario, and the after-action report would then
      cite a claim that does not exist.

    An empty ``--scenario`` is allowed and recorded as empty: a step may exercise
    one drill without being narrated as part of a whole-failure scenario, and
    requiring a scenario would be inventing a requirement the plan did not state.
    """
    instant = _now_arg(now).isoformat()
    # Resolved *before* the store is opened, so an unresolvable scenario costs no
    # database work and leaves no half-written step behind.
    scenario_ref = resolve_scenario(scenario)
    store = _open_store(db_opt)
    try:
        _load_session(store, session_id)
        repo = ScheduleStore(store)
        if repo.load_schedule(schedule_id) is None:
            _refuse(
                f"unknown schedule: {schedule_id!r}; register it with "
                "`mayhem schedule add` before injecting it into a game day"
            )
        if repo.load_step(session_id, step_id) is not None:
            _refuse(
                f"game-day step {step_id!r} already exists in session {session_id!r}; a "
                "second inject would stage the same dispatch twice"
            )
        step = repo.save_step(
            GameDayStepRecord(
                session_id=session_id,
                step_id=step_id,
                step_seq=step_seq,
                scenario=scenario_ref,
                schedule_id=schedule_id,
                hold_state=HoldState.HELD,
                hold_reason=hold_reason,
                created_at=instant,
                updated_at=instant,
            )
        )
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    payload = {"staged": True, **_step_payload(step)}
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(
        f"step {style.cyan(step.step_id)} staged in {session_id} -> {schedule_id}, "
        f"{style.state('held')}"
    )
    click.echo("  the scheduler will refuse this schedule's fire until the hold is released")


@game_day_step.command("steps")
@click.argument("session_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def steps(session_id: str, db_opt: str | None, as_json: bool) -> None:
    """List a session's dispatch steps and their hold states, seq-ordered."""
    store = _open_store(db_opt)
    try:
        _load_session(store, session_id)
        rows = ScheduleStore(store).steps_for_session(session_id)
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    if echo_machine(
        {"session_id": session_id, "steps": [_step_payload(r) for r in rows]}, as_json=as_json
    ):
        return
    if not rows:
        click.echo(f"no dispatch steps staged for {session_id}")
        return
    for row in rows:
        holder = row.released_by or "-"
        click.echo(f"  {row.step_id:<20} {row.schedule_id:<20} {row.hold_state.value:<11} {holder}")


@game_day_step.command("release")
@click.argument("session_id")
@click.argument("step_id")
@click.option("--facilitator", required=True, help="Who is releasing the hold.")
@click.option("--reason", required=True, help="Why the drill may now run.")
@click.option("--role", default="facilitator", show_default=True, help="Their role.")
@click.option("--now", default=None, help="Instant to stamp (defaults to the host clock).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def release(
    session_id: str,
    step_id: str,
    facilitator: str,
    reason: str,
    role: str,
    now: str | None,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Release a held dispatch step. Names the facilitator and the reason.

    Delegates to :func:`mayhem.controller.scheduler.release_hold`, so the
    refusals live in one place: a step that is not held, a blank facilitator, and
    a blank reason are all refused there and are not re-implemented here.
    """
    instant = _now_arg(now).isoformat()
    store = _open_store(db_opt)
    try:
        repo = ScheduleStore(store)
        step = repo.load_step(session_id, step_id)
        if step is None:
            click.echo(f"unknown game-day step: {session_id}:{step_id}", err=True)
            raise SystemExit(1)
        try:
            released = release_hold(
                step,
                OperatorAcknowledgement(actor=facilitator, role=role, reason=reason, at=instant),
                at=instant,
            )
        except InvariantViolationError as exc:
            click.echo(f"refused: {exc}", err=True)
            raise SystemExit(1) from exc
        stored = repo.save_step(released)
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    payload = {"released": True, **_step_payload(stored)}
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(
        f"step {style.cyan(step_id)} released by {stored.released_by}; "
        f"schedule {stored.schedule_id} may now fire when its own gates allow"
    )


@game_day_step.command("hold")
@click.argument("session_id")
@click.argument("step_id")
@click.option("--facilitator", required=True, help="Who is re-holding the step.")
@click.option("--reason", required=True, help="Why the hold is back in force.")
@click.option("--now", default=None, help="Instant to stamp (defaults to the host clock).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def hold(
    session_id: str,
    step_id: str,
    facilitator: str,
    reason: str,
    now: str | None,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Re-hold a released step. A game day that changed its mind says so.

    The release is **not** erased: :attr:`GameDayStepRecord.released_by` and
    ``released_at`` are left in place while ``hold_state`` goes back to ``held``,
    so a reader can see that the step was released once and then re-held. A
    record that quietly forgot the release would make the re-hold look like the
    step had never been let go at all.
    """
    instant = _now_arg(now).isoformat()
    store = _open_store(db_opt)
    try:
        repo = ScheduleStore(store)
        step = repo.load_step(session_id, step_id)
        if step is None:
            click.echo(f"unknown game-day step: {session_id}:{step_id}", err=True)
            raise SystemExit(1)
        if step.hold_state is HoldState.DISPATCHED:
            _refuse(
                f"step {step_id!r} has already dispatched; a step that ran cannot be "
                "re-held, because the hold it would impose is in the past"
            )
        held = step.model_copy(
            update={"hold_state": HoldState.HELD, "hold_reason": reason, "updated_at": instant}
        )
        stored = repo.save_step(held)
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    payload = {"held": True, **_step_payload(stored)}
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(
        f"step {style.cyan(step_id)} re-held by {facilitator}: "
        f"schedule {stored.schedule_id} will refuse to fire"
    )


@game_day_step.command("note")
@click.argument("session_id")
@click.option(
    "--kind",
    type=click.Choice([kind.value for kind in ArtifactKind]),
    default=ArtifactKind.NOTE.value,
    show_default=True,
    help="Decision, note, or graded finding.",
)
@click.option("--actor", required=True, help="Who is recording this.")
@click.option("--text", required=True, help="What they are recording.")
@click.option(
    "--severity",
    type=click.Choice([severity.value for severity in Severity]),
    default=None,
    help="Required for --kind finding; refused for the other two.",
)
@click.option("--step-id", default="", help="Dispatch step this artifact is about.")
@click.option("--run-id", default="", help="Run a --kind decision let go.")
@click.option("--now", default=None, help="Instant to stamp (defaults to the host clock).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def note(
    session_id: str,
    kind: str,
    actor: str,
    text: str,
    severity: str | None,
    step_id: str,
    run_id: str,
    now: str | None,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Record a game-day artifact: a decision, a note, or a graded finding.

    Records only. Nothing here approves, dispatches, or changes a hold — an
    artifact that could authorise an action would be a second approval model, and
    this codebase has exactly one.

    The kind-specific rules are the artifact model's, not this surface's: a
    finding without ``--severity`` is refused, and ``--severity`` on a note or a
    decision is refused rather than dropped, so a graded note cannot become an
    ungraded one after the fact.
    """
    instant = _now_arg(now).isoformat()
    store = _open_store(db_opt)
    try:
        _load_session(store, session_id)
        kind_value = ArtifactKind(kind)
        try:
            artifact = record_artifact(
                store,
                GameDayArtifact(
                    artifact_id=default_artifact_id(session_id, kind_value, actor, at=instant),
                    session_id=session_id,
                    kind=kind_value,
                    actor=actor,
                    text=text,
                    at=instant,
                    step_id=step_id,
                    severity=Severity(severity) if severity is not None else None,
                    run_id=run_id,
                ),
            )
        except InvariantViolationError as exc:
            click.echo(f"refused: {exc}", err=True)
            raise SystemExit(1) from exc
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    if echo_machine({"recorded": True, **artifact.to_payload()}, as_json=as_json):
        return
    click.echo(f"recorded {artifact.describe()}")
    click.echo(f"  digest {artifact.digest[:16]}")
