"""``mayhem game-day``: plan-only sessions with explicit human approval.

Every command here is plan-only or state-recording. Starting a session requires
the same explicit approval the rest of Mayhem uses (``--execute`` plus a named
approver), and a critical fault demands dual control.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import click

from mayhem.cli.context import CliContext
from mayhem.cli.resolver import make_group
from mayhem.domain.game_day import (
    ApprovalGate,
    FreezeWindow,
    GameDayError,
    GameDaySession,
    OperatorAcknowledgement,
    SessionState,
    start as start_session,
)
from mayhem.infra.game_day_repository import GameDayRepository
from mayhem.infra.store import Store

game_day = make_group("game-day", "Plan and run controlled game-day sessions.")


def _open_store(db_opt: str | None) -> Store:
    ctx = click.get_current_context()
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return Store.open_migrated(db_opt or obj.db)


@game_day.command("create")
@click.option("--name", default="", help="Human-readable session name.")
@click.option("--id", "session_id", default=None, help="Session id (generated when omitted).")
@click.option("--plan-id", default="", help="Plan this session will execute.")
@click.option("--campaign-id", default="", help="Campaign this session belongs to.")
@click.option("--starts-at", default="", help="Freeze window start (ISO-8601).")
@click.option("--ends-at", default="", help="Freeze window end (ISO-8601).")
@click.option(
    "--critical-fault",
    "critical_faults",
    multiple=True,
    help="Critical fault in scope (repeatable; two or more enables dual control).",
)
@click.option(
    "--approvers",
    default=1,
    show_default=True,
    help="How many distinct approvers are required.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def create(
    name: str,
    session_id: str | None,
    plan_id: str,
    campaign_id: str,
    starts_at: str,
    ends_at: str,
    critical_faults: tuple[str, ...],
    approvers: int,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Create a game-day session. Plan-only: nothing is executed."""
    window = None
    if bool(starts_at) != bool(ends_at):
        raise click.UsageError("--starts-at and --ends-at must be given together")
    if starts_at:
        window = FreezeWindow(starts_at=starts_at, ends_at=ends_at)
    stamp = datetime.now(UTC).isoformat()
    session = GameDaySession(
        id=session_id or f"gd-{uuid.uuid4().hex[:8]}",
        name=name,
        state=SessionState.PLANNED,
        window=window,
        gate=ApprovalGate(
            required_approvers=max(1, approvers),
            critical_faults=critical_faults,
            dual_control_for_critical=bool(critical_faults),
        ),
        plan_id=plan_id,
        campaign_id=campaign_id,
        critical_faults=critical_faults,
        created_at=stamp,
        updated_at=stamp,
    )
    store = _open_store(db_opt)
    try:
        stored = GameDayRepository(store).save(session)
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(stored.to_dict(), indent=2, sort_keys=True))
        return
    click.echo(f"game day {stored.id} planned (state {stored.state.value})")
    if stored.window:
        click.echo(f"  window: {stored.window.starts_at} → {stored.window.ends_at}")
    click.echo(f"  approvers required: {stored.gate.required_approvers}")


@game_day.command("approve")
@click.argument("session_id")
@click.option("--actor", required=True, help="Who is approving.")
@click.option("--role", default="approver", show_default=True, help="Their role.")
@click.option("--reason", default="", help="Why they are approving.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def approve(
    session_id: str, actor: str, role: str, reason: str, db_opt: str | None, as_json: bool
) -> None:
    """Record one named approval for a session."""
    store = _open_store(db_opt)
    try:
        repo = GameDayRepository(store)
        session = repo.load(session_id)
        if session is None:
            click.echo(f"unknown game-day session: {session_id}", err=True)
            raise SystemExit(1)
        stored = repo.save(
            session.with_approval(
                OperatorAcknowledgement(actor=actor, role=role, reason=reason)
            )
        )
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(stored.to_dict(), indent=2, sort_keys=True))
        return
    click.echo(
        f"approval recorded for {stored.id}: {len(set(stored.gate.approved_by))} distinct approver(s)"
    )


@game_day.command("show")
@click.argument("session_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def show(session_id: str, db_opt: str | None, as_json: bool) -> None:
    """Show one session."""
    store = _open_store(db_opt)
    try:
        session = GameDayRepository(store).load(session_id)
    finally:
        store.close()
    if session is None:
        click.echo(f"unknown game-day session: {session_id}", err=True)
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(session.to_dict(), indent=2, sort_keys=True))
        return
    click.echo(f"game day {session.id}: {session.state.value}")
    if session.window:
        click.echo(f"  window: {session.window.starts_at} → {session.window.ends_at}")
    click.echo(f"  approvers: {', '.join(session.gate.approved_by) or 'none'}")
    if session.critical_faults:
        click.echo(f"  critical faults: {', '.join(session.critical_faults)}")
    if session.evidence_bundle:
        click.echo(f"  evidence bundle: {session.evidence_bundle}")


@game_day.command("list")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def list_sessions(db_opt: str | None, as_json: bool) -> None:
    """List game-day sessions."""
    store = _open_store(db_opt)
    try:
        sessions = GameDayRepository(store).list_sessions()
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps([s.to_dict() for s in sessions], indent=2, sort_keys=True))
        return
    if not sessions:
        click.echo("no game-day sessions")
        return
    for session in sessions:
        click.echo(f"{session.id:<16} {session.state.value:<18} {session.name}")


@game_day.command("start")
@click.argument("session_id")
@click.option(
    "--execute",
    is_flag=True,
    help="Explicit approval to move the session into the running state.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def start_cmd(ctx: click.Context, session_id: str, execute: bool, db_opt: str | None, as_json: bool) -> None:
    """Start a session. Without ``--execute`` this is a plan-only preview."""
    from mayhem.cli.app import implicit_execution_allowed
    from mayhem.domain.execution_intent import require_explicit_approval

    store = _open_store(db_opt)
    try:
        repo = GameDayRepository(store)
        session = repo.load(session_id)
        if session is None:
            click.echo(f"unknown game-day session: {session_id}", err=True)
            raise SystemExit(1)
        dry_run = bool(getattr(ctx.obj, "dry_run", False))
        if not (execute or dry_run):
            # Plan-only preview: report what starting would do and stop. No
            # approval is needed because nothing is mutated on this path.
            try:
                planned = start_session(session)
            except GameDayError as exc:
                click.echo(f"cannot start: {exc}", err=True)
                raise SystemExit(1) from exc
            if as_json:
                click.echo(
                    json.dumps(
                        {
                            "started": False,
                            "reason": "pass --execute to start",
                            "plan": planned.to_dict(),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                click.echo(
                    f"plan only: session {session_id} would start "
                    f"(approvers: {', '.join(session.gate.approved_by) or 'none'}); "
                    "pass --execute to start"
                )
            return
        # Structural: the approval gate sits after the preview return and
        # before the state change, so no reachable mutation happens without it.
        require_explicit_approval(
            "game-day start", approved=execute, allow_implicit=implicit_execution_allowed()
        )
        try:
            updated = start_session(session)
        except GameDayError as exc:
            if as_json:
                click.echo(json.dumps({"started": False, "reason": str(exc)}, indent=2))
            else:
                click.echo(f"refused: {exc}", err=True)
            raise SystemExit(1) from exc
        stored = repo.save(updated)
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps({"started": True, **stored.to_dict()}, indent=2, sort_keys=True))
        return
    click.echo(f"game day {stored.id} running")


@game_day.command("pause")
@click.argument("session_id")
@click.option("--operator", required=True, help="Who is pausing the session.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def pause_cmd(
    session_id: str, operator: str, db_opt: str | None, as_json: bool
) -> None:
    """Pause a running session."""
    from mayhem.domain.game_day import pause as pause_session

    store = _open_store(db_opt)
    try:
        repo = GameDayRepository(store)
        session = repo.load(session_id)
        if session is None:
            click.echo(f"unknown game-day session: {session_id}", err=True)
            raise SystemExit(1)
        try:
            stored = repo.save(
                pause_session(
                    session, OperatorAcknowledgement(actor=operator, role="operator")
                )
            )
        except GameDayError as exc:
            click.echo(f"refused: {exc}", err=True)
            raise SystemExit(1) from exc
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(stored.to_dict(), indent=2, sort_keys=True))
        return
    click.echo(f"game day {stored.id} paused by {operator}")


@game_day.command("complete")
@click.argument("session_id")
@click.option(
    "--evidence-bundle",
    required=True,
    help="Path or digest of the session's final evidence bundle.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def complete_cmd(
    session_id: str, evidence_bundle: str, db_opt: str | None, as_json: bool
) -> None:
    """Complete a session with its final evidence bundle."""
    from mayhem.domain.game_day import complete as complete_session

    store = _open_store(db_opt)
    try:
        repo = GameDayRepository(store)
        session = repo.load(session_id)
        if session is None:
            click.echo(f"unknown game-day session: {session_id}", err=True)
            raise SystemExit(1)
        try:
            stored = repo.save(complete_session(session, evidence_bundle))
        except GameDayError as exc:
            click.echo(f"refused: {exc}", err=True)
            raise SystemExit(1) from exc
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(stored.to_dict(), indent=2, sort_keys=True))
        return
    click.echo(f"game day {stored.id} completed; evidence bundle {stored.evidence_bundle}")
