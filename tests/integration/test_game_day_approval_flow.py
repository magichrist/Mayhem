"""Game-day approval flow end to end (v0.9.0 expansion task 17)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from click.testing import CliRunner

from mayhem.domain.game_day import SessionState

WINDOW_START = datetime.now(UTC) - timedelta(hours=1)
WINDOW_END = datetime.now(UTC) + timedelta(hours=1)


def _ctx(db):
    from mayhem.cli.context import CliContext

    return CliContext(db=str(db))


def _create(db, **overrides) -> str:
    from mayhem.cli.game_day import create

    args = [
        "--name",
        overrides.get("name", "quarterly game day"),
        "--id",
        overrides.get("id", "gd-test"),
        "--starts-at",
        WINDOW_START.isoformat(),
        "--ends-at",
        WINDOW_END.isoformat(),
    ]
    for fault in overrides.get("critical_faults", ()):
        args += ["--critical-fault", fault]
    if "approvers" in overrides:
        args += ["--approvers", str(overrides["approvers"])]
    result = CliRunner().invoke(create, args, obj=_ctx(db))
    assert result.exit_code == 0, result.output
    return "gd-test"


def test_approval_flow_from_plan_to_completion(tmp_path) -> None:
    from mayhem.cli.game_day import (
        approve,
        list_sessions,
        show,
        start_cmd,
    )
    from mayhem.cli.game_day import (
        complete_cmd as complete,
    )
    from mayhem.infra.game_day_repository import GameDayRepository
    from mayhem.infra.store import Store

    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    session_id = _create(db)
    assert session_id == "gd-test"

    # A session cannot start without approval.
    refused = runner.invoke(start_cmd, [session_id, "--execute"], obj=_ctx(db))
    assert refused.exit_code == 1
    assert "needs 1 approval" in refused.output

    approved = runner.invoke(
        approve, [session_id, "--actor", "sre@example", "--reason", "window agreed"], obj=_ctx(db)
    )
    assert approved.exit_code == 0, approved.output

    started = runner.invoke(start_cmd, [session_id, "--execute", "--json"], obj=_ctx(db))
    assert started.exit_code == 0, started.output
    assert json.loads(started.output)["state"] == "running"

    store = Store.open_migrated(db)
    try:
        assert GameDayRepository(store).load(session_id).state is SessionState.RUNNING
    finally:
        store.close()

    finished = runner.invoke(
        complete, [session_id, "--evidence-bundle", "bundle-abc", "--json"], obj=_ctx(db)
    )
    assert finished.exit_code == 0, finished.output
    assert json.loads(finished.output)["evidence_bundle"] == "bundle-abc"

    listed = runner.invoke(list_sessions, ["--json"], obj=_ctx(db))
    assert json.loads(listed.output)[0]["state"] == "completed"

    shown = runner.invoke(show, [session_id], obj=_ctx(db))
    assert "evidence bundle: bundle-abc" in shown.output


def test_start_without_execute_is_a_plan_only_preview(tmp_path) -> None:
    from mayhem.cli.game_day import approve, start_cmd
    from mayhem.infra.game_day_repository import GameDayRepository
    from mayhem.infra.store import Store

    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    _create(db)
    runner.invoke(approve, ["gd-test", "--actor", "sre@example"], obj=_ctx(db))

    preview = runner.invoke(start_cmd, ["gd-test"], obj=_ctx(db))
    assert "plan only" in preview.output
    assert "--execute" in preview.output

    store = Store.open_migrated(db)
    try:
        # The preview must not have moved the session.
        assert GameDayRepository(store).load("gd-test").state is SessionState.PLANNED
    finally:
        store.close()


def test_dual_control_blocks_a_single_approver(tmp_path) -> None:
    from mayhem.cli.game_day import approve, start_cmd
    from mayhem.infra.store import Store

    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    _create(db, critical_faults=("fs.disk_fill",))
    runner.invoke(approve, ["gd-test", "--actor", "sre@example"], obj=_ctx(db))

    refused = runner.invoke(start_cmd, ["gd-test", "--execute"], obj=_ctx(db))
    assert refused.exit_code == 1
    assert "dual control" in refused.output

    runner.invoke(approve, ["gd-test", "--actor", "em@example"], obj=_ctx(db))
    started = runner.invoke(start_cmd, ["gd-test", "--execute"], obj=_ctx(db))
    assert started.exit_code == 0, started.output


def test_expired_freeze_window_refuses_at_the_cli(tmp_path) -> None:
    from mayhem.cli.game_day import approve, create, start_cmd
    from mayhem.infra.store import Store

    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    past = datetime.now(UTC) - timedelta(days=2)
    created = runner.invoke(
        create,
        [
            "--id",
            "gd-old",
            "--starts-at",
            (past - timedelta(hours=1)).isoformat(),
            "--ends-at",
            past.isoformat(),
        ],
        obj=_ctx(db),
    )
    assert created.exit_code == 0, created.output
    runner.invoke(approve, ["gd-old", "--actor", "sre@example"], obj=_ctx(db))
    refused = runner.invoke(start_cmd, ["gd-old", "--execute"], obj=_ctx(db))
    assert refused.exit_code == 1
    assert "outside its freeze window" in refused.output


def test_pause_and_resume_flow(tmp_path) -> None:
    from mayhem.cli.game_day import approve, pause_cmd, start_cmd
    from mayhem.infra.game_day_repository import GameDayRepository
    from mayhem.infra.store import Store

    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    _create(db)
    runner.invoke(approve, ["gd-test", "--actor", "sre@example"], obj=_ctx(db))
    runner.invoke(start_cmd, ["gd-test", "--execute"], obj=_ctx(db))

    paused = runner.invoke(
        pause_cmd, ["gd-test", "--operator", "operator@example", "--json"], obj=_ctx(db)
    )
    assert paused.exit_code == 0, paused.output
    assert json.loads(paused.output)["state"] == "paused"

    store = Store.open_migrated(db)
    try:
        assert GameDayRepository(store).load("gd-test").state is SessionState.PAUSED
    finally:
        store.close()

    # A paused session resumes, but still behind the explicit flag.
    preview = runner.invoke(start_cmd, ["gd-test"], obj=_ctx(db))
    assert "plan only" in preview.output
    resumed = runner.invoke(start_cmd, ["gd-test", "--execute"], obj=_ctx(db))
    assert resumed.exit_code == 0, resumed.output

    store = Store.open_migrated(db)
    try:
        assert GameDayRepository(store).load("gd-test").state is SessionState.RUNNING
    finally:
        store.close()


def test_unknown_session_is_reported(tmp_path) -> None:
    from mayhem.cli.game_day import show, start_cmd
    from mayhem.infra.store import Store

    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    assert runner.invoke(show, ["nope"], obj=_ctx(db)).exit_code == 1
    assert runner.invoke(start_cmd, ["nope", "--execute"], obj=_ctx(db)).exit_code == 1


def test_session_start_never_builds_an_engine(tmp_path, monkeypatch) -> None:
    from mayhem.cli.game_day import approve, start_cmd
    from mayhem.infra.store import Store

    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("game-day start must not build an execution engine")

    monkeypatch.setattr("mayhem.controller.executor.RunEngine", explode)
    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    _create(db)
    runner.invoke(approve, ["gd-test", "--actor", "sre@example"], obj=_ctx(db))
    assert runner.invoke(start_cmd, ["gd-test", "--execute"], obj=_ctx(db)).exit_code == 0
