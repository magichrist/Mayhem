"""CLI enforcement of the execution-intent contract (v0.9.0).

Three properties are pinned here:

* every mutating command refuses without an explicit intent,
* a preview never creates a lease (or even a run row), and
* a global ``--dry-run`` never authorizes a mutation — not even when
  ``--execute`` is also passed.

This module is *not* marked ``implicit_execution``: every test here either
asserts a refusal (deleting the switch first, so the v0.9.0 default is what is
under test) or names the switch explicitly.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from mayhem.cli.app import implicit_execution_allowed, main
from mayhem.cli.errors import error_to_exit_code, map_exception_to_error
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.execution_intent import (
    APPROVAL_EXPIRED,
    IMPLICIT_EXECUTION_ENV,
    INTENT_MISMATCH,
    INTENT_REQUIRED,
    ExecutionIntentRefused,
)
from mayhem.domain.experiments import ExecutionPlan
from mayhem.domain.preflight import plan_hash_for
from mayhem.infra.store import Store

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"


def _minimal_plan() -> ExecutionPlan:
    from mayhem.domain.experiments import ExperimentKind, PlannedStep, Wait

    return ExecutionPlan(
        run_id="r-intent-pipe",
        kind=ExperimentKind.DRILL,
        steps=(PlannedStep(id="s1", seq=1, raw_action=Wait(timeout=1.0)),),
        config_snapshot_id="c1",
        topology_snapshot_id="t1",
        environment_fingerprint="fp-1",
    )


_MINIMAL_PLAN = _minimal_plan()

SPEC = """\
kind: drill
name: pause-drill
config:
  risk_ceiling: critical
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
execution:
  - parallel: [testcase-api]
"""


def _spec(tmp_path: Path) -> Path:
    path = tmp_path / "spec.yaml"
    path.write_text(SPEC)
    return path


def _module_source(name: str) -> str:
    import importlib
    import inspect

    return inspect.getsource(importlib.import_module(name))


def _cli_imports(name: str) -> set[str]:
    """Every ``mayhem.cli.*`` module ``name`` imports, at any level."""
    import ast

    modules: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(name))):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return {module for module in modules if module.startswith("mayhem.cli")}


def _env_reads(name: str) -> set[str]:
    """Attribute accesses on ``os.environ`` / ``os.getenv`` inside ``name``."""
    import ast

    reads: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(name))):
        if not isinstance(node, ast.Attribute) or node.attr not in {"environ", "getenv"}:
            continue
        base = node.value
        if isinstance(base, ast.Name) and base.id == "os":
            reads.add(f"os.{node.attr}")
        elif isinstance(base, ast.Attribute) and base.attr == "os":
            reads.add(f"os.{node.attr}")
    return reads


def _no_implicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(IMPLICIT_EXECUTION_ENV, raising=False)


def _counts(db: Path) -> tuple[int, int]:
    """(runs, fault_leases) rows in the store — 0/0 means nothing happened."""
    store = Store.open_migrated(db)
    try:
        runs = store.query("SELECT id FROM runs")
        leases = store.query("SELECT id FROM fault_leases")
        return len(runs), len(leases)
    finally:
        store.close()


def _stub_engine() -> MagicMock:
    """A RunEngine stand-in that records the plan it was asked to execute."""
    engine = MagicMock()
    result = engine.execute.return_value
    result.status = "completed"
    result.summary_md.return_value = "run completed"
    result.dirty_leases = ()
    return engine


def _seed_stored_plan(db: Path, plan: ExecutionPlan) -> str:
    """Insert a completed run row so ``--plan-id`` can find its plan."""
    store = Store.open_migrated(db)
    try:
        with store.write() as conn:
            conn.execute(
                "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at)"
                " VALUES (?, '{}', '{}', 'now')",
                (f"c-{plan.run_id}",),
            )
            conn.execute(
                "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
                " status, environment_fingerprint, config_snapshot_id)"
                " VALUES (?, 'exp', 'deterministic', '{}', ?, 1, 'completed', 'env', ?)",
                (plan.run_id, plan.model_dump_json(), f"c-{plan.run_id}"),
            )
    finally:
        store.close()
    return plan.run_id


def _compiled_plan(tmp_path: Path, db: Path) -> ExecutionPlan:
    """Compile a real plan by running once against a stubbed engine."""
    engine = _stub_engine()
    with patch("mayhem.cli.services.RunEngine", return_value=engine):
        main(
            [
                "--db",
                str(db),
                "--skip-gate",
                "run",
                str(_spec(tmp_path)),
                "-c",
                str(COMPOSE_FILE),
                "--execute",
            ]
        )
    return engine.execute.call_args.args[0]


def _make_campaign(db: Path, spec: Path) -> str:
    """Create a draft campaign holding one experiment; return its id."""
    assert main(["--db", str(db), "campaign", "create", "dry-run-campaign"]) == int(
        ExitCode.SUCCESS
    )
    store = Store.open_migrated(db)
    try:
        rows = store.query("SELECT id FROM campaigns ORDER BY created_at DESC LIMIT 1")
        campaign_id = str(rows[0][0])
    finally:
        store.close()
    assert main(["--db", str(db), "campaign", "add-experiment", campaign_id, str(spec)]) == int(
        ExitCode.SUCCESS
    )
    return campaign_id


def _campaign_status(db: Path, campaign_id: str) -> str:
    store = Store.open_migrated(db)
    try:
        rows = store.query("SELECT status FROM campaigns WHERE id = ?", (campaign_id,))
    finally:
        store.close()
    return str(rows[0][0])


def _seed_stale_lease(db: Path, run_id: str, lease_id: str) -> None:
    """A live, expired-by-age lease a janitor/recovery pass would reclaim."""
    from datetime import timedelta

    from mayhem.domain.common import utc_now
    from mayhem.domain.leases import FaultLease, LeaseState
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    store = Store.open_migrated(db)
    try:
        lease = FaultLease.model_validate(
            {
                "id": lease_id,
                "run_id": run_id,
                "fault_id": "proc.pause",
                "owner_agent": "ag-1",
                "targets": ["n1"],
                "undo_ops": ({"op": "noop", "args": {}},),
                "verify_probes": (
                    {"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": True},
                ),
                "ttl_seconds": 1.0,
                "state": LeaseState.ACTIVE,
                "created_at": utc_now() - timedelta(seconds=10),
            }
        )
        SQLiteLeaseSink(store).save(lease)
    finally:
        store.close()


def _lease_state(db: Path, lease_id: str) -> str:
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    store = Store.open_migrated(db)
    try:
        lease = SQLiteLeaseSink(store).load(lease_id)
    finally:
        store.close()
    return "" if lease is None else str(lease.state.value)


def _exploding_service(on_execute):
    """A RecoveryService stand-in whose ``execute`` fails the test loudly."""

    class _Plan:
        state = SimpleNamespace(value="not_needed")
        leases: tuple[object, ...] = ()

        def model_dump(self, **kwargs: object) -> dict[str, object]:
            return {"state": "not_needed", "leases": []}

    class _Service:
        def __init__(self, store: object) -> None:
            self._store = store

        def plan(self, run_ids: object, **kwargs: object) -> _Plan:
            return _Plan()

        def execute(self, value: object, **kwargs: object) -> object:
            on_execute(**kwargs)
            raise AssertionError("unreachable")

    return _Service


class TestRunRequiresAnApproval:
    def test_run_without_execute_previews_and_touches_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        spec = _spec(tmp_path)
        rc = main(["--db", str(db), "--skip-gate", "run", str(spec), "-c", str(COMPOSE_FILE)])
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "pass --execute to run" in captured.err
        assert _counts(db) == (0, 0)

    def test_run_without_execute_never_constructs_an_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _no_implicit(monkeypatch)
        spec = _spec(tmp_path)
        with patch("mayhem.cli.services.RunEngine") as engine_cls:
            main(
                [
                    "--db",
                    str(tmp_path / "run.db"),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        engine_cls.assert_not_called()

    def test_run_dry_run_previews_without_an_approval(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        spec = _spec(tmp_path)
        rc = main(
            [
                "--db",
                str(db),
                "--dry-run",
                "--skip-gate",
                "run",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == int(ExitCode.SUCCESS)
        assert "dry-run" in capsys.readouterr().out
        assert _counts(db) == (0, 0)

    def test_short_e_is_the_same_approval_as_execute(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """`mayhem run -e` must authorize exactly like `--execute` — not less."""
        seen = {}
        for flag in ("-e", "--execute"):
            engine = MagicMock()
            result = engine.execute.return_value
            result.status = "completed"
            result.summary_md.return_value = "run completed"
            result.dirty_leases = ()
            with (
                patch("mayhem.cli.services.RunEngine", return_value=engine),
                patch("mayhem.cli.lifecycle._write_evidence_after_run"),
                patch("mayhem.cli.lifecycle.engine_for", return_value=engine) as engine_for,
            ):
                rc = main(
                    [
                        "--db",
                        str(tmp_path / f"run-{flag.strip('-')}.db"),
                        "--skip-gate",
                        "run",
                        str(_spec(tmp_path)),
                        "-c",
                        str(COMPOSE_FILE),
                        flag,
                    ]
                )
            capsys.readouterr()
            assert rc == int(ExitCode.SUCCESS), flag
            assert engine.execute.call_count == 1, f"{flag} did not execute"
            kwargs = engine_for.call_args.kwargs
            assert kwargs["require_intent"] is True, flag
            assert kwargs["intent"] is not None, flag
            # run_id is seeded per invocation, so compare the approval identity
            # (the actor string) rather than the generated run id.
            seen[flag] = kwargs["intent"].actor

        assert seen["-e"] == seen["--execute"] == "cli:--execute"

    def test_run_without_either_flag_still_only_previews(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Adding -e must not weaken the refusal for the unapproved path."""
        spec = _spec(tmp_path)
        with patch("mayhem.cli.services.RunEngine", side_effect=AssertionError("engine built")):
            rc = main(
                [
                    "--db",
                    str(tmp_path / "run.db"),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        assert rc == int(ExitCode.SUCCESS)
        assert "pass --execute to run" in capsys.readouterr().err
        assert _counts(tmp_path / "run.db") == (0, 0)

    def test_run_execute_mints_an_intent_bound_to_the_plan(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _spec(tmp_path)
        engine = MagicMock()
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "run completed"
        result.dirty_leases = ()
        with (
            patch("mayhem.cli.services.RunEngine", return_value=engine),
            patch("mayhem.cli.lifecycle._write_evidence_after_run") as write_evidence,
            patch("mayhem.cli.lifecycle.engine_for", return_value=engine) as engine_for,
        ):
            rc = main(
                [
                    "--db",
                    str(tmp_path / "run.db"),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            )
        assert rc == int(ExitCode.SUCCESS)
        capsys.readouterr()
        kwargs = engine_for.call_args.kwargs
        assert kwargs["require_intent"] is True
        intent = kwargs["intent"]
        assert intent is not None
        plan = engine.execute.call_args.args[0]
        assert intent.plan_hash == plan_hash_for(plan)
        assert intent.actor == "cli:--execute"
        # The approval that authorized the run is recorded with the evidence.
        assert write_evidence.call_args.kwargs["intent"] is intent

    def test_run_from_plan_without_execute_still_previews(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        spec = _spec(tmp_path)
        plan_file = tmp_path / "plan.json"
        engine = MagicMock()
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "run completed"
        result.dirty_leases = ()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            # First produce a plan file from an approved run.
            assert main(
                [
                    "--db",
                    str(db),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            ) == int(ExitCode.SUCCESS)
            plan = engine.execute.call_args.args[0]
            plan_file.write_text(plan.model_dump_json())
            # Guard: the replay below only previews if the file really is a
            # valid ExecutionPlan (otherwise the command falls through to the
            # spec path and this test would assert nothing about --from-plan).
            assert ExecutionPlan.model_validate(json.loads(plan_file.read_text())).run_id == (
                plan.run_id
            )
            capsys.readouterr()
            # Now replay it without an approval.
            rc = main(
                [
                    "--db",
                    str(db),
                    "--skip-gate",
                    "run",
                    "--from-plan",
                    str(plan_file),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "pass --execute to run" in captured.err
        assert _counts(db)[1] == 0  # no lease was created by the replay


class TestOtherMutatingCommandsRefuse:
    def test_maniac_without_execute_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        spec = _spec(tmp_path)
        rc = main(
            [
                "--db",
                str(tmp_path / "maniac.db"),
                "--skip-gate",
                "maniac",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
            ]
        )
        err = capsys.readouterr().err
        assert rc == int(ExitCode.SAFETY_REFUSAL)
        assert INTENT_REQUIRED in err
        assert _counts(tmp_path / "maniac.db") == (0, 0)

    def test_campaign_run_without_execute_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        rc = main(
            [
                "--db",
                str(tmp_path / "campaign.db"),
                "campaign",
                "run",
                "c-1",
            ]
        )
        assert rc == int(ExitCode.SAFETY_REFUSAL)
        assert INTENT_REQUIRED in capsys.readouterr().err

    def test_explore_live_mode_without_execute_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        rc = main(
            [
                "--db",
                str(tmp_path / "explore.db"),
                "experiment",
                "explore",
                "-c",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == int(ExitCode.SAFETY_REFUSAL)
        assert INTENT_REQUIRED in capsys.readouterr().err
        assert _counts(tmp_path / "explore.db") == (0, 0)

    def test_explore_dry_run_is_still_a_preview(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "explore.db"
        rc = main(["--db", str(db), "experiment", "explore", "-c", str(COMPOSE_FILE), "--dry-run"])
        assert rc == int(ExitCode.SUCCESS)
        assert _counts(db) == (0, 0)

    def test_legacy_recover_shim_without_execute_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        rc = main(["--db", str(tmp_path / "recover.db"), "recover", "r-unknown"])
        err = capsys.readouterr().err
        assert rc == int(ExitCode.SAFETY_REFUSAL)
        assert INTENT_REQUIRED in err

    def test_legacy_recover_shim_with_execute_is_allowed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        rc = main(["--db", str(tmp_path / "recover.db"), "recover", "r-unknown", "--execute"])
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing to recover" in captured.out

    def test_explicit_recover_execute_needs_no_extra_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        rc = main(["--db", str(tmp_path / "recover.db"), "recover", "execute", "r-unknown"])
        assert rc == int(ExitCode.SUCCESS)
        captured = capsys.readouterr()
        assert "recovered lease" not in captured.out
        assert "recovered lease" not in captured.err

    def test_janitor_dry_run_never_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "janitor.db"
        assert main(["--db", str(db), "janitor", "--json"]) == int(ExitCode.SUCCESS)
        payload = json.loads(capsys.readouterr().out)
        assert payload["execute"] is False
        assert _counts(db) == (0, 0)

    def test_global_dry_run_downgrades_janitor_apply_to_a_preview(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "janitor.db"
        rc = main(["--db", str(db), "--dry-run", "janitor", "--json", "--execute"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == int(ExitCode.SUCCESS)
        assert payload["execute"] is False

    def test_dependency_install_without_approval_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        spec = _spec(tmp_path)
        rc = main(
            [
                "--db",
                str(tmp_path / "dep.db"),
                "prepare",
                "dependencies",
                "install",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == int(ExitCode.SAFETY_REFUSAL)
        assert INTENT_REQUIRED in capsys.readouterr().err

    def test_dependency_install_dry_run_is_still_a_preview(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        spec = _spec(tmp_path)
        rc = main(
            [
                "--db",
                str(tmp_path / "dep.db"),
                "prepare",
                "dependencies",
                "install",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
                "--dry-run",
            ]
        )
        assert rc == int(ExitCode.SUCCESS)
        assert _counts(tmp_path / "dep.db") == (0, 0)


class TestCompatibilitySwitch:
    def test_the_switch_restores_the_implicit_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        spec = _spec(tmp_path)
        engine = MagicMock()
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "run completed"
        result.dirty_leases = ()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(tmp_path / "run.db"),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        assert rc == int(ExitCode.SUCCESS)
        assert engine.execute.called

    def test_the_implicit_run_records_no_intent_in_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        spec = _spec(tmp_path)
        engine = MagicMock()
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "run completed"
        result.dirty_leases = ()
        with (
            patch("mayhem.cli.services.RunEngine", return_value=engine),
            patch("mayhem.cli.lifecycle._write_evidence_after_run") as write_evidence,
        ):
            main(
                [
                    "--db",
                    str(tmp_path / "run.db"),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        assert write_evidence.call_args.kwargs["intent"] is None

    def test_the_implicit_maniac_mints_no_intent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An implicit run has no approval to record, so it records none.

        ``maniac`` minted an intent unconditionally, which made an implicit
        (compatibility-switch) maniac look approved in its evidence envelope —
        contradicting the documented ``execution_intent: null`` and the
        behaviour of ``run`` and ``campaign run``.
        """
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        engine = _stub_engine()
        with (
            patch("mayhem.cli.services.RunEngine", return_value=engine),
            patch("mayhem.cli.lifecycle._write_evidence_after_run") as write_evidence,
            patch("mayhem.cli.lifecycle.engine_for", return_value=engine) as engine_for,
        ):
            rc = main(
                [
                    "--db",
                    str(tmp_path / "maniac.db"),
                    "--skip-gate",
                    "maniac",
                    str(_spec(tmp_path)),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        assert rc == int(ExitCode.SUCCESS)
        assert engine_for.call_args.kwargs["intent"] is None
        assert write_evidence.call_args.kwargs["intent"] is None

    def test_approved_maniac_still_mints_an_intent(self, tmp_path: Path) -> None:
        engine = _stub_engine()
        with (
            patch("mayhem.cli.services.RunEngine", return_value=engine),
            patch("mayhem.cli.lifecycle._write_evidence_after_run") as write_evidence,
            patch("mayhem.cli.lifecycle.engine_for", return_value=engine) as engine_for,
        ):
            main(
                [
                    "--db",
                    str(tmp_path / "maniac.db"),
                    "--skip-gate",
                    "maniac",
                    str(_spec(tmp_path)),
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            )
        intent = engine_for.call_args.kwargs["intent"]
        assert intent is not None
        assert intent.plan_hash
        assert write_evidence.call_args.kwargs["intent"] is intent


class TestTheControllerDoesNotResolveTheSwitch:
    """``allow_implicit`` is resolved at the CLI edge and passed in (M2).

    The controller must not import the CLI layer or read ``os.environ``; if it
    did, the answer to "is the legacy switch on?" could differ between the
    command and the engine that enforces it.
    """

    def test_executor_imports_no_cli_module(self) -> None:
        assert _cli_imports("mayhem.controller.executor") == set()

    def test_executor_reads_no_environment(self) -> None:
        assert _env_reads("mayhem.controller.executor") == set()

    def test_cell_runner_does_not_import_the_cli_app_layer(self) -> None:
        # mayhem.cli.services is pre-existing coupling (the runner deliberately
        # reuses the canonical run path); mayhem.cli.app is the forbidden one.
        assert "mayhem.cli.app" not in _cli_imports("mayhem.controller.cell_runner")

    def test_gate_refuses_by_default_even_with_the_switch_in_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        from mayhem.cli.services import engine_for
        from mayhem.domain.execution_intent import ExecutionIntentRefused

        store = Store.open_migrated(tmp_path / "engine.db")
        try:
            engine = engine_for(store, "podman", require_intent=True)
            with pytest.raises(ExecutionIntentRefused) as excinfo:
                engine._require_execution_intent(_MINIMAL_PLAN)
            assert excinfo.value.code == INTENT_REQUIRED
        finally:
            store.close()

    def test_the_passed_in_answer_is_what_the_gate_uses(self, tmp_path: Path) -> None:
        from mayhem.cli.services import engine_for
        from mayhem.domain.execution_intent import ExecutionIntentRefused

        store = Store.open_migrated(tmp_path / "engine.db")
        try:
            strict = engine_for(store, "podman", require_intent=True)
            lenient = engine_for(store, "podman", require_intent=True, allow_implicit=True)
            # The switch is not in the environment here at all: only the
            # argument decides, and the default (nobody said) still refuses.
            assert lenient._require_execution_intent(_MINIMAL_PLAN) is None
            with pytest.raises(ExecutionIntentRefused):
                strict._require_execution_intent(_MINIMAL_PLAN)
        finally:
            store.close()


class TestRefusalCodesAreStable:
    @pytest.mark.parametrize("code", [INTENT_REQUIRED, APPROVAL_EXPIRED, INTENT_MISMATCH])
    def test_code_maps_to_the_existing_safety_exit_code(self, code: str) -> None:
        assert error_to_exit_code(code) == int(ExitCode.SAFETY_REFUSAL)

    def test_exit_code_enum_grew_no_new_member(self) -> None:
        assert [member.name for member in ExitCode] == [
            "SUCCESS",
            "GENERAL_FAILURE",
            "USAGE_ERROR",
            "CONFIG_ERROR",
            "VALIDATION_ERROR",
            "SAFETY_REFUSAL",
            "EXPERIMENT_FAILURE",
            "RECOVERY_FAILURE",
            "AGENT_ERROR",
            "TOOLKIT_ERROR",
            "AMBIGUOUS_COMMAND",
        ]

    def test_json_envelope_carries_the_code_and_remediation(self) -> None:
        mapped = map_exception_to_error(
            ExecutionIntentRefused(
                INTENT_REQUIRED,
                "explore refused",
                details={"action": "explore"},
                remediation="pass --execute",
            )
        )
        payload = json.loads(mapped.to_json())
        assert payload["code"] == INTENT_REQUIRED
        assert payload["exit_code"] == int(ExitCode.SAFETY_REFUSAL)
        assert payload["details"]["action"] == "explore"
        assert payload["remediation"] == "pass --execute"


class TestDryRunNeverAuthorizes:
    """A global ``--dry-run`` is a promise that nothing mutates (C1, M2).

    It must not be usable as an approval, and it must win over ``--execute``
    on every path that could otherwise reach ``RunEngine.execute``.
    """

    def test_run_dry_run_with_execute_executes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(db),
                    "--dry-run",
                    "--skip-gate",
                    "run",
                    str(_spec(tmp_path)),
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "dry-run" in captured.out + captured.err
        assert engine.execute.called is False
        assert _counts(db) == (0, 0)

    def test_run_from_plan_dry_run_with_execute_executes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        plan = _compiled_plan(tmp_path, db)
        plan_file = tmp_path / "plan.json"
        plan_file.write_text(plan.model_dump_json())
        capsys.readouterr()
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(db),
                    "--dry-run",
                    "--skip-gate",
                    "run",
                    "--from-plan",
                    str(plan_file),
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing executed" in captured.err
        assert engine.execute.called is False
        assert _counts(db)[1] == 0  # no lease was created

    def test_run_plan_id_dry_run_with_execute_executes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        plan = _compiled_plan(tmp_path, db)
        run_id = _seed_stored_plan(db, plan)
        capsys.readouterr()
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(db),
                    "--dry-run",
                    "--skip-gate",
                    "run",
                    "--plan-id",
                    run_id,
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing executed" in captured.err
        assert engine.execute.called is False
        assert _counts(db)[1] == 0

    def test_run_diff_dry_run_with_execute_executes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "run.db"
        diff_file = tmp_path / "previous.json"
        diff_file.write_text(json.dumps({"steps": {}}))
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(db),
                    "--dry-run",
                    "--skip-gate",
                    "run",
                    str(_spec(tmp_path)),
                    "-c",
                    str(COMPOSE_FILE),
                    "--diff",
                    str(diff_file),
                    "--execute",
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing executed" in captured.err
        assert engine.execute.called is False
        assert _counts(db) == (0, 0)

    def test_maniac_dry_run_with_execute_injects_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "maniac.db"
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(db),
                    "--dry-run",
                    "--skip-gate",
                    "maniac",
                    str(_spec(tmp_path)),
                    "-c",
                    str(COMPOSE_FILE),
                    "--execute",
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing injected" in captured.out
        assert engine.execute.called is False
        assert _counts(db) == (0, 0)

    def test_maniac_dry_run_alone_previews_without_an_approval(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A dry run is a preview, so it never needs the approval flag.
        _no_implicit(monkeypatch)
        db = tmp_path / "maniac.db"
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(db),
                    "--dry-run",
                    "--skip-gate",
                    "maniac",
                    str(_spec(tmp_path)),
                    "-c",
                    str(COMPOSE_FILE),
                ]
            )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing injected" in captured.out
        assert engine.execute.called is False
        assert _counts(db) == (0, 0)

    def test_campaign_run_dry_run_with_execute_leaves_the_campaign_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The compatibility switch is deliberately ON here: it must not be able
        # to wave --dry-run through.
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        db = tmp_path / "campaign.db"
        campaign_id = _make_campaign(db, _spec(tmp_path))
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(["--db", str(db), "--dry-run", "campaign", "run", campaign_id, "--execute"])
        out = capsys.readouterr().out
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing mutated" in out
        assert engine.execute.called is False
        # The status UPDATE never ran, so the campaign is still a draft.
        assert _campaign_status(db, campaign_id) == "draft"
        assert _counts(db) == (0, 0)

    def test_campaign_run_dry_run_alone_previews_the_campaign(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "campaign.db"
        campaign_id = _make_campaign(db, _spec(tmp_path))
        engine = _stub_engine()
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(["--db", str(db), "--dry-run", "campaign", "run", campaign_id])
        out = capsys.readouterr().out
        assert rc == int(ExitCode.SUCCESS)
        assert "nothing mutated" in out
        assert engine.execute.called is False
        assert _campaign_status(db, campaign_id) == "draft"

    def test_explore_global_dry_run_with_execute_executes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "explore.db"
        rc = main(
            [
                "--db",
                str(db),
                "--dry-run",
                "experiment",
                "explore",
                "-c",
                str(COMPOSE_FILE),
                "--execute",
            ]
        )
        assert rc == int(ExitCode.SUCCESS)
        assert _counts(db) == (0, 0)

    def test_explore_local_dry_run_with_execute_executes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "explore.db"
        rc = main(
            [
                "--db",
                str(db),
                "experiment",
                "explore",
                "-c",
                str(COMPOSE_FILE),
                "--dry-run",
                "--execute",
            ]
        )
        assert rc == int(ExitCode.SUCCESS)
        assert _counts(db) == (0, 0)

    def test_recover_execute_dry_run_previews_the_plan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        rc = main(
            [
                "--db",
                str(tmp_path / "recover.db"),
                "--dry-run",
                "recover",
                "execute",
                "r-unknown",
            ]
        )
        captured = capsys.readouterr()
        assert rc == int(ExitCode.SUCCESS)
        assert "recovery plan" in captured.out
        assert "nothing compensated" in captured.err

    def test_recover_execute_dry_run_never_calls_the_service(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Structural proof: ``RecoveryService.execute`` is unreachable."""
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")

        def _boom(**_kwargs: object) -> None:
            raise AssertionError("RecoveryService.execute must not run under --dry-run")

        import mayhem.cli.lifecycle as lifecycle

        monkeypatch.setattr(lifecycle, "_recovery_service", _exploding_service(_boom))
        rc = main(
            [
                "--db",
                str(tmp_path / "recover.db"),
                "--dry-run",
                "recover",
                "execute",
                "r-unknown",
            ]
        )
        assert rc == int(ExitCode.SUCCESS)

    def test_legacy_recover_shim_dry_run_never_compensates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The shim is an implicit spelling of a mutating command, so --dry-run
        # has to be honoured there too — with and without --execute, and with
        # the compatibility switch on.
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        for extra in ([], ["--execute"]):
            db = tmp_path / f"recover-{len(extra)}.db"
            _seed_stale_lease(db, "r-dry", "l-dry")
            rc = main(["--db", str(db), "--dry-run", "recover", "r-dry", *extra])
            captured = capsys.readouterr()
            assert rc == int(ExitCode.SUCCESS), (extra, captured.err)
            assert "nothing compensated" in captured.err, (extra, captured.err)
            assert "recovered lease" not in captured.out
            assert _lease_state(db, "l-dry") == "active"

    def test_janitor_dry_run_never_applies_transitions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Even with the compatibility switch on and --execute passed, a stale
        # lease is planned, never reclaimed.
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        db = tmp_path / "janitor.db"
        _seed_stale_lease(db, "r-stale", "l-stale")
        rc = main(["--db", str(db), "--dry-run", "janitor", "--json", "--execute"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == int(ExitCode.SUCCESS)
        assert payload["execute"] is False
        assert payload["would_recover"] == ["l-stale"]
        assert _lease_state(db, "l-stale") == "active"

    def test_dependency_install_dry_run_installs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # --dry-run is never an approval for an install, even with the switch on.
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        from mayhem.cli import dependency as dependency_mod

        monkeypatch.setattr(
            dependency_mod, "run_tool", lambda *a, **k: pytest.fail("no package may be installed")
        )
        rc = main(
            [
                "--db",
                str(tmp_path / "dep.db"),
                "--dry-run",
                "prepare",
                "dependencies",
                "install",
                str(_spec(tmp_path)),
                "-c",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == int(ExitCode.SUCCESS)
        assert _counts(tmp_path / "dep.db") == (0, 0)


class TestImplicitExecutionSwitchLivesInTheAppLayer:
    """The environment is read once, by the application layer (M3)."""

    def test_missing_variable_is_not_implicit(self) -> None:
        assert implicit_execution_allowed({}) is False

    def test_exactly_one_enables_it(self) -> None:
        assert implicit_execution_allowed({IMPLICIT_EXECUTION_ENV: "1"}) is True

    @pytest.mark.parametrize("value", ("0", "", "true", "yes", "11"))
    def test_anything_but_one_is_not_implicit(self, value: str) -> None:
        assert implicit_execution_allowed({IMPLICIT_EXECUTION_ENV: value}) is False

    def test_surrounding_whitespace_is_ignored(self) -> None:
        assert implicit_execution_allowed({IMPLICIT_EXECUTION_ENV: " 1 "}) is True

    def test_the_process_environment_is_the_default_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(IMPLICIT_EXECUTION_ENV, raising=False)
        assert implicit_execution_allowed() is False
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        assert implicit_execution_allowed() is True

    def test_the_domain_never_reads_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A domain decision must not depend on ambient state."""
        from mayhem.domain.execution_intent import require_execution_intent

        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        with pytest.raises(ExecutionIntentRefused):
            require_execution_intent(None, plan_hash="", action="run")
