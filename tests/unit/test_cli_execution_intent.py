"""CLI enforcement of the execution-intent contract (v0.9.0).

Two properties are pinned here:

* every mutating command refuses without an explicit intent, and
* a preview never creates a lease (or even a run row).

The suite-wide compatibility switch is on by default (see ``tests/conftest.py``);
each test that asserts a *refusal* deletes it first, so it exercises the v0.9.0
default rather than the escape hatch.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mayhem.cli.app import main
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
            assert (
                main(
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
                )
                == int(ExitCode.SUCCESS)
            )
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
        rc = main(["--db", str(db), "explore", "-c", str(COMPOSE_FILE), "--dry-run"])
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
        assert "nothing to recover" in capsys.readouterr().out

    def test_janitor_dry_run_never_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "janitor.db"
        assert main(["--db", str(db), "janitor", "--json"]) == int(ExitCode.SUCCESS)
        payload = json.loads(capsys.readouterr().out)
        assert payload["execute"] is False
        assert _counts(db) == (0, 0)

    def test_global_dry_run_refuses_janitor_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _no_implicit(monkeypatch)
        db = tmp_path / "janitor.db"
        rc = main(["--db", str(db), "--dry-run", "janitor", "--execute"])
        assert rc == int(ExitCode.SAFETY_REFUSAL)
        assert INTENT_REQUIRED in capsys.readouterr().err

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


class TestRefusalCodesAreStable:
    @pytest.mark.parametrize(
        "code", [INTENT_REQUIRED, APPROVAL_EXPIRED, INTENT_MISMATCH]
    )
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
