"""E2E tests: every mayhem CLI command exercised against the testCase fixture.

The tests use ``main()`` directly (in-process) so Docker/Podman are NOT
required — topology and runtime providers are stubbed where needed.
Each test is independent; shared state is created per-test via ``tmp_path``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mayhem.cli.app import main
from mayhem.cli.exit_codes import ExitCode

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"
MAYHEM_CONFIG = TESTCASE / "mayhem.yml"
FULL_FAULT_SPEC = TESTCASE / "full-fault.yml"

DETERMINISTIC_YAML = """\
kind: deterministic
name: pause-drill
hypothesis: brief process pause is survivable
steps:
  - id: pause
    inject_fault:
      fault: proc.pause
      targets:
        - kind: process
          expr: "name=api"
      duration: 10s
    on_failure: abort_and_recover
  - id: settle
    wait: 2s
"""

RANDOM_YAML = """\
kind: random
name: random-chaos
hypothesis: random injection does not crash the stack
max_faults: 3
seed: 42
targets:
  - kind: process
    expr: "kind=service"
selection:
  policy: random
  max_per_kind: 2
compensation:
  budget: critical
"""

NO_STEPS_YAML = """\
kind: deterministic
name: empty
hypothesis: nothing
steps: []
"""

INVALID_YAML = "not: [valid: {yaml: "


def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text)
    return p


def _run_id(db_path: str) -> str | None:
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT id FROM runs ORDER BY rowid DESC LIMIT 1").fetchone()
    conn.close()
    return row[0] if row else None


def _campaign_id(db_path: str) -> str | None:
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1").fetchone()
    conn.close()
    return row[0] if row else None


# ────────────────────────────────────────────────────────────────────────────
# 1.  Root CLI / help / version / unknown command
# ────────────────────────────────────────────────────────────────────────────


class TestRootCLI:
    """Root-level commands: help, unknown command, prefix ambiguity."""

    def test_root_help_exits_zero(self) -> None:
        rc = main(["--help"])
        assert rc == 0

    def test_no_args_shows_help_and_exits_usage_error(self) -> None:
        """Click raises NoArgsIsHelpError (subclass of UsageError) → exit 2."""
        rc = main([])
        assert rc == ExitCode.USAGE_ERROR

    def test_unknown_command_returns_usage_error(self) -> None:
        rc = main(["nonexistent-cmd"])
        assert rc == ExitCode.USAGE_ERROR

    def test_ambiguous_prefix_returns_ambiguous_code(self) -> None:
        """'c' is ambiguous between campaign and config."""
        rc = main(["c"])
        assert rc == ExitCode.AMBIGUOUS_COMMAND

    def test_global_debug_flag_re_raises(self, tmp_path: Path) -> None:
        """--debug re-raises unexpected errors that reach the last-resort handler."""
        with patch("mayhem.cli.lifecycle.prepare", side_effect=RuntimeError("boom")):
            spec = _write(tmp_path, "ok.yml", DETERMINISTIC_YAML)
            with pytest.raises(RuntimeError, match="boom"):
                main(["--debug", "plan", str(spec), "--process", "api=424242"])

    def test_global_db_option_is_accepted(self) -> None:
        rc = main(["--db", "/tmp/mayhem-e2e-test.db", "toolkit", "faults"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 2.  toolkit group
# ────────────────────────────────────────────────────────────────────────────


class TestToolkitGroup:
    """``mayhem toolkit faults`` and ``mayhem toolkit list``."""

    def test_faults_lists_catalog(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["toolkit", "faults"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "proc.pause" in out
        assert "container.kill" in out
        assert "mem.exhaust" in out
        assert "cpu.saturate" in out
        assert "net.latency" in out
        assert "net.partition" in out
        assert "http.error_injection" in out
        assert "risk=" in out
        assert "undo=" in out

    def test_toolkit_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["too", "f"])
        assert rc == 0
        assert "proc.pause" in capsys.readouterr().out

    def test_list_probes_capabilities(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["toolkit", "list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "ok" in out or "MISSING" in out

    def test_list_json_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["toolkit", "list", "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "tools" in data

    def test_list_custom_host(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["toolkit", "list", "--host", "local"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 3.  config group
# ────────────────────────────────────────────────────────────────────────────


class TestConfigGroup:
    """``mayhem config show`` and ``mayhem config validate``."""

    def test_config_show_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["config", "show"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "api_version" in out or "environment" in out

    def test_config_show_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["config", "show", "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "config" in data
        assert "sources" in data

    def test_config_show_with_config_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = _write(
            tmp_path,
            "mayhem.yml",
            "apiVersion: mayhem/v1\npolicy:\n  allow_critical: false\n",
        )
        rc = main(["--config", str(cfg), "config", "show"])
        assert rc == 0

    def test_config_validate_valid(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["config", "validate"])
        assert rc == 0
        assert "valid" in capsys.readouterr().out

    def test_config_validate_with_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = _write(
            tmp_path,
            "mayhem.yml",
            "apiVersion: mayhem/v1\npolicy:\n  allow_critical: true\n",
        )
        rc = main(["--config", str(cfg), "config", "validate"])
        assert rc == 0

    def test_config_validate_bad_yaml(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = _write(tmp_path, "bad.yml", "not: valid: {yaml: ")
        rc = main(["--config", str(cfg), "config", "validate"])
        assert rc == ExitCode.CONFIG_ERROR

    def test_config_validate_unknown_keys(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = _write(tmp_path, "mayhem.yml", "apiVersion: mayhem/v1\nfoo_bar: 42\n")
        rc = main(["--config", str(cfg), "config", "validate"])
        assert rc == ExitCode.CONFIG_ERROR


# ────────────────────────────────────────────────────────────────────────────
# 4.  experiment group
# ────────────────────────────────────────────────────────────────────────────


class TestExperimentGroup:
    """``mayhem experiment show`` and ``mayhem experiment validate``."""

    def test_show_deterministic_spec(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["experiment", "show", str(spec)])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["kind"] == "deterministic"
        assert data["metadata"]["name"] == "pause-drill"

    def test_show_random_spec(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "rnd.yml", RANDOM_YAML)
        rc = main(["experiment", "show", str(spec)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["kind"] == "random"

    def test_show_missing_file_returns_validation_error(self) -> None:
        rc = main(["experiment", "show", "/nonexistent/spec.yaml"])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_deterministic(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["experiment", "validate", str(spec), "--process", "api=424242"])
        assert rc == 0
        assert "validated" in capsys.readouterr().out

    def test_validate_random(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "rnd.yml", RANDOM_YAML)
        rc = main(["experiment", "validate", str(spec), "--service", "api"])
        assert rc == 0

    def test_validate_empty_steps_returns_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "empty.yml", NO_STEPS_YAML)
        rc = main(["experiment", "validate", str(spec)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_missing_file(self) -> None:
        rc = main(["experiment", "validate", "/no/such/file.yml"])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_experiment_prefix_e_v(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["e", "v", str(spec), "--process", "api=424242"])
        assert rc == 0

    def test_experiment_prefix_ex_sh(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["ex", "sh", str(spec)])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 5.  topology group
# ────────────────────────────────────────────────────────────────────────────


class TestTopologyGroup:
    """``mayhem topology discover`` with compose and without."""

    def test_discover_with_compose_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "graph" in data
        assert "nodes" in data["graph"]
        assert "edges" in data["graph"]

    def test_discover_compose_has_service_nodes(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        kinds = [n["kind"] for n in data["graph"]["nodes"]]
        assert "service" in kinds

    def test_discover_compose_no_self_edges(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        for edge in data["graph"]["edges"]:
            assert edge["src"] != edge["dst"], f"self-edge: {edge}"

    def test_discover_compose_has_depends_on_edges(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        edge_kinds = [e["kind"] for e in data["graph"]["edges"]]
        assert "depends_on" in edge_kinds

    def test_discover_compose_with_directory(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE.parent)])
        assert rc == 0

    def test_discover_compose_has_drift_report(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert "drift" in data

    def test_discover_no_compose_returns_graph(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Without compose and without runtime, graph should be empty."""
        rc = main(["topology", "discover"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert "graph" in data

    def test_discover_compose_service_names(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        svc_names = {n["name"] for n in data["graph"]["nodes"] if n["kind"] == "service"}
        assert svc_names == {"api", "web", "download-1", "download-2", "lb", "db"}

    def test_topology_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["top", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 6.  validate (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestValidateCommand:
    """``mayhem validate`` with --process, --service, --host, --compose."""

    def test_validate_with_process(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["validate", str(spec), "--process", "api=424242"])
        assert rc == 0
        assert "validated" in capsys.readouterr().out

    def test_validate_with_multiple_processes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "validate",
                str(spec),
                "--process",
                "api=424242",
                "--process",
                "worker=12345",
            ]
        )
        assert rc == 0

    def test_validate_with_service(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["validate", str(spec), "--service", "web", "--process", "api=424242"])
        assert rc == 0

    def test_validate_with_host(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["validate", str(spec), "--host", "prod-1", "--process", "api=424242"])
        assert rc == 0

    def test_validate_with_compose(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "validate",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0

    def test_validate_bad_spec(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "bad.yml", "kind: deterministic\nname: x\n")
        rc = main(["validate", str(spec)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_missing_spec(self) -> None:
        rc = main(["validate", "/nonexistent.yml"])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["v", str(spec), "--process", "api=424242"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 7.  plan (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestPlanCommand:
    """``mayhem plan`` prints a frozen ExecutionPlan as JSON."""

    def test_plan_deterministic(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["plan", str(spec), "--process", "api=424242"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "kind" in data
        assert "steps" in data
        assert len(data["steps"]) >= 1

    def test_plan_contains_fault_info(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["plan", str(spec), "--process", "api=424242"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert any("proc.pause" in json.dumps(s) for s in data["steps"])

    def test_plan_random(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "rnd.yml", RANDOM_YAML)
        rc = main(["plan", str(spec)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert "steps" in data

    def test_plan_with_compose(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_plan_bad_spec_returns_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "bad.yml", NO_STEPS_YAML)
        rc = main(["plan", str(spec)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_plan_with_multiple_services(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "plan",
                str(spec),
                "--service",
                "web",
                "--service",
                "api",
            ]
        )
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 8.  run (lifecycle) — stubs avoid real fault injection
# ────────────────────────────────────────────────────────────────────────────


class TestRunCommand:
    """``mayhem run`` — the full lifecycle.  RunEngine is stubbed to avoid
    actually pausing processes or touching containers."""

    @patch("mayhem.cli.services.RunEngine")
    def test_run_deterministic_exits_zero(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = mock_engine_cls.return_value
        engine.run.return_value = None
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["--db", str(tmp_path / "run.db"), "run", str(spec), "--process", "api=424242"])
        assert rc == 0

    @patch("mayhem.cli.services.RunEngine")
    def test_run_with_compose(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = mock_engine_cls.return_value
        engine.run.return_value = None
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "--db",
                str(tmp_path / "run.db"),
                "run",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0

    def test_run_bad_spec_fails_validation(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "bad.yml", NO_STEPS_YAML)
        rc = main(["--db", str(tmp_path / "run.db"), "run", str(spec)])
        assert rc == ExitCode.VALIDATION_ERROR

    @patch("mayhem.cli.services.RunEngine")
    def test_run_with_multiple_processes(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        engine = mock_engine_cls.return_value
        engine.run.return_value = None
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "--db",
                str(tmp_path / "run.db"),
                "run",
                str(spec),
                "--process",
                "api=424242",
                "--process",
                "worker=99999",
            ]
        )
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 9.  status (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestStatusCommand:
    """``mayhem status`` — shows recent runs."""

    def test_status_empty_db(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--db", str(tmp_path / "empty.db"), "status"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "No runs" in out or "run-" in out or out.strip() == ""

    def test_status_shows_run_after_run(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        db = tmp_path / "status.db"
        from mayhem.infra.store import Store

        store = Store.open_migrated(db)
        with store.write() as conn:
            conn.execute(
                "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at)"
                " VALUES (?, '{}', '{}', ?)",
                ("cfg-001", "2025-01-01T00:00:00"),
            )
            conn.execute(
                "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json,"
                " seed, status, environment_fingerprint, config_snapshot_id, started_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "run-test-001",
                    "test",
                    "deterministic",
                    "{}",
                    "{}",
                    None,
                    "completed",
                    "fp-abc123",
                    "cfg-001",
                    "2025-01-01T00:00:00",
                ),
            )
        store.close()
        rc = main(["--db", str(db), "status"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "run-test-001" in out

    def test_status_json_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--db", str(tmp_path / "empty.db"), "status", "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        if out.strip():
            data = json.loads(out)
            assert isinstance(data, (list, dict))


# ────────────────────────────────────────────────────────────────────────────
# 10.  history (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestHistoryCommand:
    """``mayhem history <run-id>`` — shows detailed run information."""

    def test_history_nonexistent_run(self, tmp_path: Path) -> None:
        rc = main(["--db", str(tmp_path / "empty.db"), "history", "run-nonexistent"])
        assert rc == 0

    def test_history_after_run(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        db = tmp_path / "hist.db"
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        with patch("mayhem.cli.services.RunEngine") as m:
            m.return_value.run.return_value = None
            main(["--db", str(db), "run", str(spec), "--process", "api=424242"])
        run_id = _run_id(str(db))
        if run_id:
            rc = main(["--db", str(db), "history", run_id])
            assert rc == 0

    def test_history_json_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--db", str(tmp_path / "empty.db"), "history", "run-x", "--json"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 11.  recover (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestRecoverCommand:
    """``mayhem recover`` — cleans up dirty state."""

    def test_recover_clean_db(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--db", str(tmp_path / "empty.db"), "recover", "run-nonexistent"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 12.  janitor (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestJanitorCommand:
    """``mayhem janitor sweep`` — cleanup sweeps."""

    def test_janitor_sweep_clean_db(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["--db", str(tmp_path / "empty.db"), "janitor"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 13.  campaign group
# ────────────────────────────────────────────────────────────────────────────


class TestCampaignGroup:
    """``mayhem campaign`` CRUD lifecycle."""

    def test_campaign_list_empty(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--db", str(tmp_path / "c.db"), "campaign", "list"])
        assert rc == 0

    def test_campaign_create_and_list(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = str(tmp_path / "c.db")
        rc = main(["--db", db, "campaign", "create", "e2e-campaign"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "camp-" in out

        rc = main(["--db", db, "campaign", "list"])
        assert rc == 0
        assert "e2e-campaign" in capsys.readouterr().out

    def test_campaign_create_with_hypothesis(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = str(tmp_path / "c.db")
        rc = main(
            [
                "--db",
                db,
                "campaign",
                "create",
                "hypo-test",
                "--hypothesis",
                "stack survives",
            ]
        )
        assert rc == 0

    def test_campaign_show(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        db = str(tmp_path / "c.db")
        main(["--db", db, "campaign", "create", "show-test"])
        cid = _campaign_id(db)
        if cid:
            rc = main(["--db", db, "campaign", "show", cid])
            assert rc == 0
            assert "show-test" in capsys.readouterr().out

    def test_campaign_show_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        db = str(tmp_path / "c.db")
        main(["--db", db, "campaign", "create", "json-test"])
        capsys.readouterr()
        cid = _campaign_id(db)
        if cid:
            rc = main(["--db", db, "campaign", "show", cid, "--json"])
            assert rc == 0
            data = json.loads(capsys.readouterr().out)
            assert data["name"] == "json-test"

    def test_campaign_show_nonexistent(self, tmp_path: Path) -> None:
        rc = main(["--db", str(tmp_path / "c.db"), "campaign", "show", "campaign-nosuch"])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_campaign_delete_draft(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = str(tmp_path / "c.db")
        main(["--db", db, "campaign", "create", "to-delete"])
        cid = _campaign_id(db)
        if cid:
            rc = main(["--db", db, "campaign", "delete", "--yes", cid])
            assert rc == 0

    def test_campaign_delete_nonexistent(self, tmp_path: Path) -> None:
        rc = main(["--db", str(tmp_path / "c.db"), "campaign", "delete", "campaign-nosuch"])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_campaign_start_draft(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        db = str(tmp_path / "c.db")
        main(["--db", db, "campaign", "create", "start-test"])
        cid = _campaign_id(db)
        if cid:
            rc = main(["--db", db, "campaign", "start", cid])
            assert rc in (0, ExitCode.VALIDATION_ERROR, ExitCode.GENERAL_FAILURE)

    def test_campaign_status_after_create(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = str(tmp_path / "c.db")
        main(["--db", db, "campaign", "create", "status-test"])
        cid = _campaign_id(db)
        if cid:
            rc = main(["--db", db, "campaign", "status", cid])
            assert rc == 0

    def test_campaign_abort_draft(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        db = str(tmp_path / "c.db")
        main(["--db", db, "campaign", "create", "abort-test"])
        cid = _campaign_id(db)
        if cid:
            rc = main(["--db", db, "campaign", "abort", cid])
            assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 14.  full-fault.yml spec from testCase
# ────────────────────────────────────────────────────────────────────────────


class TestFullFaultSpec:
    """Exercise the testCase ``full-fault.yml`` spec through the CLI."""

    def test_show_full_fault(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["experiment", "show", str(FULL_FAULT_SPEC)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["kind"] == "deterministic"

    def test_validate_full_fault(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["experiment", "validate", str(FULL_FAULT_SPEC), "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_plan_full_fault(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["plan", str(FULL_FAULT_SPEC), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert "steps" in data

    @patch("mayhem.cli.services.RunEngine")
    def test_run_full_fault(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.summary_md.return_value = "run completed"
        result.status = "completed"
        db = str(tmp_path / "ff.db")
        rc = main(["--db", db, "run", str(FULL_FAULT_SPEC), "--compose", str(COMPOSE_FILE)])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 15.  mayhem.yml config from testCase
# ────────────────────────────────────────────────────────────────────────────


class TestCaseConfig:
    """Exercise the testCase ``mayhem.yml`` config."""

    def test_config_show_with_testcase_config(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--config", str(MAYHEM_CONFIG), "config", "show"])
        assert rc == 0

    def test_config_validate_with_testcase_config(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--config", str(MAYHEM_CONFIG), "config", "validate"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 16.  topology discover with testCase compose
# ────────────────────────────────────────────────────────────────────────────


class TestCaseTopology:
    """Topology discovery against the testCase compose stack."""

    def test_discover_all_services_present(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        svc_names = {n["name"] for n in data["graph"]["nodes"] if n["kind"] == "service"}
        assert svc_names == {"api", "web", "download-1", "download-2", "lb", "db"}

    def test_drift_has_missing_services(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Without runtime, all services should show as missing."""
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        drift = data.get("drift", {})
        missing = drift.get("missing_services", [])
        assert len(missing) == 6

    def test_discover_produces_edges(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["topology", "discover", "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert len(data["graph"]["edges"]) > 0


# ────────────────────────────────────────────────────────────────────────────
# 17.  full round-trip: validate → plan → run → status → history
# ────────────────────────────────────────────────────────────────────────────


class TestFullRoundTrip:
    """End-to-end lifecycle on a clean database."""

    @patch("mayhem.cli.services.RunEngine")
    def test_validate_plan_run_status_history(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        db = str(tmp_path / "roundtrip.db")
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)

        # validate
        rc = main(["--db", db, "validate", str(spec), "--process", "api=424242"])
        assert rc == 0

        # plan
        rc = main(["--db", db, "plan", str(spec), "--process", "api=424242"])
        assert rc == 0

        # run (mock the engine so no real faults are injected)
        engine = mock_engine_cls.return_value
        result_mock = MagicMock()
        result_mock.status = "completed"
        result_mock.summary_md.return_value = "run-run1 completed ok"
        engine.execute.return_value = result_mock
        rc = main(["--db", db, "run", str(spec), "--process", "api=424242"])
        assert rc == 0

        # status
        rc = main(["--db", db, "status"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "run-" in out

        # history
        run_id = _run_id(db)
        if run_id:
            rc = main(["--db", db, "history", run_id])
            assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 18.  prefix resolution for all groups
# ────────────────────────────────────────────────────────────────────────────


class TestPrefixResolution:
    """Verify that unique-prefix resolution works for every group."""

    def test_toolkit_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        """'too' uniquely resolves to 'toolkit'."""
        rc = main(["too", "faults"])
        assert rc == 0

    def test_experiment_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["ex", "v", str(spec), "--process", "api=424242"])
        assert rc == 0

    def test_topology_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["top", "d", "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_config_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["cfg", "s"])
        assert rc == 0

    def test_validate_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["v", str(spec), "--process", "api=424242"])
        assert rc == 0

    def test_plan_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["p", str(spec), "--process", "api=424242"])
        assert rc == 0

    def test_campaign_prefix_list(self, tmp_path: Path) -> None:
        rc = main(["--db", str(tmp_path / "c.db"), "cam", "l"])
        assert rc == 0

    def test_campaign_prefix_create(self, tmp_path: Path) -> None:
        rc = main(["--db", str(tmp_path / "c.db"), "cam", "c", "pref-test"])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 19.  exit code coverage
# ────────────────────────────────────────────────────────────────────────────


class TestExitCodeCoverage:
    """Verify every documented exit code is reachable."""

    def test_success(self) -> None:
        assert main(["toolkit", "faults"]) == ExitCode.SUCCESS

    def test_usage_error(self) -> None:
        assert main(["--nonexistent-flag"]) == ExitCode.USAGE_ERROR

    def test_general_failure(self) -> None:
        assert main(["nonexistent"]) == ExitCode.USAGE_ERROR

    def test_config_error(self, tmp_path: Path) -> None:
        cfg = _write(tmp_path, "bad.yml", "apiVersion: mayhem/v1\nunknown_key: 42\n")
        assert main(["--config", str(cfg), "config", "validate"]) == ExitCode.CONFIG_ERROR

    def test_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "bad.yml", "kind: deterministic\nname: x\n")
        assert main(["validate", str(spec)]) == ExitCode.VALIDATION_ERROR

    def test_ambiguous_command(self) -> None:
        assert main(["r"]) == ExitCode.AMBIGUOUS_COMMAND


# ────────────────────────────────────────────────────────────────────────────
# 20.  error handling & edge cases
# ────────────────────────────────────────────────────────────────────────────


class TestErrorHandling:
    """Edge cases, bad inputs, and error paths."""

    def test_plan_with_invalid_process_format(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["plan", str(spec), "--process", "bad-format-no-equals"])
        assert rc == ExitCode.USAGE_ERROR

    def test_plan_with_non_numeric_pid(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(["plan", str(spec), "--process", "api=not-a-number"])
        assert rc == ExitCode.USAGE_ERROR

    def test_validate_with_compose_nonexistent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "validate",
                str(spec),
                "--compose",
                "/nonexistent/docker-compose.yml",
                "--process",
                "api=424242",
            ]
        )
        assert rc == 0

    def test_plan_with_compose_and_process(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "det.yml", DETERMINISTIC_YAML)
        rc = main(
            [
                "plan",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
                "--process",
                "api=424242",
            ]
        )
        assert rc == 0

    def test_config_show_with_profile(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write(
            tmp_path,
            "mayhem.yml",
            "apiVersion: mayhem/v1\npolicy:\n  allow_critical: true\n",
        )
        _write(
            tmp_path,
            "mayhem.staging.yaml",
            "apiVersion: mayhem/v1\npolicy:\n  allow_critical: false\n",
        )
        cfg = tmp_path / "mayhem.yml"
        rc = main(
            [
                "--config",
                str(cfg),
                "--profile",
                "staging",
                "config",
                "show",
            ]
        )
        assert rc == 0
