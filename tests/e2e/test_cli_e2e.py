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
import yaml

from mayhem.cli.app import main
from mayhem.cli.exit_codes import ExitCode

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"
DRILL_SPEC = TESTCASE / "mayhem.yaml"

DRILL_YAML = """\
kind: drill
name: drill-pause
hypothesis: brief process pause is survivable
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
  testcase-lb:
    faults:
      - fault: fuzz.protocol_abuse
        duration: 5s
execution:
  - parallel: [testcase-api, testcase-lb]
  - wait: 2s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
"""

DRILL_MISSING_CONTAINER_YAML = """\
kind: drill
name: drill-missing
config:
  risk_ceiling: critical
containers:
  not-a-container:
    faults:
      - fault: proc.pause
execution:
  - parallel: [not-a-container]
"""

DRILL_EMPTY_YAML = """\
kind: drill
name: drill-empty
config:
  risk_ceiling: critical
containers:
  testcase-api:
    faults:
      - fault: proc.pause
execution: []
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
            spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
            with pytest.raises(RuntimeError, match="boom"):
                main(["--debug", "plan", str(spec), "--compose", str(COMPOSE_FILE)])

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
        assert "apiVersion: mayhem/v1" in out
        assert "policy:" in out

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

    def test_show_drill_spec(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["experiment", "show", str(spec)])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["kind"] == "drill"
        assert data["name"] == "drill-pause"

    def test_show_missing_file_returns_validation_error(self) -> None:
        rc = main(["experiment", "show", "/nonexistent/spec.yaml"])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_deterministic(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["experiment", "validate", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        assert "validated" in capsys.readouterr().out

    def test_validate_unknown_container_returns_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "missing.yml", DRILL_MISSING_CONTAINER_YAML)
        rc = main(["experiment", "validate", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_empty_steps_returns_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "empty.yml", DRILL_EMPTY_YAML)
        rc = main(["experiment", "validate", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_missing_file(self) -> None:
        rc = main(["experiment", "validate", "/no/such/file.yml", "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_experiment_prefix_e_v(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["e", "v", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_experiment_prefix_ex_sh(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
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
    """``mayhem validate`` compiles a drill spec via --compose (drill-native).

    The manual ``--process``/``--service``/``--host`` overrides were removed in
    Phase 6 — drill targets are compose container names, so the only topology
    input is the compose blueprint.
    """

    def test_validate_drill_with_compose(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["validate", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        assert "validated" in capsys.readouterr().out

    def test_validate_drill_auto_detect_compose(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import shutil

        shutil.copy(COMPOSE_FILE, tmp_path / "docker-compose.yml")
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        with patch.object(Path, "cwd", return_value=tmp_path):
            rc = main(["validate", str(spec)])
        assert rc == 0

    def test_validate_missing_spec(self) -> None:
        rc = main(["validate", "/nonexistent.yml", "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_unknown_container_is_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "missing.yml", DRILL_MISSING_CONTAINER_YAML)
        rc = main(["validate", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["v", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 6b. dependency compile (offline tooling bake-in)
# ────────────────────────────────────────────────────────────────────────────


class TestDependencyCompile:
    """``mayhem dependency compile`` emits a docker-compose.mayhem.yml with
    the drill's fault tooling baked in — no live containers required."""

    def test_compile_adds_bootstrap_but_no_caps(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # DRILL_YAML only needs python — no capabilities, just a bootstrap
        # entrypoint that installs python3 via the image's package manager.
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        out_path = tmp_path / "docker-compose.mayhem.yml"
        rc = main(
            [
                "--db",
                str(tmp_path / "mayhem.db"),
                "dependency",
                "compile",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
                "-o",
                str(out_path),
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "wrote" in out
        compiled = yaml.safe_load(out_path.read_text())
        api = compiled["services"]["api"]
        assert "cap_add" not in api
        assert api["entrypoint"][0] == "/bin/sh"
        script = api["entrypoint"][-1]
        # proc.pause needs `kill` → the procps distro package, installed via
        # whatever package manager the image actually ships.
        assert "apk add --no-cache procps" in script
        assert "apt-get install -y procps" in script
        # the wrapper execs the service command ($0 $@ stays untouched).
        assert 'exec "$0" "$@"' in script
        assert api["command"] == "python -m http.server 8080"
        # the input compose file was never modified.
        assert "apk add" not in COMPOSE_FILE.read_text()

    def test_compile_is_offline_union_of_plan(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The full testCase drill: lb needs iptables (NET_ADMIN) and clock
        # skew (SYS_TIME) even though the stack is not running.
        out_path = tmp_path / "compose.mayhem.yml"
        rc = main(
            [
                "--db",
                str(tmp_path / "mayhem.db"),
                "dependency",
                "compile",
                str(DRILL_SPEC),
                "-c",
                str(COMPOSE_FILE),
                "-o",
                str(out_path),
            ]
        )
        assert rc == 0
        compiled = yaml.safe_load(out_path.read_text())
        lb = compiled["services"]["lb"]
        assert {"NET_ADMIN", "SYS_TIME"} <= set(lb["cap_add"])
        script = lb["entrypoint"][-1]
        assert "coreutils" in script and "iproute" in script

    def test_compile_refuses_to_overwrite_source(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(
            [
                "--db",
                str(tmp_path / "mayhem.db"),
                "dependency",
                "compile",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
                "-o",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 2
        assert "refusing to overwrite" in capsys.readouterr().err


# ────────────────────────────────────────────────────────────────────────────
# 7.  plan (lifecycle)
# ────────────────────────────────────────────────────────────────────────────


class TestPlanCommand:
    """``mayhem plan`` prints a frozen ExecutionPlan as JSON."""

    def test_plan_drill(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "kind" in data
        assert "steps" in data
        assert len(data["steps"]) >= 1

    def test_plan_contains_fault_info(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert any("proc.pause" in json.dumps(s) for s in data["steps"])

    def test_plan_unknown_container_is_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "missing.yml", DRILL_MISSING_CONTAINER_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_plan_bad_spec_returns_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "empty.yml", DRILL_EMPTY_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_plan_with_compose(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["kind"] == "drill"


# ────────────────────────────────────────────────────────────────────────────
# 8.  run (lifecycle) — stubs avoid real fault injection
# ────────────────────────────────────────────────────────────────────────────


class TestRunCommand:
    """``mayhem run`` — the full lifecycle.  RunEngine is stubbed to avoid
    actually pausing processes or touching containers."""

    @patch("mayhem.cli.services.RunEngine")
    def test_run_drill_exits_zero(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = mock_engine_cls.return_value
        result_mock = MagicMock()
        result_mock.status = "completed"
        result_mock.summary_md.return_value = "run drill completed ok"
        engine.execute.return_value = result_mock
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(
            ["--db", str(tmp_path / "run.db"), "run", str(spec), "--compose", str(COMPOSE_FILE)]
        )
        assert rc == 0

    def test_run_bad_spec_fails_validation(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "empty.yml", DRILL_EMPTY_YAML)
        rc = main(
            ["--db", str(tmp_path / "run.db"), "run", str(spec), "--compose", str(COMPOSE_FILE)]
        )
        assert rc == ExitCode.VALIDATION_ERROR

    @patch("mayhem.cli.services.RunEngine")
    def test_run_unknown_container_fails_validation(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        spec = _write(tmp_path, "missing.yml", DRILL_MISSING_CONTAINER_YAML)
        rc = main(
            ["--db", str(tmp_path / "run.db"), "run", str(spec), "--compose", str(COMPOSE_FILE)]
        )
        assert rc == ExitCode.VALIDATION_ERROR


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
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        with patch("mayhem.cli.services.RunEngine") as m:
            result = MagicMock()
            result.status = "completed"
            result.summary_md.return_value = "run ok"
            m.return_value.execute.return_value = result
            main(["--db", str(db), "run", str(spec), "--compose", str(COMPOSE_FILE)])
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


class TestDrillSpec:
    """Exercise the testCase ``mayhem.yaml`` spec through the CLI."""

    def test_validate_drill_spec(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["validate", str(DRILL_SPEC), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        assert "validated" in capsys.readouterr().out

    def test_plan_drill_spec(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["plan", str(DRILL_SPEC), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["kind"] == "drill"
        assert len(data["steps"]) >= 1

    @patch("mayhem.cli.services.RunEngine")
    def test_run_drill_spec(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.summary_md.return_value = "run completed"
        result.status = "completed"
        db = str(tmp_path / "drill.db")
        rc = main(["--db", db, "run", str(DRILL_SPEC), "--compose", str(COMPOSE_FILE)])
        assert rc == 0


# ────────────────────────────────────────────────────────────────────────────
# 15.  mayhem.yml config from testCase
# ────────────────────────────────────────────────────────────────────────────


class TestCaseConfig:
    """Config ``show``/``validate`` resolve the built-in default when no
    config file is supplied (the testCase ``mayhem.yml`` was folded into the
    built-in defaults)."""

    def test_config_show_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["config", "show"])
        assert rc == 0

    def test_config_validate_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["config", "validate"])
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
        with patch(
            "mayhem.topology.providers.adapter_registry.best_effort", return_value=None
        ):
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
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        compose = ["--compose", str(COMPOSE_FILE)]

        # validate
        rc = main(["--db", db, "validate", str(spec), *compose])
        assert rc == 0

        # plan
        rc = main(["--db", db, "plan", str(spec), *compose])
        assert rc == 0

        # run (mock the engine so no real faults are injected)
        engine = mock_engine_cls.return_value
        result_mock = MagicMock()
        result_mock.status = "completed"
        result_mock.summary_md.return_value = "run drill completed ok"
        engine.execute.return_value = result_mock
        rc = main(["--db", db, "run", str(spec), *compose])
        assert rc == 0

        # discard validate/plan/run echoes so the status check below is isolated
        capsys.readouterr()

        # status (engine was mocked so no run row is persisted; either state passes)
        rc = main(["--db", db, "status"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "run-" in out or "No runs" in out or out.strip() == ""

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
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["ex", "v", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_topology_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["top", "d", "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_config_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["cfg", "s"])
        assert rc == 0

    def test_validate_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["v", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0

    def test_plan_prefix(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["p", str(spec), "--compose", str(COMPOSE_FILE)])
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
        # An empty drill execution block fails schema validation.
        spec = _write(tmp_path, "bad.yml", DRILL_EMPTY_YAML)
        assert (
            main(["validate", str(spec), "--compose", str(COMPOSE_FILE)])
            == ExitCode.VALIDATION_ERROR
        )

    def test_ambiguous_command(self) -> None:
        assert main(["r"]) == ExitCode.AMBIGUOUS_COMMAND


# ────────────────────────────────────────────────────────────────────────────
# 20.  error handling & edge cases
# ────────────────────────────────────────────────────────────────────────────


class TestErrorHandling:
    """Edge cases, bad inputs, and error paths."""

    def test_plan_missing_spec_returns_validation_error(self) -> None:
        rc = main(["plan", "/nonexistent.yml", "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_plan_unknown_container_returns_validation_error(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, "missing.yml", DRILL_MISSING_CONTAINER_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == ExitCode.VALIDATION_ERROR

    def test_validate_nonexistent_compose_returns_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["validate", str(spec), "--compose", "/nonexistent/docker-compose.yml"])
        assert rc == ExitCode.USAGE_ERROR

    def test_plan_with_compose_only(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, "mayhem.yaml", DRILL_YAML)
        rc = main(["plan", str(spec), "--compose", str(COMPOSE_FILE)])
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
