"""Comprehensive CLI command/subcommand audit tests.

These tests exercise every CLI command group and subcommand without requiring
Docker, Podman, Kubernetes, or any live runtime. External services are mocked
at the service seam so each command's argument parsing, error handling, output
format, and exit codes are verified in isolation.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

from mayhem.cli.app import app, main
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS
from mayhem.cli.exit_codes import ExitCode

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _invoke(*args: str, catch_exceptions: bool = True):
    return CliRunner().invoke(app, list(args), catch_exceptions=catch_exceptions)


def _main(args: list[str]):
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


def _tmp_db(tmp_path: Path) -> str:
    return str(tmp_path / "audit.db")


def _safe_json(output: str):
    """Parse JSON, returning None if output is empty or invalid."""
    output = output.strip()
    if not output:
        return None
    return json.loads(output)


# ===========================================================================
# discover
# ===========================================================================


class TestDiscover:
    """`mayhem discover` — topology/faults/capabilities/engines."""

    def test_topology_help(self):
        result = _invoke("discover", "topology", "--help")
        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_topology_auto_detect_missing_compose(self, tmp_path, monkeypatch):
        with monkeypatch.context() as mp:
            mp.chdir(str(tmp_path))
            result = _invoke("discover", "topology")
            # No compose file: mayhem falls back to the local host graph (exit 0)
            assert result.exit_code == 0
            payload = _safe_json(result.output)
            assert payload is not None
            assert "graph" in payload

    def test_topology_with_compose_file(self, tmp_path, monkeypatch):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  api:\n    image: nginx\n    container_name: api\n")
        with patch("mayhem.cli.services.build_graph") as mock_build:
            mock_build.return_value = SimpleNamespace(
                nodes=[],
                edges=[],
                container_names=list,
                node_ids_for_container=lambda _: [],
            )
            result = _invoke("discover", "topology", "--compose", str(compose))
        assert result.exit_code == 0, result.output

    def test_faults_list(self):
        result = _invoke("discover", "faults")
        assert result.exit_code == 0
        assert "proc.pause" in result.output

    def test_faults_explain(self):
        result = _invoke("discover", "faults", "--explain", "proc.pause")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert payload["id"] == "proc.pause"

    def test_faults_text(self):
        # `discover faults` has no --json flag; output is a text table.
        result = _invoke("discover", "faults")
        assert result.exit_code == 0
        assert "proc.pause" in result.output

    def test_capabilities_json(self):
        result = _invoke("discover", "capabilities", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert "capabilities" in payload
        for row in payload["capabilities"]:
            assert row["live_verified"] is False

    def test_engines(self, monkeypatch):
        from mayhem.infra.engine_probe import EngineDescriptor

        descriptors = [
            EngineDescriptor(
                name="docker",
                binary="/usr/bin/docker",
                binary_available=True,
                version="24.0",
                compose_supported=True,
                signals=("SIGTERM",),
                network_capabilities=("net.admin",),
                storage_capabilities=("overlay",),
            ),
        ]
        monkeypatch.setattr(
            "mayhem.infra.engine_probe.detect_available_engines", lambda: descriptors
        )
        result = _invoke("discover", "engines")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        names = [e["name"] for e in payload["engines"]]
        assert "docker" in names
        assert "podman" in names
        assert "kubernetes" in names


# ===========================================================================
# prepare
# ===========================================================================


class TestPrepare:
    """`mayhem prepare` — config/dependencies/validate/plan."""

    def test_config_show_json(self):
        result = _invoke("prepare", "config", "show", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert "config" in payload
        assert "sources" in payload

    def test_config_show_text(self):
        result = _invoke("prepare", "config", "show")
        assert result.exit_code == 0

    def test_config_explain_json(self):
        result = _invoke("prepare", "config", "explain", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, list)
        assert any(r["field"] == "policy" for r in payload)

    def test_config_validate_ok(self):
        result = _invoke("prepare", "config", "validate")
        assert result.exit_code == 0
        assert "configuration valid" in result.output.lower()

    def test_dependencies_check_help(self):
        result = _invoke("prepare", "dependencies", "check", "--help")
        assert result.exit_code == 0

    def test_dependencies_install_help(self):
        result = _invoke("prepare", "dependencies", "install", "--help")
        assert result.exit_code == 0

    def test_dependencies_compile_help(self):
        result = _invoke("prepare", "dependencies", "compile", "--help")
        assert result.exit_code == 0

    def test_validate_help(self):
        result = _invoke("prepare", "validate", "--help")
        assert result.exit_code == 0

    def test_validate_missing_spec(self, tmp_path):
        result = _invoke("prepare", "validate", str(tmp_path / "nonexistent.yaml"))
        assert result.exit_code != 0

    def test_plan_help(self):
        result = _invoke("prepare", "plan", "--help")
        assert result.exit_code == 0


# ===========================================================================
# experiment
# ===========================================================================


class TestExperiment:
    """`mayhem experiment` — show/validate/compose."""

    def test_show_help(self):
        result = _invoke("experiment", "show", "--help")
        assert result.exit_code == 0

    def test_show_valid_spec(self, tmp_path):
        spec = tmp_path / "drill.yaml"
        spec.write_text(
            "apiVersion: mayhem/v1\nkind: drill\nname: matrix-drill\n"
            "config:\n  risk_ceiling: critical\ncontainers:\n  api:\n"
            "    faults:\n      - fault: proc.pause\n        duration: 10s\n"
            "execution:\n  - parallel: [api]\n"
        )
        result = _invoke("experiment", "show", str(spec))
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert payload["name"] == "matrix-drill"

    def test_show_missing_spec(self):
        result = _invoke("experiment", "show", "/nonexistent/spec.yaml")
        assert result.exit_code != 0

    def test_validate_help(self):
        result = _invoke("experiment", "validate", "--help")
        assert result.exit_code == 0

    def test_compose_help(self):
        result = _invoke("experiment", "compose", "--help")
        assert result.exit_code == 0


# ===========================================================================
# extend
# ===========================================================================


class TestExtend:
    """`mayhem extend` — faults/capabilities/dependencies/providers."""

    def test_faults_help(self):
        result = _invoke("extend", "faults", "--help")
        assert result.exit_code == 0

    def test_capabilities_help(self):
        result = _invoke("extend", "capabilities", "--help")
        assert result.exit_code == 0

    def test_dependencies_help(self):
        result = _invoke("extend", "dependencies", "--help")
        assert result.exit_code == 0

    def test_providers_inspect_help(self):
        result = _invoke("extend", "providers", "inspect", "--help")
        assert result.exit_code == 0

    def test_providers_load_help(self):
        result = _invoke("extend", "providers", "load", "--help")
        assert result.exit_code == 0


# ===========================================================================
# inspect
# ===========================================================================


class TestInspect:
    """`mayhem inspect` — doctor/leases/runs/history/coverage/expert/next/... ."""

    def test_doctor_json(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "inspect", "doctor", "--json")
        assert result.exit_code in {0, 4}
        payload = _safe_json(result.output)
        assert payload is not None
        assert "diagnostics" in payload
        assert "summary" in payload

    def test_doctor_quiet(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "inspect", "doctor", "--quiet")
        assert result.exit_code in {0, 4}

    def test_leases_json(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "inspect", "leases", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert "leases" in payload

    def test_runs_json(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "inspect", "runs", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, list)

    def test_history_missing_run(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "inspect", "history", "nonexistent-run")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert "steps" in payload

    def test_coverage_help(self):
        result = _invoke("inspect", "coverage", "--help")
        assert result.exit_code == 0

    def test_expert_help(self):
        result = _invoke("inspect", "expert", "--help")
        assert result.exit_code == 0

    def test_next_help(self):
        result = _invoke("inspect", "next", "--help")
        assert result.exit_code == 0

    def test_replay_help(self):
        result = _invoke("inspect", "replay", "--help")
        assert result.exit_code == 0

    def test_graph_help(self):
        result = _invoke("inspect", "graph", "--help")
        assert result.exit_code == 0

    def test_coverage_diff_help(self):
        result = _invoke("inspect", "coverage-diff", "--help")
        assert result.exit_code == 0

    def test_residual_help(self):
        result = _invoke("inspect", "residual", "--help")
        assert result.exit_code == 0


# ===========================================================================
# lifecycle (run/maniac/verify/history)
# ===========================================================================


class TestLifecycle:
    """Lifecycle command edge cases."""

    def test_run_missing_spec(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "run", str(tmp_path / "nonexistent.yaml"))
        assert result.exit_code != 0

    def test_maniac_help(self):
        result = _invoke("maniac", "--help")
        assert result.exit_code == 0

    def test_maniac_no_spec(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "maniac")
        assert result.exit_code != 0

    def test_verify_missing_run(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "verify", "nonexistent-run")
        assert result.exit_code == 2

    def test_verify_help(self):
        result = _invoke("verify", "--help")
        assert result.exit_code == 0

    def test_inspect_history_help(self):
        result = _invoke("inspect", "history", "--help")
        assert result.exit_code == 0

    def test_inspect_history_missing_run(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "inspect", "history", "nonexistent-run")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert "steps" in payload


# ===========================================================================
# recover
# ===========================================================================


class TestRecover:
    """`mayhem recover` — status/plan/execute."""

    def test_recover_status_missing_run_ids(self):
        result = _invoke("recover", "status")
        assert result.exit_code == 2

    def test_recover_plan_missing_run_ids(self):
        result = _invoke("recover", "plan")
        assert result.exit_code == 2

    def test_recover_execute_missing_run_ids(self):
        result = _invoke("recover", "execute")
        assert result.exit_code == 2

    def test_recover_status_help(self):
        result = _invoke("recover", "status", "--help")
        assert result.exit_code == 0

    def test_recover_plan_help(self):
        result = _invoke("recover", "plan", "--help")
        assert result.exit_code == 0

    def test_recover_execute_help(self):
        result = _invoke("recover", "execute", "--help")
        assert result.exit_code == 0

    def test_recover_status_json(self, tmp_path, monkeypatch):
        db = _tmp_db(tmp_path)
        with patch("mayhem.cli.lifecycle._recovery_service") as mock_service:
            mock_result = SimpleNamespace(
                state=SimpleNamespace(value="not_needed"),
                run_ids=("run-1",),
                leases=[],
                model_dump=lambda **kw: {"state": "not_needed", "run_ids": ["run-1"], "leases": []},
            )
            mock_service.return_value.status.return_value = mock_result
            result = _invoke("--db", db, "recover", "status", "run-1", "--json")
            assert result.exit_code == 0
            payload = _safe_json(result.output)
            assert payload is not None
            assert payload["state"] == "not_needed"

    def test_recover_plan_json(self, tmp_path, monkeypatch):
        db = _tmp_db(tmp_path)
        with patch("mayhem.cli.lifecycle._recovery_service") as mock_service:
            mock_result = SimpleNamespace(
                state=SimpleNamespace(value="not_needed"),
                run_ids=("run-1",),
                leases=[],
                model_dump=lambda **kw: {"state": "not_needed", "run_ids": ["run-1"], "leases": []},
            )
            mock_service.return_value.plan.return_value = mock_result
            result = _invoke("--db", db, "recover", "plan", "run-1", "--json")
            assert result.exit_code == 0
            payload = _safe_json(result.output)
            assert payload is not None
            assert payload["state"] == "not_needed"


# ===========================================================================
# bundle
# ===========================================================================


class TestBundle:
    """`mayhem bundle` — build/show/verify/keygen/keys/sign/signatures."""

    def test_bundle_help(self):
        result = _invoke("bundle", "--help")
        assert result.exit_code == 0

    def test_bundle_build_help(self):
        result = _invoke("bundle", "build", "--help")
        assert result.exit_code == 0

    def test_bundle_show_help(self):
        result = _invoke("bundle", "show", "--help")
        assert result.exit_code == 0

    def test_bundle_verify_help(self):
        result = _invoke("bundle", "verify", "--help")
        assert result.exit_code == 0

    def test_bundle_keygen_help(self):
        result = _invoke("bundle", "keygen", "--help")
        assert result.exit_code == 0

    def test_bundle_keys_help(self):
        result = _invoke("bundle", "keys", "--help")
        assert result.exit_code == 0

    def test_bundle_sign_help(self):
        result = _invoke("bundle", "sign", "--help")
        assert result.exit_code == 0

    def test_bundle_signatures_help(self):
        result = _invoke("bundle", "signatures", "--help")
        assert result.exit_code == 0


# ===========================================================================
# prove
# ===========================================================================


class TestProve:
    """`mayhem prove` — safety proof rendering."""

    def test_prove_help(self):
        result = _invoke("prove", "--help")
        assert result.exit_code == 0

    def test_prove_missing_run(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "prove", "nonexistent-run")
        assert result.exit_code != 0


# ===========================================================================
# policy
# ===========================================================================


class TestPolicy:
    """`mayhem policy` — publish/list/show/retire/resolve/explain."""

    def test_policy_help(self):
        result = _invoke("policy", "--help")
        assert result.exit_code == 0

    def test_policy_publish_help(self):
        result = _invoke("policy", "publish", "--help")
        assert result.exit_code == 0

    def test_policy_list_help(self):
        result = _invoke("policy", "list", "--help")
        assert result.exit_code == 0

    def test_policy_show_help(self):
        result = _invoke("policy", "show", "--help")
        assert result.exit_code == 0

    def test_policy_retire_help(self):
        result = _invoke("policy", "retire", "--help")
        assert result.exit_code == 0

    def test_policy_resolve_help(self):
        result = _invoke("policy", "resolve", "--help")
        assert result.exit_code == 0

    def test_policy_explain_help(self):
        result = _invoke("policy", "explain", "--help")
        assert result.exit_code == 0

    def test_policy_publish_missing_file(self, tmp_path):
        result = _invoke("policy", "publish", str(tmp_path / "nonexistent.yaml"))
        assert result.exit_code != 0

    def test_policy_list_empty(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "policy", "list", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, dict)
        assert payload["count"] == 0
        assert payload["bundles"] == []


# ===========================================================================
# secrets
# ===========================================================================


class TestSecrets:
    """`mayhem secrets` — grant/revoke/list/explain."""

    def test_secrets_help(self):
        result = _invoke("secrets", "--help")
        assert result.exit_code == 0

    def test_secrets_grant_help(self):
        result = _invoke("secrets", "grant", "--help")
        assert result.exit_code == 0

    def test_secrets_revoke_help(self):
        result = _invoke("secrets", "revoke", "--help")
        assert result.exit_code == 0

    def test_secrets_list_help(self):
        result = _invoke("secrets", "list", "--help")
        assert result.exit_code == 0

    def test_secrets_explain_help(self):
        result = _invoke("secrets", "explain", "--help")
        assert result.exit_code == 0

    def test_secrets_list_empty(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "secrets", "list", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, dict)
        assert payload["count"] == 0
        assert payload["grants"] == []


# ===========================================================================
# agent
# ===========================================================================


class TestAgent:
    """`mayhem agent` — enroll/list/show/revoke."""

    def test_agent_help(self):
        result = _invoke("agent", "--help")
        assert result.exit_code == 0

    def test_agent_enroll_help(self):
        result = _invoke("agent", "enroll", "--help")
        assert result.exit_code == 0

    def test_agent_list_help(self):
        result = _invoke("agent", "list", "--help")
        assert result.exit_code == 0

    def test_agent_show_help(self):
        result = _invoke("agent", "show", "--help")
        assert result.exit_code == 0

    def test_agent_revoke_help(self):
        result = _invoke("agent", "revoke", "--help")
        assert result.exit_code == 0

    def test_agent_list_empty(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "agent", "list", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, dict)
        assert payload["count"] == 0
        assert payload["agents"] == []


# ===========================================================================
# stop
# ===========================================================================


class TestStop:
    """`mayhem stop` — emergency stop."""

    def test_stop_help(self):
        result = _invoke("stop", "--help")
        assert result.exit_code == 0

    def test_stop_missing_run_id(self):
        result = _invoke("stop")
        assert result.exit_code != 0

    def test_stop_nonexistent_run(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "stop", "nonexistent-run")
        assert result.exit_code != 0


# ===========================================================================
# janitor
# ===========================================================================


class TestJanitor:
    """`mayhem janitor` — lease cleanup."""

    def test_janitor_help(self):
        result = _invoke("janitor", "--help")
        assert result.exit_code == 0

    def test_janitor_json(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _invoke("--db", db, "janitor", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert "execute" in payload


# ===========================================================================
# ci
# ===========================================================================


class TestCI:
    """`mayhem ci` — check/status/summary/suite/workflow."""

    def test_ci_help(self):
        result = _invoke("ci", "--help")
        assert result.exit_code == 0

    def test_ci_check_help(self):
        result = _invoke("ci", "check", "--help")
        assert result.exit_code == 0

    def test_ci_status_help(self):
        result = _invoke("ci", "status", "--help")
        assert result.exit_code == 0

    def test_ci_summary_help(self):
        result = _invoke("ci", "summary", "--help")
        assert result.exit_code == 0

    def test_ci_suite_help(self):
        result = _invoke("ci", "suite", "--help")
        assert result.exit_code == 0

    def test_ci_workflow_help(self):
        result = _invoke("ci", "workflow", "--help")
        assert result.exit_code == 0


# ===========================================================================
# cloud
# ===========================================================================


class TestCloud:
    """`mayhem cloud` — capabilities/check-permission/estimate-cost."""

    def test_cloud_help(self):
        result = _invoke("cloud", "--help")
        assert result.exit_code == 0

    def test_cloud_capabilities_help(self):
        result = _invoke("cloud", "capabilities", "--help")
        assert result.exit_code == 0

    def test_cloud_check_permission_help(self):
        result = _invoke("cloud", "check-permission", "--help")
        assert result.exit_code == 0

    def test_cloud_estimate_cost_help(self):
        result = _invoke("cloud", "estimate-cost", "--help")
        assert result.exit_code == 0


# ===========================================================================
# marketplace
# ===========================================================================


class TestMarketplace:
    """`mayhem marketplace` — inspect/install/list/search/template."""

    def test_marketplace_help(self):
        result = _invoke("marketplace", "--help")
        assert result.exit_code == 0

    def test_marketplace_inspect_help(self):
        result = _invoke("marketplace", "inspect", "--help")
        assert result.exit_code == 0

    def test_marketplace_install_help(self):
        result = _invoke("marketplace", "install", "--help")
        assert result.exit_code == 0

    def test_marketplace_list_help(self):
        result = _invoke("marketplace", "list", "--help")
        assert result.exit_code == 0

    def test_marketplace_search_help(self):
        result = _invoke("marketplace", "search", "--help")
        assert result.exit_code == 0

    def test_marketplace_template_help(self):
        result = _invoke("marketplace", "template", "--help")
        assert result.exit_code == 0


# ===========================================================================
# sandbox
# ===========================================================================


class TestSandbox:
    """`mayhem sandbox` — down/status/up."""

    def test_sandbox_help(self):
        result = _invoke("sandbox", "--help")
        assert result.exit_code == 0

    def test_sandbox_down_help(self):
        result = _invoke("sandbox", "down", "--help")
        assert result.exit_code == 0

    def test_sandbox_status_help(self):
        result = _invoke("sandbox", "status", "--help")
        assert result.exit_code == 0

    def test_sandbox_up_help(self):
        result = _invoke("sandbox", "up", "--help")
        assert result.exit_code == 0


# ===========================================================================
# support-bundle
# ===========================================================================


class TestSupportBundle:
    """`mayhem support-bundle` — build."""

    def test_support_bundle_help(self):
        result = _invoke("support-bundle", "--help")
        assert result.exit_code == 0

    def test_support_bundle_build_help(self):
        result = _invoke("support-bundle", "build", "--help")
        assert result.exit_code == 0


# ===========================================================================
# upgrade
# ===========================================================================


class TestUpgrade:
    """`mayhem upgrade` — channels/check."""

    def test_upgrade_help(self):
        result = _invoke("upgrade", "--help")
        assert result.exit_code == 0

    def test_upgrade_channels_help(self):
        result = _invoke("upgrade", "channels", "--help")
        assert result.exit_code == 0

    def test_upgrade_check_help(self):
        result = _invoke("upgrade", "check", "--help")
        assert result.exit_code == 0


# ===========================================================================
# enterprise
# ===========================================================================


class TestEnterprise:
    """`mayhem enterprise` — compliance-map/walkthrough."""

    def test_enterprise_help(self):
        result = _invoke("enterprise", "--help")
        assert result.exit_code == 0

    def test_enterprise_compliance_map_help(self):
        result = _invoke("enterprise", "compliance-map", "--help")
        assert result.exit_code == 0

    def test_enterprise_walkthrough_help(self):
        result = _invoke("enterprise", "walkthrough", "--help")
        assert result.exit_code == 0


# ===========================================================================
# game-day
# ===========================================================================


class TestGameDay:
    """`mayhem game-day` — create/approve/show/list/start/pause/complete."""

    def test_game_day_help(self):
        result = _invoke("game-day", "--help")
        assert result.exit_code == 0

    def test_game_day_create_help(self):
        result = _invoke("game-day", "create", "--help")
        assert result.exit_code == 0

    def test_game_day_approve_help(self):
        result = _invoke("game-day", "approve", "--help")
        assert result.exit_code == 0

    def test_game_day_show_help(self):
        result = _invoke("game-day", "show", "--help")
        assert result.exit_code == 0

    def test_game_day_list_help(self):
        result = _invoke("game-day", "list", "--help")
        assert result.exit_code == 0

    def test_game_day_start_help(self):
        result = _invoke("game-day", "start", "--help")
        assert result.exit_code == 0

    def test_game_day_pause_help(self):
        result = _invoke("game-day", "pause", "--help")
        assert result.exit_code == 0

    def test_game_day_complete_help(self):
        result = _invoke("game-day", "complete", "--help")
        assert result.exit_code == 0


# ===========================================================================
# game-day-step
# ===========================================================================


class TestGameDayStep:
    """`mayhem game-day-step` — hold/inject/note/release/steps."""

    def test_game_day_step_help(self):
        result = _invoke("game-day-step", "--help")
        assert result.exit_code == 0

    def test_game_day_step_hold_help(self):
        result = _invoke("game-day-step", "hold", "--help")
        assert result.exit_code == 0

    def test_game_day_step_inject_help(self):
        result = _invoke("game-day-step", "inject", "--help")
        assert result.exit_code == 0

    def test_game_day_step_note_help(self):
        result = _invoke("game-day-step", "note", "--help")
        assert result.exit_code == 0

    def test_game_day_step_release_help(self):
        result = _invoke("game-day-step", "release", "--help")
        assert result.exit_code == 0

    def test_game_day_step_steps_help(self):
        result = _invoke("game-day-step", "steps", "--help")
        assert result.exit_code == 0


# ===========================================================================
# schedule
# ===========================================================================


class TestSchedule:
    """`mayhem schedule` — add/delete/disable/enable/fairness/list/next/runs/show/tick."""

    def test_schedule_help(self):
        result = _invoke("schedule", "--help")
        assert result.exit_code == 0

    def test_schedule_add_help(self):
        result = _invoke("schedule", "add", "--help")
        assert result.exit_code == 0

    def test_schedule_delete_help(self):
        result = _invoke("schedule", "delete", "--help")
        assert result.exit_code == 0

    def test_schedule_disable_help(self):
        result = _invoke("schedule", "disable", "--help")
        assert result.exit_code == 0

    def test_schedule_enable_help(self):
        result = _invoke("schedule", "enable", "--help")
        assert result.exit_code == 0

    def test_schedule_fairness_help(self):
        result = _invoke("schedule", "fairness", "--help")
        assert result.exit_code == 0

    def test_schedule_list_help(self):
        result = _invoke("schedule", "list", "--help")
        assert result.exit_code == 0

    def test_schedule_next_help(self):
        result = _invoke("schedule", "next", "--help")
        assert result.exit_code == 0

    def test_schedule_runs_help(self):
        result = _invoke("schedule", "runs", "--help")
        assert result.exit_code == 0

    def test_schedule_show_help(self):
        result = _invoke("schedule", "show", "--help")
        assert result.exit_code == 0

    def test_schedule_tick_help(self):
        result = _invoke("schedule", "tick", "--help")
        assert result.exit_code == 0


# ===========================================================================
# risk-preview
# ===========================================================================


class TestRiskPreview:
    """`mayhem risk-preview` — nodes/plan."""

    def test_risk_preview_help(self):
        result = _invoke("risk-preview", "--help")
        assert result.exit_code == 0

    def test_risk_preview_nodes_help(self):
        result = _invoke("risk-preview", "nodes", "--help")
        assert result.exit_code == 0

    def test_risk_preview_plan_help(self):
        result = _invoke("risk-preview", "plan", "--help")
        assert result.exit_code == 0


# ===========================================================================
# boundary
# ===========================================================================


class TestBoundary:
    """`mayhem boundary` — report/review."""

    def test_boundary_help(self):
        result = _invoke("boundary", "--help")
        assert result.exit_code == 0

    def test_boundary_report_help(self):
        result = _invoke("boundary", "report", "--help")
        assert result.exit_code == 0

    def test_boundary_review_help(self):
        result = _invoke("boundary", "review", "--help")
        assert result.exit_code == 0


# ===========================================================================
# api
# ===========================================================================


class TestAPI:
    """`mayhem api` — openapi/pages/parameters/routes/serve/ui."""

    def test_api_help(self):
        result = _invoke("api", "--help")
        assert result.exit_code == 0

    def test_api_openapi_help(self):
        result = _invoke("api", "openapi", "--help")
        assert result.exit_code == 0

    def test_api_pages_help(self):
        result = _invoke("api", "pages", "--help")
        assert result.exit_code == 0

    def test_api_parameters_help(self):
        result = _invoke("api", "parameters", "--help")
        assert result.exit_code == 0

    def test_api_routes_help(self):
        result = _invoke("api", "routes", "--help")
        assert result.exit_code == 0

    def test_api_serve_help(self):
        result = _invoke("api", "serve", "--help")
        assert result.exit_code == 0

    def test_api_ui_help(self):
        result = _invoke("api", "ui", "--help")
        assert result.exit_code == 0


# ===========================================================================
# lowlevel
# ===========================================================================


class TestLowlevel:
    """`mayhem lowlevel` — admit/explain/primitives."""

    def test_lowlevel_help(self):
        result = _invoke("lowlevel", "--help")
        assert result.exit_code == 0

    def test_lowlevel_admit_help(self):
        result = _invoke("lowlevel", "admit", "--help")
        assert result.exit_code == 0

    def test_lowlevel_explain_help(self):
        result = _invoke("lowlevel", "explain", "--help")
        assert result.exit_code == 0

    def test_lowlevel_primitives_help(self):
        result = _invoke("lowlevel", "primitives", "--help")
        assert result.exit_code == 0


# ===========================================================================
# probe
# ===========================================================================


class TestProbe:
    """`mayhem probe` — build/catalogue/condition/connectors/tolerances/uncover."""

    def test_probe_help(self):
        result = _invoke("probe", "--help")
        assert result.exit_code == 0

    def test_probe_build_help(self):
        result = _invoke("probe", "build", "--help")
        assert result.exit_code == 0

    def test_probe_catalogue_help(self):
        result = _invoke("probe", "catalogue", "--help")
        assert result.exit_code == 0

    def test_probe_condition_help(self):
        result = _invoke("probe", "condition", "--help")
        assert result.exit_code == 0

    def test_probe_connectors_help(self):
        result = _invoke("probe", "connectors", "--help")
        assert result.exit_code == 0

    def test_probe_tolerances_help(self):
        result = _invoke("probe", "tolerances", "--help")
        assert result.exit_code == 0

    def test_probe_uncover_help(self):
        result = _invoke("probe", "uncover", "--help")
        assert result.exit_code == 0


# ===========================================================================
# ha
# ===========================================================================


class TestHA:
    """`mayhem ha` — cert/promote/rotate/update."""

    def test_ha_help(self):
        result = _invoke("ha", "--help")
        assert result.exit_code == 0

    def test_ha_cert_help(self):
        result = _invoke("ha", "cert", "--help")
        assert result.exit_code == 0

    def test_ha_promote_help(self):
        result = _invoke("ha", "promote", "--help")
        assert result.exit_code == 0

    def test_ha_rotate_help(self):
        result = _invoke("ha", "rotate", "--help")
        assert result.exit_code == 0

    def test_ha_update_help(self):
        result = _invoke("ha", "update", "--help")
        assert result.exit_code == 0


# ===========================================================================
# commands / completion
# ===========================================================================


class TestCommandsAndCompletion:
    """`mayhem commands` and `mayhem completion`."""

    def test_commands_show_json(self):
        result = _invoke("commands", "show", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, list)
        assert len(payload) == len(COMMAND_SPECS)

    def test_commands_show_yaml(self):
        result = _invoke("commands", "show", "--format", "yaml")
        assert result.exit_code == 0

    def test_completion_help(self):
        result = _invoke("completion", "--help")
        assert result.exit_code == 0


# ===========================================================================
# Command registry contract tests
# ===========================================================================


class TestCommandRegistryContract:
    """The command registry must match the Click app surface exactly."""

    NAMESPACE_NAMES = frozenset(
        {
            "developer",
            "drill",
            "environment",
            "evidence",
            "extensions",
            "governance",
            "orchestration",
            "platform",
            "runs",
            "workspace",
        }
    )

    def test_registry_names_match_app_commands(self):
        registry_names = {spec.name for spec in COMMAND_SPECS}
        expected = registry_names | self.NAMESPACE_NAMES
        assert set(app.commands) == expected, (
            f"missing={sorted(expected - set(app.commands))} "
            f"extra={sorted(set(app.commands) - expected)}"
        )

    def test_every_command_has_help_text(self):
        for name in app.list_commands(None):
            if name in self.NAMESPACE_NAMES:
                continue  # namespaces have help text set via NAMESPACE_SPECS
            assert name in COMMAND_HELP, f"{name} missing from COMMAND_HELP"
            help_str = app.commands[name].get_short_help_str(limit=100)
            assert help_str
            assert "deprecated" not in help_str.lower()

    def test_commands_show_json_count(self):
        result = _invoke("commands", "show", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, list)
        # `commands show` inventories COMMAND_SPECS (40 original commands),
        # not the 10 namespaces registered separately via NAMESPACE_SPECS.
        assert len(payload) == len(COMMAND_SPECS)

    def test_every_spec_has_unique_name(self):
        names = [spec.name for spec in COMMAND_SPECS]
        assert len(names) == len(set(names))

    def test_workflow_closed_vocabulary(self):
        valid = {"discover", "prepare", "experiment", "run", "inspect", "recover", "extend"}
        for spec in COMMAND_SPECS:
            assert spec.workflow in valid, f"{spec.name}: workflow {spec.workflow!r} not in {valid}"

    def test_mutating_flag_is_bool(self):
        for spec in COMMAND_SPECS:
            assert isinstance(spec.mutating, bool)

    def test_help_group_is_nonempty(self):
        for spec in COMMAND_SPECS:
            assert spec.help_group
            assert isinstance(spec.help_group, str)


# ===========================================================================
# Global options and exit codes
# ===========================================================================


class TestGlobalOptions:
    """Root-level options propagate correctly."""

    def test_version(self):
        result = _invoke("--version")
        assert result.exit_code == 0
        assert "mayhem" in result.output

    def test_unknown_command_usage_error(self):
        result = _invoke("nonexistent-command")
        assert result.exit_code == 2

    def test_podman_and_kubernetes_mutually_exclusive(self):
        result = _invoke("--podman", "--kubernetes", "commands", "show")
        assert result.exit_code == 2

    def test_format_json(self):
        result = _invoke("commands", "show", "--json")
        assert result.exit_code == 0
        payload = _safe_json(result.output)
        assert payload is not None
        assert isinstance(payload, list)

    def test_no_color_sets_env(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        result = _invoke("--no-color", "commands", "show")
        assert result.exit_code == 0
        import os

        assert os.environ.get("NO_COLOR") == "1"

    def test_dry_run_flag_accepted(self):
        result = _invoke("--dry-run", "commands", "show")
        assert result.exit_code == 0

    def test_skip_gate_flag_accepted(self):
        result = _invoke("--skip-gate", "commands", "show")
        assert result.exit_code == 0

    def test_allow_critical_flag_accepted(self):
        result = _invoke("--allow-critical", "commands", "show")
        assert result.exit_code == 0

    def test_debug_flag_accepted(self):
        result = _invoke("--debug", "commands", "show")
        assert result.exit_code == 0

    def test_target_flag_accepted(self):
        result = _invoke("--target", "staging", "commands", "show")
        assert result.exit_code == 0

    def test_db_flag_accepted(self, tmp_path):
        db = str(tmp_path / "test.db")
        result = _invoke("--db", db, "commands", "show")
        assert result.exit_code == 0

    def test_config_flag_accepted(self, tmp_path):
        config = tmp_path / "mayhem.yaml"
        config.write_text("apiVersion: mayhem/v1\npolicy:\n  risk_ceiling: medium\n")
        result = _invoke("--config", str(config), "prepare", "config", "show")
        assert result.exit_code == 0


# ===========================================================================
# Exit codes
# ===========================================================================


class TestExitCodes:
    """Exit codes are stable across refactors."""

    def test_success_is_zero(self):
        assert ExitCode.SUCCESS == 0

    def test_usage_error_is_two(self):
        assert ExitCode.USAGE_ERROR == 2

    def test_config_error_is_three(self):
        assert ExitCode.CONFIG_ERROR == 3

    def test_validation_error_is_four(self):
        assert ExitCode.VALIDATION_ERROR == 4

    def test_safety_refusal_is_five(self):
        assert ExitCode.SAFETY_REFUSAL == 5

    def test_experiment_failure_is_six(self):
        assert ExitCode.EXPERIMENT_FAILURE == 6

    def test_general_failure_is_one(self):
        assert ExitCode.GENERAL_FAILURE == 1

    def test_ambiguous_command_is_ten(self):
        assert ExitCode.AMBIGUOUS_COMMAND == 10

    def test_recovery_failure_is_seven(self):
        assert ExitCode.RECOVERY_FAILURE == 7

    def test_agent_error_is_eight(self):
        assert ExitCode.AGENT_ERROR == 8

    def test_toolkit_error_is_nine(self):
        assert ExitCode.TOOLKIT_ERROR == 9
