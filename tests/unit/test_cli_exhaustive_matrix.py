from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from click.testing import CliRunner

from mayhem.cli import config_cmd, lifecycle
from mayhem.cli import inspect as inspect_cli
from mayhem.cli.app import _STATE, app, main
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.topology import TopologyGraph
from mayhem.providers.loader import ProviderInspection, ProviderLoadReport

if TYPE_CHECKING:
    from pathlib import Path

ACTIVE_ROOTS = {
    "campaign",
    "commands",
    "discover",
    "doctor",
    "experiment",
    "extend",
    "init",
    "inspect",
    "janitor",
    "maniac",
    "prepare",
    "recover",
    "run",
    "verify",
}

ACTIVE_GROUP_PATHS = {
    "campaign": (
        "list",
        "create",
        "show",
        "status",
        "delete",
        "approve",
        "pause",
        "resume",
        "plan",
        "start",
        "archive",
        "abort",
        "add-experiment",
        "run",
    ),
    "commands": ("show",),
    "discover": ("topology", "faults", "capabilities", "engines"),
    "experiment": ("show", "validate", "explore"),
    "extend": ("faults", "capabilities", "dependencies", "providers"),
    "prepare": (
        "config",
        "validate",
        "dependencies",
        "check",
        "plan",
    ),
    "inspect": ("doctor", "run", "leases", "runs", "history", "coverage", "expert", "next"),
    "recover": ("status", "plan", "execute"),
}

REMOVED_ROOTS = {
    "cfg",
    "config",
    "coverage",
    "dependency",
    "expert",
    "explore",
    "history",
    "next",
    "plan",
    "status",
    "toolkit",
    "topology",
    "validate",
}

DRILL = """\
kind: drill
apiVersion: mayhem/v1
name: matrix-drill
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
execution:
  - parallel: [testcase-api]
"""


@pytest.fixture(autouse=True)
def _restore_cli_state() -> None:
    original = _STATE.copy()
    yield
    _STATE.clear()
    _STATE.update(original)


def _run(*args: str) -> Any:
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def _main(args: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(args)
    return code, stdout.getvalue(), stderr.getvalue()


def _all_group_paths() -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    for group, children in ACTIVE_GROUP_PATHS.items():
        paths.append((group,))
        for child in children:
            paths.append((group, child))
            command = app.commands[group].commands[child]
            for nested_name in sorted(getattr(command, "commands", {})):
                paths.append((group, child, nested_name))
    return paths


def _config_stub() -> SimpleNamespace:
    return SimpleNamespace(
        model_dump=lambda **kwargs: {"target": {"containers": []}, "runtime": "docker"}
    )


def _prepared_stub() -> SimpleNamespace:
    return SimpleNamespace(fingerprint="f" * 64, recovery_grace=300.0)


def _compiled_stub() -> SimpleNamespace:
    return SimpleNamespace(
        run_id="r-matrix",
        plan=SimpleNamespace(steps=(), model_dump_json=lambda **kwargs: '{"run_id":"r-matrix"}'),
    )


def _install_compile_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lifecycle, "_graph_from", lambda *args, **kwargs: (TopologyGraph(), "fake"))
    monkeypatch.setattr(lifecycle, "prepare", lambda **kwargs: _prepared_stub())
    monkeypatch.setattr(lifecycle, "plan_from_spec", lambda *args, **kwargs: _compiled_stub())


def test_root_inventory_and_concise_metadata_are_exact() -> None:
    assert set(app.commands) == ACTIVE_ROOTS
    assert {spec.name for spec in COMMAND_SPECS} == ACTIVE_ROOTS
    for spec in COMMAND_SPECS:
        command = app.commands[spec.name]
        assert command.help == COMMAND_HELP[spec.name]
        assert command.get_short_help_str(limit=120)
        assert "deprecated" not in (command.help or "").lower()
        assert "replacement" not in (command.help or "").lower()
        assert "deprecated" not in str(spec)
        assert "replacement" not in str(spec)


@pytest.mark.parametrize("name", sorted(ACTIVE_ROOTS))
def test_every_active_root_parses_help(name: str) -> None:
    result = _run(name, "--help")
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert COMMAND_HELP[name] in result.output


@pytest.mark.parametrize("path", _all_group_paths())
def test_every_active_group_and_subcommand_parses_help(path: tuple[str, ...]) -> None:
    result = _run(*path, "--help")
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "Options:" in result.output or "Commands:" in result.output


@pytest.mark.parametrize("group", sorted(ACTIVE_GROUP_PATHS))
def test_group_child_inventory_is_exact(group: str) -> None:
    assert set(app.commands[group].commands) == set(ACTIVE_GROUP_PATHS[group])


def test_nested_group_inventory_is_exact() -> None:
    assert set(app.commands["prepare"].commands["config"].commands) == {
        "show",
        "explain",
        "validate",
    }
    assert set(app.commands["prepare"].commands["dependencies"].commands) == {
        "check",
        "install",
        "compile",
    }
    assert set(app.commands["extend"].commands["providers"].commands) == {"inspect", "load"}


@pytest.mark.parametrize("name", sorted(REMOVED_ROOTS))
def test_removed_root_names_are_absent_and_usage_errors(name: str) -> None:
    assert app.commands.get(name) is None
    result = _run(name, "--help")
    assert result.exit_code == 2
    assert "No command matches" in result.output


def test_command_map_has_only_active_rows_and_stable_formats() -> None:
    runner = CliRunner()
    text_result = runner.invoke(app, ["commands", "show"], catch_exceptions=False)
    json_result = runner.invoke(app, ["commands", "show", "--json"], catch_exceptions=False)
    format_json_result = runner.invoke(
        app, ["commands", "show", "--format", "json"], catch_exceptions=False
    )
    yaml_result = runner.invoke(
        app, ["commands", "show", "--format", "yaml"], catch_exceptions=False
    )

    assert text_result.exit_code == 0
    assert json_result.exit_code == 0
    assert format_json_result.exit_code == 0
    assert yaml_result.exit_code == 0
    rows = json.loads(json_result.output)
    assert json.loads(format_json_result.output) == rows
    assert yaml.safe_load(yaml_result.output) == rows
    assert {row["command"] for row in rows} == ACTIVE_ROOTS
    assert all("deprecated" not in row for row in rows)
    assert all("replacement" not in row for row in rows)
    assert all(
        set(row)
        == {
            "command",
            "workflow",
            "help_group",
            "mutating",
            "sample_invocation",
        }
        for row in rows
    )
    assert all(name in text_result.output for name in ACTIVE_ROOTS)


def test_unique_prefixes_resolve_at_each_level() -> None:
    prefixes = (
        ("p", "v", "--help"),
        ("inspect", "coverage", "--help"),
        ("experi", "s", "--help"),
    )
    for path in prefixes:
        result = _run(*path)
        assert result.exit_code == 0, path
        assert "Usage:" in result.output


def test_ambiguous_prefix_returns_ambiguous_command_envelope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["c"])
    captured = capsys.readouterr()
    assert code == int(ExitCode.AMBIGUOUS_COMMAND)
    assert "campaign" in captured.err
    assert "commands" in captured.err
    assert "ambiguous" in captured.err


@pytest.mark.xfail(
    strict=True,
    reason="root prefix resolution runs before the app callback records the global format",
)
def test_root_prefix_resolution_honors_global_json_format(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["--format", "json", "unknown-root"])
    payload = json.loads(capsys.readouterr().err)
    assert code == int(ExitCode.USAGE_ERROR)
    assert payload["code"] == "usage_error"


def test_global_context_options_propagate_to_service_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "global.db"
    config = tmp_path / "mayhem.yaml"
    captured: dict[str, object] = {}

    def effective_config(
        config_path: str | None,
        profile: str | None,
        policy: str | None,
    ) -> tuple[SimpleNamespace, dict[str, str]]:
        captured.update(
            {
                "config_path": config_path,
                "profile": profile,
                "policy": policy,
            }
        )
        return _config_stub(), {"base": config_path or "default"}

    monkeypatch.setattr(config_cmd, "effective_config", effective_config)
    code, output, error = _main(
        [
            "--db",
            str(db),
            "--config",
            str(config),
            "--profile",
            "ci",
            "--policy",
            "strict",
            "--target",
            "staging",
            "prepare",
            "config",
            "show",
            "--json",
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    assert captured == {
        "config_path": str(config),
        "profile": "ci",
        "policy": "strict",
    }
    assert json.loads(output)["config"] == _config_stub().model_dump(mode="json")
    assert error == ""


def test_global_format_and_no_color_propagate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    db = tmp_path / "state.db"
    code = main(
        [
            "--db",
            str(db),
            "--format",
            "json",
            "--no-color",
            "commands",
            "show",
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    assert os.environ["NO_COLOR"] == "1"
    from mayhem.cli.app import _STATE

    assert _STATE["format"] == "json"
    assert _STATE["no_color"] == "1"


def test_global_usage_errors_have_stable_codes_and_json_envelopes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(_STATE, "format", "text")
    code = main(["unknown-root"])
    error = capsys.readouterr().err
    assert code == int(ExitCode.USAGE_ERROR)
    assert "No command matches 'unknown-root'." in error

    code = main(["--format", "json", "--podman", "--kubernetes", "commands", "show"])
    error = capsys.readouterr().err
    assert code == int(ExitCode.USAGE_ERROR)
    assert "mutually exclusive" in error


def test_global_options_reach_diagnostics_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "inspect.db"
    config = tmp_path / "config.yaml"
    captured: dict[str, object] = {}

    def diagnostics(**kwargs: object) -> list[object]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr(inspect_cli, "run_diagnostics", diagnostics)
    monkeypatch.setattr(inspect_cli, "structured_diagnostics", lambda records: [])
    code = main(
        [
            "--db",
            str(db),
            "--config",
            str(config),
            "--profile",
            "ci",
            "--policy",
            "strict",
            "--target",
            "staging",
            "inspect",
            "doctor",
            "--json",
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    assert captured["db_path"] == str(db)
    assert captured["config_path"] == str(config)
    assert captured["profile"] == "ci"
    assert captured["policy"] == "strict"
    assert captured["target"] == "staging"


def test_domain_config_refusal_maps_to_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "bad.yaml"

    def reject(*args: object, **kwargs: object) -> tuple[object, dict[str, str]]:
        raise SchemaValidationError("config", "unknown profile")

    monkeypatch.setattr(config_cmd, "effective_config", reject)
    code = main(["--format", "json", "--config", str(config), "prepare", "config", "show"])
    payload = json.loads(capsys.readouterr().err)
    assert code == int(ExitCode.CONFIG_ERROR)
    assert payload["code"] == "config_error"
    assert payload["exit_code"] == int(ExitCode.CONFIG_ERROR)
    assert "unknown profile" in payload["message"]


def test_discover_faults_has_static_catalog_success_and_json_explain() -> None:
    result = _run("discover", "faults")
    assert result.exit_code == 0
    assert "proc.pause" in result.output
    explained = _run("discover", "faults", "--explain", "proc.pause")
    assert explained.exit_code == 0
    assert json.loads(explained.output)["id"] == "proc.pause"


def test_discover_engines_and_capabilities_use_fakes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptors = [
        SimpleNamespace(
            name=name,
            binary=f"/fake/{name}",
            binary_available=True,
            version="fake",
            compose_supported=True,
            signals=("SIGTERM",),
            network_capabilities=("net.admin",),
            storage_capabilities=("overlay",),
        )
        for name in ("podman", "docker")
    ]
    monkeypatch.setattr(
        "mayhem.domain.runtime_adapter.detect_available_engines",
        lambda: descriptors,
    )
    engines = _run("discover", "engines")
    assert engines.exit_code == 0
    engine_payload = json.loads(engines.output)
    assert [row["name"] for row in engine_payload["engines"]] == [
        "docker",
        "kubernetes",
        "podman",
    ]
    assert engine_payload["engines"][0]["binary_available"] is True

    report = SimpleNamespace(
        model_dump=lambda **kwargs: {
            "tools": [{"manifest": {"tool": "fake", "provides": ["net"]}, "version": "1"}]
        }
    )
    monkeypatch.setattr("mayhem.cli.services.probe_capabilities", lambda **kwargs: report)
    capabilities = _run("discover", "capabilities", "--json")
    assert capabilities.exit_code == 0
    assert json.loads(capabilities.output)["tools"][0]["manifest"]["tool"] == "fake"


def test_extend_provider_inspect_and_load_use_loader_fake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = ProviderLoadReport(
        providers=(
            ProviderInspection(
                provider_id="fake.provider",
                status="ready",
                source="entry_point",
                metadata={"version": "1"},
            ),
        )
    )
    loaded = ProviderLoadReport(
        providers=(ProviderInspection("fake.provider", "loaded", "entry_point"),),
        loaded=("fake.provider",),
    )

    class Loader:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def inspect_entry_points(self, provider_ids: tuple[str, ...]) -> ProviderLoadReport:
            return report

        def load_entry_points(self, provider_ids: tuple[str, ...]) -> ProviderLoadReport:
            return loaded

    monkeypatch.setattr("mayhem.cli.extend.ProviderLoader", Loader)
    inspect_result = _run(
        "extend", "providers", "inspect", "--entry-point", "fake.provider", "--json"
    )
    load_result = _run("extend", "providers", "load", "--entry-point", "fake.provider", "--json")
    assert inspect_result.exit_code == 0
    assert load_result.exit_code == 0
    assert json.loads(inspect_result.output)["providers"][0]["status"] == "ready"
    assert json.loads(load_result.output)["loaded"] == ["fake.provider"]


def test_extend_provider_source_conflict_is_usage_error(tmp_path: Path) -> None:
    catalog = tmp_path / "providers.json"
    catalog.write_text("{}")
    result = _run("extend", "providers", "inspect", "--catalog", str(catalog), "--entry-point", "x")
    assert result.exit_code == 2
    assert "choose either --catalog or --entry-point" in result.output


@pytest.mark.parametrize("path", (("prepare", "validate"), ("experiment", "validate")))
def test_prepare_and_experiment_validate_use_compile_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: tuple[str, str]
) -> None:
    spec = tmp_path / "spec.yaml"
    compose = tmp_path / "docker-compose.yml"
    spec.write_text(DRILL)
    compose.write_text("services: {}\n")
    _install_compile_fakes(monkeypatch)
    code, output, error = _main([*path, str(spec), "--compose", str(compose)])
    assert code == int(ExitCode.SUCCESS)
    assert "validated r-matrix" in output
    assert error == ""


def test_prepare_plan_json_uses_preflight_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = tmp_path / "spec.yaml"
    compose = tmp_path / "docker-compose.yml"
    spec.write_text(DRILL)
    compose.write_text("services: {}\n")
    _install_compile_fakes(monkeypatch)
    monkeypatch.setattr(lifecycle, "_preflight_for_run", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(lifecycle, "render_preflight_json", lambda preflight: '{"planned": true}')
    code, output, error = _main(["prepare", "plan", str(spec), "--compose", str(compose), "--json"])
    assert code == 0
    assert json.loads(output) == {"planned": True}
    assert error == ""


def test_experiment_show_and_inspect_success_use_local_state(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    show = _run("experiment", "show", str(spec))
    assert show.exit_code == 0
    assert json.loads(show.output)["name"] == "matrix-drill"

    db = tmp_path / "inspect.db"
    code, output, error = _main(["--db", str(db), "inspect", "leases", "--json"])
    assert code == 0
    assert json.loads(output)["leases"] == []
    assert error == ""
    code, _, error = _main(["--db", str(db), "inspect", "run", "missing"])
    assert code == 2
    assert "no such run" in error


def test_campaign_lifecycle_json_and_local_database_behavior(tmp_path: Path) -> None:
    db = tmp_path / "campaign.db"
    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    code, created, _ = _main(["--db", str(db), "campaign", "create", "matrix", "--json"])
    assert code == 0
    campaign_id = json.loads(created)["id"]

    code, listed, _ = _main(["--db", str(db), "campaign", "list", "--json"])
    assert code == 0
    assert [row["id"] for row in json.loads(listed)] == [campaign_id]
    code, shown, _ = _main(["--db", str(db), "campaign", "show", campaign_id, "--json"])
    assert code == 0
    assert json.loads(shown)["status"] == "draft"
    for args in (
        ("campaign", "add-experiment", campaign_id, str(spec), "--json"),
        ("campaign", "plan", campaign_id, "--json"),
        ("campaign", "status", campaign_id),
        ("campaign", "approve", campaign_id, "--json"),
        ("campaign", "start", campaign_id, "--json"),
        ("campaign", "pause", campaign_id, "--json"),
        ("campaign", "resume", campaign_id, "--json"),
        ("campaign", "archive", campaign_id, "--json"),
    ):
        code, _, error = _main(["--db", str(db), *args])
        assert code == 0, (args, error)
    code, shown, _ = _main(["--db", str(db), "campaign", "show", campaign_id, "--json"])
    assert code == 0
    assert json.loads(shown)["status"] == "completed"
    code, _, _ = _main(["--db", str(db), "campaign", "abort", campaign_id])
    assert code == int(ExitCode.GENERAL_FAILURE)


def test_campaign_delete_and_no_experiment_refusals(tmp_path: Path) -> None:
    db = tmp_path / "campaign.db"
    code, created, _ = _main(["--db", str(db), "campaign", "create", "draft", "--json"])
    assert code == 0
    campaign_id = json.loads(created)["id"]
    code, _, _ = _main(["--db", str(db), "campaign", "run", campaign_id])
    assert code == 2
    code, _, _ = _main(["--db", str(db), "campaign", "delete", campaign_id, "--yes", "--json"])
    assert code == 0
    code, _, _ = _main(["--db", str(db), "campaign", "show", campaign_id, "--json"])
    assert code == int(ExitCode.VALIDATION_ERROR)


def test_recover_status_plan_and_execute_use_service_fake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "recover.db"
    plan = SimpleNamespace(
        state=SimpleNamespace(value="not_needed"),
        run_ids=("run-1",),
        target_profiles=(),
        leases=(),
        model_dump=lambda **kwargs: {"state": "not_needed", "run_ids": ["run-1"], "leases": []},
    )
    execution = SimpleNamespace(
        state=SimpleNamespace(value="not_needed"),
        run_ids=("run-1",),
        expired=(),
        recovered=(),
        dirty=(),
        handoff_path=None,
        model_dump=lambda **kwargs: {"state": "not_needed", "recovered": [], "dirty": []},
    )

    class Service:
        def status(self, run_ids: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
            assert run_ids == ("run-1",)
            return plan

        def plan(self, run_ids: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
            return plan

        def execute(self, value: SimpleNamespace, **kwargs: object) -> SimpleNamespace:
            return execution

    monkeypatch.setattr(lifecycle, "_recovery_service", lambda store: Service())
    for command in ("status", "plan", "execute"):
        code, output, error = _main(["--db", str(db), "recover", command, "run-1", "--json"])
        assert code == 0, (command, error)
        assert json.loads(output)["state"] == "not_needed"


def test_recover_usage_requires_run_ids() -> None:
    result = _run("recover", "status")
    assert result.exit_code == 2
    assert "Missing argument" in result.output or "run_ids" in result.output


def test_top_level_init_is_filesystem_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = _run("init", "--non-interactive", "--output", str(tmp_path / "mayhem.yaml"))
    assert result.exit_code == 0
    assert (tmp_path / "mayhem.yaml").exists()
    assert (tmp_path / "drill.starter.yaml").exists()
    assert "created" in result.output


def test_top_level_janitor_and_verify_usage_are_service_safe(tmp_path: Path) -> None:
    db = tmp_path / "janitor.db"
    code, output, error = _main(["--db", str(db), "janitor", "--json"])
    assert code == 0
    assert json.loads(output)["execute"] is False
    assert error == ""
    verify = _run("verify")
    assert verify.exit_code == 2


def test_top_level_malformed_active_commands_report_usage_errors() -> None:
    cases = (
        ("run", "--from-plan", "a.json", "--plan-id", "r-1"),
        ("maniac",),
        ("prepare", "config", "show", "--format", "xml"),
        ("discover", "topology", "--runtime", "vm"),
    )
    for args in cases:
        result = _run(*args)
        assert result.exit_code == 2, args


def test_error_mapping_is_stable_for_service_and_domain_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def reject(**kwargs: object) -> None:
        raise MayhemCliError(
            "safety_refusal",
            "blast radius exceeded",
            details={"token": "secret", "reason": "host count"},
            remediation="reduce scope",
        )

    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    monkeypatch.setattr(lifecycle, "_graph_from", lambda *args, **kwargs: (TopologyGraph(), "fake"))
    monkeypatch.setattr(lifecycle, "prepare", reject)
    assert main(
        [
            "--db",
            str(tmp_path / "errors.db"),
            "--format",
            "json",
            "prepare",
            "validate",
            str(spec),
        ]
    ) == int(ExitCode.SAFETY_REFUSAL)
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "safety_refusal"
    assert payload["details"]["token"] == "***redacted***"
    assert payload["details"]["reason"] == "host count"
    assert payload["remediation"] == "reduce scope"
