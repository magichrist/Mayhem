"""Plan 20 Phase 3 — ``mayhem sandbox`` / ``support-bundle`` / ``upgrade`` surface.

Three properties, each defended by tests that use fakes, never live infra:

1. **The sandbox lifecycle is the Phase 2 provisioner with an injected
   runner.** ``up`` provisions through :class:`SandboxProvisioner` over a
   recording fake (no subprocess, no docker), ``down`` tears down through
   the same runner, and ``status`` never touches a runtime at all — it
   reads the compose document the provisioner wrote.
2. **A support bundle is built by ``build_support_bundle`` and its bytes are
   written to ``--out``.** Secret-graded fields are dropped and named in
   the manifest; the sealed mode banner travels with the bundle.
3. **An upgrade check is ``validate_upgrade`` read aloud.** Admissible moves
   exit 0; refused moves (downgrade, unparseable version, air-gapped rapid)
   exit with the safety-refusal code and name the rule.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.sandbox_service import (
    COMPOSE_FILENAME,
    CommandOutcome,
    SandboxProvisioner,
    SandboxRequest,
    SandboxRunner,
    blueprint_services,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class FakeRunner(SandboxRunner):
    """A recording fake: answers from a script, touches no runtime."""

    def __init__(self, *, fail_on: str | None = None, running: Sequence[str] | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_on = fail_on
        self.running = running

    def run(self, argv: Sequence[str]) -> CommandOutcome:
        recorded = tuple(argv)
        self.calls.append(recorded)
        action = recorded[recorded.index("-f") + 2]
        if action == self.fail_on:
            return CommandOutcome(argv=recorded, returncode=1, stderr="fake: boom")
        if action == "ps":
            services = self.running if self.running is not None else blueprint_services()
            return CommandOutcome(argv=recorded, returncode=0, stdout="\n".join(services))
        if action == "down":
            return CommandOutcome(argv=recorded, returncode=0, stdout="")
        return CommandOutcome(argv=recorded, returncode=0, stdout="")

    @property
    def actions(self) -> tuple[str, ...]:
        return tuple(call[call.index("-f") + 2] for call in self.calls)


def _runner(monkeypatch, fake: FakeRunner):  # type: ignore[no-untyped-def]
    from mayhem.cli import sandbox_cmd

    monkeypatch.setattr(sandbox_cmd, "SubprocessSandboxRunner", lambda: fake)  # type: ignore[arg-type]
    return fake


def _run(*args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


# --- sandbox up/down/status -----------------------------------------------------


def test_sandbox_up_provisions_through_the_provisioner_with_a_fake_runner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """`up` runs the documented config→pull→up→ps sequence and reports ready."""
    fake = _runner(monkeypatch, FakeRunner())
    result = _run("sandbox", "up", "--dir", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert fake.actions == ("config", "pull", "up", "ps")
    assert (tmp_path / COMPOSE_FILENAME).is_file()
    assert "ready=True" in result.output


def test_sandbox_up_json_reports_the_same_environment(tmp_path: Path, monkeypatch) -> None:
    fake = _runner(monkeypatch, FakeRunner())
    result = _run("sandbox", "up", "--dir", str(tmp_path), "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ready"] is True
    assert payload["services"] == list(blueprint_services())
    assert {row["host"] for row in payload["registry_egress"]} == {"docker.io", "ghcr.io"}
    assert fake.actions == ("config", "pull", "up", "ps")


def test_sandbox_up_refusal_names_the_rule_and_exits_safety_refusal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A failed step is a named refusal, never a half-built environment report."""
    _runner(monkeypatch, FakeRunner(fail_on="pull"))
    result = _run("sandbox", "up", "--dir", str(tmp_path))
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "sandbox.image_pull_failed" in result.output


def test_sandbox_up_with_an_invalid_name_refuses_before_any_command(
    tmp_path: Path, monkeypatch
) -> None:
    fake = _runner(monkeypatch, FakeRunner())
    result = _run("sandbox", "up", "--name", "Not A Name", "--dir", str(tmp_path))
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "sandbox.invalid_name" in result.output
    assert fake.calls == []


def test_sandbox_up_under_an_air_gap_refuses_with_the_cause_named(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """An air gap on the local model is a declaration mismatch, refused before any command.

    The cross-check (:func:`air_gap_refusal`) fires before image egress is
    even resolved: an air-gapped policy on the local deployment model means
    one of the two declarations is wrong, and mayhem refuses to guess which.
    A matched air-gapped model refuses one step later, at image egress.
    """
    fake = _runner(monkeypatch, FakeRunner())
    result = _run("sandbox", "up", "--dir", str(tmp_path), "--air-gapped")
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "sandbox.policy_unresolved" in result.output
    assert "air gap" in result.output
    assert fake.calls == []


def test_sandbox_down_tears_down_without_provisioning(tmp_path: Path, monkeypatch) -> None:
    """`down` issues one `down` command — no config, no pull, no start."""
    fake = _runner(monkeypatch, FakeRunner())
    # Provision the compose document first through the real provisioner + fake,
    # exactly as `up` would have written it.
    provisioner = SandboxProvisioner(runner=fake)
    provisioner.provision(SandboxRequest(name="sbx", directory=tmp_path))
    runner_calls = len(fake.calls)
    result = _run("sandbox", "down", "--name", "sbx", "--dir", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert len(fake.calls) == runner_calls + 1
    assert fake.actions[-1] == "down"
    assert "removed" in result.output


def test_sandbox_status_reads_without_touching_a_runtime(tmp_path: Path, monkeypatch) -> None:
    """Status renders the blueprint and registries with no compose document present."""
    fake = _runner(monkeypatch, FakeRunner())
    result = _run("sandbox", "status", "--dir", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert fake.calls == []
    assert "frontend" in result.output
    assert "docker.io" in result.output
    assert "absent" in result.output


def test_sandbox_status_reads_the_topology_back_when_the_document_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fake = _runner(monkeypatch, FakeRunner())
    provisioner = SandboxProvisioner(runner=fake)
    provisioner.provision(SandboxRequest(name="sbx", directory=tmp_path))
    before = len(fake.calls)
    result = _run("sandbox", "status", "--name", "sbx", "--dir", str(tmp_path), "--json")
    assert result.exit_code == 0, result.output
    assert len(fake.calls) == before  # status issues no commands
    payload = json.loads(result.output)
    assert payload["compose_present"] is True
    assert payload["node_ids"] == [f"svc-{service}" for service in blueprint_services()]


# --- support-bundle build -------------------------------------------------------


def _section_file(tmp_path: Path, name: str, fields: dict) -> Path:  # type: ignore[type-arg]
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(fields), encoding="utf-8")
    return path


def test_support_bundle_build_writes_bytes_and_manifest(tmp_path: Path) -> None:
    config = _section_file(tmp_path, "config", {"log_level": "info", "endpoint": "https://x/v1"})
    out = tmp_path / "bundle.json"
    result = _run("support-bundle", "build", "--section", f"config={config}", "--out", str(out))
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["sections"][0]["name"] == "config"
    assert document["manifest"]["redaction_rules"]
    assert "TRAINING" in document["manifest"]["mode_banner"]
    assert "no mutation performed" in document["manifest"]["mode_banner"]


def test_support_bundle_build_drops_secrets_and_names_them(tmp_path: Path) -> None:
    env = _section_file(tmp_path, "env", {"api_token": "tok-123", "log_level": "info"})
    out = tmp_path / "bundle.json"
    result = _run(
        "support-bundle",
        "build",
        "--section",
        f"env={env}",
        "--grade",
        "env.api_token=secret",
        "--out",
        str(out),
    )
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["sections"][0]["fields"] == {"log_level": "info"}
    assert document["manifest"]["dropped_secret_fields"] == ["env.api_token"]


def test_support_bundle_build_json_manifest_reports_production_refusal(tmp_path: Path) -> None:
    config = _section_file(tmp_path, "config", {"log_level": "info"})
    out = tmp_path / "bundle.json"
    result = _run(
        "support-bundle",
        "build",
        "--section",
        f"config={config}",
        "--out",
        str(out),
        "--json",
    )
    assert result.exit_code == 0, result.output
    manifest = json.loads(result.output)
    assert manifest["production_presentation"].startswith("support.non_production_bundle")


def test_support_bundle_build_with_an_empty_bundle_is_a_validation_error(tmp_path: Path) -> None:
    result = _run("support-bundle", "build", "--out", str(tmp_path / "b.json"))
    assert result.exit_code == 2  # --section is required


# --- upgrade channels/check -----------------------------------------------------


def test_upgrade_channels_lists_all_three_cadences() -> None:
    result = _run("upgrade", "channels")
    assert result.exit_code == 0, result.output
    assert "stable" in result.output
    assert "extended" in result.output
    assert "rapid" in result.output


def test_upgrade_channels_json_is_data_not_prose() -> None:
    result = _run("upgrade", "channels", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [row["channel"] for row in payload["channels"]] == ["stable", "extended", "rapid"]
    assert payload["channels"][2]["supports_air_gapped"] is False


def test_upgrade_check_admits_a_forward_move() -> None:
    result = _run(
        "upgrade", "check", "--channel", "stable", "--current", "1.1.0", "--target", "1.2.0"
    )
    assert result.exit_code == 0, result.output
    assert "admissible" in result.output


def test_upgrade_check_refuses_a_downgrade_by_name() -> None:
    result = _run(
        "upgrade", "check", "--channel", "stable", "--current", "1.2.0", "--target", "1.1.0"
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "upgrade.downgrade_refused" in result.output


def test_upgrade_check_refuses_an_unparseable_version_by_name() -> None:
    result = _run(
        "upgrade", "check", "--channel", "stable", "--current", "1.1.0", "--target", "soon"
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "upgrade.unparseable_version" in result.output


def test_upgrade_check_refuses_rapid_on_an_air_gapped_site() -> None:
    result = _run(
        "upgrade",
        "check",
        "--channel",
        "rapid",
        "--current",
        "1.1.0",
        "--target",
        "1.2.0",
        "--model",
        "air_gapped",
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "upgrade.air_gapped_channel" in result.output


def test_upgrade_check_json_reports_admissibility() -> None:
    result = _run(
        "upgrade",
        "check",
        "--channel",
        "stable",
        "--current",
        "1.1.0",
        "--target",
        "1.1.0",
        "--json",
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["admissible"] is True
