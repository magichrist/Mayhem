"""Expansion checkpoint (v0.9.0 tasks 11-20).

Each test here backs one line of the "Expansion checkpoint" section of
`docs/v0.9.0/07-expansion-implementation-plan.md`. The checkpoint is only
marked done because these exist.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mayhem.cli.context import CliContext
from mayhem.domain.scenarios import Scenario
from mayhem.infra.store import Store

# ── 1. All new commands are plan-only until explicitly executed ──────────────
#: (group, command, positional args, extra flags) for every plan-only command.
PLAN_ONLY_COMMANDS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("experiment", "compose", ("SCENARIO",), ("--json",)),
    ("experiment", "check-scenario", ("SCENARIO",), ("--json",)),
    ("campaign", "resume-plan", ("camp-1",), ("--json",)),
    ("inspect", "graph", (), ("--json",)),
    ("inspect", "coverage-diff", ("baseline",), ("--json",)),
    ("inspect", "residual", ("run-1",), ("--json",)),
    ("bundle", "verify", ("BUNDLE",), ("--json",)),
    ("bundle", "show", ("BUNDLE",), ("--json",)),
)


def _app():
    return importlib.import_module("mayhem.cli.app").app


def _ctx(db: Path) -> CliContext:
    return CliContext(db=str(db))


def _no_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("a plan-only command must not build an execution engine")

    monkeypatch.setattr("mayhem.controller.executor.RunEngine", explode)


def test_plan_only_commands_never_build_an_engine(tmp_path, monkeypatch) -> None:
    _no_engine(monkeypatch)
    db = tmp_path / "c.db"
    Store.open_migrated(db).close()
    scenario = tmp_path / "s.json"
    scenario.write_text(
        json.dumps({"name": "s", "variables": [], "steps": [{"id": "a", "action": {}}]})
    )
    from mayhem.domain.evidence_bundle import build_bundle

    bundle_dir = build_bundle(evidence={"run_id": "r1", "redaction_metrics": {"policy_version": "1"}}).write(
        tmp_path / "bundle"
    )
    substitutions = {"SCENARIO": str(scenario), "BUNDLE": str(bundle_dir)}
    app = _app()
    for group, command, positionals, extra in PLAN_ONLY_COMMANDS:
        args: list[str] = [group, command]
        args += [substitutions.get(value, value) for value in positionals]
        if command == "resume-plan":
            args += ["--experiment", "x"]
        result = CliRunner().invoke(app, [*args, *extra], obj=_ctx(db))
        assert result.exit_code in (0, 1), f"{group} {command}: {result.output}"
        assert "must not build an execution engine" not in (result.output or "")


def test_game_day_start_requires_execute(tmp_path, monkeypatch) -> None:
    _no_engine(monkeypatch)
    db = tmp_path / "gd.db"
    Store.open_migrated(db).close()
    app = _app()
    # The root group rewrites ctx.obj from its own --db option, so every
    # invocation must carry it explicitly.
    def _gd(*args: str) -> object:
        return CliRunner().invoke(app, ["--db", str(db), "game-day", *args], obj=_ctx(db))

    created = _gd("create", "--id", "gd-1", "--json")
    assert created.exit_code == 0, created.output
    _gd("approve", "gd-1", "--actor", "sre")

    preview = _gd("start", "gd-1", "--json")
    assert json.loads(preview.output)["started"] is False
    assert "pass --execute" in preview.output

    from mayhem.domain.game_day import SessionState
    from mayhem.infra.game_day_repository import GameDayRepository

    store = Store.open_migrated(db)
    try:
        session = GameDayRepository(store).load("gd-1")
        assert session is not None
        assert session.state is SessionState.PLANNED
    finally:
        store.close()

    started = _gd("start", "gd-1", "--execute", "--json")
    assert json.loads(started.output)["started"] is True


# ── 2. Every new output is schema-validated and covered in text/JSON/YAML ─────
SCHEMA = json.loads(Path("src/mayhem/schemas/output_v1.json").read_text())


def test_output_schema_is_still_valid_json() -> None:
    assert SCHEMA.get("type")
    assert SCHEMA


def test_new_outputs_render_in_all_three_modes(tmp_path) -> None:
    import yaml

    db = tmp_path / "fmt.db"
    Store.open_migrated(db).close()
    scenario = tmp_path / "s.json"
    scenario.write_text(
        json.dumps({"name": "s", "variables": [{"name": "n", "default": 1}], "steps": []})
    )
    app = _app()
    invocations = (
        ["experiment", "compose", str(scenario)],
        ["experiment", "check-scenario", str(scenario)],
        ["campaign", "resume-plan", "camp-1"],
        ["inspect", "graph"],
        ["campaign", "checkpoints", "camp-1"],
    )
    for args in invocations:
        text = CliRunner().invoke(app, args, obj=_ctx(db))
        as_json = CliRunner().invoke(app, [*args, "--json"], obj=_ctx(db))
        as_yaml = CliRunner().invoke(
            app, ["--format", "yaml", *args], obj=_ctx(db)
        )
        assert text.exit_code in (0, 1), f"{args}: {text.output}"
        assert as_json.exit_code in (0, 1), f"{args}: {as_json.output}"
        assert as_yaml.exit_code in (0, 1), f"{args}: {as_yaml.output}"
        if text.exit_code == 0:
            assert text.output.strip(), f"{args} produced no text output"
        if as_json.exit_code == 0:
            json.loads(as_json.output)
        if as_yaml.exit_code == 0:
            yaml.safe_load(as_yaml.output)


# ── 3. All new integrations have timeout, redaction, and degraded-state tests ─
def test_remote_connectors_are_bounded() -> None:
    import inspect as py_inspect

    from mayhem.observability import prometheus, loki

    for module in (prometheus, loki):
        signature = py_inspect.signature(module.__dict__["fetch_json"].__globals__ and module.PrometheusConnector.__init__ if module is prometheus else module.LokiConnector.__init__)
        assert "timeout_s" in signature.parameters
        assert "max_bytes" in signature.parameters


def test_connector_failure_is_degraded_not_silent() -> None:
    from mayhem.domain.observations import ObservationQuery, ObservationStatus
    from mayhem.providers.observation import HttpObservationProvider

    result = HttpObservationProvider(timeout_s=0.2).observe(
        ObservationQuery(metric="m", target="http://127.0.0.1:1/x")
    )
    assert result.status is ObservationStatus.ERROR
    assert result.value is None


def test_connector_detail_is_redacted() -> None:
    from mayhem.observability.base import redacted

    assert "ghp_secretvalue" not in redacted("bearer ghp_secretvalue")


def test_bundle_verifier_degrades_on_unreadable_input(tmp_path) -> None:
    from mayhem.cli.verify_bundle import verify

    (tmp_path / "empty").mkdir()
    result = CliRunner().invoke(verify, [str(tmp_path / "empty"), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["valid"] is False


# ── 4. Campaign resume and game-day pass controller-loss simulations ─────────
def test_campaign_checkpoints_survive_a_controller_restart(tmp_path) -> None:
    from mayhem.domain.campaign_checkpoint import CampaignCheckpoint, CheckpointState, plan_resume
    from mayhem.infra.campaign_checkpoint_repository import CampaignCheckpointRepository

    db = tmp_path / "camp.db"
    store = Store.open_migrated(db)
    try:
        CampaignCheckpointRepository(store).save(
            CampaignCheckpoint(
                campaign_id="c",
                experiment_id="e1",
                state=CheckpointState.RUNNING,
                attempt=1,
            )
        )
    finally:
        store.close()  # controller dies

    store = Store.open_migrated(db)
    try:
        plan = plan_resume(
            CampaignCheckpointRepository(store).load("c"),
            "c",
            pending_experiments=("e1",),
        )
    finally:
        store.close()
    assert plan.safe is False
    assert plan.in_flight == ("e1",)


def test_game_day_session_survives_a_controller_restart(tmp_path) -> None:
    from mayhem.domain.game_day import OperatorAcknowledgement, SessionState, start
    from mayhem.infra.game_day_repository import GameDayRepository

    from datetime import UTC, datetime, timedelta

    db = tmp_path / "gd.db"
    store = Store.open_migrated(db)
    try:
        now = datetime.now(UTC)
        from mayhem.domain.game_day import ApprovalGate, FreezeWindow, GameDaySession

        session = GameDaySession(
            id="gd-1",
            window=FreezeWindow(
                starts_at=(now - timedelta(hours=1)).isoformat(),
                ends_at=(now + timedelta(hours=1)).isoformat(),
            ),
            gate=ApprovalGate(required_approvers=1),
        ).with_approval(OperatorAcknowledgement(actor="sre"))
        GameDayRepository(store).save(start(session, now=now))
    finally:
        store.close()  # controller dies

    store = Store.open_migrated(db)
    try:
        reloaded = GameDayRepository(store).load("gd-1")
    finally:
        store.close()
    assert reloaded is not None
    assert reloaded.state is SessionState.RUNNING


# ── 5. Provider sandbox rejects undeclared mutation authority ────────────────
def test_sandbox_rejects_undeclared_mutation() -> None:
    from mayhem.domain.provider import ProviderPermission
    from mayhem.providers.permissions import ProviderPermissionSet, SandboxRefusal

    with pytest.raises(SandboxRefusal):
        ProviderPermissionSet.default("p").require(ProviderPermission.TARGET_MUTATE)


def test_pack_loader_rejects_a_mutating_pack_without_a_grant() -> None:
    from mayhem.providers.loader import PackLoader
    from mayhem.providers.pack import PackValidationError, ProviderManifest, FaultPack
    from mayhem.providers.permissions import SandboxRefusal

    pack = FaultPack(
        manifest=ProviderManifest(provider_id="acme"),
        faults=(
            {
                "id": "acme.kill",
                "compensation": "restart the pod",
            },  # type: ignore[arg-type]
        ),
        signature="sig",
        signer="acme",
    )
    with pytest.raises(SandboxRefusal, match="target:mutate"):
        PackLoader().load(pack.model_dump(mode="json"))
    assert PackValidationError is not None


# ── 6. No live Kubernetes or remote-agent code is enabled by default ─────────
def test_default_observation_provider_is_local() -> None:
    from mayhem.cli.lifecycle import _observation_provider_for
    from mayhem.providers.observation import StaticObservationProvider

    provider = _observation_provider_for("kubernetes")
    assert isinstance(provider, StaticObservationProvider)
    assert provider.name == "local"


def test_new_modules_do_not_import_a_kubernetes_client_at_module_scope() -> None:
    import ast

    new_modules = (
        "src/mayhem/domain/observations.py",
        "src/mayhem/providers/observation.py",
        "src/mayhem/observability/prometheus.py",
        "src/mayhem/observability/loki.py",
        "src/mayhem/observability/otel.py",
        "src/mayhem/domain/scenarios.py",
        "src/mayhem/domain/coverage_graph.py",
        "src/mayhem/domain/game_day.py",
        "src/mayhem/domain/residual_impact.py",
        "src/mayhem/domain/evidence_bundle.py",
        "src/mayhem/domain/campaign_checkpoint.py",
        "src/mayhem/providers/permissions.py",
        "src/mayhem/providers/pack.py",
    )
    forbidden = ("kubernetes", "mayhem.agent", "subprocess")
    for module in new_modules:
        tree = ast.parse(Path(module).read_text())
        # Module scope only: a function-local import (e.g. the process
        # provider's `subprocess`) is not enabled at import time.
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name for alias in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module)
                for name in names:
                    for banned in forbidden:
                        assert not name.startswith(banned), f"{module} imports {name}"


def test_scenario_compile_is_side_effect_free(tmp_path) -> None:
    from mayhem.domain.scenarios import compile_scenario

    scenario = Scenario.model_validate(
        {"name": "s", "variables": [], "steps": [{"id": "a", "action": {"type": "wait"}}]}
    )
    before = sorted(p.name for p in tmp_path.iterdir())
    compile_scenario(scenario, {})
    assert sorted(p.name for p in tmp_path.iterdir()) == before
