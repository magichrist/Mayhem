"""v0.9.0 task 2 — one resolved runtime context per plan.

The invariant under test: the engine, target profile, namespace, kubeconfig
context, and topology fingerprint are resolved *once* (during application
preflight) and then carried unchanged through preflight and execution. An
ambiguous automatic engine selection is refused before any planning happens.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from mayhem.controller.preflight import build_preflight
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import ExecutionPlan, ExperimentKind, PlannedStep, Wait
from mayhem.domain.runtime_context import RuntimeContext
from mayhem.domain.topology import ContainerNode, HostNode, TopologyGraph

K8S_CONFIG = """\
targets:
  prod:
    engine: kubernetes
    context: prod-eu
    namespace: checkout
  dev:
    engine: kubernetes
    context: dev-us
    namespace: sandbox
"""


def _both_engines(name: str) -> str | None:
    return f"/usr/bin/{name}" if name in ("docker", "podman") else None


def _plan(run_id: str = "r-ctx") -> ExecutionPlan:
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(PlannedStep(id="wait-0000", seq=0, raw_action=Wait(type="wait", duration=1.0)),),
        config_snapshot_id="cfg-abc",
        topology_snapshot_id="topo-abc",
        environment_fingerprint="fp-123",
    )


def _graph() -> TopologyGraph:
    from mayhem.domain.identity import RuntimeIdentity

    return TopologyGraph(
        nodes=(
            HostNode(id="h-local", name="local"),
            ContainerNode(
                id="c-api",
                name="api",
                engine="docker",
                runtime_identity=RuntimeIdentity(
                    runtime="docker", host_id="h-local", runtime_id="abc123"
                ),
            ),
        )
    )


def _preflight(
    *,
    engine: str | None,
    runtime: RuntimeContext | None,
    config_path: str | None = None,
    target: str | None = None,
) -> Any:
    return build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=config_path,
        profile=None,
        allow_critical=False,
        target=target if target is not None else (runtime.target_profile if runtime else None),
        engine=engine,
        plan=_plan(),
        safety=None,
        fingerprint="fp-123",
        config_snapshot_id="cfg-abc",
        topology_snapshot_id="topo-abc",
        runtime=runtime,
    )


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------


def test_runtime_context_is_frozen_and_carries_the_documented_fields() -> None:
    ctx = RuntimeContext(
        engine="kubernetes",
        target_profile="prod",
        namespace="checkout",
        context="prod-eu",
        runtime_version="v1.29.0",
        provider_version="31.1.0",
        topology_fingerprint="abc123",
    )
    assert ctx.engine == "kubernetes"
    assert (ctx.target_profile, ctx.namespace, ctx.context) == ("prod", "checkout", "prod-eu")
    assert (ctx.runtime_version, ctx.provider_version) == ("v1.29.0", "31.1.0")
    assert ctx.topology_fingerprint == "abc123"
    with pytest.raises(ValidationError):
        ctx.engine = "docker"


def test_runtime_context_defaults_are_optional() -> None:
    ctx = RuntimeContext(engine="podman")
    assert ctx.target_profile is None
    assert ctx.namespace is None
    assert ctx.context is None
    assert ctx.runtime_version is None
    assert ctx.provider_version is None
    assert ctx.topology_fingerprint is None
    assert json.loads(ctx.model_dump_json())["engine"] == "podman"


# ---------------------------------------------------------------------------
# Ambiguity is refused before planning
# ---------------------------------------------------------------------------


def test_ambiguous_automatic_engine_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mayhem.domain import runtime_adapter as ra

    monkeypatch.setattr(ra.shutil, "which", _both_engines)
    from mayhem.cli.services import resolve_runtime_context

    with pytest.raises(InvariantViolationError) as excinfo:
        resolve_runtime_context(engine=None)
    assert excinfo.value.rule == "engine_ambiguous"
    assert "multiple engines available" in str(excinfo.value)
    assert "docker" in str(excinfo.value)
    assert "podman" in str(excinfo.value)


def test_explicit_engine_is_never_ambiguous(monkeypatch: pytest.MonkeyPatch) -> None:
    from mayhem.cli.services import resolve_runtime_context
    from mayhem.domain import runtime_adapter as ra

    monkeypatch.setattr(ra.shutil, "which", _both_engines)
    assert resolve_runtime_context(engine="docker").engine == "docker"
    assert resolve_runtime_context(engine="podman").engine == "podman"


def test_unavailable_engine_keeps_the_legacy_podman_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mayhem.cli.services import resolve_runtime_context
    from mayhem.domain import runtime_adapter as ra

    monkeypatch.setattr(ra.shutil, "which", lambda _name: None)
    assert resolve_runtime_context(engine=None).engine == "podman"
    with pytest.raises(InvariantViolationError) as excinfo:
        resolve_runtime_context(engine=None, unavailable_fallback=None)
    assert excinfo.value.rule == "engine_unavailable"


def test_single_available_engine_is_auto_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    from mayhem.cli.services import resolve_runtime_context
    from mayhem.domain import runtime_adapter as ra

    monkeypatch.setattr(
        ra.shutil, "which", lambda name: "/usr/bin/podman" if name == "podman" else None
    )
    assert resolve_runtime_context(engine=None).engine == "podman"


# ---------------------------------------------------------------------------
# Kubernetes never touches the docker/podman descriptors
# ---------------------------------------------------------------------------


def test_kubernetes_resolution_never_probes_container_engines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mayhem.cli.services import resolve_runtime_context
    from mayhem.domain import runtime_adapter as ra

    config = tmp_path / "mayhem.yaml"
    config.write_text(K8S_CONFIG)

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("kubernetes must not use container-engine descriptors")

    monkeypatch.setattr(ra, "describe_engine", _boom)
    monkeypatch.setattr(ra, "detect_available_engines", _boom)

    ctx = resolve_runtime_context(engine="kubernetes", target="prod", config_path=str(config))
    assert ctx.engine == "kubernetes"
    assert ctx.context == "prod-eu"
    assert ctx.namespace == "checkout"
    assert ctx.target_profile == "prod"


# ---------------------------------------------------------------------------
# Resolved once, carried unchanged
# ---------------------------------------------------------------------------


def test_explicit_engine_survives_preflight_and_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mayhem.cli.services import engine_for, resolve_runtime_context
    from mayhem.domain import runtime_adapter as ra
    from mayhem.infra.store import Store

    monkeypatch.setattr(ra.shutil, "which", _both_engines)
    runtime = resolve_runtime_context(engine="docker")

    # Re-resolution must never happen downstream.
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("engine re-resolved after the context was resolved")

    monkeypatch.setattr(ra, "resolve_engine_selection", _boom)

    preflight = _preflight(engine="docker", runtime=runtime)
    assert preflight.engine == "docker"
    assert preflight.runtime_context is not None
    assert preflight.runtime_context.engine == "docker"
    assert preflight.to_dict()["runtime_context"]["engine"] == "docker"

    store = Store.open_migrated(Path(":memory:"))
    try:
        engine = engine_for(store, "docker", runtime=runtime)
    finally:
        store.close()
    assert engine._engine == "docker"
    assert engine._runtime is runtime


def test_legacy_positional_engine_call_still_works() -> None:
    from mayhem.cli.services import engine_for
    from mayhem.infra.store import Store

    store = Store.open_migrated(Path(":memory:"))
    try:
        engine = engine_for(store, "podman")
    finally:
        store.close()
    assert engine._engine == "podman"
    assert engine._runtime is None
    assert engine._k8s_context is None


def test_context_and_fingerprint_are_preserved_into_the_execution_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mayhem.cli.services import engine_for, resolve_runtime_context, with_topology_fingerprint
    from mayhem.domain import runtime_adapter as ra
    from mayhem.infra.store import Store

    config = tmp_path / "mayhem.yaml"
    config.write_text(K8S_CONFIG)
    monkeypatch.setattr(ra.shutil, "which", lambda _name: None)

    runtime = resolve_runtime_context(engine="kubernetes", target="dev", config_path=str(config))
    assert (runtime.context, runtime.namespace) == ("dev-us", "sandbox")

    graph = _graph()
    runtime = with_topology_fingerprint(runtime, graph)
    assert runtime.topology_fingerprint == ra.topology_fingerprint_for_engine("kubernetes", graph)

    preflight = _preflight(engine="kubernetes", runtime=runtime)
    assert preflight.engine == "kubernetes"
    assert preflight.runtime_context is runtime
    assert preflight.k8s_context == "dev-us"
    assert preflight.k8s_namespace == "sandbox"
    assert preflight.k8s_target_scope == "dev"

    store = Store.open_migrated(Path(":memory:"))
    try:
        engine = engine_for(store, "kubernetes", runtime=runtime)
    finally:
        store.close()
    assert engine._k8s_context == "dev-us"
    assert engine._runtime.topology_fingerprint == runtime.topology_fingerprint
    assert engine._runtime is runtime


def test_fingerprint_attached_to_preflight_reaches_the_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mayhem.cli.services import resolve_runtime_context, with_topology_fingerprint
    from mayhem.domain import runtime_adapter as ra

    monkeypatch.setattr(ra.shutil, "which", lambda _name: None)
    runtime = resolve_runtime_context(engine="podman")
    runtime = with_topology_fingerprint(runtime, _graph())
    preflight = _preflight(engine="podman", runtime=runtime)
    payload = preflight.to_dict()["runtime_context"]
    assert payload["topology_fingerprint"] == runtime.topology_fingerprint
    assert payload["engine"] == "podman"


def test_preflight_without_runtime_context_is_unchanged() -> None:
    preflight = _preflight(engine="podman", runtime=None)
    assert preflight.engine == "podman"
    assert preflight.runtime_context is None
    assert preflight.to_dict()["runtime_context"] is None


# ---------------------------------------------------------------------------
# CLI wiring: the same object reaches preflight and the engine
# ---------------------------------------------------------------------------

DRILL = """\
kind: drill
apiVersion: mayhem/v1
name: ctx-drill
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  api:
    faults:
      - fault: proc.pause
        duration: 10s
execution:
  - parallel: [api]
"""


def _install_compile_fakes(monkeypatch: pytest.MonkeyPatch, plan: Any) -> None:
    from mayhem.cli import lifecycle

    monkeypatch.setattr(lifecycle, "_graph_from", lambda *a, **k: (_graph(), "fake"))
    monkeypatch.setattr(
        lifecycle,
        "prepare",
        lambda **kwargs: SimpleNamespace(
            config_snapshot_id="cfg-abc",
            topology_snapshot_id="topo-abc",
            fingerprint="fp-123",
            safety=SimpleNamespace(allow_critical_cli=True),
            recovery_grace=300.0,
        ),
    )
    monkeypatch.setattr(
        lifecycle, "plan_from_spec", lambda *a, **k: SimpleNamespace(run_id="r-ctx", plan=plan)
    )


def test_cli_run_resolves_one_context_for_preflight_and_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app

    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    _install_compile_fakes(monkeypatch, _plan())

    seen_preflight: list[Any] = []
    real_build = build_preflight

    def _record(**kwargs: Any) -> Any:
        seen_preflight.append(kwargs.get("runtime"))
        return real_build(**kwargs)

    monkeypatch.setattr(lifecycle, "build_preflight", _record)
    engines: list[Any] = []

    def _engine_for(*args: Any, **kwargs: Any) -> Any:
        engines.append(kwargs.get("runtime"))
        return SimpleNamespace(execute=_run_result)

    monkeypatch.setattr(lifecycle, "engine_for", _engine_for)
    monkeypatch.setattr(
        lifecycle, "_gate_enabled", lambda: False
    )  # keep the gate off so no real container probes happen

    result = CliRunner().invoke(
        app,
        [
            "run",
            str(spec),
            "--compose",
            "docker-compose.yml",
            "--engine",
            "docker",
            "--execute",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert seen_preflight, "run never built a preflight"
    assert all(r is not None for r in seen_preflight)
    assert engines, "run never built an execution engine"
    assert all(r is not None for r in engines)
    assert len({id(r) for r in seen_preflight}) == 1, "engine was re-resolved mid-run"
    assert engines[0] is seen_preflight[0], "preflight and execution saw different contexts"
    assert seen_preflight[0].engine == "docker"
    assert seen_preflight[0].topology_fingerprint is not None


def _run_result(plan: Any) -> Any:
    from mayhem.controller.executor import RunResult

    return RunResult(
        run_id=plan.run_id,
        status="completed",
        started_at_epoch_s=0.0,
        ended_at_epoch_s=0.0,
    )


def test_maniac_never_rebinds_the_engine_name_to_a_runengine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: ``maniac`` used to shadow the engine *name* with the RunEngine.

    The preflight and evidence payloads therefore received a ``RunEngine``
    object in their ``engine: str`` field. The resolved context makes that
    unrepresentable — the local is now named ``run_engine``.
    """
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app

    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    _install_compile_fakes(monkeypatch, _plan())
    monkeypatch.setattr(
        lifecycle,
        "plan_maniac_from_spec",
        lambda *a, **k: SimpleNamespace(run_id="r-ctx", plan=_plan()),
    )
    monkeypatch.setattr(
        lifecycle,
        "_resolve_maniac_sources",
        lambda *a, **k: (str(tmp_path / "spec.yaml"), None, None),
    )
    monkeypatch.setattr(
        lifecycle, "engine_for", lambda *a, **k: SimpleNamespace(execute=_run_result)
    )
    monkeypatch.setattr(lifecycle, "_gate_enabled", lambda: False)

    evidence: list[Any] = []
    monkeypatch.setattr(
        lifecycle,
        "_write_evidence_after_run",
        lambda **kwargs: evidence.append(kwargs.get("engine")),
    )

    result = CliRunner().invoke(
        app,
        ["--db", str(tmp_path / "m.db"), "maniac", str(tmp_path / "spec.yaml"), "-c", str(compose)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert evidence, "maniac never wrote evidence"
    assert all(isinstance(engine, str) for engine in evidence), evidence
    assert set(evidence) == {"podman"}


# ---------------------------------------------------------------------------
# The preflight cross-check is a check, not a second resolution (M3/M4)
# ---------------------------------------------------------------------------


def test_preflight_prefers_the_resolved_context_over_a_reread_profile(
    tmp_path: Path,
) -> None:
    """The ``runtime`` branch in ``build_preflight`` is live and authoritative.

    The same config document is handed to *both* the resolver and the
    preflight cross-check, and they deliberately disagree: the context wins, so
    a re-read can never re-derive context/namespace.
    """
    config = tmp_path / "mayhem.yaml"
    config.write_text(K8S_CONFIG)
    runtime = RuntimeContext(
        engine="kubernetes",
        target_profile="dev",
        context="resolved-ctx",
        namespace="resolved-ns",
    )
    preflight = _preflight(
        engine="kubernetes", runtime=runtime, config_path=str(config), target="dev"
    )
    assert preflight.k8s_context == "resolved-ctx"
    assert preflight.k8s_namespace == "resolved-ns"
    assert preflight.k8s_target_scope == "dev"
    # The cross-check still validates the selected profile.
    assert preflight.blocked_items == ()
    assert not any("ambiguous" in w for w in preflight.warnings)


def test_preflight_cross_check_still_reports_ambiguity_with_a_context(
    tmp_path: Path,
) -> None:
    """Two profiles and no ``--target`` still warns even when a context exists."""
    config = tmp_path / "mayhem.yaml"
    config.write_text(K8S_CONFIG)
    runtime = RuntimeContext(engine="kubernetes", context="c", namespace="n")
    preflight = _preflight(engine="kubernetes", runtime=runtime, config_path=str(config))
    assert any("ambiguous" in w for w in preflight.warnings)


def test_preflight_cross_check_still_blocks_a_non_kubernetes_profile(
    tmp_path: Path,
) -> None:
    config = tmp_path / "mayhem.yaml"
    config.write_text("targets:\n  local:\n    engine: docker\n")
    runtime = RuntimeContext(engine="kubernetes", target_profile="local")
    preflight = _preflight(
        engine="kubernetes", runtime=runtime, config_path=str(config), target="local"
    )
    assert any("is not a Kubernetes profile" in item for item in preflight.blocked_items)


# ---------------------------------------------------------------------------
# I4: engine/runtime disagreement is refused, not silently resolved
# ---------------------------------------------------------------------------


def test_engine_for_refuses_an_engine_runtime_mismatch() -> None:
    from mayhem.cli.services import engine_for
    from mayhem.infra.store import Store

    runtime = RuntimeContext(engine="docker")
    store = Store.open_migrated(Path(":memory:"))
    try:
        with pytest.raises(InvariantViolationError) as excinfo:
            engine_for(store, "podman", runtime=runtime)
    finally:
        store.close()
    assert excinfo.value.rule == "runtime_engine_mismatch"
    assert "podman" in str(excinfo.value)
    assert "docker" in str(excinfo.value)


def test_engine_for_accepts_a_matching_engine_and_an_omitted_one() -> None:
    from mayhem.cli.services import engine_for
    from mayhem.infra.store import Store

    runtime = RuntimeContext(engine="kubernetes", context="prod-eu")
    store = Store.open_migrated(Path(":memory:"))
    try:
        matching = engine_for(store, "kubernetes", runtime=runtime)
        assert matching._engine == "kubernetes"
        # Omitted engine: the context is the only source of truth.
        inferred = engine_for(store, runtime=runtime)
        assert inferred._engine == "kubernetes"
        assert inferred._k8s_context == "prod-eu"
        # Legacy: no context at all keeps the historical podman default.
        legacy = engine_for(store)
        assert legacy._engine == "podman"
    finally:
        store.close()


def test_runengine_refuses_an_engine_runtime_mismatch() -> None:
    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink
    from mayhem.infra.store import Store

    store = Store.open_migrated(Path(":memory:"))
    try:
        with pytest.raises(InvariantViolationError) as excinfo:
            RunEngine(
                store,
                SQLiteLeaseSink(store),
                engine="docker",
                runtime=RuntimeContext(engine="podman"),
            )
    finally:
        store.close()
    assert excinfo.value.rule == "runtime_engine_mismatch"


def test_runengine_accepts_engine_only_and_runtime_only() -> None:
    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink
    from mayhem.infra.store import Store

    store = Store.open_migrated(Path(":memory:"))
    try:
        sink = SQLiteLeaseSink(store)
        assert RunEngine(store, sink, engine="podman")._engine == "podman"
        assert RunEngine(store, sink)._engine is None
        ctx = RunEngine(store, sink, runtime=RuntimeContext(engine="podman"))
        assert ctx._engine == "podman"
    finally:
        store.close()


# ---------------------------------------------------------------------------
# I5: version probing is lazy, never a per-command tax
# ---------------------------------------------------------------------------


def test_resolution_does_not_probe_engine_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mayhem.cli.services import resolve_runtime_context
    from mayhem.domain import runtime_adapter as ra

    seen: list[str] = []

    def _fake_detect() -> list[Any]:
        seen.append("probed")
        return [ra.describe_engine("podman").model_copy(update={"version": "podman 6.0.0"})]

    monkeypatch.setattr(ra, "detect_available_engines", _fake_detect)
    ctx = resolve_runtime_context(engine="podman")
    assert seen == [], "resolve_runtime_context must not probe engine versions"
    assert ctx.runtime_version is None


def test_with_runtime_version_probes_on_demand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mayhem.cli.services import resolve_runtime_context, with_runtime_version
    from mayhem.domain import runtime_adapter as ra

    seen: list[str] = []

    def _fake_detect() -> list[Any]:
        seen.append("probed")
        return [ra.describe_engine("podman").model_copy(update={"version": "podman 6.0.0"})]

    monkeypatch.setattr(ra, "detect_available_engines", _fake_detect)
    ctx = resolve_runtime_context(engine="podman")
    assert seen == []
    versioned = with_runtime_version(ctx)
    assert seen == ["probed"]
    assert versioned.runtime_version == "podman 6.0.0"
    # The original context is untouched: the context is immutable.
    assert ctx.runtime_version is None
    # Kubernetes never probes container engines.
    assert with_runtime_version(RuntimeContext(engine="kubernetes")).runtime_version is None
    assert seen == ["probed"]


# ---------------------------------------------------------------------------
# I1: the ambiguity refusal is reachable from the CLI, and the unflagged
#     compatibility default is pinned on purpose
# ---------------------------------------------------------------------------


def test_cli_discover_refuses_an_ambiguous_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``mayhem discover topology`` with two engines on PATH reaches the refusal."""
    from click.testing import CliRunner

    from mayhem.cli.topology import discover
    from mayhem.domain import runtime_adapter as ra

    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    monkeypatch.setattr(ra.shutil, "which", _both_engines)

    result = CliRunner().invoke(discover, ["--compose", str(compose)])
    assert result.exit_code != 0
    assert "multiple engines available" in result.output
    assert "--runtime" in result.output


def test_cli_run_without_an_engine_flag_keeps_the_podman_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Compatibility pin: an unflagged run does *not* refuse for ambiguity.

    ``_resolve_engine_from_state()`` turns "no flag" into the explicit
    selection ``podman``, so the automatic (ambiguity-refusing) path is never
    reached by ``mayhem run``. This is a deliberate, pinned behaviour — change
    it only with a product decision, and update this test with it.
    """
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app
    from mayhem.domain import runtime_adapter as ra

    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    _install_compile_fakes(monkeypatch, _plan())
    monkeypatch.setattr(ra.shutil, "which", _both_engines)
    monkeypatch.setattr(lifecycle, "_gate_enabled", lambda: False)
    monkeypatch.setattr(
        lifecycle, "engine_for", lambda *a, **k: SimpleNamespace(execute=_run_result)
    )

    result = CliRunner().invoke(
        app,
        [
            "--db",
            str(tmp_path / "m.db"),
            "run",
            str(spec),
            "--compose",
            str(compose),
            "--execute",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "multiple engines available" not in result.output


# ---------------------------------------------------------------------------
# I3: plan and run cross-check the *same* config document
# ---------------------------------------------------------------------------

AMBIGUOUS_K8S_CONFIG = """\
targets:
  prod:
    engine: kubernetes
    context: prod-eu
    namespace: checkout
  dev:
    engine: kubernetes
    context: dev-us
    namespace: sandbox
"""


def _target_profile_signals(preflight: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The target-profile warnings/blocks a preflight reports."""
    warnings = tuple(w for w in preflight.warnings if "target profile" in w)
    blocks = tuple(b for b in preflight.blocked_items if "target profile" in b)
    return warnings, blocks


def _run_preflight_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config: Path, *args: str
) -> Any:
    """Drive a CLI command and return the last preflight it built."""
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app

    _install_compile_fakes(monkeypatch, _plan())
    monkeypatch.setattr(lifecycle, "_gate_enabled", lambda: False)
    monkeypatch.setattr(
        lifecycle, "engine_for", lambda *a, **k: SimpleNamespace(execute=_run_result)
    )
    captured: list[Any] = []
    real_build = build_preflight

    def _record(**kwargs: Any) -> Any:
        preflight = real_build(**kwargs)
        captured.append(preflight)
        return preflight

    monkeypatch.setattr(lifecycle, "build_preflight", _record)
    result = CliRunner().invoke(
        app,
        ["--db", str(tmp_path / f"{args[1]}.db"), "--config", str(config), *args],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert captured, f"{args[0]} never built a preflight"
    return captured[-1]


def test_plan_and_run_apply_the_same_target_profile_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--config <path>`` must reach the preflight cross-check in both commands.

    Without ``config_path`` threading the preflight would fall back to the
    default config document and the two commands would disagree about whether
    the Kubernetes target profile is ambiguous.
    """
    config = tmp_path / "mayhem.yaml"
    config.write_text(AMBIGUOUS_K8S_CONFIG)
    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")

    plan_pf = _run_preflight_command(
        tmp_path, monkeypatch, config, "-k", "prepare", "plan", str(spec), "-c", str(compose)
    )
    run_pf = _run_preflight_command(
        tmp_path, monkeypatch, config, "-k", "run", str(spec), "-c", str(compose)
    )

    assert _target_profile_signals(plan_pf) == _target_profile_signals(run_pf)
    # Sanity: the ambiguity warning is actually present, so the comparison above
    # is not vacuously true.
    assert any("ambiguous" in w for w in plan_pf.warnings)
    assert plan_pf.engine == run_pf.engine == "kubernetes"


def test_maniac_threads_the_config_into_its_preflight_cross_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "mayhem.yaml"
    config.write_text(AMBIGUOUS_K8S_CONFIG)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    _install_compile_fakes(monkeypatch, _plan())
    monkeypatch.setattr(lifecycle_module(), "_gate_enabled", lambda: False)
    monkeypatch.setattr(
        lifecycle_module(), "engine_for", lambda *a, **k: SimpleNamespace(execute=_run_result)
    )
    monkeypatch.setattr(
        lifecycle_module(),
        "plan_maniac_from_spec",
        lambda *a, **k: SimpleNamespace(run_id="r-ctx", plan=_plan()),
    )
    monkeypatch.setattr(
        lifecycle_module(),
        "_resolve_maniac_sources",
        lambda *a, **k: (str(tmp_path / "spec.yaml"), None, None),
    )
    captured: list[Any] = []
    real_build = build_preflight

    def _record(**kwargs: Any) -> Any:
        preflight = real_build(**kwargs)
        captured.append(preflight)
        return preflight

    monkeypatch.setattr(lifecycle_module(), "build_preflight", _record)

    from click.testing import CliRunner

    from mayhem.cli.app import app

    result = CliRunner().invoke(
        app,
        [
            "--db",
            str(tmp_path / "m.db"),
            "--config",
            str(config),
            "-k",
            "maniac",
            str(tmp_path / "spec.yaml"),
            "-c",
            str(compose),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert captured, "maniac never built a preflight"
    assert any("ambiguous" in w for w in captured[-1].warnings)


def lifecycle_module() -> Any:
    from mayhem.cli import lifecycle

    return lifecycle


# ---------------------------------------------------------------------------
# I6: every lifecycle command threads the one context
# ---------------------------------------------------------------------------


def test_cli_plan_propagates_the_context_to_preflight_and_planning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app

    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    _install_compile_fakes(monkeypatch, _plan())

    graph_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        lifecycle, "_graph_from", lambda *a, **k: (graph_calls.append(k) or _graph(), "fake")
    )
    planned: list[dict[str, Any]] = []
    monkeypatch.setattr(
        lifecycle,
        "plan_from_spec",
        lambda *a, **k: (
            planned.append(k),
            SimpleNamespace(run_id="r-ctx", plan=_plan()),
        )[1],
    )
    preflights: list[RuntimeContext | None] = []
    real_build = build_preflight

    def _record(**kwargs: Any) -> Any:
        preflights.append(kwargs.get("runtime"))
        return real_build(**kwargs)

    monkeypatch.setattr(lifecycle, "build_preflight", _record)

    result = CliRunner().invoke(
        app,
        ["--db", str(tmp_path / "p.db"), "prepare", "plan", str(spec), "-c", str(compose)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # Discovery and planning agree on the resolved engine.
    assert graph_calls[-1]["engine"] == planned[-1]["engine"] == "podman"
    assert preflights and preflights[-1] is not None
    assert preflights[-1].engine == "podman"
    assert preflights[-1].topology_fingerprint is not None


def test_cli_validate_propagates_the_context_to_discovery_and_planning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app

    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    _install_compile_fakes(monkeypatch, _plan())

    graph_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        lifecycle, "_graph_from", lambda *a, **k: (graph_calls.append(k) or _graph(), "fake")
    )
    planned: list[dict[str, Any]] = []
    monkeypatch.setattr(
        lifecycle,
        "plan_from_spec",
        lambda *a, **k: (
            planned.append(k),
            SimpleNamespace(run_id="r-ctx", plan=_plan()),
        )[1],
    )

    result = CliRunner().invoke(
        app,
        ["--db", str(tmp_path / "v.db"), "prepare", "validate", str(spec), "-c", str(compose)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert graph_calls[-1]["engine"] == planned[-1]["engine"] == "podman"


def test_cli_maniac_propagates_the_context_to_preflight_and_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from mayhem.cli import lifecycle
    from mayhem.cli.app import app

    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    _install_compile_fakes(monkeypatch, _plan())
    monkeypatch.setattr(lifecycle, "_gate_enabled", lambda: False)
    monkeypatch.setattr(
        lifecycle,
        "plan_maniac_from_spec",
        lambda *a, **k: SimpleNamespace(run_id="r-ctx", plan=_plan()),
    )
    monkeypatch.setattr(
        lifecycle,
        "_resolve_maniac_sources",
        lambda *a, **k: (str(tmp_path / "spec.yaml"), None, None),
    )
    preflights: list[RuntimeContext | None] = []
    real_build = build_preflight

    def _record(**kwargs: Any) -> Any:
        preflights.append(kwargs.get("runtime"))
        return real_build(**kwargs)

    monkeypatch.setattr(lifecycle, "build_preflight", _record)
    engines: list[RuntimeContext | None] = []
    monkeypatch.setattr(
        lifecycle,
        "engine_for",
        lambda *a, **k: (engines.append(k.get("runtime")), SimpleNamespace(execute=_run_result))[1],
    )

    result = CliRunner().invoke(
        app,
        [
            "--db",
            str(tmp_path / "m.db"),
            "maniac",
            str(tmp_path / "spec.yaml"),
            "-c",
            str(compose),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert preflights and preflights[-1] is not None
    assert engines and engines[-1] is preflights[-1], "maniac used two different contexts"
    assert preflights[-1].engine == "podman"
    assert preflights[-1].topology_fingerprint is not None


# ---------------------------------------------------------------------------
# I2: `discover topology` resolves its context from the same inputs it
#     validates the Kubernetes target profile with
# ---------------------------------------------------------------------------

K8S_MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: mayhem
  labels:
    app: api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: docker.io/library/python:3.13-alpine
          command: ["python", "-m", "http.server", "8080"]
"""


def test_cli_discover_resolves_the_context_from_the_selected_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--target``/``--config`` must feed the runtime context, not just the
    validation lookup, so discovery and the emitted context cannot disagree.
    """
    import json as _json

    from click.testing import CliRunner

    from mayhem.agents import k8s_resolve
    from mayhem.cli.app import app

    config = tmp_path / "mayhem.yaml"
    config.write_text(K8S_CONFIG)
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(K8S_MANIFEST)

    seen: list[dict[str, Any]] = []
    real_resolve = k8s_resolve.resolve_k8s_target_context

    def _record(**kwargs: Any) -> Any:
        seen.append(kwargs)
        return real_resolve(**kwargs)

    monkeypatch.setattr(k8s_resolve, "resolve_k8s_target_context", _record)

    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "discover",
            "topology",
            "--runtime",
            "kubernetes",
            "--target",
            "dev",
            "--mode",
            "dry-run",
            "--manifest",
            str(manifest),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen, "kubernetes discovery never resolved its target context"
    assert seen[-1]["profile_context"] == "dev-us"
    assert seen[-1]["profile_namespace"] == "sandbox"
    payload = _json.loads(result.output)
    assert payload["kubernetes"]["context"] == "dev-us"
    assert payload["kubernetes"]["namespace"] == "sandbox"
    assert payload["engine"] == "kubernetes"


def test_engine_mismatch_is_rendered_as_a_cli_error_not_a_traceback() -> None:
    """The refusal survives the CLI boundary as a structured error."""
    from mayhem.cli.errors import map_exception_to_error
    from mayhem.cli.services import engine_for
    from mayhem.infra.store import Store

    store = Store.open_migrated(Path(":memory:"))
    try:
        with pytest.raises(InvariantViolationError) as excinfo:
            engine_for(store, "docker", runtime=RuntimeContext(engine="podman"))
    finally:
        store.close()
    err = map_exception_to_error(excinfo.value)
    assert err.code == "validation_error"
    assert "disagrees with the resolved runtime" in err.message
    assert err.remediation


# ---------------------------------------------------------------------------
# The preflight carries the same guard, and None always means "unspecified"
# ---------------------------------------------------------------------------


def test_reconcile_engine_semantics() -> None:
    """The single shared rule: one source of truth for the guard."""
    from mayhem.domain.runtime_context import reconcile_engine

    ctx = RuntimeContext(engine="kubernetes", context="prod-eu")
    # Neither: unspecified, the caller applies its own default.
    assert reconcile_engine(None, None) is None
    # Engine only (legacy callers).
    assert reconcile_engine("podman", None) == "podman"
    assert reconcile_engine("", None) is None  # blank == unspecified
    # Runtime only.
    assert reconcile_engine(None, ctx) == "kubernetes"
    assert reconcile_engine("", ctx) == "kubernetes"
    # Both, agreeing.
    assert reconcile_engine("kubernetes", ctx) == "kubernetes"
    # Both, disagreeing: refused, naming both sides.
    with pytest.raises(InvariantViolationError) as excinfo:
        reconcile_engine("podman", ctx)
    assert excinfo.value.rule == "runtime_engine_mismatch"
    assert "podman" in str(excinfo.value)
    assert "kubernetes" in str(excinfo.value)


def test_build_preflight_refuses_an_engine_runtime_mismatch() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _preflight(engine="podman", runtime=RuntimeContext(engine="docker"))
    assert excinfo.value.rule == "runtime_engine_mismatch"
    assert "podman" in str(excinfo.value)
    assert "docker" in str(excinfo.value)


def test_build_preflight_refuses_before_safety_or_plan_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal happens before any safety/blast-radius work runs."""
    from mayhem.controller import preflight as preflight_module

    touched: list[str] = []

    def _boom(name: str) -> Any:
        def _inner(*_args: Any, **_kwargs: Any) -> Any:
            touched.append(name)
            raise AssertionError(f"preflight ran {name} before reconciling the runtime")

        return _inner

    monkeypatch.setattr(preflight_module, "validate_plan", _boom("validate_plan"))
    monkeypatch.setattr(preflight_module, "_blast_radius_for", _boom("_blast_radius_for"))

    with pytest.raises(InvariantViolationError) as excinfo:
        build_preflight(
            spec_path=None,
            compose=None,
            graph=object(),
            store=None,
            config_path=None,
            profile=None,
            allow_critical=False,
            target=None,
            engine="docker",
            plan=_plan(),
            safety=object(),  # type: ignore[arg-type]
            runtime=RuntimeContext(engine="podman"),
        )
    assert excinfo.value.rule == "runtime_engine_mismatch"
    assert touched == [], "safety work ran before the runtime was reconciled"


def test_preflight_from_services_refuses_a_mismatch_before_building_anything() -> None:
    from mayhem.controller.preflight import preflight_from_services

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("preflight_from_services did work before reconciling")

    import mayhem.cli.services as services_module

    original_build_graph = services_module.build_graph
    services_module.build_graph = _boom
    try:
        with pytest.raises(InvariantViolationError) as excinfo:
            preflight_from_services(
                spec_path=None,
                compose=None,
                store=None,
                config_path=None,
                profile=None,
                allow_critical=False,
                target=None,
                engine="kubernetes",
                runtime=RuntimeContext(engine="podman"),
            )
        assert excinfo.value.rule == "runtime_engine_mismatch"
    finally:
        services_module.build_graph = original_build_graph


def test_build_preflight_accepts_engine_only_runtime_only_and_agreement() -> None:
    # Legacy: engine only.
    assert _preflight(engine="podman", runtime=None).engine == "podman"
    # Runtime only (engine unspecified).
    ctx = RuntimeContext(engine="kubernetes", context="prod-eu", namespace="checkout")
    preflight = _preflight(engine=None, runtime=ctx)
    assert preflight.engine == "kubernetes"
    assert preflight.k8s_context == "prod-eu"
    assert preflight.k8s_namespace == "checkout"
    # Both, agreeing.
    both = _preflight(engine="kubernetes", runtime=ctx)
    assert both.engine == "kubernetes"
    assert both.runtime_context is ctx


def test_engine_for_treats_none_engine_as_unspecified() -> None:
    from mayhem.cli.services import engine_for
    from mayhem.infra.store import Store

    ctx = RuntimeContext(engine="kubernetes", context="prod-eu")
    store = Store.open_migrated(Path(":memory:"))
    try:
        # An explicit None is "unspecified", not an engine named None.
        explicit_none = engine_for(store, None, runtime=ctx)
        assert explicit_none._engine == "kubernetes"
        assert explicit_none._k8s_context == "prod-eu"
        # Omitted and explicit None behave identically.
        assert engine_for(store, runtime=ctx)._engine == "kubernetes"
        # Legacy positional default preserved.
        assert engine_for(store, "podman")._engine == "podman"
        assert engine_for(store)._engine == "podman"
        assert engine_for(store, None)._engine == "podman"
        # A real disagreement is still refused.
        with pytest.raises(InvariantViolationError) as excinfo:
            engine_for(store, "podman", runtime=ctx)
        assert excinfo.value.rule == "runtime_engine_mismatch"
    finally:
        store.close()


def test_runengine_treats_none_engine_as_unspecified() -> None:
    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink
    from mayhem.infra.store import Store

    ctx = RuntimeContext(engine="kubernetes", context="prod-eu")
    store = Store.open_migrated(Path(":memory:"))
    try:
        sink = SQLiteLeaseSink(store)
        assert RunEngine(store, sink, engine=None, runtime=ctx)._engine == "kubernetes"
        assert RunEngine(store, sink, engine=None)._engine is None
        assert RunEngine(store, sink, engine="docker")._engine == "docker"
        assert RunEngine(store, sink)._engine is None
        with pytest.raises(InvariantViolationError) as excinfo:
            RunEngine(store, sink, engine="podman", runtime=ctx)
        assert excinfo.value.rule == "runtime_engine_mismatch"
    finally:
        store.close()
