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


def _preflight(*, engine: str, runtime: RuntimeContext | None) -> Any:
    return build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target=runtime.target_profile if runtime is not None else None,
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
        ctx.engine = "docker"  # type: ignore[misc]


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
