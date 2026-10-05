"""Application services for the CLI — the only place CLI touches mayhem internals.

Handlers stay thin: they translate arguments into service calls and results
into output. Everything here is UI-framework-agnostic so a future REST/UI
layer can reuse it verbatim.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from mayhem.cli.errors import MayhemCliError
from mayhem.config import load_config, save_snapshot
from mayhem.controller.executor import RunEngine, RunResult
from mayhem.controller.planner import plan_drill, plan_maniac
from mayhem.controller.safety import SafetyContext, environment_fingerprint
from mayhem.domain.experiments import BlastRadiusBudget, DrillSpec, ExecutionPlan
from mayhem.domain.quota import DamageQuota
from mayhem.domain.runtime_context import RuntimeContext, reconcile_engine
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ProcessNode,
    TopologyGraph,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store
from mayhem.spec import load_drill

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.controller.preflight_gate import PreflightGate
    from mayhem.domain.events import Event
    from mayhem.domain.execution_intent import ExecutionIntent
    from mayhem.domain.prediction import BlastCeilings
    from mayhem.infra.budget_enforcement import RunBudgetGuard
    from mayhem.toolkit.registry import CapabilityReport

DEFAULT_DB = "mayhem.db"


def open_store(db: str) -> Store:
    return Store.open_migrated(Path(db))


def selected_engine() -> str:
    """The engine selected at the root (``-k/--kubernetes``, ``-p/--podman``).

    Returns ``"kubernetes"``, ``"docker"``, ``"podman"``, or ``""`` (auto).
    Every CLI command that builds fault material routes through this so the
    ``-k`` flag has the same effect everywhere: discovery, planning, and
    execution all target the same engine as ``topology discover``.
    """
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine

    return _resolve_engine(str(_STATE.get("engine", ""))) or ""


def _engine_version(name: str) -> str | None:
    """Best-effort version string for a container engine, or ``None``.

    Never raises: an unknown engine (``kubernetes`` has no container-engine
    descriptor) or an unreadable binary yields ``None`` rather than a guess.
    """
    try:
        from mayhem.infra.engine_probe import detect_available_engines

        for candidate in detect_available_engines():
            if candidate.name == name:
                version = candidate.version
                return version if isinstance(version, str) and version else None
    except Exception:
        return None
    return None


def _kubernetes_provider_version() -> str | None:
    """Version of the Kubernetes SDK backing discovery, or ``None``."""
    try:
        from importlib.metadata import version

        return version("kubernetes")
    except Exception:
        return None


def with_runtime_version(runtime: RuntimeContext) -> RuntimeContext:
    """Return *runtime* with the engine version probed, on demand.

    Probing shells out (``docker --version`` / ``podman --version``), so it is
    kept out of :func:`resolve_runtime_context` — every command would otherwise
    pay two subprocesses for a field it does not display. Call this only where
    the version is actually rendered (today: ``topology discover``).
    """
    if runtime.engine == "kubernetes":
        return runtime
    version = _engine_version(runtime.engine)
    if version is None or version == runtime.runtime_version:
        return runtime
    return runtime.model_copy(update={"runtime_version": version})


def resolve_runtime_context(
    *,
    engine: str | None = None,
    target: str | None = None,
    config_path: str | None = None,
    profile: str | None = None,
    unavailable_fallback: str | None = "podman",
) -> RuntimeContext:
    """Resolve the runtime **once** for a plan (v0.9.0).

    Selection rules, in order:

    1. An explicit ``engine`` (``--engine docker``, the root ``-k/--kubernetes``
       or ``-p/--podman`` flag) always wins and is never re-probed for
       availability — that is the user's decision.
    2. Otherwise the engine is auto-detected. Two engines on ``PATH`` is
       ambiguous and is refused (``InvariantViolationError`` rule
       ``engine_ambiguous``) rather than guessed.
    3. No engine on ``PATH`` keeps the CLI's long-standing ``podman`` default
       (``unavailable_fallback``). Pass ``unavailable_fallback=None`` to
       surface the ``engine_unavailable`` refusal instead — what
       ``topology discover`` does.

    For ``kubernetes`` the kubeconfig context and namespace are read from the
    selected target profile; container engines never touch the docker/podman
    descriptors when the engine is ``kubernetes``. ``profile`` is the
    configuration overlay (``mayhem.{profile}.yaml``), so a target profile
    declared only in that overlay is still found — the same effective
    configuration every other consumer resolves.

    ``runtime_version`` is *not* probed here (that would cost two subprocesses
    on every command); use :func:`with_runtime_version` where it is displayed.
    """
    from mayhem.domain.errors import InvariantViolationError

    selected = (engine or "").strip().lower()
    if selected:
        resolved_engine = selected
    else:
        from mayhem.infra.engine_probe import resolve_engine_selection

        try:
            resolved_engine = resolve_engine_selection(None).name
        except InvariantViolationError as exc:
            if getattr(exc, "rule", "") == "engine_unavailable" and unavailable_fallback:
                resolved_engine = unavailable_fallback
            else:
                raise

    namespace: str | None = None
    kube_context: str | None = None
    provider_version: str | None = None
    if resolved_engine == "kubernetes":
        provider_version = _kubernetes_provider_version()
        selected_profile = _select_target_profile(target, config_path, profile)
        if selected_profile is not None and getattr(selected_profile, "engine", "kubernetes") == (
            "kubernetes"
        ):
            kube_context = selected_profile.context
            namespace = selected_profile.namespace

    return RuntimeContext(
        engine=resolved_engine,
        target_profile=target,
        namespace=namespace,
        context=kube_context,
        provider_version=provider_version,
    )


def _select_target_profile(
    target: str | None, config_path: str | None, profile: str | None = None
) -> Any:
    """The target profile a selection resolves to, or ``None``.

    Resolution goes through the one configuration seam
    (:func:`mayhem.config.select_target_profile`), so a profile contributed by
    the ``mayhem.{profile}.yaml`` overlay is visible here exactly as it is to
    topology, preflight, and diagnostics. ``profile`` is the configuration
    overlay, not a target-profile name.

    Selection semantics are unchanged, and mirror
    ``mayhem.controller.preflight._k8s_profile``: an explicit ``--target``
    wins, a single configured profile is inferred, and anything ambiguous
    resolves to nothing rather than guessing.
    """
    from mayhem.config import select_target_profile as _select

    try:
        return _select(config_path, profile=profile, target=target)
    except Exception:
        return None


def with_topology_fingerprint(
    runtime: RuntimeContext, graph: TopologyGraph | None
) -> RuntimeContext:
    """Return *runtime* with the fingerprint of *graph* attached.

    The engine has to be known before the topology can be built, so the
    fingerprint is attached in a second, purely local step — the engine, target,
    namespace, and context are never re-resolved.
    """
    if graph is None:
        return runtime
    try:
        from mayhem.domain.runtime_adapter import topology_fingerprint_for_engine

        fingerprint = topology_fingerprint_for_engine(runtime.engine, graph)
    except Exception:
        return runtime
    return runtime.model_copy(update={"topology_fingerprint": fingerprint})


def engine_fault_kinds() -> tuple[str, ...]:
    """Catalog fault ids that can run under the CLI-selected engine.

    With ``-k/--kubernetes`` only the k8s driver's available families are
    returned (pod/node targets); otherwise the full catalog applies
    (docker/podman compose runtimes). Landscape, coverage, and suggestion
    commands scope themselves with this, so ``-k`` never surfaces a fault the
    selected engine cannot execute.
    """
    from mayhem.domain.catalog import all_definitions

    if selected_engine() == "kubernetes":
        from mayhem.controller.k8s_runtime import k8s_available_faults

        return tuple(k8s_available_faults())
    return tuple(sorted(d.id for d in all_definitions() if not d.catalog_only))


def build_graph(
    compose: str | None,
    *,
    engine_name: str | None = None,
    target: str | None = None,
    config_path: str | None = None,
    profile: str | None = None,
) -> TopologyGraph:
    """Build a topology graph from a compose blueprint or the live cluster.

    Drill specs are compose-native (Phase 6): the graph is derived from
    ``docker-compose.yaml`` — unless ``--kubernetes`` was set at the root, in
    which case the graph comes straight from the kubeconfig-resolved cluster
    (no blueprint involved). ``compose`` defaults to auto-detect in the
    caller (``_resolve_compose``), so reaching here with ``None`` and a
    container engine means no blueprint was found. ``profile`` is the
    configuration overlay, so a Kubernetes target profile declared only there is
    still honoured.
    """
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine
    from mayhem.topology.providers.adapter_registry import best_effort as runtime_best_effort
    from mayhem.topology.providers.compose import ComposeFileProvider
    from mayhem.topology.service import TopologyService

    engine = engine_name or _resolve_engine(str(_STATE.get("engine", "")))

    if engine == "kubernetes":
        if compose is None:
            return _kubernetes_discovery_graph(
                target=target, config_path=config_path, profile=profile
            )
        from mayhem.topology.providers.k8s_manifest import KubernetesManifestProvider
        from mayhem.topology.service import TopologyService as _ManifestTopologyService

        manifest_provider = KubernetesManifestProvider(compose)
        if not manifest_provider.is_available():
            raise ValueError(
                f"kubernetes blueprint {compose!r} not found — pass a k8s manifest "
                "bundle via --compose or drop --compose to discover the live cluster"
            )
        if not manifest_provider.resource_kinds:
            return _kubernetes_discovery_graph()
        return _ManifestTopologyService().discover([manifest_provider]).graph

    if compose is None:
        raise ValueError(
            "no docker-compose blueprint found — pass --compose <path> "
            "or place a compose file in the working directory"
        )
    compose_provider = ComposeFileProvider(compose)
    runtime_provider = runtime_best_effort(engine)
    if runtime_provider is not None:
        runtime_provider.filter_by_compose(
            compose_provider.project_name,
            compose_provider.service_names,
        )

    result = (
        TopologyService()
        .discover(
            [provider for provider in (compose_provider, runtime_provider) if provider is not None]
        )
        .graph
    )

    existing_process_names = {n.name for n in result.nodes if n.kind == NodeKind.PROCESS}
    extra_nodes: list[Any] = []
    extra_edges: list[Edge] = []
    for svc in result.nodes:
        if svc.kind == NodeKind.SERVICE and svc.name not in existing_process_names:
            proc_id = f"p-{svc.name}"
            extra_nodes.append(ProcessNode(id=proc_id, name=svc.name, pid=0, host_id="h-local"))
            extra_edges.append(Edge(src=svc.id, dst=proc_id, kind=EdgeKind.RUNS_ON))
    if extra_nodes:
        result = TopologyGraph(
            nodes=tuple(result.nodes) + tuple(extra_nodes),
            edges=tuple(result.edges) + tuple(extra_edges),
        )
    return result


def _kubernetes_discovery_graph(
    target: str | None = None, config_path: str | None = None, profile: str | None = None
) -> TopologyGraph:
    """Discover the topology from the live cluster (``--kubernetes`` engine).

    Mirrors the kubernetes branch of ``mayhem discover topology``: the graph
    is kubeconfig/context driven and needs no compose blueprint. Raises
    ``ValueError`` so callers that wrap it (``_graph_from``) surface a usable
    usage error when the SDK is missing or the cluster is unreachable.
    """
    from mayhem.topology.providers.kubernetes import (
        KUBERNETES_IMPORT_ERROR,
        KUBERNETES_SDK_MISSING_HINT,
        KubernetesProvider,
    )
    from mayhem.topology.service import TopologyService

    if KUBERNETES_IMPORT_ERROR is not None:
        raise ValueError("Kubernetes discovery SDK unavailable. " + KUBERNETES_SDK_MISSING_HINT)
    context = None
    namespace = None
    workload_selector = None
    if target is not None:
        from mayhem.config import select_target_profile

        found = select_target_profile(config_path, profile=profile, target=target)
        if found is None:
            raise ValueError(f"unknown Kubernetes target profile {target!r}")
        if found.engine != "kubernetes":
            raise ValueError(f"target profile {target!r} is not a Kubernetes profile")
        context = found.context
        namespace = found.namespace
        workload_selector = found.workload_selector
    provider = KubernetesProvider(
        "kubernetes",
        context=context,
        namespace=namespace,
        workload_selector=workload_selector,
    )
    if not provider.is_available():
        details = provider.readiness_details()
        raise ValueError(
            "Kubernetes cluster is not reachable: "
            f"{details.get('error', 'check context and namespace')}"
        )
    return TopologyService().discover([provider]).graph


@dataclass(frozen=True, slots=True)
class Prepared:
    config_snapshot_id: str
    topology_snapshot_id: str
    fingerprint: str
    safety: SafetyContext
    recovery_grace: float = 300.0


def prepare(
    *,
    config_path: str | None,
    profile: str | None,
    policy: str | None = None,
    allow_critical: bool,
    store: Store,
    graph: TopologyGraph,
    compose: str | None,
    spec_path: str | None = None,
    target: str | None = None,
) -> Prepared:
    from mayhem.cli.app import _STATE

    effective_policy = policy or _STATE.get("policy") or None
    cfg, sources = load_config(
        config_path=config_path,
        profile=profile,
        policy=effective_policy,
        environ={"MAYHEM_LOG_LEVEL": "INFO"},
        skip_default_file_if_spec=spec_path,
    )
    cfg_snapshot_id = save_snapshot(store, cfg, sources)
    target_profile = target or _STATE.get("target", "") or None

    fingerprint = environment_fingerprint(
        host_names=[n.name for n in graph.of_kind(NodeKind.HOST)],
        compose_digest=_compose_digest(compose),
        profile=profile,
        policy_id=effective_policy,
        target_profile=target_profile,
    )
    topo_snapshot_id = "topo-" + fingerprint[:12]
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO topology_snapshots (id, run_id, graph_json, drift_report,"
            " fingerprint) VALUES (?, NULL, ?, '{}', ?)",
            (topo_snapshot_id, graph.model_dump_json(), fingerprint),
        )

    budget = cfg.blast_radius or BlastRadiusBudget()
    effective_policy = policy or _STATE.get("policy") or ""
    return Prepared(
        config_snapshot_id=cfg_snapshot_id,
        topology_snapshot_id=topo_snapshot_id,
        fingerprint=fingerprint,
        safety=SafetyContext(
            policy=cfg.policy,
            budget=budget,
            damage_quota=budget.damage_quota or DamageQuota(),
            fingerprint=fingerprint,
            allow_critical_cli=allow_critical,
            policy_id=effective_policy,
            target_profile=target_profile,
        ),
        recovery_grace=cfg.recovery_grace,
    )


@dataclass(frozen=True, slots=True)
class CompiledPlan:
    run_id: str
    plan: ExecutionPlan
    #: The authored spec the plan was compiled from, when the plan came from
    #: one. Carried rather than re-read: the steady-state block lives on the
    #: spec, not on the frozen plan, so a post-run evaluation that re-read the
    #: file would be grading whatever the file says *now* rather than what ran.
    #: ``None`` for a plan loaded from a file or the store — those carry no
    #: spec at all, and a missing spec renders nothing rather than guessing.
    spec: DrillSpec | None = None


def plan_from_spec(
    spec_path: str,
    graph: TopologyGraph,
    *,
    prepared: Prepared,
    engine: str = "podman",
) -> CompiledPlan:
    """Compile a drill spec into a frozen :class:`ExecutionPlan`.

    The drill spec is validated (schema), then every referenced container is
    required to exist in the topology graph before the plan is compiled
    ([ADR-0019]/[ADR-0021]). ``engine`` flows into the plan so PIDs/IPs are
    resolved against the right runtime at execution time ([ADR-0020]).
    """
    spec = load_drill(spec_path)
    # The run id is `r-<name>-<suffix>`: the readable base keeps the drill
    # identifiable, while the unique suffix lets any number of runs against the
    # same spec be recorded in one persistent DB without colliding on the
    # `runs.id` PRIMARY KEY.
    run_id = f"r-{spec.name}-{uuid.uuid4().hex[:8]}"
    policy_id = getattr(prepared.safety, "policy_id", "") or ""
    if not policy_id:
        from mayhem.cli.app import _STATE

        policy_id = _STATE.get("policy", "") or "default"
    common: dict[str, str] = {
        "config_snapshot_id": prepared.config_snapshot_id,
        "topology_snapshot_id": prepared.topology_snapshot_id,
        "environment_fingerprint": prepared.fingerprint,
        "policy_id": policy_id,
    }
    plan = plan_drill(
        run_id,
        spec,
        graph,
        **common,
        engine=engine,
        spec_dir=str(Path(spec_path).parent),
    )
    return CompiledPlan(run_id=run_id, plan=plan, spec=spec)


def plan_maniac_from_spec(
    spec_path: str,
    graph: TopologyGraph,
    *,
    prepared: Prepared,
    engine: str = "podman",
    config_path: str | None = None,
    profile: str | None = None,
    steps: int | None = None,
    spec: DrillSpec | None = None,
) -> CompiledPlan:
    """Compile a drill spec into a random maniac plan (ADR-M5-1).

    Behaves like :func:`plan_from_spec` (schema validation, topology
    resolution) but replaces the authored execution with ``run_level`` random
    rounds. The maniac settings come from the spec's own ``config.maniac``
    block when present, otherwise from the layered ``mayhem.yaml`` config
    (``maniac:`` key); the spec wins when both exist (ADR-M5-1). ``steps``
    (CLI ``-s/--steps``) overrides the round count on top of either source.

    ``spec`` supplies an already-built spec instead of loading ``spec_path``
    — the ``mayhem maniac -c compose`` no-spec mode synthesizes its config
    from the topology (:func:`mayhem.controller.planner.synthesize_maniac_spec`)
    and has no file to load. ``spec_path`` then names the cwd for relative
    artifacts (load-script embedding) and is not read.
    """
    document = spec if spec is not None else load_drill(spec_path)
    maniac = document.config.maniac
    if maniac is None:
        cfg, _sources = load_config(
            config_path=config_path,
            profile=profile,
            environ={},
            skip_default_file_if_spec=None if spec is not None else spec_path,
        )
        maniac = cfg.maniac
    if steps is not None:
        maniac = maniac.model_copy(update={"run_level": steps})
    run_id = f"r-{document.name}-{uuid.uuid4().hex[:8]}"
    common: dict[str, str] = {
        "config_snapshot_id": prepared.config_snapshot_id,
        "topology_snapshot_id": prepared.topology_snapshot_id,
        "environment_fingerprint": prepared.fingerprint,
    }
    plan = plan_maniac(
        run_id,
        document,
        graph,
        **common,
        engine=engine,
        spec_dir=str(Path(spec_path).parent if spec_path else Path.cwd()),
        maniac=maniac,
    )
    return CompiledPlan(run_id=run_id, plan=plan, spec=document)


def engine_for(
    store: Store,
    engine: str | None = None,
    *,
    live_graph: Callable[[], TopologyGraph] | None = None,
    on_event: Callable[[Event], None] | None = None,
    bypass: dict[tuple[str, str], str] | None = None,
    recovery_grace: float = 300.0,
    k8s_context: str | None = None,
    runtime: RuntimeContext | None = None,
    intent: ExecutionIntent | None = None,
    require_intent: bool = False,
    allow_implicit: bool = False,
    gate: PreflightGate | None = None,
    budget_guard: RunBudgetGuard | None = None,
) -> RunEngine:
    """Build the :class:`RunEngine` for a run.

    ``runtime`` is the context resolved once during application preflight. When
    given it is authoritative: the engine name and the kubeconfig context come
    from it, so the executor cannot re-resolve a *different* runtime than the
    one the plan was compiled against.

    ``engine`` is optional: an omitted, ``None``, or blank value means
    *unspecified* and is never treated as a disagreement with ``runtime``. With
    neither supplied, the historical default applies and the engine is
    ``"podman"``. Legacy callers that pass an engine keep working; passing
    *both* is allowed only when they agree — a disagreement raises
    ``InvariantViolationError`` (``runtime_engine_mismatch``) here, before any
    plan is compiled or any lease acquired.

    ``intent``/``require_intent`` carry the v0.9.0 execution-intent contract
    through to :meth:`RunEngine.execute`. They are optional so a direct
    programmatic construction keeps working; every CLI surface passes
    ``require_intent=True`` so an unapproved plan is refused before a run row
    is opened.

    ``allow_implicit`` is the *already resolved* answer to "is the documented
    ``MAYHEM_ALLOW_IMPLICIT_EXECUTION=1`` compatibility switch on?". It is a
    parameter rather than a lookup so the environment is read once, at the CLI
    edge (:func:`mayhem.cli.app.implicit_execution_allowed`), and the controller
    never touches ``os.environ``. The default ``False`` is the safe answer: a
    caller that says nothing requires an approval.

    ``gate``/``budget_guard`` are the same shape for the two refusing controls
    a deployment configures rather than mayhem: plan 10's preflight gate and
    plan 23's resource budget. Both default to ``None``, which is the additive
    *no gate configured* / *this run is not budgeted* state and leaves the run
    byte-identical to one from before either lane existed — this factory attaches
    neither by reading anything itself, so a caller that says nothing gets the
    documented absence and not a silent default. What is passed in arrives
    through :func:`mayhem.cli.execution.attach_preflight_gate` /
    :func:`~mayhem.cli.execution.attach_resource_budget`, the one decision at one
    place; the budget guard is attached *before* the gate so ``budget:available``
    reads the guard this run will be admitted against rather than reporting it
    missing. A caller that has no deployment binding — the CLI's own default, and
    every programmatic construction today — passes nothing and is unchanged.
    """
    resolved_engine = reconcile_engine(engine, runtime) or "podman"
    run = RunEngine(
        store,
        SQLiteLeaseSink(store),
        engine=resolved_engine,
        live_graph=live_graph,
        on_event=on_event,
        bypass=bypass,
        recovery_grace=recovery_grace,
        k8s_context=runtime.context if runtime is not None else k8s_context,
        runtime=runtime,
        intent=intent,
        require_intent=require_intent,
        allow_implicit=allow_implicit,
    )
    # The attach helpers are imported inside the branches that use them, so the
    # ungated path resolves no module it did not need before either lane existed.
    # ``budget_guard`` first, and the order is load-bearing: ``budget:available``
    # reads the guard this run is about to be admitted against, and a gate
    # consulted before the guard is attached would report the budget missing on a
    # run that has one.
    if budget_guard is not None:
        from mayhem.cli.execution import attach_resource_budget

        run = attach_resource_budget(run, budget_guard)
    if gate is not None:
        from mayhem.cli.execution import attach_preflight_gate

        run = attach_preflight_gate(run, gate)
    return run


def recent_runs(store: Store, limit: int) -> list[dict[str, Any]]:
    rows = store.query(
        "SELECT id, kind, status, started_at, controller_pid "
        "FROM runs ORDER BY started_at DESC LIMIT ?",
        (limit,),
    )
    return [dict(row) for row in rows]


def run_detail(store: Store, run_id: str) -> dict[str, Any] | None:
    rows = store.query("SELECT * FROM runs WHERE id = ?", (run_id,))
    return dict(rows[0]) if rows else None


def run_journal(store: Store, run_id: str) -> dict[str, Any]:
    steps = [
        dict(row)
        for row in store.query(
            "SELECT seq, id, action_type, status, started_at, ended_at, error"
            " FROM step_runs WHERE run_id = ? ORDER BY seq",
            (run_id,),
        )
    ]
    events = [
        dict(row)
        for row in store.query(
            "SELECT ts, kind, payload_json FROM events WHERE run_id = ? ORDER BY ts",
            (run_id,),
        )
    ]
    leases = [
        dict(row)
        for row in store.query(
            "SELECT id, state, fault_id, release_mechanism, resolved_target_json FROM fault_leases"
            " WHERE run_id = ? ORDER BY created_epoch_s",
            (run_id,),
        )
    ]
    return {"steps": steps, "events": events, "leases": leases}


def effective_config(
    config_path: str | None, profile: str | None, policy: str | None = None
) -> tuple[Any, dict[str, str]]:
    from mayhem.cli.app import _STATE

    effective_policy = policy or _STATE.get("policy") or None
    return load_config(
        config_path=config_path, profile=profile, policy=effective_policy, environ={}
    )


def probe_capabilities(host: str) -> CapabilityReport:
    from mayhem.toolkit.registry import default_registry

    return default_registry().probe(host=host)


class CampaignExecutionError(Exception):
    """Raised when a campaign abort-campaign policy hits an unexpected error."""


class ObservationSink(Protocol):
    """Anything able to append rows to the observations table."""

    def save_observation(
        self,
        kind: str,
        *,
        run_id: str = "",
        source: str = "",
        data: dict[str, object] | None = None,
    ) -> None: ...


@dataclass
class CampaignRunEntry:
    """Outcome of one experiment spec executed within a campaign."""

    spec_path: str
    run_id: str
    status: str  # completed | failed
    verdict: str = ""
    plan_id: str = ""
    evidence_id: str = ""


@dataclass
class CampaignRunResult:
    """Aggregate result of executing a campaign's experiment sequence."""

    campaign_id: str
    status: str  # completed | failed | aborted
    runs: list[CampaignRunEntry] = field(default_factory=list)

    def summary_md(self) -> str:
        lines = [f"# Campaign {self.campaign_id}", "", f"**status**: {self.status}"]
        lines.append(f"**runs**: {len(self.runs)}")
        for entry in self.runs:
            mark = "ok" if entry.status == "completed" else "FAIL"
            lines.append(f"- [{mark}] {entry.spec_path} → {entry.run_id}")
        return "\n".join(lines)


def run_campaign_sequence(
    *,
    campaign_id: str,
    experiments: list[str],
    policy: dict[str, Any],
    window: dict[str, Any],
    store: ObservationSink,
    run_one: Callable[[str], RunResult],
    now_fn: Callable[[], float] = time.time,
) -> CampaignRunResult:
    """Execute one spec at a time in order, honoring campaign policy and window.

    ``run_one(spec_path)`` is the injectable per-spec executor, returning a
    :class:`RunResult` or raising on failure. The on_failure policy is
    ``abort_campaign`` (stop at first failure), ``skip_and_continue``, or
    ``retry_then_abort`` (one bounded retry, then abort). ``window.max_duration_s``
    is a hard deadline; ``window.cooldown_between_experiments_s`` is slept
    between specs.
    """
    on_failure = policy.get("on_experiment_failure", "abort_campaign")
    max_duration_s = float(window.get("max_duration_s") or 3600.0)
    cooldown_s = max(0.0, float(window.get("cooldown_between_experiments_s") or 0.0))

    started = now_fn()
    result = CampaignRunResult(campaign_id=campaign_id, status="completed")
    for i, spec_path in enumerate(experiments):
        elapsed = now_fn() - started
        if elapsed >= max_duration_s:
            result.status = "aborted"
            store.save_observation(
                "campaign_stop",
                source=campaign_id,
                data={"reason": "deadline_passed", "elapsed_s": elapsed},
            )
            break

        def _attempt(path: str) -> RunResult | None:
            try:
                return run_one(path)
            except Exception as exc:
                if on_failure == "abort_campaign":
                    raise CampaignExecutionError(path, exc) from exc
                return None

        def _record(ran: RunResult, _sp: str = spec_path, _i: int = i) -> None:
            result.runs.append(
                CampaignRunEntry(
                    spec_path=_sp,
                    run_id=ran.run_id,
                    status=ran.status,
                    verdict=ran.verdict.value if ran.verdict else "",
                    plan_id=ran.run_id,
                    evidence_id=f"evidence-{ran.run_id}",
                )
            )
            store.save_observation(
                "campaign_run",
                run_id=ran.run_id,
                source=campaign_id,
                data={
                    "spec": _sp,
                    "status": ran.status,
                    "index": _i,
                    "campaign_id": campaign_id,
                    "plan_id": ran.run_id,
                    "evidence_id": f"evidence-{ran.run_id}",
                    "verdict": ran.verdict.value if ran.verdict else "",
                },
            )

        ran = _attempt(spec_path)
        if ran is not None:
            _record(ran)

        if ran is not None and ran.status == "completed":
            pass  # continue; cooldown after non-final specs below
        elif ran is not None:  # failed / aborted
            if on_failure == "skip_and_continue":
                continue
            if on_failure == "retry_then_abort":
                retry = _attempt(spec_path)
                if retry is not None and retry.status == "completed":
                    _record(retry)
                    continue
            result.status = "failed"
            break
        elif on_failure != "skip_and_continue":
            result.status = "failed"
            break

        if i < len(experiments) - 1 and cooldown_s > 0:
            time.sleep(cooldown_s)

    if result.status == "completed":
        store.save_observation(
            "campaign_done",
            source=campaign_id,
            data={"runs": len(result.runs)},
        )
    return result


def _compose_digest(graph_source: str | None) -> str:
    if graph_source is None:
        return "no-compose"
    return hashlib.sha256(Path(graph_source).read_bytes()).hexdigest()


# =============================================================================
# The gate context a read-only surface evaluates against
# =============================================================================


def gate_context_for_plan(
    *,
    fingerprint: str,
    ceilings: BlastCeilings | None = None,
) -> SafetyContext:
    """A :class:`~mayhem.controller.safety.SafetyContext` for evaluating a plan.

    Shared by every surface that evaluates a recorded plan without running it —
    ``risk-preview`` and ``plan prove`` — because a second opinion of the limits
    would be a second answer to "what does admission allow here".

    The budget and policy come from the effective configuration when one could
    be read and from the gate's own defaults otherwise. The defaults are the
    gate's, not this function's, so an unconfigured evaluation asks the same
    question admission would.

    ``fingerprint`` is required rather than defaulted: the caller owns whether
    the live identity was re-derived, and a default here would silently make
    "the drift check did not run" indistinguishable from "the drift check
    passed".
    """
    from mayhem.config import PolicyCfg

    policy = PolicyCfg()
    budget = BlastRadiusBudget()
    try:
        from mayhem.config import load_config

        config, _sources = load_config()
        policy = config.policy
        budget = config.blast_radius
    except Exception:
        # Default limits, disclosed by the caller in its rendered notes. An
        # evaluation that refused because mayhem.yaml was absent would be a
        # surface nobody could use on a fresh checkout, and the gate's defaults
        # are honest limits to report against.
        pass
    return SafetyContext(
        policy=policy,
        budget=budget,
        fingerprint=fingerprint,
        damage_quota=DamageQuota(),
        blast_ceilings=ceilings,
    )


# =============================================================================
# Reading what the store already holds
# =============================================================================


@dataclass(frozen=True, slots=True)
class RecordedRun:
    """A run's frozen plan and the topology snapshot it was planned against.

    Read out of ``runs.plan_json`` and ``topology_snapshots.graph_json`` — the
    two blobs every read-only surface reads, so each one describes the same
    plan and the same graph the run would. ``graph`` is ``None`` when the
    run recorded no snapshot, which is a refusal rather than an empty graph: an
    empty topology reads as "nothing would be affected".
    """

    run_id: str
    plan: ExecutionPlan
    graph: TopologyGraph | None
    snapshot_id: str
    environment_fingerprint: str


def load_recorded_run(store: Store, run_id: str) -> RecordedRun:
    """Read one run's plan and topology snapshot out of the store.

    Raises:
        MayhemCliError: ``validation_error`` if the store holds no such run, or
            holds a plan it cannot parse.
    """
    from mayhem.domain.experiments import ExecutionPlan as _Plan
    from mayhem.domain.topology import TopologyGraph as _Graph

    rows = store.query(
        "SELECT plan_json, topology_snapshot_id, environment_fingerprint FROM runs WHERE id = ?",
        (run_id,),
    )
    if not rows:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"no such run {run_id!r}: mayhem holds no recorded plan for it, and a report "
                "over nothing is not a report"
            ),
            details={"run_id": run_id},
            remediation="run mayhem inspect runs to list the runs mayhem recorded",
        )
    row = rows[0]
    try:
        plan = _Plan.model_validate_json(str(row["plan_json"]))
    except ValueError as exc:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"the stored plan for run {run_id!r} cannot be read: {exc}. mayhem "
                "refuses to preview a plan it cannot parse, because a preview built "
                "from a partly-read plan would describe a plan that was never run"
            ),
            details={"run_id": run_id},
            remediation="re-record the run, or re-plan it against current topology",
        ) from None
    snapshot_id = str(row["topology_snapshot_id"] or "")
    graph: TopologyGraph | None = None
    if snapshot_id:
        stored = store.query(
            "SELECT graph_json FROM topology_snapshots WHERE id = ?", (snapshot_id,)
        )
        if stored:
            try:
                graph = _Graph.model_validate_json(str(stored[0]["graph_json"]))
            except ValueError as exc:
                raise MayhemCliError(
                    code="validation_error",
                    message=(
                        f"the topology snapshot {snapshot_id!r} for run {run_id!r} cannot "
                        f"be read: {exc}. mayhem will not preview against a graph it could "
                        "not parse, because the blast radius would be computed over nothing"
                    ),
                    details={"run_id": run_id, "topology_snapshot_id": snapshot_id},
                    remediation="re-run discovery and re-plan against the current topology",
                ) from None
    return RecordedRun(
        run_id=run_id,
        plan=plan,
        graph=graph,
        snapshot_id=snapshot_id,
        environment_fingerprint=str(row["environment_fingerprint"] or ""),
    )
