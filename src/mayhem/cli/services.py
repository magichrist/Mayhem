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

from mayhem.config import load_config, save_snapshot
from mayhem.controller.executor import RunEngine, RunResult
from mayhem.controller.planner import plan_drill, plan_maniac
from mayhem.controller.safety import SafetyContext, environment_fingerprint
from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
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

    from mayhem.domain.events import Event
    from mayhem.toolkit.registry import CapabilityReport

DEFAULT_DB = "mayhem.db"


def open_store(db: str) -> Store:
    return Store.open_migrated(Path(db))


def build_graph(compose: str | None) -> TopologyGraph:
    """Build a topology graph from a compose blueprint (ADR-0006).

    Drill specs are compose-native (Phase 6): the graph is always derived
    from ``docker-compose.yaml``, so the manual ``--process``/``--service``/
    ``--host`` overrides are gone. ``compose`` defaults to auto-detect in the
    caller (``_resolve_compose``), so reaching here with ``None`` means no
    blueprint was found.
    """
    if compose is None:
        raise ValueError(
            "no docker-compose blueprint found — pass --compose <path> "
            "or place a compose file in the working directory"
        )
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine
    from mayhem.topology.providers.adapter_registry import best_effort as runtime_best_effort
    from mayhem.topology.providers.compose import ComposeFileProvider
    from mayhem.topology.service import TopologyService

    engine = _resolve_engine(str(_STATE.get("engine", "")))

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


@dataclass(frozen=True, slots=True)
class Prepared:
    config_snapshot_id: str
    topology_snapshot_id: str
    fingerprint: str
    safety: SafetyContext


def prepare(
    *,
    config_path: str | None,
    profile: str | None,
    allow_critical: bool,
    store: Store,
    graph: TopologyGraph,
    compose: str | None,
    spec_path: str | None = None,
) -> Prepared:
    cfg, sources = load_config(
        config_path=config_path,
        profile=profile,
        environ={"MAYHEM_LOG_LEVEL": "INFO"},
        skip_default_file_if_spec=spec_path,
    )
    cfg_snapshot_id = save_snapshot(store, cfg, sources)

    fingerprint = environment_fingerprint(
        host_names=[n.name for n in graph.of_kind(NodeKind.HOST)],
        compose_digest=_compose_digest(compose),
        profile=profile,
    )
    topo_snapshot_id = "topo-" + fingerprint[:12]
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO topology_snapshots (id, run_id, graph_json, drift_report,"
            " fingerprint) VALUES (?, NULL, ?, '{}', ?)",
            (topo_snapshot_id, graph.model_dump_json(), fingerprint),
        )

    budget = cfg.blast_radius or BlastRadiusBudget()
    return Prepared(
        config_snapshot_id=cfg_snapshot_id,
        topology_snapshot_id=topo_snapshot_id,
        fingerprint=fingerprint,
        safety=SafetyContext(
            policy=cfg.policy,
            budget=budget,
            fingerprint=fingerprint,
            allow_critical_cli=allow_critical,
        ),
    )


@dataclass(frozen=True, slots=True)
class CompiledPlan:
    run_id: str
    plan: ExecutionPlan


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
    common: dict[str, str] = {
        "config_snapshot_id": prepared.config_snapshot_id,
        "topology_snapshot_id": prepared.topology_snapshot_id,
        "environment_fingerprint": prepared.fingerprint,
    }
    plan = plan_drill(
        run_id,
        spec,
        graph,
        **common,
        engine=engine,
        spec_dir=str(Path(spec_path).parent),
    )
    return CompiledPlan(run_id=run_id, plan=plan)


def plan_maniac_from_spec(
    spec_path: str,
    graph: TopologyGraph,
    *,
    prepared: Prepared,
    engine: str = "podman",
    config_path: str | None = None,
    profile: str | None = None,
) -> CompiledPlan:
    """Compile a drill spec into a random maniac plan (ADR-M5-1).

    Behaves like :func:`plan_from_spec` (schema validation, topology
    resolution) but replaces the authored execution with ``run_level`` random
    rounds. The maniac settings come from the spec's own ``config.maniac``
    block when present, otherwise from the layered ``mayhem.yaml`` config
    (``maniac:`` key); the spec wins when both exist (ADR-M5-1).
    """
    spec = load_drill(spec_path)
    maniac = spec.config.maniac
    if maniac is None:
        cfg, _sources = load_config(
            config_path=config_path,
            profile=profile,
            environ={},
            skip_default_file_if_spec=spec_path,
        )
        maniac = cfg.maniac
    run_id = f"r-{spec.name}-{uuid.uuid4().hex[:8]}"
    common: dict[str, str] = {
        "config_snapshot_id": prepared.config_snapshot_id,
        "topology_snapshot_id": prepared.topology_snapshot_id,
        "environment_fingerprint": prepared.fingerprint,
    }
    plan = plan_maniac(
        run_id,
        spec,
        graph,
        **common,
        engine=engine,
        spec_dir=str(Path(spec_path).parent),
        maniac=maniac,
    )
    return CompiledPlan(run_id=run_id, plan=plan)


def engine_for(
    store: Store,
    engine: str = "podman",
    *,
    live_graph: Callable[[], TopologyGraph] | None = None,
    on_event: Callable[[Event], None] | None = None,
    bypass: dict[tuple[str, str], str] | None = None,
) -> RunEngine:
    return RunEngine(
        store,
        SQLiteLeaseSink(store),
        engine=engine,
        live_graph=live_graph,
        on_event=on_event,
        bypass=bypass,
    )


def recent_runs(store: Store, limit: int) -> list[dict[str, Any]]:
    rows = store.query(
        "SELECT id, kind, status, started_at FROM runs ORDER BY started_at DESC LIMIT ?",
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
            "SELECT id, state, fault_id, release_mechanism FROM fault_leases"
            " WHERE run_id = ? ORDER BY created_epoch_s",
            (run_id,),
        )
    ]
    return {"steps": steps, "events": events, "leases": leases}


def effective_config(config_path: str | None, profile: str | None) -> tuple[Any, dict[str, str]]:
    return load_config(config_path=config_path, profile=profile, environ={})


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
                )
            )
            store.save_observation(
                "campaign_run",
                run_id=ran.run_id,
                source=campaign_id,
                data={"spec": _sp, "status": ran.status, "index": _i},
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
