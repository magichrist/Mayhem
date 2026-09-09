"""End-of-run resilience & redundancy report (ADR-M6-1).

After a drill run completes — or fails — the executor attaches a
:class:`ResilienceReport` to the :class:`RunResult`. The report answers two
questions the step log cannot:

* *How resilient is the system?*  A deterministic 0-100 score mixing step
  performance, self-healing (did the stack come back by itself or did the run
  end with dirty leases / dead targets?) and redundancy (did the target sit in
  a replica group whose survivors kept serving while one member was faulted?).
* *What is broken right now?*  A post-run diagnosis pass inspects every
  container that was targeted by a fault — even when the run failed — and
  explains the current container state (state/exit code/restart count + short
  log tail) so a dead container that did not self-heal is called out in plain
  words instead of just "FAIL".

Both parts are best-effort and bounded: the diagnosis never raises (a failed
inspect becomes a diagnosis line), and the score is purely derived from data
already available at run end, so the drill result itself is never altered.

Every output is deterministic and explainable — the score carries a breakdown
of how the three components were measured.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.toolkit.tool_runner import run_tool

if TYPE_CHECKING:
    from mayhem.controller.executor import StepReport
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph

# Component weights disclosed in the breakdown (ADR-M6-1).
_STEP_WEIGHT = 0.35
_SELF_HEAL_WEIGHT = 0.35
_REDUNDANCY_WEIGHT = 0.30

# Deterministic grade bands over the 0-100 score (ADR-M6-1). The labels use
# the maturity vocabulary of resilience engineering (Hollnagel et al. 2006).
# A run can only earn an A when every faulted replica group kept a survivor,
# every executed fault landed cleanly, and nothing needed manual remediation.
_GRADE_BANDS: tuple[tuple[int, str, str], ...] = (
    (90, "A", "resilient"),
    (75, "B", "solid"),
    (60, "C", "acceptable"),
    (45, "D", "fragile"),
    (0, "F", "needs attention"),
)

#: Engines report a live container roughly as "running" / "Up 2 hours".
_ALIVE_PREFIXES = ("running", "up ")


def _is_alive(state: str) -> bool:
    return state.strip().lower().startswith(_ALIVE_PREFIXES)


@dataclass(frozen=True)
class ResilienceReport:
    """Score + breakdown + post-run container diagnosis for one run."""

    score: int
    step_performance: float
    self_healing: float
    redundancy: float | None  # None when no replica groups could be measured
    breakdown: tuple[str, ...] = ()
    diagnosis: tuple[str, ...] = ()

    @property
    def grade(self) -> str:
        """Single-letter grade (A-F) for the score, per ``_GRADE_BANDS``."""
        for threshold, letter, _label in _GRADE_BANDS:
            if self.score >= threshold:
                return letter
        return "F"  # unreachable: score is clamped to 0-100

    @property
    def grade_label(self) -> str:
        """Human-readable label for the grade band."""
        for threshold, _letter, label in _GRADE_BANDS:
            if self.score >= threshold:
                return label
        return "needs attention"

    def summary_md(self) -> str:
        """Structured resilience report: score, grounded metrics, findings.

        The metrics follow established dependability research rather than ad
        hoc labels: fault-injection *fidelity* (does a fault experiment measure
        what it claims — Hsueh, Tsai & Iyer, IEEE Computer 30(4), 1997),
        *recovery* (the "respond" potential of resilience engineering —
        Hollnagel, Woods & Leveson 2006) and *redundancy efficacy* (M-of-N
        fault tolerance — Avizienis, Laprie & Randell 2001). Each metric is
        reported exactly once so the score stays auditable.
        """
        lines = [
            f"**resilience**: {self.score}/100 — grade {self.grade} ({self.grade_label})",
            "",
            "metrics:",
            "",
            "| metric | result | model |",
            "|---|---|---|",
            (
                f"| fault-injection fidelity | {self.step_performance:.0%} | "
                "fault-validity of executed steps — Hsueh, Tsai & Iyer, "
                "*Fault Injection Techniques and Tools*, IEEE Computer 30(4), "
                "1997 |"
            ),
            (
                f"| recovery | {self.self_healing:.0%} | self-healing without "
                "manual intervention — *Resilience Engineering: Concepts and "
                "Precepts*, Hollnagel, Woods & Leveson, Ashgate 2006 |"
            ),
        ]
        if self.redundancy is None:
            lines.append(
                "| redundancy efficacy | not measured | no replica groups "
                "resolved — M-of-N fault tolerance, Avizienis, Laprie & "
                "Randell 2001 |"
            )
        else:
            lines.append(
                f"| redundancy efficacy | {self.redundancy:.0%} | faulted "
                "replica groups that kept a survivor — M-of-N fault tolerance, "
                "Avizienis, Laprie & Randell 2001 |"
            )
        lines.append("")
        lines.append(
            f"**weighting**: fidelity {_STEP_WEIGHT:.0%}, "
            f"recovery {_SELF_HEAL_WEIGHT:.0%}, "
            f"redundancy {_REDUNDANCY_WEIGHT:.0%} (ADR-M6-1)"
        )
        # Raw breakdown carries a redundancy bullet; the table above already
        # reports it once, so it is not repeated in the observations.
        observations = [line for line in self.breakdown if not line.startswith("redundancy:")]
        if observations:
            lines += ["", "observations:"]
            lines += [f"  - {line}" for line in observations]
        if self.diagnosis:
            lines.append("")
            lines.append("**diagnosis**:")
            lines += [f"  - {line}" for line in self.diagnosis]
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Scoring — pure functions over run-end data, no engine access.
# --------------------------------------------------------------------------- #


def _step_performance(reports: Sequence[StepReport]) -> float:
    """Fraction of executed steps that completed cleanly.

    Bypassed steps are *neutral*: the fault never ran (impact gate refused it),
    so they neither credit nor penalize performance — they are reported in the
    breakdown instead.
    """
    executed = [r for r in reports if not r.bypassed]
    if not executed:
        return 0.0
    return sum(1 for r in executed if r.ok) / len(executed)


def _self_healing(
    targeted: frozenset[str],
    dirty_leases: Sequence[str],
    alive: frozenset[str] | None,
) -> float:
    """How well the stack recovered on its own.

    Base 1.0. A dirty lease (manual remediation required) halves the credit;
    any targeted container found dead at run end subtracts half a point
    proportionally — a container that stayed down means the system did not
    self-heal.
    """
    base = 1.0
    if dirty_leases:
        base -= 0.5
    if alive is not None and targeted:
        dead = len(targeted - alive)
        base -= 0.5 * (dead / len(targeted))
    return max(0.0, min(1.0, base))


def _redundancy(
    reports: Sequence[StepReport],
    step_targets: Mapping[str, Sequence[str]],
    groups: Mapping[str, Sequence[str]] | None,
    alive: frozenset[str] | None,
) -> float | None:
    """Replica survival while a member of the group was faulted.

    For every executed fault step, its targeted container is placed in its
    replica group. A single-member group has no redundancy (credit 0); a
    multi-member group with a survivor at run end absorbed the fault (credit
    1). When the live graph is unavailable the structural group size still
    credits multi-replica targets, and unknown aliveness is never punished.
    """
    if groups is None:
        return None
    survival: list[float] = []
    for report in reports:
        if report.bypassed:
            continue
        faulted = [t for t in step_targets.get(report.step_id, ()) if t in groups]
        if not faulted:
            continue
        members = tuple(groups[faulted[0]])
        if len(members) < 2:
            survival.append(0.0)  # single member: no redundancy to absorb the fault
            continue
        if alive is None:
            survival.append(1.0)  # structural redundancy, aliveness unmeasured
            continue
        survivors = [m for m in members if m in alive]
        survival.append(1.0 if survivors else 0.0)
    if not survival:
        return None
    return sum(survival) / len(survival)


def score_run(
    *,
    reports: Sequence[StepReport],
    targeted: frozenset[str],
    dirty_leases: Sequence[str],
    groups: Mapping[str, Sequence[str]] | None,
    alive: frozenset[str] | None,
    step_targets: Mapping[str, Sequence[str]] | None = None,
) -> ResilienceReport:
    """Compute the 0-100 resilience score from run-end observations.

    ``targeted`` is the set of container node ids any fault attempted against.
    ``groups`` maps each targeted node id to the ids of its replica-group
    members (including itself); ``alive`` is the set of container node ids
    still running at run end (``None`` when unknown — e.g. no live graph).
    ``step_targets`` maps step ids to the node ids that step's fault targeted
    (built by the executor from the plan); when omitted every targeted node is
    assumed faulted by every step, which is only used when the caller has no
    plan data.

    Deterministic and disclosure-first: the breakdown names the three weighted
    components and any measurement that was skipped.
    """
    resolved_targets = (
        {sid: tuple(ids) for sid, ids in step_targets.items()}
        if step_targets is not None
        else {r.step_id: tuple(sorted(targeted)) for r in reports}
    )

    step_performance = _step_performance(reports)
    self_healing = _self_healing(targeted, dirty_leases, alive)
    redundancy = _redundancy(reports, resolved_targets, groups, alive)
    if groups is None:
        redundancy = None

    components: list[tuple[float, float]] = [
        (_STEP_WEIGHT, step_performance),
        (_SELF_HEAL_WEIGHT, self_healing),
    ]
    if redundancy is not None:
        components.append((_REDUNDANCY_WEIGHT, redundancy))

    breakdown: list[str] = []
    executed = [r for r in reports if not r.bypassed]
    breakdown.append(
        f"steps: {sum(1 for r in executed if r.ok)}/{len(executed)} ok"
        f" ({sum(1 for r in reports if r.bypassed)} bypassed)"
    )
    breakdown.append(
        f"dirty leases: {len(dirty_leases)}"
        + (" (manual remediation required)" if dirty_leases else "")
    )
    if alive is not None and targeted:
        breakdown.append(f"targets alive after run: {len(targeted & alive)}/{len(targeted)}")
    if redundancy is None:
        breakdown.append("redundancy: not measured (no live replica groups resolved)")
    elif redundancy < 1.0:
        breakdown.append(f"redundancy: {redundancy:.0%} of faulted replica groups kept a survivor")
    else:
        breakdown.append("redundancy: all faulted groups kept a survivor")

    total = sum(w for w, _ in components)
    if not components or total <= 0:
        score = 0
    else:
        score = round(100 * sum(w * v for w, v in components) / total)
        score = max(0, min(100, score))

    return ResilienceReport(
        score=score,
        step_performance=step_performance,
        self_healing=self_healing,
        redundancy=redundancy,
        breakdown=tuple(breakdown),
    )


# --------------------------------------------------------------------------- #
# Post-run diagnosis — engine-backed, best-effort, never raises.
# --------------------------------------------------------------------------- #

InspectRunner = Callable[[str], tuple[str, str, str]]
LogsRunner = Callable[[str], str]


def _default_inspect_runner(engine: str, timeout_s: float = 8.0) -> InspectRunner:
    def run(ref: str) -> tuple[str, str, str]:
        result = run_tool(
            [
                engine,
                "inspect",
                "--format",
                "{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}",
                ref,
            ],
            timeout_s=timeout_s,
        )
        if result.exit_code != 0:
            raise RuntimeError(result.stderr.strip() or f"{engine} inspect failed")
        status, *rest = result.stdout.strip().split("|", 2)
        exit_code = rest[0].strip() if rest else "?"
        restarts = rest[1].strip() if len(rest) > 1 else "?"
        return status, exit_code, restarts

    return run


def _default_logs_runner(engine: str, timeout_s: float = 8.0, tail: int = 15) -> LogsRunner:
    def run(ref: str) -> str:
        result = run_tool(
            [engine, "logs", "--tail", str(tail), ref],
            timeout_s=timeout_s,
        )
        if result.exit_code != 0:
            return ""
        return result.stdout.strip()

    return run


def _explain(
    node_id: str,
    name: str | None,
    status: str,
    exit_code: str,
    restarts: str,
) -> str:
    """Plain-English diagnosis line for a non-running target container."""
    label = f" ({name})" if name else ""
    if restarts not in ("?", "0") and status not in ("running",):
        return (
            f"{node_id}{label}: state={status} exit_code={exit_code} "
            f"restarts={restarts} → restarted but did not stay up"
        )
    if exit_code == "137":
        return (
            f"{node_id}{label}: state={status} exit_code=137 restarts=0 → "
            f"killed (SIGKILL) and never restarted: the orchestrator/restart "
            f"policy did not self-heal it"
        )
    return (
        f"{node_id}{label}: state={status} exit_code={exit_code} restarts={restarts} "
        f"→ container is down and not self-healing (no restart policy or "
        f"orchestrator recreated it)"
    )


def collect_diagnosis(
    engine: str,
    refs: Sequence[tuple[str, str | None]],
    *,
    inspect_runner: InspectRunner | None = None,
    logs_runner: LogsRunner | None = None,
) -> tuple[str, ...]:
    """Inspect every targeted container after the run and explain issues.

    ``refs`` are ``(node_id, engine_ref)`` pairs; the engine ref is the real
    container name or full runtime id the engine can resolve (falls back to
    the node id). Healthy running containers are summarized as a single count;
    any container that is down, restarted-and-down, or gone gets a detailed
    diagnosis line plus a short log tail.

    Best-effort: a failed inspect becomes a ``not found`` diagnosis line and
    never raises.
    """
    if not refs or not engine:
        return ()
    inspect = inspect_runner or _default_inspect_runner(engine)
    logs = logs_runner or _default_logs_runner(engine)

    lines: list[str] = []
    healthy = 0
    for node_id, ref in refs:
        query = ref or node_id
        try:
            status, exit_code, restarts = inspect(query)
        except Exception as exc:  # container gone / engine unreachable
            lines.append(
                f"{node_id} ({ref or '?'}): not found by {engine} — "
                f"container was removed or {engine} unreachable ({type(exc).__name__})"
            )
            continue
        if _is_alive(status):
            healthy += 1
            continue
        line = _explain(node_id, ref, status, exit_code, restarts)
        tail = logs(query)
        if tail:
            tail_line = tail.splitlines()[-1].strip()
            if tail_line:
                line += f"; last log: {tail_line[:200]}"
        lines.append(line)

    if healthy:
        lines.insert(0, f"targeted containers healthy after run: {healthy}/{len(refs)}")
    return tuple(lines)


# --------------------------------------------------------------------------- #
# Executor wrapper — ties the live graph + engine into score + diagnosis.
# --------------------------------------------------------------------------- #


def _target_refs(
    plan: ExecutionPlan,
    graph: TopologyGraph | None,
) -> list[tuple[str, str | None]]:
    """Engine-resolvable refs for every container any fault targeted.

    Prefers the live graph's real container name / full runtime id; falls back
    to the planned runtime identity so a container removed mid-run is still
    looked up (and reported "not found").
    """
    from mayhem.domain.topology import ContainerNode  # noqa: PLC0415

    seen: dict[str, str | None] = {}

    def record(node_id: str, runtime_id: str | None) -> None:
        if node_id not in seen:
            seen[node_id] = None
        if runtime_id and seen[node_id] is None:
            seen[node_id] = runtime_id

    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        rt = fault.runtime_identity
        for target in fault.targets:
            for node_id in target.node_ids:
                record(node_id, rt.runtime_id if rt is not None else None)

    if graph is not None:
        for node_id in seen:
            node = graph.by_id(node_id)
            if isinstance(node, ContainerNode):
                if node.container_name:
                    seen[node_id] = node.container_name
                elif node.runtime_identity is not None and node.runtime_identity.runtime_id:
                    seen[node_id] = node.runtime_identity.runtime_id
    return list(seen.items())


def _replica_groups(graph: TopologyGraph) -> dict[str, tuple[str, ...]]:
    """Map each container node id to its replica-group members.

    A replica group is the set of containers behind the same compose service
    (``CONTAINED_IN`` edges to one ``svc-*`` node); a container not in any
    compose service is its own single-member group.
    """
    from mayhem.domain.topology import EdgeKind, NodeKind  # noqa: PLC0415

    groups_of: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind is not EdgeKind.CONTAINED_IN:
            continue
        groups_of.setdefault(edge.dst, []).append(edge.src)
    members: dict[str, tuple[str, ...]] = {}
    for group_members in groups_of.values():
        for member in group_members:
            members[member] = tuple(group_members)
    for node in graph.nodes:
        if node.kind is not NodeKind.CONTAINER:
            continue
        if node.id not in members:
            members[node.id] = (node.id,)
    return members


def _live_alive(graph: TopologyGraph) -> frozenset[str]:
    """Container node ids still running at run end."""
    from mayhem.domain.topology import NodeKind  # noqa: PLC0415

    return frozenset(
        node.id
        for node in graph.nodes
        if node.kind is NodeKind.CONTAINER and _is_alive(str(getattr(node, "state", "")))
    )


def _step_targets_from_plan(
    plan: ExecutionPlan,
) -> dict[str, tuple[str, ...]]:
    return {
        step.id: tuple(
            node_id
            for target in (step.fault.targets if step.fault is not None else ())
            for node_id in target.node_ids
        )
        for step in plan.steps
    }


def build_resilience_report(
    plan: ExecutionPlan,
    reports: Sequence[StepReport],
    dirty_leases: Sequence[str],
    graph: TopologyGraph | None,
    engine: str | None,
    *,
    inspect_runner: InspectRunner | None = None,
    logs_runner: LogsRunner | None = None,
) -> ResilienceReport:
    """Compute the end-of-run resilience score and post-run diagnosis.

    Best-effort: a missing/unreadable live graph still yields a score over the
    components that are measurable (redundancy drops out), the diagnosis pass
    uses the planned runtime identities so removed containers are still
    reported, and no exception escapes to the caller. ``inspect_runner`` /
    ``logs_runner`` override the engine-backed defaults (tests, offline runs).
    """
    targeted = frozenset(
        node_id
        for step in plan.steps
        if step.fault is not None
        for target in step.fault.targets
        for node_id in target.node_ids
    )

    groups: dict[str, tuple[str, ...]] | None = None
    alive: frozenset[str] | None = None
    if graph is not None:
        try:
            groups = _replica_groups(graph)
            alive = _live_alive(graph)
        except Exception:
            groups, alive = None, None

    report = score_run(
        reports=reports,
        targeted=targeted,
        dirty_leases=dirty_leases,
        groups=groups,
        alive=alive,
        step_targets=_step_targets_from_plan(plan),
    )

    if engine and targeted:
        refs = _target_refs(plan, graph)
        if refs:
            try:
                diagnosis = collect_diagnosis(
                    engine,
                    refs,
                    inspect_runner=inspect_runner,
                    logs_runner=logs_runner,
                )
            except Exception:
                diagnosis = ()
            if diagnosis:
                report = ResilienceReport(
                    score=report.score,
                    step_performance=report.step_performance,
                    self_healing=report.self_healing,
                    redundancy=report.redundancy,
                    breakdown=report.breakdown,
                    diagnosis=diagnosis,
                )
    return report
