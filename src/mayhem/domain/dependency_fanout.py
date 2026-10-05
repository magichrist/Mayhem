"""Plan 05 Phase 4 — dependency fan-out accounting.

A fault aimed at one dependency does not stay aimed at one dependency. Aiming at
`ext-postgres` reaches every service that ``DEPENDS_ON`` it, transitively, and
that widening is real: the services do go down. What was missing was the
*accounting* of it.

Before this module, :func:`mayhem.controller.safety._affected_node_ids` flattened
targets and their dependents into one ``frozenset`` and handed it to the blast
caps. That set is correct and it is **silent**: a service that was targeted
directly and a service that was reached because something it depends on was
targeted arrive as the same kind of string. So a plan whose fan-out tripled after
someone widened a selector looked exactly like the plan it replaced, and no
record said which nodes were collateral.

This module makes the widening explicit and sealed:

* :func:`dependency_fanout` returns a :class:`DependencyFanout` naming what was
  aimed at, what was **reached through** it, and — the half that is easy to forget
  — what was **not** reached;
* :func:`unresolved_dependency` refuses a target naming a dependency the graph
  does not contain, so a selector that silently resolves to nothing is a plan-time
  refusal rather than a run that "injects nowhere and reports success";
* the record carries its own digest, so it can be sealed and later re-verified.

**This is accounting, not a new blast-radius rule.** It mints no limit, refuses no
plan that :func:`~mayhem.controller.safety.check_blast_radius` would allow, and
changes no cap's arithmetic. :func:`mayhem.controller.safety` still decides; this
tells an auditor what that decision was reached through. The one thing it *does*
add is the unresolvable-dependency refusal, which is Phase 5's negative control and
is listed under its own rule id so the two are never confused.

What this does NOT do
---------------------

* **It does not see dependencies the graph does not declare.** Fan-out is
  computed from ``DEPENDS_ON`` and ``CONNECTS_VIA`` edges. A service that calls
  a third-party API with no edge in the topology is not in the closure, and
  :attr:`DependencyFanout.unreached_dependencies` will honestly report that it
  could not be seen. That is a property of the input, and the record names it
  rather than implying completeness it cannot have.
* **It does not claim a fault *did* reach anything.** It says what the graph says
  *would* be reached, at plan time, from the topology snapshot in hand. A live
  run's actual reach is evidence, not projection.
* **It does not replace the per-service blast caps**, which count
  ``services_hit``/``hosts_hit`` and are unchanged by this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.domain.topology import EdgeKind, NodeKind

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from mayhem.domain.topology import TopologyGraph

#: A targeted node id is not in the topology graph, so the fault aims at nothing.
RULE_DEPENDENCY_UNRESOLVED = "dependency.unresolved"
#: A targeted node exists but has no dependency relationship to account for.
RULE_DEPENDENCY_NO_EDGES = "dependency.unobserved"

#: The edge kinds that make one node's fate another's. A fault on the destination
#: of such an edge reaches the source. Deliberately the same pair
#: :meth:`~mayhem.domain.topology.TopologyGraph.dependents_closure` walks, so the
#: projection here and the blast-radius closure cannot disagree about reach.
REACHING_EDGES: frozenset[EdgeKind] = frozenset({EdgeKind.DEPENDS_ON, EdgeKind.CONNECTS_VIA})


@dataclass(frozen=True, slots=True)
class ReachedNode:
    """One node the fan-out reaches, and how it got there.

    ``via`` is the node immediately downstream that led to it and ``depth`` the
    number of edges from a directly-targeted node. ``depth == 1`` means it depends
    directly on what was aimed at; higher means the widening compounded, which is
    the case a reader most needs told apart from the first hop.
    """

    node_id: str
    kind: NodeKind
    depth: int
    via: str

    def describe(self) -> str:
        return f"{self.node_id} ({self.kind.value}) at depth {self.depth} via {self.via}"


@dataclass(frozen=True, slots=True)
class DependencyFanout:
    """What a fault aimed at these dependencies reaches, and what it does not.

    ``aimed`` is the caller's own targets; ``reached`` is everything else in the
    closure, each with its path. ``unreached_dependencies`` is the other half of
    the finding and the reason this type exists: the dependency nodes the graph
    *does* contain that the closure does **not** touch. A record that listed only
    what was hit would read as complete; naming what was missed is what makes
    "a fault aimed at one dependency cannot silently take its neighbors" a
    checkable property rather than an aspiration.
    """

    fault_id: str
    aimed: frozenset[str]
    reached: tuple[ReachedNode, ...] = ()
    unreached_dependencies: frozenset[str] = frozenset()
    undeclared_dependents: frozenset[str] = frozenset()

    # -- the views a caller actually reads ---------------------------------- #

    @property
    def affected(self) -> frozenset[str]:
        """Every node the fault touches: what it aimed at plus what it reached."""
        return frozenset(self.aimed) | frozenset(node.node_id for node in self.reached)

    @property
    def collateral(self) -> frozenset[str]:
        """Only what it reached — the widening on its own, with no targets mixed in."""
        return frozenset(node.node_id for node in self.reached)

    @property
    def max_depth(self) -> int:
        """The longest chain of consequences, or 0 when the fault reached nothing."""
        return max((node.depth for node in self.reached), default=0)

    @property
    def widened(self) -> bool:
        """True when the fault reaches anything it did not aim at.

        The single question this module exists to answer, and it is a property of
        the record rather than of a caller's expectation: a plan can be reviewed
        for ``widened`` without knowing what the planner believed.
        """
        return bool(self.collateral)

    def reached_at_depth(self, depth: int) -> tuple[ReachedNode, ...]:
        return tuple(node for node in self.reached if node.depth == depth)

    def describe(self) -> str:
        if not self.reached:
            return f"{self.fault_id} aimed at {sorted(self.aimed)} and reached nothing through them"
        return (
            f"{self.fault_id} aimed at {sorted(self.aimed)} and reached {len(self.reached)} "
            f"node(s) to depth {self.max_depth}; nearest: "
            + ", ".join(node.describe() for node in self.reached_at_depth(1)[:3])
        )

    # -- the sealed form ----------------------------------------------------- #

    def to_dict(self) -> dict[str, object]:
        """The record, JSON-safe, without its digest."""
        return {
            "fault_id": self.fault_id,
            "aimed": sorted(self.aimed),
            "reached": [
                {
                    "node_id": node.node_id,
                    "kind": node.kind.value,
                    "depth": node.depth,
                    "via": node.via,
                }
                for node in self.reached
            ],
            "unreached_dependencies": sorted(self.unreached_dependencies),
            "undeclared_dependents": sorted(self.undeclared_dependents),
        }

    @property
    def record(self) -> dict[str, object]:
        """The record plus a digest over it, so an edited projection is detectable.

        Same shape as every other sealed payload in the codebase: the digest covers
        every other key, so a reader recomputes it from the payload and tells
        whether the record was edited after the fact.
        """
        body = self.to_dict()
        return {**body, "sealed_digest": sha256_hex(canonical_json(body))}


def _reverse(graph: TopologyGraph) -> dict[str, list[str]]:
    """``dst -> [src]`` for the edges that make a destination's fate reach its source."""
    reverse: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind in REACHING_EDGES:
            reverse.setdefault(edge.dst, []).append(edge.src)
    return reverse


def _kinds(graph: TopologyGraph) -> dict[str, NodeKind]:
    return {node.id: node.kind for node in graph.nodes}


def dependency_fanout(
    graph: TopologyGraph,
    *,
    fault_id: str,
    targets: Iterable[str],
) -> DependencyFanout:
    """What ``targets`` reaches, computed once and recorded explicitly.

    A breadth-first walk over the same edges
    :meth:`~mayhem.domain.topology.TopologyGraph.dependents_closure` uses, with one
    addition: it records the *path* each node was reached by, so a reader can tell
    a first-hop consequence from a compounded one.

    Targets that are not in the graph are **not** an error here — this function
    projects, and :func:`unresolved_dependency` is what refuses. A caller that
    wants the refusal asks for it; a caller that only wants the projection gets
    it, and the missing ids simply appear nowhere in the record, which is the
    honest reading of a topology that does not contain them.
    """
    aimed = frozenset(targets)
    reverse = _reverse(graph)
    kinds = _kinds(graph)

    reached: list[ReachedNode] = []
    seen: set[str] = set(aimed)
    # (node, depth, the node that led to it) so each reached node keeps its path.
    frontier: list[tuple[str, int]] = [(node_id, 0) for node_id in sorted(aimed)]
    while frontier:
        current, depth = frontier.pop(0)
        for upstream in sorted(reverse.get(current, ())):
            if upstream in seen:
                continue
            seen.add(upstream)
            reached.append(
                ReachedNode(
                    node_id=upstream,
                    kind=kinds.get(upstream, NodeKind.SERVICE),
                    depth=depth + 1,
                    via=current,
                )
            )
            frontier.append((upstream, depth + 1))

    # The other half of the finding: dependency nodes the graph contains that this
    # fan-out does not touch. An empty set is a real statement -- "aiming here
    # disturbs no other dependency" -- rather than an absence of information.
    touched = frozenset(aimed) | frozenset(node.node_id for node in reached)
    unreached = frozenset(
        node.id for node in graph.of_kind(NodeKind.EXTERNAL_DEPENDENCY) if node.id not in touched
    )

    # Services that depend on something aimed at, reached by an edge the graph
    # declares. Kept as its own field so a reviewer can ask "which of my services
    # are exposed to this?" without re-walking the graph.
    exposed = frozenset(node.node_id for node in reached if node.kind is NodeKind.SERVICE)

    return DependencyFanout(
        fault_id=fault_id,
        aimed=aimed,
        reached=tuple(reached),
        unreached_dependencies=unreached,
        undeclared_dependents=exposed,
    )


def unresolved_dependency(
    graph: TopologyGraph,
    *,
    fault_id: str,
    targets: Iterable[str],
    rule_id: str = RULE_DEPENDENCY_UNRESOLVED,
) -> InvariantViolationError | None:
    """The refusal a fan-out projection cannot make, or ``None`` when it can.

    A fault aimed at a dependency the topology does not contain resolves to
    nothing: no node, no edge, no blast radius — and, historically, no complaint
    either, because the empty affected-set passes every cap. This is the
    plan's negative control stated as a rule: **a dependency fault aimed at a
    non-existent upstream refuses at plan time, never injects nowhere and reports
    success.**

    Only *targeted* ids are checked, not the closure. A dependency reached
    transitively is in the graph by construction, because the walk followed an
    edge to it, so checking it would be checking the walker's own bookkeeping.

    Returns the error rather than raising it, so the caller decides whether it is
    a refusal at admission or a line in a report; :func:`require_resolved_dependencies`
    raises it for callers that have already decided.
    """
    present = {node.id for node in graph.nodes}
    missing = sorted(node_id for node_id in targets if node_id not in present)
    if not missing:
        return None
    known = sorted(node.id for node in graph.of_kind(NodeKind.EXTERNAL_DEPENDENCY))
    if known:
        shown = known[:8]
        declared = (
            f"the graph declares {len(known)} dependency node(s): {shown}"
            f"{'...' if len(known) > len(shown) else ''}"
        )
    else:
        declared = (
            "the graph declares no dependency nodes at all, so a dependency-targeting "
            "fault cannot be aimed at anything"
        )
    return InvariantViolationError(
        rule_id,
        f"fault {fault_id} targets {missing}, which the topology snapshot does not "
        f"contain; the fault would resolve to no node and affect nothing, which is a "
        f"silent success rather than an injection; {declared}",
    )


def require_resolved_dependencies(
    graph: TopologyGraph,
    *,
    fault_id: str,
    targets: Iterable[str],
) -> None:
    """Raise rather than return, for callers already at a refusal point."""
    refusal = unresolved_dependency(graph, fault_id=fault_id, targets=targets)
    if refusal is not None:
        raise refusal


@dataclass(frozen=True, slots=True)
class FanoutLedger:
    """Every step's fan-out, and the aggregate it implies.

    The cumulative half matters because a plan's exposure is the union of its
    steps': three faults each reaching one service is not three services, and a
    per-step record that were read on its own would under-report the union. This
    is accounting over a plan, not a new limit — no cap is applied here.
    """

    steps: tuple[DependencyFanout, ...] = field(default=())

    @property
    def affected(self) -> frozenset[str]:
        """Every node any step touches."""
        found: set[str] = set()
        for step in self.steps:
            found |= step.affected
        return frozenset(found)

    @property
    def collateral(self) -> frozenset[str]:
        """Every node reached that no step aimed at."""
        found: set[str] = set()
        for step in self.steps:
            found |= step.collateral
        return frozenset(found)

    @property
    def max_depth(self) -> int:
        return max((step.max_depth for step in self.steps), default=0)

    def widened_steps(self) -> tuple[str, ...]:
        """Which steps widened, by fault id — the answer a reviewer asks for."""
        return tuple(step.fault_id for step in self.steps if step.widened)

    def describe(self) -> str:
        if not self.steps:
            return "no steps, no fan-out"
        return (
            f"{len(self.steps)} step(s) touch {len(self.affected)} node(s), "
            f"{len(self.collateral)} of them reached rather than aimed at; "
            f"widened: {list(self.widened_steps()) or 'none'}"
        )

    def to_dict(self) -> dict[str, object]:
        """The ledger, JSON-safe, plus a digest over every other key.

        The aggregate sits *inside* the digest rather than beside it: a record
        whose summary could be edited without invalidating it is worse than no
        summary at all, because the summary is the part a skimming reader trusts.
        """
        body: dict[str, object] = {
            "steps": [step.to_dict() for step in self.steps],
            "aggregate": {
                "affected": sorted(self.affected),
                "collateral": sorted(self.collateral),
                "max_depth": self.max_depth,
                "widened_steps": list(self.widened_steps()),
            },
        }
        return {**body, "sealed_digest": sha256_hex(canonical_json(body))}


def fanout_ledger(
    graph: TopologyGraph,
    steps: Sequence[tuple[str, Sequence[str]]],
    *,
    require_resolved: bool = True,
) -> FanoutLedger:
    """Compute every step's fan-out, refusing an unresolvable dependency first.

    ``steps`` is ``(fault_id, target node ids)`` in plan order. With
    ``require_resolved`` on — the default — an unresolvable dependency raises
    before any projection is computed, so a plan cannot be *reported* as having a
    clean zero-width fan-out when the truth is that one of its steps aims at
    nothing. Turning it off gives a caller that genuinely wants the raw
    projection of an unresolvable plan, which is a diagnostic need and is named
    rather than being the default.
    """
    records: list[DependencyFanout] = []
    for fault_id, targets in steps:
        if require_resolved:
            require_resolved_dependencies(graph, fault_id=fault_id, targets=targets)
        records.append(dependency_fanout(graph, fault_id=fault_id, targets=targets))
    return FanoutLedger(steps=tuple(records))
