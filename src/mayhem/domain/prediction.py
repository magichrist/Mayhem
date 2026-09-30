"""Blast-radius impact prediction — plan 14 Phase 1, the read-only twin of the gate.

:func:`predict_impact` is pure computation over a *frozen* topology graph plus a
*frozen* execution plan. It performs no IO, reads no clock, and draws no
randomness, so the same graph plus the same plan always yields an identical
prediction. That determinism is the property the rest of plan 14 rests on: a
preview nobody can reproduce is not a preview, and a preview that cannot be
re-derived from a stored plan cannot be sealed with that plan in Phase 4.

Three rules shape this module.

**The arithmetic is the gate's arithmetic.** The affected set is built exactly
the way ``controller.safety._affected_node_ids`` builds it — the step's resolved
targets unioned with :meth:`TopologyGraph.dependents_closure` — and the
per-step numbers are the same computations ``check_blast_radius`` performs
against the same :class:`~mayhem.domain.experiments.BlastRadiusBudget` and the
same :class:`~mayhem.domain.quota.DamageQuota`. The code is *duplicated* here
rather than shared on purpose: the shared implementation lives in
``controller``, and ``domain`` may not import upward into it (the "domain layer
has zero IO and no upward imports" contract). The duplication is pinned by a
test that asserts the predicted affected set equals the gate's closure and the
predicted rule ids equal the gate's refusals, so the two cannot drift apart
quietly.

**A prediction is never permissive.** :func:`is_never_permissive` states that
relationship as a single named predicate: every rule id the real gate refused
must already be flagged by the prediction. Over-reporting is allowed and is
usually correct, because a preview is computed from a snapshot while a gate runs
against live state. Under-reporting is a defect, and the predicate is the thing
a test pins so the defect cannot be introduced unnoticed.

**An unmeasured prediction says so.** A prediction computed over an empty graph
has an empty affected set, which is a fact about *nothing having been observed*,
not about *nothing being affected*. It is marked ``basis=EMPTY_GRAPH`` and
:func:`approval_refusal_reason` refuses it. The same refusal applies to a target
id the graph does not contain (reported in
:attr:`ImpactPrediction.unresolved_target_ids`) and to a stale prediction — one
whose recorded graph or plan identity no longer matches the inputs it claims to
describe. "We could not look" is never rendered as "all clear" (the same
discipline ``domain.residual_impact`` applies to unavailable snapshots).

For the same reason, replica accounting only counts node kinds that *are*
instances — containers, pods, processes. A service node, a host node, or a
cluster node carries no instance count anywhere in the model, so grouping them
one-per-node would report "100% of capacity lost" from a node whose capacity was
never observed. They are excluded and :attr:`ImpactPrediction.capacity_known` goes
false, which reads as "could not tell".

Phase 1 scope: this module computes and reports. It does not gate, does not
mutate, and does not decide. The ceilings it checks
(:class:`BlastCeilings`) are *predicted* violations here; Phase 4 is where
admission enforces the same rule ids.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
from mayhem.domain.hashing import digest
from mayhem.domain.quota import RULE_BUDGET, RULE_PER_FAULT_CEILING, DamageLedger, DamageQuota
from mayhem.domain.topology import (
    ContainerNode,
    NodeKind,
    PodNode,
    ServiceNode,
    TopologyGraph,
    TopologyNode,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

# --- rule ids -----------------------------------------------------------------
# The seven below are the ids ``controller.safety.check_blast_radius`` and the
# damage ledger already emit. They are spelled out here as literals so the two
# sides can be compared by string equality: a prediction that reported
# ``prediction.max_hosts`` could not be checked against a gate that refuses with
# ``blast_radius.max_hosts``, and the never-permissive predicate would silently
# pass on two disjoint vocabularies.

RULE_MAX_SERVICES_PCT = "blast_radius.max_services_pct"
RULE_MAX_HOSTS = "blast_radius.max_hosts"
RULE_MAX_CONCURRENT_FAULTS = "blast_radius.max_concurrent_faults"
RULE_MAX_DURATION_PER_FAULT_S = "blast_radius.max_duration_per_fault_s"
RULE_FORBIDDEN_FAULT_PAIRS = "blast_radius.forbidden_fault_pairs"

#: Plan 14 §"Controls" ceilings. Not yet enforced anywhere in the gate — Phase 4
#: admits on them — so they get their own ids and a prediction that reports them
#: is describing a rule the gate does not yet evaluate.
RULE_MAX_AFFECTED_NODES = "blast_radius.max_affected_nodes"
RULE_MAX_DEPENDENCY_DEPTH = "blast_radius.max_dependency_depth"
RULE_MAX_CUSTOMER_FACING_SERVICES = "blast_radius.max_customer_facing_services"
RULE_MAX_AFFECTED_PCT = "blast_radius.max_affected_pct"
RULE_PROTECTED_NODE = "blast_radius.protected_node"

#: Every rule id this module can report. A prediction carrying anything outside
#: this set failed to describe its own vocabulary.
KNOWN_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_MAX_SERVICES_PCT,
        RULE_MAX_HOSTS,
        RULE_MAX_CONCURRENT_FAULTS,
        RULE_MAX_DURATION_PER_FAULT_S,
        RULE_FORBIDDEN_FAULT_PAIRS,
        RULE_PER_FAULT_CEILING,
        RULE_BUDGET,
        RULE_MAX_AFFECTED_NODES,
        RULE_MAX_DEPENDENCY_DEPTH,
        RULE_MAX_CUSTOMER_FACING_SERVICES,
        RULE_MAX_AFFECTED_PCT,
        RULE_PROTECTED_NODE,
    }
)

#: Edge kinds that constitute a dependency, matching the pair
#: :meth:`TopologyGraph.dependents_closure` walks. Duplicated as a constant so a
#: change to the closure's edge set cannot silently leave the fan-out depth
#: walking a different graph.
DEPENDENCY_EDGE_KINDS: frozenset[str] = frozenset({"depends_on", "connects_via"})

PREDICTION_SCHEMA_VERSION = "1.0"


class PredictionBasis(StrEnum):
    """What the prediction was actually computed over.

    ``EMPTY_GRAPH`` is the important member: it distinguishes "this plan affects
    nothing" from "we had no topology to measure it against". Only the second
    is a problem, and only the first may be shown as a clean result.
    """

    GRAPH = "graph"
    EMPTY_GRAPH = "empty_graph"


# --- inputs -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlastCeilings:
    """Plan 14 §"Controls" — the limits a prediction checks.

    Every ceiling is ``None`` by default, meaning *not configured*, which is
    deliberately distinct from ``0`` (which nothing could pass). An unconfigured
    ceiling is not checked and never reported as satisfied.
    """

    max_affected_nodes: int | None = None
    max_dependency_depth: int | None = None
    max_customer_facing_services: int | None = None
    max_affected_pct: float | None = None
    #: Node ids that must never be inside a predicted blast (plan 14 §"Controls",
    #: "protected service list"). Matched against the *targeted* nodes, not the
    #: fan-out: an unavoidable dependent of a protected service is a fact to
    #: surface, not a reason to refuse the prediction.
    protected_node_ids: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class CostRateCard:
    """What one unit of impaired node-time is worth, when somebody has said so.

    The repository carries no cloud price table, and inventing one here would
    turn an estimate into a fabricated quote. So the default rate is ``0.0`` and
    the resulting :class:`CostEstimate` reports ``priced=False``: an unpriced
    estimate is disclosed as unpriced, never rendered as free.
    """

    #: Price of one node-hour of impaired service, in ``currency``.
    usd_per_node_hour: float = 0.0
    currency: str = "USD"
    #: Named provenance for the rate, carried into the estimate so a reader can
    #: tell an authored rate from a guess.
    basis: str = "no rate card supplied"

    @property
    def priced(self) -> bool:
        return self.usd_per_node_hour > 0.0


# --- outputs ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ViolatedRule:
    """One rule the predicted plan breaks, with the values that broke it.

    ``observed`` and ``limit`` are the numbers the comparison used, not a
    re-derivation: reporting the value the decision was made on is the whole
    point, because a preview that says "too many hosts" without saying *how
    many* forces the reader to re-run the math and get their own answer.
    Non-numeric rules (``forbidden_fault_pairs``, ``protected_node``) leave both
    ``None`` and name what was observed in ``observed_ids`` / ``detail``.
    """

    rule_id: str
    step_id: str
    step_index: int
    fault_id: str
    observed: float | None
    limit: float | None
    unit: str
    detail: str
    observed_ids: tuple[str, ...] = ()
    remediation: str = ""

    @property
    def exceeded_by(self) -> float | None:
        """How far past the limit the observed value sits, or ``None``."""
        if self.observed is None or self.limit is None:
            return None
        return self.observed - self.limit


@dataclass(frozen=True, slots=True)
class NodeDepth:
    """One node in the dependency fan-out, and how far from a target it sits."""

    node_id: str
    kind: str
    depth: int
    #: ``True`` when the node was itself targeted; targeted nodes sit at depth 0
    #: even when another target also depends on them.
    targeted: bool = False


@dataclass(frozen=True, slots=True)
class DependencyFanOut:
    """How far a step's damage propagates, and into how many nodes.

    ``max_depth`` is the longest dependency hop from a targeted node to a node in
    the fan-out; a directly targeted node is depth 0, so a plan whose targets
    impair nothing downstream reports ``max_depth == 0`` rather than a
    misleading "no depth".
    """

    nodes: tuple[NodeDepth, ...] = ()
    max_depth: int = 0

    @property
    def dependent_ids(self) -> tuple[str, ...]:
        """Fan-out members that were not themselves targeted."""
        return tuple(n.node_id for n in self.nodes if not n.targeted)

    @property
    def dependent_count(self) -> int:
        return len(self.dependent_ids)


@dataclass(frozen=True, slots=True)
class ReplicaGroupLoss:
    """One replica group, and how much of it the plan would take away.

    ``group_id`` is derived from the graph alone (see :func:`replica_group_id`),
    so a group never depends on data the topology does not carry. A node with
    no replicas is a group of one, which is the honest answer rather than an
    omitted group.
    """

    group_id: str
    members: tuple[str, ...]
    lost: tuple[str, ...]

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def lost_count(self) -> int:
        return len(self.lost)

    @property
    def survivors(self) -> tuple[str, ...]:
        lost = set(self.lost)
        return tuple(m for m in self.members if m not in lost)

    @property
    def loss_ratio(self) -> float:
        """Share of the group expected to be gone, from ``0.0`` to ``1.0``."""
        if not self.members:
            return 0.0
        return len(self.lost) / len(self.members)

    @property
    def redundancy_cleared(self) -> bool:
        """True when at least one replica of the group survives the blast."""
        return bool(self.survivors)


@dataclass(frozen=True, slots=True)
class ReplicaLoss:
    """The replica-loss delta for a plan, in total and per group."""

    groups: tuple[ReplicaGroupLoss, ...] = ()
    #: ``False`` when the graph carried no replica-bearing nodes at all. Callers
    #: must not read a ``0.0`` capacity change as "no capacity lost" while this
    #: is ``False`` — there was nothing to lose.
    measured: bool = False

    @property
    def lost_total(self) -> int:
        return sum(g.lost_count for g in self.groups)

    @property
    def member_total(self) -> int:
        return sum(g.member_count for g in self.groups)

    @property
    def fully_lost_group_ids(self) -> tuple[str, ...]:
        """Groups with no survivor left — the ones that cannot absorb anything."""
        return tuple(g.group_id for g in self.groups if not g.redundancy_cleared)


@dataclass(frozen=True, slots=True)
class StepCost:
    """One step's share of the cost estimate."""

    step_id: str
    fault_id: str
    affected_nodes: int
    duration_s: float
    affected_node_seconds: float
    usd: float


@dataclass(frozen=True, slots=True)
class CostEstimate:
    """What the blast is expected to cost, or an explicit statement that nobody
    has priced it.

    ``priced=False`` with ``total_usd == 0.0`` is the disclosure: the estimate
    is unpriced, not free. ``affected_node_seconds`` is always real — it is
    measured, not money — so a caller can plug its own rate in later.
    """

    currency: str
    priced: bool
    basis: str
    affected_node_seconds: float
    total_usd: float
    per_step: tuple[StepCost, ...] = ()


@dataclass(frozen=True, slots=True)
class StepImpact:
    """The gate's numbers for one fault step, plus this plan's own controls."""

    step_id: str
    step_index: int
    fault_id: str
    target_ids: tuple[str, ...]
    affected_ids: tuple[str, ...]
    services_hit: int
    services_total: int
    services_pct: float
    hosts_hit: int
    duration_s: float
    node_count: int
    damage_s: float


@dataclass(frozen=True, slots=True)
class ImpactPrediction:
    """The read-only twin of the real gate, for one frozen plan on one frozen graph.

    Everything here is a measurement or an arithmetic consequence of one. Nothing
    here authorises anything: a prediction with no violated rules means *this
    snapshot showed no breach*, not *the plan is approved*.
    """

    plan_identity: str
    graph_identity: str
    basis: PredictionBasis
    steps: tuple[StepImpact, ...] = ()
    #: Only nodes the graph actually contains. A target id the graph does not
    #: hold is reported in :attr:`unresolved_target_ids` instead, because a
    #: prediction may not claim to affect a node it never saw.
    affected_node_ids: tuple[str, ...] = ()
    #: Target ids from the plan that the graph does not contain.
    unresolved_target_ids: tuple[str, ...] = ()
    fan_out: DependencyFanOut = DependencyFanOut()
    replica_loss: ReplicaLoss = ReplicaLoss()
    #: Signed percentage change in serving capacity across the touched replica
    #: groups: ``0.0`` when no group loses a member, negative when one does.
    expected_capacity_change_pct: float = 0.0
    #: ``False`` when the graph carried no replica groups to measure against.
    capacity_known: bool = False
    violated_rules: tuple[ViolatedRule, ...] = ()
    cost: CostEstimate = CostEstimate(
        currency="USD", priced=False, basis="not computed", affected_node_seconds=0.0, total_usd=0.0
    )
    #: Step index at which the walk stopped because a per-step limit fired, or
    #: ``None``. The gate raises on the first breach, so a prediction that kept
    #: going would report numbers the gate never reaches.
    truncated_at_step: int | None = None
    notes: tuple[str, ...] = ()
    schema_version: str = PREDICTION_SCHEMA_VERSION

    @property
    def rule_ids(self) -> frozenset[str]:
        """Rule ids this prediction flagged."""
        return frozenset(rule.rule_id for rule in self.violated_rules)

    @property
    def within_policy(self) -> bool:
        """True when nothing was flagged on this snapshot.

        Only meaningful together with :func:`approval_refusal_reason`: a stale
        or unmeasured prediction is not "within policy", it is not an answer.
        """
        return not self.violated_rules

    @property
    def empty(self) -> bool:
        """True when the prediction found no graph-resident node to affect.

        Empty because the graph is empty, or because every target was
        unresolvable, is a statement about *observation* — never about safety.
        Pair it with :attr:`unresolved_target_ids` and
        :func:`approval_refusal_reason` before drawing any conclusion from it.
        """
        return not self.affected_node_ids


# --- identity -----------------------------------------------------------------


def plan_identity(plan: ExecutionPlan) -> str:
    """Canonical identity of a plan — the same bytes the diff hashes.

    ``controller.plan_diff`` hashes ``plan.model_dump(mode="json")`` through
    ``canonical_json``; :func:`mayhem.domain.hashing.digest` is that same
    canonical form reduced to sha256. Reproducing the definition here (rather
    than importing ``plan_diff``, which lives above the domain boundary) is what
    lets a sealed prediction and a later plan diff be compared directly.
    """
    return digest(plan.model_dump(mode="json"))


def graph_identity(graph: TopologyGraph) -> str:
    """Canonical identity of a graph snapshot, used for staleness detection."""
    return digest(graph.model_dump(mode="json"))


# --- graph arithmetic ---------------------------------------------------------


def _reverse_dependencies(graph: TopologyGraph) -> dict[str, list[str]]:
    """``node_id -> ids that depend on it``, over the dependency edge kinds.

    Same edge set as :meth:`TopologyGraph.dependents_closure` walks. Nodes are
    returned sorted so any traversal built on this mapping walks in the same
    order every run.
    """
    reverse: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind.value not in DEPENDENCY_EDGE_KINDS:
            continue
        reverse.setdefault(edge.dst, []).append(edge.src)
    return {node_id: sorted(set(sources)) for node_id, sources in reverse.items()}


def affected_node_ids(graph: TopologyGraph, target_ids: Iterable[str]) -> frozenset[str]:
    """Targets plus everything transitively depending on them.

    The exact set ``controller.safety._affected_node_ids`` computes: a node is
    affected if it was targeted or if some dependency edge chain leads back to a
    targeted node. Depends on nothing but the graph.
    """
    targets = frozenset(target_ids)
    reverse = _reverse_dependencies(graph)
    seen: set[str] = set()
    frontier = sorted(targets)
    while frontier:
        current = frontier.pop()
        for upstream in reverse.get(current, ()):
            if upstream != current and upstream not in targets and upstream not in seen:
                seen.add(upstream)
                frontier.append(upstream)
    return targets | seen


def dependency_fan_out(graph: TopologyGraph, target_ids: Iterable[str]) -> DependencyFanOut:
    """Breadth-first depth of every node a blast reaches from its targets.

    Breadth-first is not an implementation detail: it is what makes the depth a
    distance rather than a traversal artefact, so two graphs with the same
    dependency shape report the same ``max_depth`` no matter what order the
    edges were discovered in.
    """
    targets = frozenset(target_ids)
    reverse = _reverse_dependencies(graph)
    depths: dict[str, int] = dict.fromkeys(targets, 0)
    frontier = sorted(targets)
    while frontier:
        current = frontier.pop(0)
        for upstream in reverse.get(current, ()):
            if upstream == current:
                continue  # self-loop: no propagation
            candidate = depths[current] + 1
            known = depths.get(upstream)
            if known is None or candidate < known:
                depths[upstream] = candidate
                frontier.append(upstream)
    nodes = tuple(
        NodeDepth(
            node_id=node_id,
            kind=node_kind(graph, node_id),
            depth=depth,
            targeted=node_id in targets,
        )
        for node_id, depth in sorted(depths.items(), key=lambda item: (item[1], item[0]))
    )
    return DependencyFanOut(nodes=nodes, max_depth=max((n.depth for n in nodes), default=0))


def node_kind(graph: TopologyGraph, node_id: str) -> str:
    """Kind label of a node id, or ``"unknown"`` for an id the graph lacks.

    A target id absent from the graph still gets a fan-out depth (the walk is
    over ids, not nodes), so this must not raise — an unresolvable id is a fact
    the caller surfaces, not an exception here.
    """
    node = graph.by_id(node_id)
    return node.kind.value if node is not None else "unknown"


def replica_group_id(node: TopologyNode) -> str | None:
    """The replica group a node belongs to, or ``None`` if it is not an instance.

    Replica-ness is a graph fact, not an annotation, but only for node kinds that
    *are* instances. The existing node models already carry the key that says so:

    * containers group by ``(runtime, host_id, compose service)`` — the compose
      service label, falling back to the ``container_name`` authoring key. Two
      instances of one service on one host are replicas; two different services
      on one host are not.
    * pods group by ``(namespace, owner_name)`` — the workload owns the
      replicas, so every pod of a ReplicaSet lands in one group.
    * processes are singleton instances: a pid is one process, and a second pid
      for the same program is a different process, not a spare copy.

    Everything else returns ``None`` and is therefore *excluded* from replica
    accounting. That is the deliberate call, and it is the difference between a
    measurement and a fabrication: a service node, a host node, or a cluster node
    carries no instance count anywhere in the model, so a group of one would
    report "100% of the capacity lost" from a node whose capacity was never
    observed. The caller sees ``measured=False`` instead, which reads as "could
    not tell" rather than "nothing left".
    """
    if isinstance(node, ContainerNode):
        metadata = node.runtime_metadata
        label = (metadata.service if metadata is not None else None) or node.container_name
        if label:
            host = node.runtime_identity.host_id or ""
            return f"container:{node.runtime_identity.runtime}:{host}:{label}"
        return None
    if isinstance(node, PodNode) and node.owner_name:
        return f"pod:{node.namespace}:{node.owner_name}"
    if isinstance(node, PodNode):
        return f"pod-singleton:{node.namespace}:{node.id}"
    if node.kind is NodeKind.PROCESS:
        return f"process:{node.id}"
    return None


def replica_loss(graph: TopologyGraph, target_ids: Iterable[str]) -> ReplicaLoss:
    """Replica-loss delta for a set of directly targeted nodes.

    Only *targeted* nodes count as lost. A node that merely depends on a target
    is impaired, not removed, so counting it as a lost replica would invent
    redundancy loss the plan does not cause.
    """
    targets = frozenset(target_ids)
    groups: dict[str, list[str]] = {}
    for node in graph.nodes:
        group_id = replica_group_id(node)
        if group_id is not None:
            groups.setdefault(group_id, []).append(node.id)
    touched = [
        ReplicaGroupLoss(
            group_id=group_id,
            members=tuple(sorted(members)),
            lost=tuple(sorted(targets.intersection(members))),
        )
        for group_id, members in sorted(groups.items())
        if targets.intersection(members)
    ]
    return ReplicaLoss(groups=tuple(touched), measured=bool(touched))


def expected_capacity_change_pct(loss: ReplicaLoss) -> float:
    """Share of the touched groups' serving capacity expected to disappear.

    Negative, or ``0.0`` when nothing is lost. Returns ``0.0`` for an
    *unmeasured* loss as well — which is why :attr:`ReplicaLoss.measured` exists
    and why the caller surfaces it: a zero from an unmeasured loss means "we
    could not tell", and rendering it as "no capacity lost" would be a lie.
    """
    if not loss.measured or not loss.member_total:
        return 0.0
    return -round(100.0 * loss.lost_total / loss.member_total, 3)


def customer_facing_node_ids(graph: TopologyGraph) -> frozenset[str]:
    """Service nodes that expose a port, i.e. the customer-facing surface.

    Exposure is the graph's own evidence of reachability from outside: a
    service with no exposed port is not the front door, and treating it as one
    would inflate the customer-facing count on every internal hop.
    """
    return frozenset(
        node.id
        for node in graph.of_kind(NodeKind.SERVICE)
        if isinstance(node, ServiceNode) and node.exposed_ports
    )


# --- per-step rules -----------------------------------------------------------


def _service_ids(graph: TopologyGraph) -> frozenset[str]:
    return frozenset(node.id for node in graph.of_kind(NodeKind.SERVICE))


def _host_ids(graph: TopologyGraph) -> frozenset[str]:
    return frozenset(node.id for node in graph.of_kind(NodeKind.HOST))


def _forbidden_pair(
    seen_fault_ids: tuple[str, ...], fault_id: str, forbidden: frozenset[frozenset[str]]
) -> frozenset[str] | None:
    """The forbidden pair this step completes, or ``None``.

    Mirrors ``controller.safety._first_forbidden_pair`` including its candidate
    set — one pair per *earlier* step, not the whole plan folded into one set —
    because that is the difference between the rule firing on long plans and
    being silently inert on them.
    """
    if not forbidden or not seen_fault_ids:
        return None
    for earlier in sorted({f for f in seen_fault_ids if f != fault_id}):
        pair = frozenset({earlier, fault_id})
        if pair in forbidden:
            return pair
    return None


def _per_step_rules(
    *,
    step: StepImpact,
    graph: TopologyGraph,
    budget: BlastRadiusBudget,
    ceilings: BlastCeilings,
    seen_fault_ids: tuple[str, ...],
) -> list[ViolatedRule]:
    """Every per-step limit this step breaks, with the values that broke it.

    Ordered by the gate's own check order so the first entry is the rule the
    gate would have raised on, which is the one worth putting in front of a
    reader.
    """
    found: list[ViolatedRule] = []

    def add(
        rule_id: str,
        measurement: tuple[float | None, float | None],
        unit: str,
        detail: str,
        remediation: str,
        *,
        observed_ids: tuple[str, ...] = (),
    ) -> None:
        """Record one breach as ``(observed, limit)`` — the pair the check used."""
        observed, limit = measurement
        found.append(
            ViolatedRule(
                rule_id=rule_id,
                step_id=step.step_id,
                step_index=step.step_index,
                fault_id=step.fault_id,
                observed=observed,
                limit=limit,
                unit=unit,
                detail=detail,
                observed_ids=observed_ids,
                remediation=remediation,
            )
        )

    if step.services_pct > budget.max_services_pct:
        add(
            RULE_MAX_SERVICES_PCT,
            (step.services_pct, budget.max_services_pct),
            "percent_of_services",
            f"{step.services_hit} of {step.services_total} services affected",
            "reduce blast or raise blast_radius.max_services_pct",
        )
    if step.hosts_hit > budget.max_hosts:
        add(
            RULE_MAX_HOSTS,
            (float(step.hosts_hit), float(budget.max_hosts)),
            "hosts",
            f"{step.hosts_hit} hosts affected",
            "reduce blast or raise blast_radius.max_hosts",
        )
    concurrent = float(len(seen_fault_ids) + 1)
    if concurrent > budget.max_concurrent_faults:
        add(
            RULE_MAX_CONCURRENT_FAULTS,
            (concurrent, float(budget.max_concurrent_faults)),
            "faults",
            f"step {step.step_index} is fault number {int(concurrent)} in the plan",
            "reduce concurrent faults or raise blast_radius.max_concurrent_faults",
        )
    if step.duration_s > budget.max_duration_per_fault_s:
        add(
            RULE_MAX_DURATION_PER_FAULT_S,
            (step.duration_s, budget.max_duration_per_fault_s),
            "seconds",
            f"{step.duration_s:g}s of fault duration",
            "shorten duration or raise blast_radius.max_duration_per_fault_s",
        )
    pair = _forbidden_pair(seen_fault_ids, step.fault_id, budget.forbidden_fault_pairs)
    if pair is not None:
        add(
            RULE_FORBIDDEN_FAULT_PAIRS,
            (None, None),
            "fault_pair",
            f"forbidden fault pair {sorted(pair)}",
            "remove the forbidden pair from blast_radius or change the fault set",
            observed_ids=tuple(sorted(pair)),
        )
    if ceilings.max_affected_nodes is not None and step.node_count > ceilings.max_affected_nodes:
        add(
            RULE_MAX_AFFECTED_NODES,
            (float(step.node_count), float(ceilings.max_affected_nodes)),
            "nodes",
            f"{step.node_count} nodes in the affected set",
            "narrow the target set or raise the affected-node ceiling",
        )
    if ceilings.max_dependency_depth is not None:
        step_depth = dependency_fan_out(graph, step.target_ids).max_depth
        if step_depth > ceilings.max_dependency_depth:
            add(
                RULE_MAX_DEPENDENCY_DEPTH,
                (float(step_depth), float(ceilings.max_dependency_depth)),
                "hops",
                f"damage reaches {step_depth} dependency hop(s) from the target",
                "target a shallower dependency, or raise the depth ceiling",
            )
    if (
        ceilings.max_affected_pct is not None
        and graph.nodes
        and step.node_count / len(graph.nodes) * 100.0 > ceilings.max_affected_pct
    ):
        add(
            RULE_MAX_AFFECTED_PCT,
            (round(step.node_count / len(graph.nodes) * 100.0, 3), ceilings.max_affected_pct),
            "percent_of_nodes",
            f"{step.node_count} of {len(graph.nodes)} nodes affected",
            "narrow the target set or raise the affected-percentage ceiling",
        )
    customer_facing = customer_facing_node_ids(graph)
    facing = tuple(sorted(customer_facing.intersection(step.affected_ids)))
    if (
        ceilings.max_customer_facing_services is not None
        and len(facing) > ceilings.max_customer_facing_services
    ):
        add(
            RULE_MAX_CUSTOMER_FACING_SERVICES,
            (float(len(facing)), float(ceilings.max_customer_facing_services)),
            "services",
            f"{len(facing)} customer-facing services affected",
            "target an internal dependency, or raise the customer-facing ceiling",
            observed_ids=facing,
        )
    hit_protected = tuple(sorted(ceilings.protected_node_ids.intersection(step.target_ids)))
    if hit_protected:
        add(
            RULE_PROTECTED_NODE,
            (float(len(hit_protected)), 0.0),
            "protected_nodes",
            f"targets include protected node(s) {list(hit_protected)}",
            "remove the protected node from the target set",
            observed_ids=hit_protected,
        )
    return found


# --- the prediction -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Walk:
    """Everything the per-step loop accumulates, so ``predict_impact`` only assembles."""

    steps: tuple[StepImpact, ...]
    rules: tuple[ViolatedRule, ...]
    costs: tuple[StepCost, ...]
    targets: frozenset[str]
    affected: frozenset[str]
    truncated_at: int | None
    notes: tuple[str, ...]


def _walk_steps(
    graph: TopologyGraph,
    plan: ExecutionPlan,
    *,
    budget: BlastRadiusBudget,
    quota: DamageQuota,
    ceilings: BlastCeilings,
    rates: CostRateCard,
) -> _Walk:
    """Evaluate every fault step in plan order, stopping where the gate stops.

    The loop is *gate-shaped on purpose*. ``validate_plan`` raises on the first
    breach, so the gate never charges the breaching step to the damage ledger and
    never looks at the steps after it. This walk does the same, which is what
    makes the reported numbers identical rather than merely similar — and it
    discloses the stop in ``truncated_at`` rather than passing the tail in
    silence.
    """
    service_ids = _service_ids(graph)
    host_ids = _host_ids(graph)
    ledger = DamageLedger()
    steps: list[StepImpact] = []
    rules: list[ViolatedRule] = []
    costs: list[StepCost] = []
    targets: set[str] = set()
    affected: set[str] = set()
    seen_fault_ids: tuple[str, ...] = ()
    truncated_at: int | None = None
    notes: list[str] = []

    for step_index, planned in enumerate(plan.steps):
        fault = planned.fault
        if fault is None:
            continue  # a wait/check step perturbs nothing
        step_targets = sorted({node_id for target in fault.targets for node_id in target.node_ids})
        affected_here = affected_node_ids(graph, step_targets)
        affected_sorted = tuple(sorted(affected_here))
        services_hit = len(affected_here.intersection(service_ids))
        duration_s = float(fault.duration)
        impact = StepImpact(
            step_id=planned.id,
            step_index=step_index,
            fault_id=fault.fault_id,
            target_ids=tuple(step_targets),
            affected_ids=affected_sorted,
            services_hit=services_hit,
            services_total=len(service_ids),
            services_pct=(services_hit / len(service_ids) * 100.0) if service_ids else 0.0,
            hosts_hit=len(affected_here.intersection(host_ids)),
            duration_s=duration_s,
            node_count=len(affected_here),
            damage_s=0.0,
        )
        targets.update(step_targets)
        affected.update(affected_here)

        step_rules = _per_step_rules(
            step=impact,
            graph=graph,
            budget=budget,
            ceilings=ceilings,
            seen_fault_ids=seen_fault_ids,
        )
        if step_rules:
            rules.extend(step_rules)
            steps.append(impact)
            truncated_at = step_index
            notes.append(
                f"prediction stopped at step {step_index} ({fault.fault_id}) on "
                f"{step_rules[0].rule_id}: the real gate refuses there, so the "
                "remaining steps were not evaluated"
            )
            break

        charge = ledger.charge(
            fault_id=fault.fault_id,
            duration_s=duration_s,
            node_ids=affected_sorted,
            quota=quota,
        )
        if charge.exceeded:
            rules.append(
                ViolatedRule(
                    rule_id=charge.rule_id,
                    step_id=planned.id,
                    step_index=step_index,
                    fault_id=fault.fault_id,
                    observed=round(charge.worst_node_s, 3),
                    limit=charge.limit_s,
                    unit="damage_seconds",
                    detail=(
                        f"step {step_index} brings {charge.worst_node} to "
                        f"{charge.worst_node_s:.3f} cumulative damage-seconds"
                    ),
                    observed_ids=(charge.worst_node,),
                    remediation=charge.remediation,
                )
            )
            steps.append(replace(impact, damage_s=round(charge.step_damage_s, 3)))
            truncated_at = step_index
            notes.append(
                f"prediction stopped at step {step_index} ({fault.fault_id}) on "
                f"{charge.rule_id}: the real gate refuses there"
            )
            break

        steps.append(replace(impact, damage_s=round(charge.step_damage_s, 3)))
        seen_fault_ids = (*seen_fault_ids, fault.fault_id)
        node_seconds = float(len(affected_here)) * duration_s
        costs.append(
            StepCost(
                step_id=planned.id,
                fault_id=fault.fault_id,
                affected_nodes=len(affected_here),
                duration_s=duration_s,
                affected_node_seconds=node_seconds,
                usd=round(node_seconds / 3600.0 * rates.usd_per_node_hour, 6),
            )
        )

    return _Walk(
        steps=tuple(steps),
        rules=tuple(rules),
        costs=tuple(costs),
        targets=frozenset(targets),
        affected=frozenset(affected),
        truncated_at=truncated_at,
        notes=tuple(notes),
    )


def predict_impact(
    graph: TopologyGraph,
    plan: ExecutionPlan,
    *,
    budget: BlastRadiusBudget | None = None,
    quota: DamageQuota | None = None,
    ceilings: BlastCeilings | None = None,
    rate_card: CostRateCard | None = None,
) -> ImpactPrediction:
    """Predict a plan's impact on a frozen graph. Pure, and read-only by construction.

    The walk is delegated to :func:`_walk_steps`, which is gate-shaped: a step
    that breaches a per-step limit is not charged to the damage ledger and ends
    the walk, mirroring ``validate_plan``, which raises on the first breach. The
    prediction therefore reports the rules the gate would refuse rather than a
    longer, differently-numbered list the gate never reaches, and discloses the
    stop in ``truncated_at_step``.

    Defaults match the gate's own defaults: a :class:`BlastRadiusBudget` and a
    :class:`DamageQuota` are both active, never ``None``. A prediction with no
    limits applied is a prediction that agrees with everything, which is not the
    same as a prediction that measured something.
    """
    walk = _walk_steps(
        graph,
        plan,
        budget=budget if budget is not None else BlastRadiusBudget(),
        quota=quota if quota is not None else DamageQuota(),
        ceilings=ceilings if ceilings is not None else BlastCeilings(),
        rates=rate_card if rate_card is not None else CostRateCard(),
    )
    rates = rate_card if rate_card is not None else CostRateCard()
    notes = list(walk.notes)
    basis = PredictionBasis.GRAPH if graph.nodes else PredictionBasis.EMPTY_GRAPH
    if basis is PredictionBasis.EMPTY_GRAPH:
        notes.append(
            "graph carried no nodes: the affected set is empty because nothing was "
            "observed, not because nothing would be affected"
        )
    # Only graph-resident nodes may appear as affected. A target the graph does
    # not hold is disclosed separately rather than being reported as a blast
    # the prediction had no evidence for.
    resident = frozenset(node.id for node in graph.nodes)
    resolved_targets = walk.targets.intersection(resident)
    unresolved = walk.targets - resident
    if unresolved:
        notes.append(
            f"target id(s) {sorted(unresolved)} are not in the graph snapshot; they are "
            "excluded from the affected set because the prediction cannot claim to affect "
            "a node it never observed — re-plan against current topology"
        )
    loss = replica_loss(graph, resolved_targets)
    cost = CostEstimate(
        currency=rates.currency,
        priced=rates.priced,
        basis=rates.basis,
        affected_node_seconds=sum(c.affected_node_seconds for c in walk.costs),
        total_usd=round(sum(c.usd for c in walk.costs), 6),
        per_step=walk.costs,
    )
    return ImpactPrediction(
        plan_identity=plan_identity(plan),
        graph_identity=graph_identity(graph),
        basis=basis,
        steps=walk.steps,
        affected_node_ids=tuple(sorted(walk.affected.intersection(resident))),
        unresolved_target_ids=tuple(sorted(unresolved)),
        fan_out=dependency_fan_out(graph, resolved_targets),
        replica_loss=loss,
        expected_capacity_change_pct=expected_capacity_change_pct(loss),
        capacity_known=loss.measured,
        violated_rules=tuple(sorted(walk.rules, key=lambda r: (r.step_index, r.rule_id))),
        cost=cost,
        truncated_at_step=walk.truncated_at,
        notes=tuple(notes),
    )


# --- predicates the rest of plan 14 is allowed to rely on ---------------------


def is_never_permissive(prediction: ImpactPrediction, gate_refused: Iterable[str]) -> bool:
    """True when the prediction flags every rule the real gate refused.

    The one-directional agreement test plan 14 Phase 1 accepts: a prediction may
    be *more* alarming than the gate (it reads a snapshot; the gate reads live
    state) but must never be calmer. Extra flagged rules pass. A refused rule the
    prediction did not flag fails, because that is exactly the case where a
    preview would have told an approver "fine" and the gate would not.
    """
    return set(gate_refused) <= prediction.rule_ids


def is_stale_against(
    prediction: ImpactPrediction,
    *,
    graph: TopologyGraph | None = None,
    plan: ExecutionPlan | None = None,
) -> bool:
    """True when the inputs have moved on from what the prediction measured.

    Drift in *either* input invalidates the prediction. A graph that changed
    after prediction may have different dependents; a plan that changed after
    prediction has different targets. Reporting on the new thing using numbers
    computed for the old thing is worse than reporting nothing.
    """
    if graph is not None and graph_identity(graph) != prediction.graph_identity:
        return True
    return plan is not None and plan_identity(plan) != prediction.plan_identity


def is_usable_for_approval(
    prediction: ImpactPrediction,
    *,
    graph: TopologyGraph | None = None,
    plan: ExecutionPlan | None = None,
) -> bool:
    """True when this prediction may be shown to someone deciding to approve.

    Usable does not mean "clean" — a prediction full of flagged rules is
    exactly what an approver needs. It means the numbers are current and were
    measured against something real.
    """
    return not approval_refusal_reason(prediction, graph=graph, plan=plan)


def approval_refusal_reason(
    prediction: ImpactPrediction,
    *,
    graph: TopologyGraph | None = None,
    plan: ExecutionPlan | None = None,
) -> str:
    """Why this prediction may not back an approval, or ``""`` if it may.

    Named reasons, never a bare ``False``: the caller is a person-facing surface
    and "refused" without a reason is the silent-pass failure mode this module
    exists to prevent.
    """
    if prediction.basis is PredictionBasis.EMPTY_GRAPH:
        return (
            "prediction was computed over an empty topology, so the empty affected "
            "set describes an unmeasured graph, not an unaffected system"
        )
    if prediction.unresolved_target_ids:
        return (
            f"target id(s) {list(prediction.unresolved_target_ids)} are absent from the "
            "graph snapshot, so their blast was never measured; re-plan against current "
            "topology"
        )
    if is_stale_against(prediction, graph=graph, plan=plan):
        return (
            "prediction is stale: the graph or plan no longer matches the identity it "
            "was computed over; re-predict against current state"
        )
    if prediction.truncated_at_step is not None:
        return (
            f"prediction stopped at step {prediction.truncated_at_step} because the plan "
            "breaches a per-step limit, so later steps were never measured"
        )
    return ""
