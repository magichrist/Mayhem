"""Blast-radius impact prediction — plan 14 Phase 1.

The properties pinned here are the ones the rest of plan 14 is built on, and
each one is a *negative* property: what the prediction must refuse to do.

* **Determinism.** The same frozen graph plus the same frozen plan must produce
  an identical prediction, twice, in any order, from equal-but-distinct
  instances. A preview nobody can re-derive is not a preview, and Phase 4 seals
  predictions with plans, so an unreproducible one cannot be sealed honestly.
* **Agreement with the gate.** The arithmetic is checked against the real
  ``controller.safety.validate_plan`` rather than against a hand-written list of
  expectations. The affected set must equal what the gate computes, and
  :func:`is_never_permissive` must hold against the gate's actual refusals. A
  duplicated-from-the-gate implementation that drifts would break here, which is
  the point of testing the duplication instead of hiding it.
* **Honesty about what was not measured.** A drifted graph makes a prediction
  stale and it is refused for approval use. An empty graph yields an explicit
  empty-affected prediction that is *also* refused for approval use, because
  "we looked at nothing" and "nothing would be affected" are different claims and
  only one of them is safe to render as a clean result.
"""

from __future__ import annotations

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.prediction import (
    RULE_FORBIDDEN_FAULT_PAIRS,
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_CONCURRENT_FAULTS,
    RULE_MAX_CUSTOMER_FACING_SERVICES,
    RULE_MAX_DEPENDENCY_DEPTH,
    RULE_MAX_DURATION_PER_FAULT_S,
    RULE_MAX_HOSTS,
    RULE_MAX_SERVICES_PCT,
    RULE_PROTECTED_NODE,
    BlastCeilings,
    CostRateCard,
    PredictionBasis,
    affected_node_ids,
    approval_refusal_reason,
    dependency_fan_out,
    graph_identity,
    is_never_permissive,
    is_stale_against,
    is_usable_for_approval,
    plan_identity,
    predict_impact,
    replica_loss,
)
from mayhem.domain.quota import RULE_BUDGET, RULE_PER_FAULT_CEILING, DamageQuota
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    PodNode,
    PortBinding,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

FP = "f" * 64


# --- fixtures -----------------------------------------------------------------


def _container(node_id: str, name: str, *, service: str | None = None) -> ContainerNode:
    return ContainerNode(
        id=node_id,
        name=name,
        engine="docker",
        runtime_identity=RuntimeIdentity(
            runtime="docker", host_id="h-local", runtime_id=f"cid-{name}"
        ),
        runtime_metadata=RuntimeMetadata.from_compose_labels(
            {"com.docker.compose.service": service} if service else {}
        ),
        container_name=service,
    )


def _graph() -> TopologyGraph:
    """A four-service chain, two hosts, two replicas of one service, two pods.

    Shaped so the tests can say precise things about arithmetic:

    * ``n-db`` <- ``n-api`` <- ``n-web`` <- ``n-edge`` is a four-deep dependency
      chain, so fan-out depth from ``n-db`` is 3 and a depth ceiling is testable.
    * ``web-1``/``web-2`` are two replicas of compose service ``web`` on one
      host, so replica loss has something real to divide.
    * ``api-1``/``api-2`` are two pods of one ReplicaSet, the Kubernetes-shaped
      half of the same question.
    * ``n-web`` is the only service with an exposed port, so the customer-facing
      count is 1 and not "however many services happen to be in the closure".
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-db", name="db"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(
                id="n-web",
                name="web",
                exposed_ports=(PortBinding(host_port=8080, container_port=8080),),
            ),
            ServiceNode(id="n-edge", name="edge"),
            HostNode(id="h-local", name="local", transport="local"),
            HostNode(id="h-remote", name="remote", transport="ssh"),
            _container("web-1", "web-1", service="web"),
            _container("web-2", "web-2", service="web"),
            PodNode(id="api-1", name="api-1", namespace="prod", owner_name="api-rs"),
            PodNode(id="api-2", name="api-2", namespace="prod", owner_name="api-rs"),
        ),
        edges=(
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-edge", dst="n-web", kind=EdgeKind.DEPENDS_ON),
            Edge(src="web-1", dst="n-web", kind=EdgeKind.EXPOSES),
            Edge(src="web-2", dst="n-web", kind=EdgeKind.EXPOSES),
            Edge(src="api-1", dst="n-api", kind=EdgeKind.RUNS_ON),
            Edge(src="api-2", dst="n-api", kind=EdgeKind.RUNS_ON),
            Edge(src="web-1", dst="h-local", kind=EdgeKind.RUNS_ON),
            Edge(src="web-2", dst="h-local", kind=EdgeKind.RUNS_ON),
        ),
    )


def _plan(
    *faults: tuple[str, str, float], run_id: str = "r-pred", graph: TopologyGraph | None = None
) -> ExecutionPlan:
    """Build a frozen plan: ``(fault_id, node_id, duration_s)`` per step.

    A ``node_id`` absent from ``graph`` is still allowed: a plan carries resolved
    ids from *its* snapshot, and a prediction computed against a different one
    legitimately meets an id it cannot resolve. That case is what
    ``unresolved_target_ids`` exists to report.
    """
    source = graph if graph is not None else _graph()
    steps: list[PlannedStep] = []
    for index, (fault_id, node_id, duration) in enumerate(faults):
        node = source.by_id(node_id)
        selector = (
            TargetSelector(kind=node.kind, expr=node.name)
            if node is not None
            else TargetSelector(kind=NodeKind.SERVICE, expr=node_id)
        )
        steps.append(
            PlannedStep(
                id=f"s{index}",
                seq=index,
                raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),),
                    duration=duration,
                ),
            )
        )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


def _permissive() -> BlastRadiusBudget:
    """Per-step limits nothing in this file trips, so a breach is unambiguous."""
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _ctx(budget: BlastRadiusBudget | None = None) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=budget or _permissive(),
        fingerprint=FP,
        damage_quota=DamageQuota(),
    )


def _gate_refusals(plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext) -> frozenset[str]:
    """Rule ids the *real* gate refuses, or empty when it admits the plan."""
    try:
        validate_plan(plan, graph, ctx)
    except SafetyRefusedError as exc:
        return frozenset({exc.decision.rule_id}) if exc.decision is not None else frozenset()
    return frozenset()


# --- determinism --------------------------------------------------------------


def test_same_graph_and_plan_produce_an_identical_prediction():
    graph, plan = _graph(), _plan(("net.latency", "n-db", 30.0))
    assert predict_impact(graph, plan, budget=_permissive()) == predict_impact(
        graph, plan, budget=_permissive()
    )


def test_determinism_survives_an_equivalent_but_distinct_graph_and_plan():
    """Re-parsing must not move a single field.

    Two equal-but-distinct instances exercise serialisation, not object identity:
    if the prediction carried a dict iteration order, a set ordering, or a
    timestamp, this is where it would show.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", 30.0), ("mem.exhaust", "web-1", 60.0))
    first = predict_impact(graph, plan, budget=_permissive())
    second = predict_impact(
        TopologyGraph.model_validate(graph.model_dump(mode="json")),
        ExecutionPlan.model_validate(plan.model_dump(mode="json")),
        budget=_permissive(),
    )
    assert first == second
    assert first.graph_identity == second.graph_identity
    assert first.plan_identity == second.plan_identity


def test_prediction_is_independent_of_a_second_steps_input_order():
    """A wait/check step perturbs nothing, so adding one must not move the numbers.

    This also pins that the walk skips ``fault is None`` the way the gate does,
    rather than inventing an empty blast for it.
    """
    graph = _graph()
    with_wait = ExecutionPlan(
        run_id="r-pred",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            _plan(("net.latency", "n-db", 30.0)).steps[0],
            PlannedStep(
                id="s-wait",
                seq=1,
                raw_action=Wait(duration=5.0),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )
    plain = _plan(("net.latency", "n-db", 30.0))
    measured = predict_impact(graph, with_wait, budget=_permissive())
    baseline = predict_impact(graph, plain, budget=_permissive())

    # The plan identity *must* differ — a different plan is a different plan.
    assert measured.plan_identity != baseline.plan_identity
    # Everything the prediction measured must not.
    assert measured.affected_node_ids == baseline.affected_node_ids
    assert measured.fan_out == baseline.fan_out
    assert measured.replica_loss == baseline.replica_loss
    assert measured.violated_rules == baseline.violated_rules
    assert measured.cost == baseline.cost
    assert measured.steps == baseline.steps


def test_plan_identity_matches_the_controller_plan_diff_hash():
    """Prediction identity and plan-diff identity must be the same bytes.

    Phase 4 seals a prediction with its plan; if the two hashed differently, a
    later diff would report a change where there was none.
    """
    from mayhem.controller.plan_diff import diff_plans

    plan = _plan(("net.latency", "n-db", 30.0))
    diff = diff_plans(plan, plan)
    assert diff["authored_hash"] == plan_identity(plan)
    assert diff["accepted_hash"] == plan_identity(plan)


# --- fan-out arithmetic -------------------------------------------------------


def test_affected_set_is_exactly_the_gate_closure():
    """The duplicated arithmetic must equal ``dependents_closure``, node for node.

    Both sides are computed independently — one through this module's walk, one
    through the graph's own method the gate calls — so drift is caught rather
    than mirrored.
    """
    graph = _graph()
    targets = ("n-db",)
    expected = frozenset(targets)
    for target in targets:
        expected |= graph.dependents_closure(target)
    assert affected_node_ids(graph, targets) == expected


def test_affected_set_matches_the_closure_for_every_node_in_the_graph():
    graph = _graph()
    for node in graph.nodes:
        expected = frozenset({node.id}) | graph.dependents_closure(node.id)
        assert affected_node_ids(graph, (node.id,)) == expected


def test_fan_out_depth_counts_dependency_hops_from_the_target():
    """``n-db`` -> ``n-api`` -> ``n-web`` -> ``n-edge`` is three hops, not four."""
    fan = dependency_fan_out(_graph(), ("n-db",))
    assert fan.max_depth == 3
    depths = {node.node_id: node.depth for node in fan.nodes}
    assert depths == {"n-db": 0, "n-api": 1, "n-web": 2, "n-edge": 3}
    assert fan.dependent_count == 3
    assert fan.dependent_ids == ("n-api", "n-web", "n-edge")


def test_fan_out_node_set_equals_the_affected_set():
    graph = _graph()
    targets = ("n-db",)
    assert {n.node_id for n in dependency_fan_out(graph, targets).nodes} == affected_node_ids(
        graph, targets
    )


def test_fan_out_of_a_dependent_does_not_mutually_inflate():
    """Targeting ``n-api`` must not make ``n-db`` (below it) a dependent.

    A naive reverse walk that re-expands the target's own dependents would put
    the target at depth 0 and still report its dependencies at depth 1 — the
    symmetric error, which would make ``n-api`` look like it impairs ``n-db``.
    """
    fan = dependency_fan_out(_graph(), ("n-api",))
    assert {n.node_id for n in fan.nodes} == {"n-api", "n-web", "n-edge"}
    assert fan.max_depth == 2


def test_a_node_with_no_dependents_reports_zero_depth_not_missing():
    fan = dependency_fan_out(_graph(), ("n-edge",))
    assert fan.max_depth == 0
    assert fan.dependent_count == 0
    assert [n.node_id for n in fan.nodes] == ["n-edge"]


# --- replica-loss arithmetic ---------------------------------------------------


def test_one_of_two_replicas_lost_is_half_the_group():
    loss = replica_loss(_graph(), ("web-1",))
    assert loss.measured is True
    assert len(loss.groups) == 1
    group = loss.groups[0]
    assert group.members == ("web-1", "web-2")
    assert group.lost == ("web-1",)
    assert group.lost_count == 1
    assert group.survivors == ("web-2",)
    assert group.loss_ratio == 0.5
    assert group.redundancy_cleared is True
    assert loss.lost_total == 1
    assert loss.member_total == 2
    assert loss.fully_lost_group_ids == ()


def test_a_pod_group_is_keyed_by_namespace_and_owner():
    """Two pods of one ReplicaSet are replicas of each other."""
    loss = replica_loss(_graph(), ("api-1", "api-2"))
    group = loss.groups[0]
    assert group.group_id == "pod:prod:api-rs"
    assert group.members == ("api-1", "api-2")
    assert group.lost == ("api-1", "api-2")
    assert group.redundancy_cleared is False
    assert loss.fully_lost_group_ids == ("pod:prod:api-rs",)


def test_both_pods_lost_moves_expected_capacity_to_minus_one_hundred():
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "api-1", 30.0), ("net.latency", "api-2", 30.0)),
        budget=_permissive(),
    )
    assert prediction.capacity_known is True
    assert prediction.expected_capacity_change_pct == -100.0


def test_replica_loss_counts_only_targeted_nodes_not_dependents():
    """An impaired dependent is not a lost replica.

    Targeting ``n-db`` pulls three services into the affected set; none of them
    is a replica of anything, so the capacity change must be zero and the
    prediction must say the loss was not measurable rather than invent a group.
    """
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "n-db", 30.0)), budget=_permissive()
    )
    assert prediction.affected_node_ids == ("n-api", "n-db", "n-edge", "n-web")
    assert prediction.replica_loss.groups == ()  # service nodes are not instances
    assert prediction.capacity_known is False
    assert prediction.expected_capacity_change_pct == 0.0


def test_two_services_on_one_host_are_not_each_other_s_replicas():
    """Container replicas key on the compose service, not the host.

    A host-scoped grouping would make every container on a host a "replica" of
    every other, which would turn a one-instance blast into a fake 50% loss.
    """
    graph = TopologyGraph(
        nodes=(
            _container("c-one", "one", service="one"),
            _container("c-two", "two", service="two"),
        ),
        edges=(),
    )
    loss = replica_loss(graph, ("c-one",))
    assert [g.group_id for g in loss.groups] == ["container:docker:h-local:one"]
    assert loss.lost_total == 1
    assert loss.member_total == 1
    assert loss.groups[0].loss_ratio == 1.0
    assert loss.groups[0].redundancy_cleared is False


def test_a_host_is_never_a_redundancy_claim():
    """A host carries no instance count, so it must not become a "100% lost" group.

    Reporting a group of one for a host would claim the host's whole capacity is
    gone, from a node whose capacity was never observed. The honest answer is no
    group at all, and ``measured=False`` so a zero capacity change is not read as
    "nothing lost".
    """
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "h-remote", 30.0)), budget=_permissive()
    )
    assert prediction.replica_loss.groups == ()
    assert prediction.replica_loss.measured is False
    assert prediction.capacity_known is False
    assert prediction.expected_capacity_change_pct == 0.0


# --- violated rules, with their observed values --------------------------------


def test_service_percentage_rule_reports_the_observed_value_and_the_limit():
    """``n-db``'s blast reaches 3 of 4 services; a 50% cap must be exceeded."""
    budget = BlastRadiusBudget(
        max_services_pct=50.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )
    prediction = predict_impact(_graph(), _plan(("net.latency", "n-db", 30.0)), budget=budget)
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_MAX_SERVICES_PCT)
    assert rule.observed == pytest.approx(100.0)
    assert rule.limit == 50.0
    assert rule.unit == "percent_of_services"
    assert rule.exceeded_by == pytest.approx(50.0)
    assert rule.fault_id == "net.latency"
    assert rule.step_id == "s0"
    assert "4 of 4 services" in rule.detail
    assert rule.remediation


def test_a_narrow_blast_reports_a_percentage_below_the_cap():
    """The other direction: ``n-edge`` reaches nobody, so 25% must read as inside.

    A rule that fired on every plan would be a rule nobody could act on.
    """
    budget = BlastRadiusBudget(
        max_services_pct=50.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )
    prediction = predict_impact(_graph(), _plan(("net.latency", "n-edge", 30.0)), budget=budget)
    assert prediction.violated_rules == ()
    assert prediction.steps[0].services_pct == pytest.approx(25.0)


def test_host_count_rule_reports_both_numbers():
    """A host reached through ``CONNECTS_VIA`` is as affected as a service.

    The gate counts hosts over the same affected set, and the two carriers count
    alike, so a preview that ignored the host edge would under-report exactly the
    case ``max_hosts`` exists to cap.
    """
    graph = TopologyGraph(
        nodes=(
            ServiceNode(id="s-api", name="api"),
            ServiceNode(id="s-web", name="web"),
            HostNode(id="h-1", name="one", transport="local"),
            HostNode(id="h-2", name="two", transport="local"),
        ),
        edges=(
            Edge(src="s-api", dst="s-web", kind=EdgeKind.DEPENDS_ON),
            # "h-1 connects via s-web" — the host reaches the service over that
            # connection, so the host is a dependent of s-web.
            Edge(src="h-1", dst="s-web", kind=EdgeKind.CONNECTS_VIA),
            Edge(src="h-2", dst="s-web", kind=EdgeKind.CONNECTS_VIA),
        ),
    )
    # Targeting ``s-web``: the API and both hosts depend on it, so both
    # hosts land in the affected set and ``max_hosts`` has something to count.
    plan = _plan(("net.latency", "s-web", 30.0), graph=graph)
    budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )
    prediction = predict_impact(graph, plan, budget=budget)
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_MAX_HOSTS)
    assert rule.observed == 2.0
    assert rule.limit == 1.0
    assert rule.unit == "hosts"
    assert "2 hosts affected" in rule.detail


def test_duration_rule_reports_the_authored_duration():
    budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=60.0,
    )
    prediction = predict_impact(_graph(), _plan(("net.latency", "n-db", 300.0)), budget=budget)
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_MAX_DURATION_PER_FAULT_S)
    assert rule.observed == 300.0
    assert rule.limit == 60.0
    assert rule.unit == "seconds"
    assert rule.exceeded_by == pytest.approx(240.0)


def test_concurrency_rule_reports_which_fault_number_breached():
    budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=1,
        max_duration_per_fault_s=float("inf"),
    )
    prediction = predict_impact(
        _graph(),
        _plan(("net.latency", "n-edge", 30.0), ("net.latency", "n-web", 30.0)),
        budget=budget,
    )
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_MAX_CONCURRENT_FAULTS)
    assert rule.observed == 2.0
    assert rule.limit == 1.0
    assert rule.step_index == 1


def test_forbidden_pair_rule_reports_the_pair_it_matched():
    budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset({frozenset({"net.latency", "mem.exhaust"})}),
    )
    prediction = predict_impact(
        _graph(),
        _plan(("net.latency", "n-edge", 30.0), ("mem.exhaust", "n-web", 30.0)),
        budget=budget,
    )
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_FORBIDDEN_FAULT_PAIRS)
    # Non-numeric rule: no fabricated observed value, the pair travels as ids.
    assert rule.observed is None
    assert rule.limit is None
    assert rule.observed_ids == ("mem.exhaust", "net.latency")
    assert rule.exceeded_by is None


def test_damage_quota_rule_reports_the_accumulated_seconds_and_the_worst_node():
    graph = _graph()
    plan = _plan(*(("net.partition", "n-edge", 300.0) for _ in range(3)))
    prediction = predict_impact(
        graph,
        plan,
        budget=_permissive(),
        quota=DamageQuota(budget_s=700.0, per_fault_ceiling_s=1e9, window_s=1e9),
    )
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_BUDGET)
    assert rule.unit == "damage_seconds"
    assert rule.observed is not None and rule.observed > 700.0
    assert rule.limit == 700.0
    assert rule.observed_ids == ("n-edge",)


def test_per_fault_damage_ceiling_is_reported_separately_from_the_budget():
    prediction = predict_impact(
        _graph(),
        _plan(("net.partition", "n-edge", 300.0)),
        budget=_permissive(),
        quota=DamageQuota(budget_s=1e9, per_fault_ceiling_s=10.0, window_s=1e9),
    )
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_PER_FAULT_CEILING)
    assert rule.observed is not None and rule.observed > 10.0
    assert rule.limit == 10.0


def test_plan_14_ceilings_report_observed_values_too():
    """The new ceilings are numeric rules and must carry numbers like the old ones."""
    prediction = predict_impact(
        _graph(),
        _plan(("net.latency", "n-db", 30.0)),
        budget=_permissive(),
        ceilings=BlastCeilings(
            max_affected_nodes=2,
            max_dependency_depth=1,
            max_affected_pct=10.0,
        ),
    )
    by_id = {r.rule_id: r for r in prediction.violated_rules}
    assert by_id[RULE_MAX_DEPENDENCY_DEPTH].observed == 3.0
    assert by_id[RULE_MAX_DEPENDENCY_DEPTH].limit == 1.0
    assert by_id[RULE_MAX_DEPENDENCY_DEPTH].unit == "hops"
    assert by_id[RULE_MAX_AFFECTED_NODES].observed == 4.0
    assert by_id[RULE_MAX_AFFECTED_PCT].limit == 10.0


def test_protected_node_rule_names_the_protected_ids_it_hit():
    prediction = predict_impact(
        _graph(),
        _plan(("net.latency", "n-web", 30.0)),
        budget=_permissive(),
        ceilings=BlastCeilings(protected_node_ids=frozenset({"n-web", "n-db"})),
    )
    rule = next(r for r in prediction.violated_rules if r.rule_id == RULE_PROTECTED_NODE)
    assert rule.observed_ids == ("n-web",)
    assert rule.observed == 1.0
    assert rule.limit == 0.0


def test_a_protected_node_that_is_only_a_dependent_is_not_a_protection_breach():
    """Protection is about targets, not about the inevitable.

    An unavoidable dependent of a protected service is a fact to surface, not a
    reason to report a breach the operator cannot act on.
    """
    prediction = predict_impact(
        _graph(),
        _plan(("net.latency", "n-db", 30.0)),
        budget=_permissive(),
        ceilings=BlastCeilings(protected_node_ids=frozenset({"n-web"})),
    )
    assert RULE_PROTECTED_NODE not in prediction.rule_ids
    assert "n-web" in prediction.affected_node_ids


def test_customer_facing_ceiling_counts_only_services_that_expose_a_port():
    """``n-web`` is the only front door here, so the count is 1, not 4."""
    graph = _graph()
    within = predict_impact(
        graph,
        _plan(("net.latency", "n-web", 30.0)),
        budget=_permissive(),
        ceilings=BlastCeilings(max_customer_facing_services=1),
    )
    assert RULE_MAX_CUSTOMER_FACING_SERVICES not in within.rule_ids

    over = predict_impact(
        graph,
        _plan(("net.latency", "n-db", 30.0)),
        budget=_permissive(),
        ceilings=BlastCeilings(max_customer_facing_services=0),
    )
    rule = next(r for r in over.violated_rules if r.rule_id == RULE_MAX_CUSTOMER_FACING_SERVICES)
    assert rule.observed == 1.0
    assert rule.limit == 0.0
    assert rule.observed_ids == ("n-web",)


def test_an_unconfigured_ceiling_is_never_reported_as_satisfied():
    """``None`` means unchecked, which is not the same as within the limit."""
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "n-db", 30.0)), budget=_permissive()
    )
    assert not prediction.violated_rules
    assert prediction.within_policy is True


# --- agreement with the real gate ---------------------------------------------


@pytest.mark.parametrize(
    ("budget", "faults"),
    [
        # Over the service-percentage cap.
        (
            BlastRadiusBudget(max_services_pct=50.0),
            (("net.latency", "n-db", 30.0),),
        ),
        # Over the concurrent-fault cap, on the second step.
        (
            BlastRadiusBudget(max_concurrent_faults=1),
            (("net.latency", "n-edge", 30.0), ("net.latency", "n-web", 30.0)),
        ),
        # Over the per-fault duration cap.
        (
            BlastRadiusBudget(max_duration_per_fault_s=60.0),
            (("net.latency", "n-db", 300.0),),
        ),
        # A forbidden pair, on the second step.
        (
            BlastRadiusBudget(
                forbidden_fault_pairs=frozenset({frozenset({"net.latency", "mem.exhaust"})})
            ),
            (("net.latency", "n-edge", 30.0), ("mem.exhaust", "n-web", 30.0)),
        ),
        # A plan the gate admits.
        (_permissive(), (("net.latency", "n-db", 30.0),)),
    ],
)
def test_prediction_is_never_permissive_against_the_real_gate(budget, faults):
    """The acceptance test, run against ``validate_plan`` rather than a stub.

    Whatever the gate refuses, the prediction must already have flagged. A
    prediction that is *more* alarming passes; one that is calmer fails, because
    that is the case where a preview would have told an approver "fine" and the
    gate would not.
    """
    graph, plan = _graph(), _plan(*faults)
    refused = _gate_refusals(plan, graph, _ctx(budget))
    prediction = predict_impact(graph, plan, budget=budget)
    assert is_never_permissive(prediction, refused), (
        f"gate refused {sorted(refused)}; prediction flagged {sorted(prediction.rule_ids)}"
    )


def test_the_prediction_stops_where_the_gate_stops():
    """Truncation is disclosure, not a shortcut.

    The gate raises on the first breach, so the prediction must report the same
    first breach and say the tail went unmeasured — never report a clean tail it
    never looked at.
    """
    budget = BlastRadiusBudget(max_duration_per_fault_s=60.0)
    graph = _graph()
    plan = _plan(
        ("net.latency", "n-edge", 30.0),
        ("net.latency", "n-web", 300.0),
        ("net.latency", "n-db", 300.0),
    )
    prediction = predict_impact(graph, plan, budget=budget)
    assert prediction.truncated_at_step == 1
    assert len(prediction.steps) == 2
    assert [s.step_id for s in prediction.steps] == ["s0", "s1"]
    assert any("not evaluated" in note for note in prediction.notes)
    assert is_usable_for_approval(prediction) is False
    assert "never measured" in approval_refusal_reason(prediction)


def test_a_clean_prediction_is_usable_for_approval():
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "n-edge", 30.0)), budget=_permissive()
    )
    assert prediction.violated_rules == ()
    assert approval_refusal_reason(prediction) == ""
    assert is_usable_for_approval(prediction) is True


# --- cost estimate ------------------------------------------------------------


def test_an_unpriced_estimate_is_disclosed_as_unpriced_never_as_free():
    """No rate card means nobody priced this, which is not the same as zero."""
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "n-db", 30.0)), budget=_permissive()
    )
    assert prediction.cost.priced is False
    assert prediction.cost.total_usd == 0.0
    assert prediction.cost.basis == "no rate card supplied"
    # The measured half is still real: node-seconds are a fact, money is not.
    assert prediction.cost.affected_node_seconds == pytest.approx(4 * 30.0)


def test_a_supplied_rate_card_prices_the_measured_node_seconds():
    prediction = predict_impact(
        _graph(),
        _plan(("net.latency", "n-db", 30.0)),
        budget=_permissive(),
        rate_card=CostRateCard(usd_per_node_hour=0.36, basis="authored test rate"),
    )
    assert prediction.cost.priced is True
    assert prediction.cost.basis == "authored test rate"
    assert prediction.cost.total_usd == pytest.approx(4 * 30.0 / 3600.0 * 0.36)
    assert len(prediction.cost.per_step) == 1
    assert prediction.cost.per_step[0].affected_nodes == 4


# --- negative control: a drifted graph is stale and refused --------------------


def test_a_prediction_over_a_drifted_graph_is_marked_stale():
    """New dependency edge, same plan: the numbers no longer describe reality."""
    before = _graph()
    after = TopologyGraph(
        nodes=before.nodes,
        edges=(*before.edges, Edge(src="n-db", dst="n-web", kind=EdgeKind.DEPENDS_ON)),
    )
    prediction = predict_impact(before, _plan(("net.latency", "n-db", 30.0)), budget=_permissive())

    assert graph_identity(before) != graph_identity(after)
    assert is_stale_against(prediction, graph=after) is True
    assert is_usable_for_approval(prediction, graph=after) is False
    reason = approval_refusal_reason(prediction, graph=after)
    assert "stale" in reason
    assert "re-predict" in reason


def test_a_prediction_is_not_stale_against_the_inputs_it_was_computed_from():
    graph, plan = _graph(), _plan(("net.latency", "n-db", 30.0))
    prediction = predict_impact(graph, plan, budget=_permissive())
    assert is_stale_against(prediction, graph=graph, plan=plan) is False
    assert is_usable_for_approval(prediction, graph=graph, plan=plan) is True


def test_a_drifted_plan_also_makes_the_prediction_stale():
    """Staleness is not only about the graph; a re-planned plan invalidates too."""
    graph = _graph()
    prediction = predict_impact(graph, _plan(("net.latency", "n-db", 30.0)), budget=_permissive())
    assert is_stale_against(prediction, plan=_plan(("net.latency", "n-edge", 30.0))) is True
    assert is_usable_for_approval(prediction, plan=_plan(("net.latency", "n-edge", 30.0))) is False


# --- negative control: an unresolvable target is disclosed, not assumed --------


def test_a_target_missing_from_the_graph_is_excluded_from_the_affected_set():
    """A prediction may not claim to affect a node it never observed.

    The plan still says "fault n-ghost"; the graph does not contain ``n-ghost``;
    so the honest report is "this target could not be measured", not a blast
    radius computed for a node nobody has evidence exists.
    """
    graph = _graph()
    prediction = predict_impact(
        graph, _plan(("net.latency", "n-ghost", 30.0)), budget=_permissive()
    )
    assert prediction.basis is PredictionBasis.GRAPH
    assert prediction.unresolved_target_ids == ("n-ghost",)
    assert "n-ghost" not in prediction.affected_node_ids
    assert any("not in the graph snapshot" in note for note in prediction.notes)


def test_a_prediction_with_an_unresolvable_target_is_refused_for_approval_use():
    """Half a measurement is not a measurement.

    ``violated_rules`` is empty and ``within_policy`` is true, so without the
    explicit refusal a reader would take this for a clean result over a graph
    that only happened to be missing the target.
    """
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "n-ghost", 30.0)), budget=_permissive()
    )
    assert prediction.violated_rules == ()
    assert is_usable_for_approval(prediction) is False
    reason = approval_refusal_reason(prediction)
    assert "n-ghost" in reason
    assert "never measured" in reason


def test_resolved_targets_are_never_reported_as_unresolved():
    prediction = predict_impact(
        _graph(), _plan(("net.latency", "n-db", 30.0)), budget=_permissive()
    )
    assert prediction.unresolved_target_ids == ()
    assert is_usable_for_approval(prediction) is True


# --- negative control: an empty graph is not a silent pass ---------------------


def test_an_empty_graph_yields_an_explicit_empty_affected_prediction():
    """The result is *explicit* — empty affected set, empty fan-out, zero cost."""
    empty = TopologyGraph(nodes=(), edges=())
    prediction = predict_impact(empty, _plan(("net.latency", "n-db", 30.0)), budget=_permissive())

    assert prediction.basis is PredictionBasis.EMPTY_GRAPH
    assert prediction.empty is True
    assert prediction.affected_node_ids == ()
    assert prediction.fan_out.nodes == ()
    assert prediction.fan_out.max_depth == 0
    assert prediction.replica_loss.measured is False
    assert prediction.capacity_known is False
    assert prediction.expected_capacity_change_pct == 0.0
    assert any("nothing was observed" in note for note in prediction.notes)


def test_an_empty_graph_prediction_is_never_a_silent_pass():
    """The whole point: empty-affected must never read as "safe to approve".

    ``violated_rules`` is empty and ``within_policy`` is true, so without an
    explicit basis check this prediction would be indistinguishable from a clean
    one over a real graph. It is refused for approval use, with a reason.
    """
    empty = TopologyGraph(nodes=(), edges=())
    prediction = predict_impact(empty, _plan(("net.latency", "n-db", 30.0)), budget=_permissive())

    assert prediction.violated_rules == ()
    assert is_usable_for_approval(prediction) is False
    reason = approval_refusal_reason(prediction)
    assert "empty topology" in reason
    assert "unmeasured graph" in reason


def test_an_empty_graph_prediction_does_not_certify_a_gate_refusal():
    """It cannot be *more* alarming than nothing, so it must not claim to be safe.

    The never-permissive predicate still fails here: an empty graph cannot
    demonstrate anything about a plan, so it must never be offered as evidence
    that a refused plan would have been fine.
    """
    empty = TopologyGraph(nodes=(), edges=())
    prediction = predict_impact(empty, _plan(("net.latency", "n-db", 30.0)), budget=_permissive())
    assert is_never_permissive(prediction, [RULE_MAX_SERVICES_PCT]) is False


def test_a_real_graph_prediction_is_distinguishable_from_an_empty_one():
    """Same plan, two graphs: the basis is what separates the two verdicts."""
    plan = _plan(("net.latency", "n-db", 30.0))
    real = predict_impact(_graph(), plan, budget=_permissive())
    empty = predict_impact(TopologyGraph(nodes=(), edges=()), plan, budget=_permissive())

    assert real.basis is PredictionBasis.GRAPH
    assert empty.basis is PredictionBasis.EMPTY_GRAPH
    assert real.within_policy is True
    assert empty.within_policy is True
    assert is_usable_for_approval(real) is True
    assert is_usable_for_approval(empty) is False


# --- the never-permissive predicate itself ------------------------------------


def test_never_permissive_passes_on_a_matching_vocabulary():
    """The predicate is a set comparison over rule ids, not a guess."""
    graph = _graph()
    budget = BlastRadiusBudget(max_services_pct=50.0)
    prediction = predict_impact(graph, _plan(("net.latency", "n-db", 30.0)), budget=budget)
    assert is_never_permissive(prediction, [RULE_MAX_SERVICES_PCT]) is True


def test_never_permissive_allows_over_reporting():
    """Extra flagged rules are the conservative direction, so they pass."""
    graph = _graph()
    prediction = predict_impact(
        graph,
        _plan(("net.latency", "n-db", 30.0)),
        budget=BlastRadiusBudget(max_services_pct=50.0),
        ceilings=BlastCeilings(max_affected_nodes=1, max_dependency_depth=1),
    )
    # The gate knows about the percentage cap; the ceilings are extra.
    assert RULE_MAX_SERVICES_PCT in prediction.rule_ids
    assert RULE_MAX_AFFECTED_NODES in prediction.rule_ids
    assert RULE_MAX_DEPENDENCY_DEPTH in prediction.rule_ids
    assert is_never_permissive(prediction, [RULE_MAX_SERVICES_PCT]) is True


def test_never_permissive_fails_when_the_gate_refused_something_unflagged():
    """The failure mode it exists to catch: a preview that is calmer than the gate."""
    graph = _graph()
    prediction = predict_impact(graph, _plan(("net.latency", "n-edge", 30.0)), budget=_permissive())
    assert prediction.violated_rules == ()
    assert is_never_permissive(prediction, [RULE_MAX_SERVICES_PCT]) is False
    assert is_never_permissive(prediction, []) is True


# --- the domain law -----------------------------------------------------------


def test_prediction_module_imports_nothing_from_an_upper_layer():
    """The layering contract, asserted locally as well as in ``test_import_contracts``.

    Cheap to check and it fails at the point of the mistake rather than in the
    contract suite, where the failure message names a contract rather than a file.
    """
    import ast
    from pathlib import Path

    forbidden = (
        "mayhem.toolkit",
        "mayhem.agents",
        "mayhem.controller",
        "mayhem.infra",
        "asyncio",
        "socket",
        "subprocess",
        "sqlite3",
        "pathlib",
        "os",
    )
    source = Path(__file__).resolve().parents[2] / "src" / "mayhem" / "domain" / "prediction.py"
    tree = ast.parse(source.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
            if node.module.startswith("mayhem."):
                imported.add(node.module)
    assert imported.isdisjoint(forbidden), sorted(imported & set(forbidden))
