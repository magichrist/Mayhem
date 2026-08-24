"""ADR-0012: triple-gated safety — G1 policy, G2 budgets, G3 drift."""
import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    check_blast_radius,
    check_fault_admission,
    environment_fingerprint,
    pre_exec_assertion,
    validate_plan,
)
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)


def _ctx(**policy_kwargs) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(**policy_kwargs),
        budget=BlastRadiusBudget(),
        fingerprint="f",
    )


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-db", name="db"),
        ),
        edges=(
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=2.0),
        ),
    )


# -- G1 ---------------------------------------------------------------------------


def test_denylist_beats_allowlist():
    ctx = _ctx(allow_faults={"proc.kill"}, deny_faults={"proc.kill"})
    with pytest.raises(SafetyRefusedError):
        check_fault_admission("proc.kill", RiskLevel.MEDIUM, ctx)


def test_not_in_allowlist_refused():
    ctx = _ctx(allow_faults=frozenset({"net.latency"}))
    with pytest.raises(SafetyRefusedError):
        check_fault_admission("proc.cpu", RiskLevel.LOW, ctx)


def test_risk_ceiling_exclusion():
    ctx = _ctx(risk_ceiling=RiskLevel.MEDIUM)
    check_fault_admission("proc.pause", RiskLevel.LOW, ctx)  # under ceiling: ok
    with pytest.raises(SafetyRefusedError, match="ceiling"):
        check_fault_admission("node.service_stop", RiskLevel.HIGH, ctx)


def test_critical_requires_double_optin():
    ctx = _ctx(allow_critical=True)  # config half only
    with pytest.raises(SafetyRefusedError, match="--allow-critical"):
        check_fault_admission("x", RiskLevel.CRITICAL, ctx)
    ctx_cli = SafetyContext(
        policy=PolicyCfg(allow_critical=True), budget=BlastRadiusBudget(),
        fingerprint="f", allow_critical_cli=True,
    )
    check_fault_admission("x", RiskLevel.CRITICAL, ctx_cli)  # both halves: ok
    with pytest.raises(SafetyRefusedError):
        check_fault_admission("x", RiskLevel.CRITICAL, _ctx())  # neither


def test_default_policy_blocks_node_reboot():
    ctx = _ctx()
    check_fault_admission("proc.cpu", RiskLevel.LOW, ctx)
    with pytest.raises(SafetyRefusedError, match="denied by default"):
        check_fault_admission("node.reboot", RiskLevel.HIGH, ctx)


def test_explicit_allowlist_overrides_default_deny():
    ctx = _ctx(allow_faults=frozenset({"node.reboot"}))
    check_fault_admission("node.reboot", RiskLevel.LOW, ctx)


# -- G2 ---------------------------------------------------------------------------


def test_blast_radius_counts_dependents():
    graph = _graph()
    permissive = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="f",
    )
    stats = check_blast_radius(graph, {"n-db"}, 10.0, (), "proc.pause", permissive)
    assert stats["services_pct"] == 100.0  # api and web both depend on db

    tight = SafetyContext(
        policy=PolicyCfg(), budget=BlastRadiusBudget(max_services_pct=50.0), fingerprint="f"
    )
    with pytest.raises(SafetyRefusedError, match="blast radius"):
        check_blast_radius(graph, {"n-db"}, 10.0, (), "proc.pause", tight)

    leaf_only = check_blast_radius(graph, {"n-web"}, 10.0, (), "proc.pause", tight)
    assert leaf_only["services_pct"] == pytest.approx(33.3, abs=0.1)


def test_duration_cap_and_forbidden_pairs():
    graph = _graph()
    ctx = SafetyContext(
        policy=PolicyCfg(), budget=BlastRadiusBudget(max_duration_per_fault_s=5.0),
        fingerprint="f",
    )
    with pytest.raises(SafetyRefusedError, match="duration"):
        check_blast_radius(graph, {"n-web"}, 10.0, (), "proc.cpu", ctx)

    pair_ctx = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(forbidden_fault_pairs=frozenset({frozenset({"a", "b"})})),
        fingerprint="f",
    )
    with pytest.raises(SafetyRefusedError, match="forbidden"):
        check_blast_radius(graph, {"n-web"}, 1.0, ("a",), "b", pair_ctx)


# -- fingerprint + G3 --------------------------------------------------------------


def test_fingerprint_is_order_insensitive_and_sensitive_to_env():
    a = environment_fingerprint(host_names=["h2", "h1"], compose_digest="d",
                                environment_name="e", environment_class="staging")
    b = environment_fingerprint(host_names=["h1", "h2"], compose_digest="d",
                                environment_name="e", environment_class="staging")
    c = environment_fingerprint(host_names=["h1", "h2"], compose_digest="d",
                                environment_name="e", environment_class="production")
    assert a == b
    assert a != c


def test_validate_plan_refuses_stale_fingerprint():
    from mayhem.domain.experiments import PlannedFault, PlannedStep, ResolvedTarget

    selector = TargetSelector(kind=NodeKind.PROCESS, expr="api")
    plan = ExecutionPlan(
        run_id="r", kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s1", seq=0,
                raw_action=InjectFault(fault="proc.cpu", selectors=(selector,), duration=5.0),
                fault=PlannedFault(
                    fault_id="proc.cpu",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-api"})),),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c", topology_snapshot_id="t",
        environment_fingerprint="other-fingerprint",
    )
    with pytest.raises(SafetyRefusedError, match="fingerprint"):
        validate_plan(plan, _graph(), _ctx())


def test_g3_drift_refusal_when_target_vanishes():
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="api")
    live = TopologyGraph(nodes=(ServiceNode(id="n-api", name="api"),))
    pre_exec_assertion([(selector, ("n-api",))], live)  # ok
    empty = TopologyGraph(
        nodes=(HostNode(id="h", name="local", transport="local"),), edges=()
    )
    with pytest.raises(SafetyRefusedError, match="drift"):
        pre_exec_assertion([(selector, ("n-api",))], empty)
