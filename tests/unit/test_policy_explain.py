from mayhem.config import PolicyCfg
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    check_blast_radius,
    check_fault_admission,
    dry_run_policy_evaluation,
)
from mayhem.domain.decisions import SafetySeverity
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import (
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)


def _ctx(**kwargs):
    return SafetyContext(
        policy=PolicyCfg(**kwargs),
        budget=BlastRadiusBudget(),
        fingerprint="f",
        policy_id="default",
    )


def _graph():
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            ServiceNode(id="n-c", name="c"),
        ),
        edges=(),
    )


def test_risk_ceiling_has_rule_id_and_remediation():
    ctx = _ctx(risk_ceiling=RiskLevel.LOW)
    try:
        check_fault_admission("net.partition", RiskLevel.HIGH, ctx)
        raise AssertionError
    except SafetyRefusedError as exc:
        assert exc.decision is not None
        assert exc.decision.rule_id == "policy.risk_ceiling"
        assert "ceiling" in exc.decision.reason
        assert exc.decision.remediation != ""


def test_blast_radius_explain():
    graph = _graph()
    tight = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=10.0),
        fingerprint="f",
    )
    try:
        check_blast_radius(graph, {"n-a", "n-b", "n-c"}, 1.0, (), "net.partition", ctx=tight)
        raise AssertionError
    except SafetyRefusedError as exc:
        assert "blast_radius.max_services_pct" in str(exc)
        assert exc.decision is not None
        assert exc.decision.rule_id == "blast_radius.max_services_pct"


def test_critical_optin_explain():
    ctx = _ctx()
    try:
        check_fault_admission("x", RiskLevel.CRITICAL, ctx)
        raise AssertionError
    except SafetyRefusedError as exc:
        assert exc.decision is not None
        assert "critical" in exc.decision.rule_id
        remediation = exc.decision.remediation.lower()
        assert "allow_critical" in remediation or "critical" in remediation


def test_capability_explain():
    from mayhem.controller.safety import validate_plan
    from mayhem.domain.runtime_adapter import (
        AdapterCapabilities,
        CapabilityVerdict,
        RuntimeAdapter,
        VerdictResult,
    )

    class _BadAdapter(RuntimeAdapter):
        @property
        def id(self):
            return "bad"

        def is_available(self):
            return True

        def capabilities(self):
            return AdapterCapabilities(
                engine="bad",
                supported=frozenset(),
                alternatives=frozenset(),
                version=None,
            )

        def evaluate(self, reqs):
            return VerdictResult(
                engine="bad",
                requirements=reqs,
                verdicts={"x": CapabilityVerdict.UNSUPPORTED.value},
                blocking=True,
            )

        def ps(self):
            return []

        def inspect(self, container_id):
            from mayhem.domain.identity import RuntimeIdentity

            return (RuntimeIdentity(runtime="bad", host_id="h", runtime_id=container_id), None)

        def exec(self, container_id, cmd, timeout_s=30):
            return ""

        def pid(self, container_id):
            return None

        def signal(self, container_id, signo):
            return None

        def netns(self, container_id):
            return None

        def filter_by_compose(self, project, services=None):
            return None

        def filter_by_names(self, names):
            return None

        def discover(self):
            from mayhem.topology.providers.base import PartialGraph

            return PartialGraph(source="bad")

    ctx = _ctx()
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    plan = ExecutionPlan(
        run_id="r",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="s1",
                seq=0,
                raw_action=InjectFault(fault="net.partition", selectors=(selector,), duration=5.0),
                fault=PlannedFault(
                    fault_id="net.partition",
                    targets=(
                        ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),
                    ),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
        policy_id="default",
    )
    try:
        validate_plan(plan, _graph(), ctx, adapter=_BadAdapter())
        raise AssertionError
    except SafetyRefusedError as exc:
        assert exc.decision is not None
        assert "capability.unsupported" in exc.decision.rule_id


def test_topology_drift_has_remediation():
    from mayhem.controller.safety import pre_exec_assertion

    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    empty = TopologyGraph(nodes=())
    try:
        pre_exec_assertion([(selector, ("n-a",))], empty)
        raise AssertionError
    except SafetyRefusedError as exc:
        assert "drift" in str(exc).lower()
        assert "target.drift" in str(exc)


def test_dry_run_returns_decisions():
    ctx = _ctx(risk_ceiling=RiskLevel.LOW)
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    plan = ExecutionPlan(
        run_id="r",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="s1",
                seq=0,
                raw_action=InjectFault(fault="net.latency", selectors=(selector,), duration=5.0),
                fault=PlannedFault(
                    fault_id="net.latency",
                    targets=(
                        ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),
                    ),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
        policy_id="default",
    )
    decs = dry_run_policy_evaluation(plan, _graph(), ctx)
    assert any(d.outcome == "deny" for d in decs) or any(d.rule_id == "dry_run.allow" for d in decs)


def test_refusal_never_downgrades_to_warning():
    ctx = _ctx(risk_ceiling=RiskLevel.LOW)
    try:
        check_fault_admission("net.partition", RiskLevel.HIGH, ctx)
        raise AssertionError
    except SafetyRefusedError as exc:
        assert exc.decision is not None
        assert exc.decision.severity != SafetySeverity.warning
        assert exc.decision.outcome == "deny"


def test_policy_id_required_in_plan():
    plan = ExecutionPlan(
        run_id="r",
        kind=ExperimentKind.DRILL,
        steps=(),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
        policy_id="strict",
    )
    assert plan.policy_id == "strict"
