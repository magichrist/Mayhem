"""v1.1.0 plan 02 phase 2 — workload-aware Kubernetes admission in the real gate.

The plan's acceptance for this phase is "unsafe workload plans refused with the
reason naming the violated rule and the observed numbers". These tests drive that
through ``controller.safety.validate_plan`` — the gate ``executor.execute`` calls
before it opens a run — not through the admission module alone, so what is
pinned is the refusal an operator would actually see.

What is pinned here:

  1. the PDB headline arithmetic surfaced through the real gate, rule id and all
     six Phase-1 workload-safety rules reached the same way (StatefulSet
     ordinal, DaemonSet coverage, anti-affinity, topology spread);
  2. the injected authorization predicate is *consulted* and a protected
     namespace is refused before any cluster read is spent;
  3. Phase 2's consumption of the facts Phase 1 carried but no rule read
     (``updated_replicas`` in flight, ``ready_replicas`` below desired, the
     liveness-probe warning);
  4. **the no-op**: a plan with no Kubernetes target produces byte-identical
     decisions to a golden, and the fake cluster client is never called;
  5. negative controls — a degraded cluster is refused, a blueprint/deposed pod
     cannot be admitted at all, and a workload that breaks two rules reports
     the most specific one (and agrees with ``admit_workload_fault``).
"""

from __future__ import annotations

from dataclasses import fields
from typing import Any

import pytest

from mayhem.agents.k8s_resolve import K8sWorkload
from mayhem.config import PolicyCfg
from mayhem.controller.k8s_admission import (
    DEFAULT_PROTECTED_NAMESPACES,
    RULE_ADMISSION_ALLOW,
    RULE_NAMESPACE_PROTECTED,
    RULE_NO_LIVE_TARGET,
    RULE_PROBE_ABSENT,
    RULE_ROLLOUT_IN_FLIGHT,
    RULE_UNREADY_REPLICAS,
    K8sAdmissionInput,
    K8sAdmissionRequest,
    K8sAuthorization,
    admit_k8s_plan,
    namespace_protection,
)
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    explain_fault_refusal,
    validate_plan,
)
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.k8s_targets import (
    K8sExclusionKind,
    K8sSelectionCandidate,
    K8sTargetSource,
    TopologySpreadConstraint,
    WorkloadFacts,
    WorkloadKind,
    admit_workload_fault,
)
from mayhem.domain.resolution import ResolvedPodTarget
from mayhem.domain.target import ResourceKind, TargetScope
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    PodNode,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

WORKLOAD = K8sWorkload(namespace="shop", kind="deployment", name="checkout")
STEP_ID = "s1"
FAULT_ID = "k8s.pod_kill"


# ── fakes ───────────────────────────────────────────────────────────────────
class FakeAdmissionClient:
    """Records every read so a test can prove the gate spent none."""

    def __init__(self, facts: WorkloadFacts | None = None) -> None:
        self._facts = facts
        self.asked: list[K8sWorkload] = []

    def workload_facts(self, workload: K8sWorkload) -> WorkloadFacts | None:
        self.asked.append(workload)
        return self._facts

    @property
    def reads(self) -> int:
        return len(self.asked)


class DenyEverything:
    """The smallest possible injected authorizer: refuse, with a reason."""

    def __init__(self, rule_id: str = "k8s.rbac_denied") -> None:
        self.rule_id = rule_id
        self.seen: list[K8sWorkload] = []

    def __call__(self, workload: K8sWorkload) -> K8sAuthorization:
        self.seen.append(workload)
        return K8sAuthorization(
            permitted=False,
            rule_id=self.rule_id,
            reason=f"identity 'chaos-bot' may not touch {workload.namespace}/{workload.name}",
        )


def _facts(**kwargs: Any) -> WorkloadFacts:
    base: dict[str, Any] = {
        "name": "checkout",
        "namespace": "shop",
        "kind": WorkloadKind.DEPLOYMENT,
        "replicas": 10,
        "ready_replicas": 10,
        "updated_replicas": 10,
        "readiness_probe": True,
        "liveness_probe": True,
        "startup_probe": True,
        "cluster_nodes_ready": 5,
        "cluster_nodes_total": 5,
    }
    base.update(kwargs)
    return WorkloadFacts(**base)


def _resolved(
    count: int = 1, *, namespace: str = "shop", uid: str = "u-1"
) -> tuple[ResolvedPodTarget, ...]:
    return tuple(
        ResolvedPodTarget(
            namespace=namespace,
            pod=f"checkout-{index:02d}",
            container="app",
            pod_uid=f"{uid}-{index}",
            container_id=f"containerd://{uid}-{index}",
            node=f"node-{index}",
        )
        for index in range(count)
    )


# ── plan / graph builders ───────────────────────────────────────────────────
def _k8s_scope(
    *,
    namespace: str = "shop",
    kind: ResourceKind = ResourceKind.DEPLOYMENT,
    name: str = "checkout",
) -> TargetScope:
    return TargetScope(
        logical_id=name,
        runtime=RuntimeLabel.KUBERNETES,
        kind=kind,
        authority={"api_group": "apps", "namespace": namespace, "name": name},
        container="app",
    )


def _pod_node(name: str, *, namespace: str = "shop") -> PodNode:
    return PodNode(
        id=f"k8s::{namespace}/pod/{name}",
        name=name,
        kind=NodeKind.POD,
        state="Running",
        namespace=namespace,
        owner_kind="Deployment",
        owner_name="checkout",
        node_name="node-0",
    )


def _k8s_graph(pod_names: tuple[str, ...] = ()) -> TopologyGraph:
    """A plan-time graph, optionally carrying the planned pods as graph nodes.

    Two shapes, because the milestone refuses k8s pod plans as
    ``k8s.unsupported`` when the pod nodes *are* in the graph (see
    ``_check_k8s_targets``). The refusal tests want that graph, to prove the
    admission speaks before the placeholder; the admission tests want the
    pod-free graph, which is what a logically-pinned ``targets:``-authored plan
    looks like, so a plan the admission *allows* is not then refused for
    something unrelated to the admission.
    """
    pods = tuple(_pod_node(name) for name in pod_names)
    return TopologyGraph(
        nodes=(
            ServiceNode(id="k8s::shop/Service/checkout", name="checkout", kind=NodeKind.SERVICE),
            *pods,
        ),
        edges=tuple(
            Edge(
                src="k8s::shop/Service/checkout",
                dst=pod.id,
                kind=EdgeKind.DEPENDS_ON,
                weight=1.0,
            )
            for pod in pods
        ),
    )


def _docker_scope() -> TargetScope:
    return TargetScope(
        logical_id="web",
        runtime=RuntimeLabel.DOCKER,
        kind=ResourceKind.CONTAINER,
        authority={"container_name": "web"},
    )


def _k8s_plan(
    *,
    step_id: str = STEP_ID,
    fault_id: str = FAULT_ID,
    pod_names: tuple[str, ...] = ("checkout-00",),
    scope: TargetScope | None = None,
    fingerprint: str = "fp",
) -> ExecutionPlan:
    """A one-step Kubernetes plan whose targets are real graph pod nodes.

    The pod nodes *are* in the graph, so ``_check_k8s_targets`` would refuse the
    plan as ``k8s.unsupported`` — which is exactly why the admission runs
    before it, and why a refusal asserted below is the admission's and not the
    placeholder's.
    """
    selector = TargetSelector(kind=NodeKind.POD, expr="checkout")
    return ExecutionPlan(
        run_id="run-1",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id=step_id,
                seq=0,
                raw_action=InjectFault(
                    fault=fault_id,
                    selectors=(selector,),
                    target=scope or _k8s_scope(),
                    duration=5.0,
                ),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(
                        ResolvedTarget(
                            selector=selector,
                            node_ids=frozenset(f"k8s::shop/pod/{n}" for n in pod_names),
                        ),
                    ),
                    target=scope or _k8s_scope(),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=fingerprint,
    )


def _ctx(
    *,
    admission: K8sAdmissionInput | None = None,
    fingerprint: str = "fp",
    max_services_pct: float = 100.0,
) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=max_services_pct),
        fingerprint=fingerprint,
        k8s_admission=admission,
    )


def _admission(
    client: FakeAdmissionClient,
    *,
    targets: tuple[ResolvedPodTarget, ...] | None = None,
    step_id: str = STEP_ID,
    workload: K8sWorkload = WORKLOAD,
    excluded: tuple[Any, ...] = (),
    authorize: Any = None,
    **kwargs: Any,
) -> K8sAdmissionInput:
    return K8sAdmissionInput(
        client=client,
        authorize=authorize or namespace_protection(),
        requests={
            step_id: K8sAdmissionRequest(
                workload=workload,
                targets=targets if targets is not None else _resolved(1),
                excluded=excluded,
            )
        },
        **kwargs,
    )


def _refusal(exc: SafetyRefusedError) -> dict[str, str]:
    return explain_fault_refusal(exc)


def _validate(plan: ExecutionPlan, admission: K8sAdmissionInput) -> SafetyContext:
    ctx = _ctx(admission=admission)
    validate_plan(plan, _k8s_graph(), ctx)
    return ctx


def _gate(plan: ExecutionPlan, admission: K8sAdmissionInput) -> SafetyRefusedError:
    """Validate against the pod-bearing graph, so a refusal is the admission's."""
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(plan, _k8s_graph(("checkout-00",)), _ctx(admission=admission))
    return excinfo.value


# ── 1. the headline PDB rule, through the real gate ─────────────────────────
class TestPdbRefusalThroughTheGate:
    def test_refusal_names_the_rule_and_shows_the_arithmetic(self) -> None:
        client = FakeAdmissionClient(_facts(replicas=10, pdb_min_available=8))
        plan = _k8s_plan(pod_names=tuple(f"checkout-{i:02d}" for i in range(4)))
        admission = _admission(client, targets=_resolved(4))

        refusal = _refusal(_gate(plan, admission))

        assert refusal["rule_id"] == "k8s.pdb_violation"
        assert refusal["reason"] == (
            "replicas=10, PDB minAvailable=8, requested kill 4 → DENY, "
            "expected availability after fault = 6, PDB requires >= 8"
        )
        assert "PDBre" not in refusal["reason"]  # the reason carries the numbers, not the code
        assert refusal["remediation"]

    def test_observed_numbers_reach_the_recorded_decision(self) -> None:
        client = FakeAdmissionClient(_facts(replicas=10, pdb_min_available=8))
        plan = _k8s_plan(pod_names=tuple(f"checkout-{i:02d}" for i in range(4)))
        ctx = _ctx(admission=_admission(client, targets=_resolved(4)))
        with pytest.raises(SafetyRefusedError) as excinfo:
            validate_plan(plan, _k8s_graph(("checkout-00",)), ctx)

        decision = excinfo.value.decision
        assert decision is not None
        assert decision.rule_id == "k8s.pdb_violation"
        assert decision.outcome == "deny"
        assert decision.inputs["observed"] == 6
        assert decision.inputs["required"] == 8
        assert decision.inputs["kill_count"] == 4
        assert decision.inputs["check"] == "pdb"
        assert decision.inputs["replicas"] == 10

    def test_the_same_facts_admit_when_the_kill_fits(self) -> None:
        client = FakeAdmissionClient(_facts(replicas=10, pdb_min_available=8))
        ctx = _validate(_k8s_plan(), _admission(client, targets=_resolved(2)))

        allows = [d for d in ctx.decisions if d.rule_id == RULE_ADMISSION_ALLOW]
        assert len(allows) == 1
        assert allows[0].outcome == "allow"
        assert client.reads == 1

    def test_the_gate_agrees_with_admit_workload_fault(self) -> None:
        """The gate's deciding rule is Phase 1's own aggregate, not a second opinion."""
        facts = _facts(replicas=10, pdb_min_available=8)
        plan = _k8s_plan(pod_names=tuple(f"checkout-{i:02d}" for i in range(4)))
        refusal = _refusal(
            _gate(plan, _admission(FakeAdmissionClient(facts), targets=_resolved(4)))
        )
        assert refusal["rule_id"] == admit_workload_fault(facts, kill_count=4).code


# ── 1b. every other Phase-1 rule, reached the same way ──────────────────────
class TestEveryWorkloadSafetyRuleReachesTheGate:
    @pytest.mark.parametrize(
        ("rule_id", "facts_kwargs", "kill_count", "expected_in_reason"),
        [
            (
                "k8s.statefulset_rollout_exceeded",
                {
                    "kind": WorkloadKind.STATEFULSET,
                    "replicas": 5,
                    "ready_replicas": 5,
                    "updated_replicas": 5,
                    "statefulset_rollout_budget": 1,
                },
                3,
                "rollout budget allows at most 1 per disruption",
            ),
            (
                "k8s.daemonset_coverage_lost",
                {
                    "kind": WorkloadKind.DAEMONSET,
                    "replicas": 2,
                    "ready_replicas": 2,
                    "updated_replicas": 2,
                    "daemonset_nodes_ready": 2,
                    "daemonset_nodes_total": 3,
                },
                2,
                "expected DaemonSet coverage after fault = 0 of 3",
            ),
            (
                "k8s.anti_affinity_no_free_domain",
                {
                    "replicas": 4,
                    "ready_replicas": 4,
                    "updated_replicas": 4,
                    "required_anti_affinity": True,
                    "anti_affinity_domains": 4,
                },
                1,
                "expected free domains for replacement = 0",
            ),
            (
                "k8s.topology_spread_blocked",
                {
                    "replicas": 6,
                    "ready_replicas": 6,
                    "updated_replicas": 6,
                    "topology_spread": (
                        TopologySpreadConstraint(
                            topology_key="topology.kubernetes.io/zone",
                            max_skew=1,
                            do_not_schedule=True,
                        ),
                    ),
                    "topology_spread_domains": 3,
                },
                4,
                "scheduler requires maxSkew <= 1",
            ),
        ],
    )
    def test_rule_refuses_through_validate_plan(
        self,
        rule_id: str,
        facts_kwargs: dict[str, Any],
        kill_count: int,
        expected_in_reason: str,
    ) -> None:
        names = tuple(f"checkout-{i:02d}" for i in range(kill_count))
        plan = _k8s_plan(pod_names=names)
        admission = _admission(
            FakeAdmissionClient(_facts(**facts_kwargs)), targets=_resolved(kill_count)
        )

        refusal = _refusal(_gate(plan, admission))

        assert refusal["rule_id"] == rule_id
        assert expected_in_reason in refusal["reason"]
        assert f"requested kill {kill_count}" in refusal["reason"]

    def test_statefulset_single_ordinal_is_admitted(self) -> None:
        facts = _facts(
            kind=WorkloadKind.STATEFULSET,
            replicas=5,
            ready_replicas=5,
            updated_replicas=5,
            statefulset_rollout_budget=1,
        )
        ctx = _validate(_k8s_plan(), _admission(FakeAdmissionClient(facts), targets=_resolved(1)))
        assert any(d.rule_id == RULE_ADMISSION_ALLOW for d in ctx.decisions)


# ── 2. the injected authorization predicate ─────────────────────────────────
class TestAuthorizationWiring:
    def test_protected_namespace_is_refused(self) -> None:
        client = FakeAdmissionClient(_facts())
        scope = _k8s_scope(namespace="kube-system")
        plan = _k8s_plan(scope=scope)
        admission = _admission(client, targets=_resolved(1))
        admission = K8sAdmissionInput(
            client=admission.client,
            authorize=namespace_protection(),
            requests=admission.requests,
        )

        refusal = _refusal(_gate(plan, admission))

        assert refusal["rule_id"] == RULE_NAMESPACE_PROTECTED
        assert "namespace 'kube-system' is protected" in refusal["reason"]
        assert "kube-system" in DEFAULT_PROTECTED_NAMESPACES

    def test_authorization_is_consulted_before_any_cluster_read(self) -> None:
        client = FakeAdmissionClient(_facts(pdb_min_available=10, replicas=2))
        denier = DenyEverything()
        admission = _admission(client, authorize=denier)

        refusal = _refusal(_gate(_k8s_plan(), admission))

        assert refusal["rule_id"] == "k8s.rbac_denied"
        assert refusal["reason"] == ("identity 'chaos-bot' may not touch shop/checkout")
        assert denier.seen == [WORKLOAD]  # the predicate really ran
        assert client.reads == 0  # and no read was spent refusing it

    def test_an_allowlist_refuses_a_namespace_outside_it(self) -> None:
        admission = _admission(
            FakeAdmissionClient(_facts()),
            authorize=namespace_protection(allowed=frozenset({"staging"})),
        )
        refusal = _refusal(_gate(_k8s_plan(), admission))
        assert refusal["rule_id"] == "k8s.authorization_denied"
        assert "outside this run's allowed namespaces" in refusal["reason"]

    def test_protection_outranks_the_allowlist(self) -> None:
        admission = _admission(
            FakeAdmissionClient(_facts()),
            authorize=namespace_protection(allowed=frozenset({"kube-system"})),
            workload=K8sWorkload(namespace="kube-system", kind="deployment", name="checkout"),
        )
        plan = _k8s_plan(scope=_k8s_scope(namespace="kube-system"))
        assert _refusal(_gate(plan, admission))["rule_id"] == RULE_NAMESPACE_PROTECTED


# ── 3. the facts Phase 1 carried and no rule read ──────────────────────────
class TestObservationValidity:
    def test_in_flight_rollout_is_refused(self) -> None:
        facts = _facts(replicas=10, ready_replicas=10, updated_replicas=4)
        refusal = _refusal(_gate(_k8s_plan(), _admission(FakeAdmissionClient(facts))))

        assert refusal["rule_id"] == RULE_ROLLOUT_IN_FLIGHT
        assert "updated_replicas=4" in refusal["reason"]
        assert "a rollout is in flight" in refusal["reason"]

    def test_unready_replicas_are_refused_only_with_a_readiness_probe(self) -> None:
        facts = _facts(replicas=10, ready_replicas=7, updated_replicas=10)
        refusal = _refusal(_gate(_k8s_plan(), _admission(FakeAdmissionClient(facts))))
        assert refusal["rule_id"] == RULE_UNREADY_REPLICAS
        assert "ready_replicas=7 (readiness probe present)" in refusal["reason"]

        # Without a readiness probe the same numbers are not a health signal.
        blind = _facts(replicas=10, ready_replicas=7, updated_replicas=10, readiness_probe=False)
        ctx = _validate(_k8s_plan(), _admission(FakeAdmissionClient(blind)))
        assert any(d.rule_id == RULE_ADMISSION_ALLOW for d in ctx.decisions)

    def test_both_degradations_are_acknowledgeable(self) -> None:
        facts = _facts(replicas=10, ready_replicas=7, updated_replicas=4)
        admission = _admission(FakeAdmissionClient(facts), acknowledge_degraded_workload=True)
        ctx = _validate(_k8s_plan(), admission)
        assert any(d.rule_id == RULE_ADMISSION_ALLOW for d in ctx.decisions)

    def test_an_unobserved_rollout_field_is_not_a_rollout(self) -> None:
        """``0`` means the client did not populate the field, not a total outage."""
        facts = _facts(replicas=10, ready_replicas=0, updated_replicas=0)
        ctx = _validate(_k8s_plan(), _admission(FakeAdmissionClient(facts)))
        assert any(d.rule_id == RULE_ADMISSION_ALLOW for d in ctx.decisions)

    def test_missing_liveness_probe_is_a_warning_not_a_refusal(self) -> None:
        facts = _facts(liveness_probe=False, startup_probe=False)
        ctx = _validate(_k8s_plan(), _admission(FakeAdmissionClient(facts)))

        warnings = [d for d in ctx.decisions if d.rule_id == RULE_PROBE_ABSENT]
        assert len(warnings) == 1
        assert warnings[0].outcome == "warn"
        assert warnings[0].severity.value == "warning"
        assert any(d.rule_id == RULE_ADMISSION_ALLOW for d in ctx.decisions)

    def test_a_probing_workload_raises_no_probe_warning(self) -> None:
        ctx = _validate(_k8s_plan(), _admission(FakeAdmissionClient(_facts())))
        assert not [d for d in ctx.decisions if d.rule_id == RULE_PROBE_ABSENT]


# ── 4. the no-op: no Kubernetes target, nothing changes ────────────────────
def _docker_plan() -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="api")
    return ExecutionPlan(
        run_id="run-docker",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s1",
                seq=0,
                raw_action=InjectFault(
                    fault="proc.pause",
                    selectors=(selector,),
                    target=_docker_scope(),
                    duration=5.0,
                ),
                fault=PlannedFault(
                    fault_id="proc.pause",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-api"})),),
                    target=_docker_scope(),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="fp",
    )


def _docker_graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
        ),
        edges=(Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


#: The exact decision stream ``validate_plan`` produces for the plan above. Any
#: decision the Kubernetes half could possibly add, move, or drop changes this.
GOLDEN_NO_KUBERNETES_TARGET = (
    ("policy.allow", "allow", "proc.pause: admitted"),
    (
        "blast_radius.allow",
        "allow",
        "proc.pause: blast radius within budget",
    ),
)


class TestNoKubernetesTargetIsANoOp:
    def _decisions(self, ctx: SafetyContext) -> tuple[tuple[str, str, str], ...]:
        return tuple((d.rule_id, d.outcome, d.reason) for d in ctx.decisions)

    def test_decisions_are_byte_identical_to_the_golden(self) -> None:
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(admission=_admission(client))
        validate_plan(_docker_plan(), _docker_graph(), ctx)
        assert self._decisions(ctx) == GOLDEN_NO_KUBERNETES_TARGET

    def test_the_same_plan_without_the_gate_produces_the_same_golden(self) -> None:
        """The golden is the *existing* behaviour, not a snapshot of the new one."""
        ctx = _ctx()
        validate_plan(_docker_plan(), _docker_graph(), ctx)
        assert self._decisions(ctx) == GOLDEN_NO_KUBERNETES_TARGET

    def test_no_cluster_read_is_spent(self) -> None:
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(admission=_admission(client))
        validate_plan(_docker_plan(), _docker_graph(), ctx)
        assert client.reads == 0
        assert client.asked == []

    def test_no_warnings_are_added(self) -> None:
        client = FakeAdmissionClient(_facts(liveness_probe=False))
        ctx = _ctx(admission=_admission(client))
        validate_plan(_docker_plan(), _docker_graph(), ctx)
        assert ctx.warnings == []

    def test_admit_k8s_plan_returns_nothing_for_a_docker_plan(self) -> None:
        outcomes = admit_k8s_plan(_docker_plan(), _admission(FakeAdmissionClient(_facts())))
        assert outcomes == ()

    def test_an_empty_plan_is_also_a_no_op(self) -> None:
        plan = ExecutionPlan(
            run_id="run-empty",
            kind=ExperimentKind.DETERMINISTIC,
            steps=(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="fp",
        )
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(admission=_admission(client))
        validate_plan(plan, _docker_graph(), ctx)
        assert client.reads == 0
        assert ctx.decisions == []

    def test_the_field_is_optional_and_defaults_to_absent(self) -> None:
        ctx = _ctx()
        assert ctx.k8s_admission is None
        # ``policy_gate`` must stay the last field (tests/unit/test_policy_gate.py).
        assert [f.name for f in fields(SafetyContext)][-1] == "policy_gate"

    def test_a_kubernetes_plan_still_hits_its_own_golden(self) -> None:
        """Guard on the guard: the no-op is not "the gate never fires"."""
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(admission=_admission(client))
        validate_plan(_k8s_plan(), _k8s_graph(), ctx)
        assert client.reads == 1
        assert [d.rule_id for d in ctx.decisions][:1] == [RULE_ADMISSION_ALLOW]


# ── 5. negative controls ────────────────────────────────────────────────────
class TestNegativeControls:
    def test_a_degraded_cluster_is_refused(self) -> None:
        facts = _facts(cluster_nodes_ready=3, cluster_nodes_total=5)
        refusal = _refusal(_gate(_k8s_plan(), _admission(FakeAdmissionClient(facts))))

        assert refusal["rule_id"] == "k8s.cluster_degraded"
        assert "cluster nodes ready=3/5" in refusal["reason"]
        assert "cluster is already degraded" in refusal["reason"]

    def test_degraded_cluster_is_acknowledgeable(self) -> None:
        facts = _facts(cluster_nodes_ready=3, cluster_nodes_total=5)
        admission = _admission(FakeAdmissionClient(facts), acknowledge_cluster_degradation=True)
        ctx = _validate(_k8s_plan(), admission)
        assert any(d.rule_id == RULE_ADMISSION_ALLOW for d in ctx.decisions)

    def test_a_blueprint_placeholder_cannot_be_admitted(self) -> None:
        """An offline manifest graph resolves nothing, so it admits nothing."""
        blueprint = K8sSelectionCandidate(
            name="checkout-blueprint",
            namespace="shop",
            source=K8sTargetSource.BLUEPRINT,
            state="blueprint",
            workload_name="checkout",
        )
        assert not blueprint.live_eligible
        request = K8sAdmissionRequest(
            workload=WORKLOAD,
            targets=(),
            excluded=(_blueprint_exclusion(blueprint),),
        )
        admission = K8sAdmissionInput(
            client=FakeAdmissionClient(_facts()),
            authorize=namespace_protection(),
            requests={STEP_ID: request},
        )

        refusal = _refusal(_gate(_k8s_plan(), admission))

        assert refusal["rule_id"] == RULE_NO_LIVE_TARGET
        assert "1 blueprint" in refusal["reason"]
        assert "manifest blueprint placeholder" in refusal["reason"]

    def test_a_deposed_pod_cannot_be_admitted(self) -> None:
        """A record with no pod uid is not evidence of a live pod."""
        admission = _admission(
            FakeAdmissionClient(_facts()),
            targets=(ResolvedPodTarget(namespace="shop", pod="checkout-00", container="app"),),
        )
        refusal = _refusal(_gate(_k8s_plan(), admission))

        assert refusal["rule_id"] == RULE_NO_LIVE_TARGET
        assert "carry no pod uid" in refusal["reason"]
        assert "deposed pod" in refusal["reason"]

    def test_an_unresolved_step_is_drift_not_a_target(self) -> None:
        """No request for the step at all: the resolver produced nothing."""
        admission = K8sAdmissionInput(
            client=FakeAdmissionClient(_facts()),
            authorize=namespace_protection(),
            requests={},
        )
        refusal = _refusal(_gate(_k8s_plan(), admission))
        assert refusal["rule_id"] == RULE_NO_LIVE_TARGET
        assert "resolved to no live pod" in refusal["reason"]
        assert "an unresolved pin are both drift, never a target" in refusal["reason"]

    def test_a_request_for_another_workload_is_refused(self) -> None:
        admission = _admission(
            FakeAdmissionClient(_facts()),
            workload=K8sWorkload(namespace="shop", kind="deployment", name="billing"),
        )
        refusal = _refusal(_gate(_k8s_plan(), admission))
        assert refusal["rule_id"] == "k8s.admission_request_mismatch"
        assert "shop/billing" in refusal["reason"]

    def test_a_pod_outside_the_planned_namespace_is_refused(self) -> None:
        admission = _admission(
            FakeAdmissionClient(_facts()), targets=_resolved(1, namespace="other")
        )
        refusal = _refusal(_gate(_k8s_plan(), admission))
        assert refusal["rule_id"] == "k8s.target_namespace_mismatch"
        assert "not in the planned namespace shop" in refusal["reason"]

    def test_a_missing_workload_is_refused(self) -> None:
        refusal = _refusal(_gate(_k8s_plan(), _admission(FakeAdmissionClient(None))))
        assert refusal["rule_id"] == "k8s.workload_missing"
        assert "does not report this deployment workload" in refusal["reason"]

    def test_two_broken_rules_report_the_most_specific_one(self) -> None:
        """PDB and anti-affinity are both violated; the arithmetic one is named."""
        facts = _facts(
            replicas=10,
            ready_replicas=10,
            updated_replicas=10,
            pdb_min_available=8,
            required_anti_affinity=True,
            anti_affinity_domains=10,
        )
        admission = _admission(FakeAdmissionClient(facts), targets=_resolved(4, uid="x"))
        refusal = _refusal(_gate(_k8s_plan(pod_names=("checkout-00",)), admission))

        assert refusal["rule_id"] == "k8s.pdb_violation"
        assert refusal["reason"].startswith("replicas=10, PDB minAvailable=8")
        assert admit_workload_fault(facts, kill_count=4).code == "k8s.pdb_violation"

    def test_the_outcome_keeps_both_refusals_as_evidence(self) -> None:
        facts = _facts(
            replicas=10,
            ready_replicas=10,
            updated_replicas=10,
            pdb_min_available=8,
            required_anti_affinity=True,
            anti_affinity_domains=10,
        )
        outcomes = admit_k8s_plan(
            _k8s_plan(), _admission(FakeAdmissionClient(facts), targets=_resolved(4, uid="x"))
        )
        assert len(outcomes) == 1
        outcome = outcomes[0]
        assert outcome.denied
        assert outcome.rule_id == "k8s.pdb_violation"
        assert [v.check.value for v in outcome.verdicts] == [
            "pdb",
            "statefulset_ordinal",
            "daemonset_coverage",
            "anti_affinity",
            "topology_spread",
            "cluster_health",
        ]
        denied = [v.check.value for v in outcome.verdicts if not v.admitted]
        assert denied == ["pdb", "anti_affinity"]
        assert outcome.refusal is not None
        assert outcome.refusal.check.value == "pdb"
        assert "k8s.pdb_violation: DENY" in outcome.describe()

    def test_the_gate_refuses_before_the_unsupported_placeholder(self) -> None:
        """The admission speaks first: a named rule beats a generic refusal."""
        refusal = _refusal(
            _gate(
                _k8s_plan(),
                _admission(FakeAdmissionClient(_facts(replicas=10, pdb_min_available=10))),
            )
        )
        assert refusal["rule_id"] == "k8s.pdb_violation"
        assert "kubernetes execution not yet supported" not in refusal["reason"]

    def test_without_the_admission_the_placeholder_still_fires(self) -> None:
        """The existing refusal order is untouched for every existing caller."""
        with pytest.raises(SafetyRefusedError) as excinfo:
            validate_plan(_k8s_plan(), _k8s_graph(("checkout-00",)), _ctx())
        assert excinfo.value.reason_code == "k8s.unsupported"
        assert "kubernetes execution not yet supported" in str(excinfo.value)

    def test_identity_refusals_still_outrank_the_admission(self) -> None:
        """A stale fingerprint is about the run, so it is answered first."""
        client = FakeAdmissionClient(_facts(pdb_min_available=10))
        plan = _k8s_plan(fingerprint="stale")
        with pytest.raises(SafetyRefusedError) as excinfo:
            validate_plan(plan, _k8s_graph(("checkout-00",)), _ctx(admission=_admission(client)))
        assert excinfo.value.reason_code == "environment.mismatch"
        assert client.reads == 0


def _blueprint_exclusion(candidate: K8sSelectionCandidate) -> Any:
    from mayhem.domain.k8s_targets import K8sSelectionExclusion

    return K8sSelectionExclusion(
        candidate=candidate,
        kind=K8sExclusionKind.BLUEPRINT,
        reason=(
            "shop/checkout-blueprint is a manifest blueprint placeholder "
            "(state=blueprint); offline graphs never select live pods"
        ),
    )
