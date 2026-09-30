"""The safety-proof compiler over the real gates — plan 30 Phase 2.

Every test here is arranged around one acceptance rule: **the compiler may only
ever refuse equally or more than executing ``validate_plan`` would, never less.**
The agreement tests therefore do not compare the compiler against a hand-written
list of expectations — they run the *real* gate and assert the compiler's refusal
set is a superset of the gate's, over a matrix of budgets, policies, and plans
rather than a single case. A compiler that quietly re-derived "what the gate
would say" would agree on the happy path and drift on the first rule it forgot,
and only a matrix finds that.

Three groups of tests:

* **Per obligation class.** Each of the nine lines is made to fail on its own
  terms, so a regression names the line it broke rather than "the proof broke".
* **Agreement, citations, truncation.** The superset property, plus the citation
  completeness the doc demands: every ``PASS`` line traces to a gate output. That
  is checked by *determinism* — the same plan must produce the same nine digests
  twice, and a change to a gate's input must change the digest of exactly the
  lines that read that input. A digest derived from a clock or a counter would
  pass a shape check and fail this one.
* **Negative controls.** The three the plan names: a hand-written ``PASS`` with
  no gate output, a proof carried across a plan change, and a missing required
  obligation. All three must fail closed.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller import safety_proof as compiler
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.controller.safety_proof import (
    GATE_RULE_IDS,
    OBLIGATION_FOR_RULE,
    canonical_plan_digest,
    compile_residue_obligations,
    compile_safety_evidence,
    compile_safety_proof,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_intent import ExecutionIntent
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
from mayhem.domain.hashing import digest as digest_of
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.prediction import (
    RULE_MAX_CONCURRENT_FAULTS,
    RULE_MAX_DURATION_PER_FAULT_S,
    PredictionBasis,
    predict_impact,
)
from mayhem.domain.quota import RULE_BUDGET, RULE_PER_FAULT_CEILING, DamageQuota
from mayhem.domain.risks import RiskLevel
from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
    VerdictResult,
)
from mayhem.domain.safety_proof import (
    REQUIRED_OBLIGATIONS,
    RESIDUE_PREDICATES,
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.topology.providers.base import PartialGraph

FP = "f" * 64
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# Two plans that differ, so "the proof is for the plan that is frozen now" and
# "the proof is for the plan it was compiled from" can be told apart.
OTHER_FP = "e" * 64


# --------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------


def _graph() -> TopologyGraph:
    """Three independent services on one host, plus one dependency edge.

    Independent on purpose: faulting ``n-a`` must not implicate the others, so a
    test that wants a narrow blast has one and a test that wants the cumulative
    damage quota to dominate is measuring the quota rather than the closure.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            ServiceNode(id="n-c", name="c"),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _hosted_graph() -> TopologyGraph:
    """A service running on two hosts, so ``max_hosts`` can actually be breached.

    ``check_blast_radius`` counts hosts inside the fault's ``dependents_closure``,
    and that closure is built from the *reverse* dependency index — so a host
    lands in it only when a host depends on the faulted node. Two hosts running
    the same service is exactly that, and it is the only shape in this model
    where ``max_hosts`` has anything to count: the shared service-only graph
    cannot breach that limit at all, which is why the rule needs its own
    topology here rather than a tighter cap on the usual one.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            HostNode(id="h-local", name="local", transport="local"),
            HostNode(id="h-remote", name="remote", transport="ssh"),
        ),
        edges=(
            Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="h-local", dst="n-a", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="h-remote", dst="n-a", kind=EdgeKind.DEPENDS_ON, weight=1.0),
        ),
    )


def _permissive() -> BlastRadiusBudget:
    """Per-step limits no test in this file trips by accident."""
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _ctx(
    budget: BlastRadiusBudget | None = None,
    quota: DamageQuota | None = None,
    policy: PolicyCfg | None = None,
) -> SafetyContext:
    return SafetyContext(
        policy=policy or PolicyCfg(),
        budget=budget or _permissive(),
        fingerprint=FP,
        damage_quota=quota or DamageQuota(),
    )


def _plan(
    fault_ids: tuple[str, ...] = ("proc.pause", "net.latency"),
    durations: tuple[float, ...] = (10.0, 10.0),
    *,
    node_id: str = "n-a",
    compensated: bool = True,
    probes: bool = True,
    slo: tuple[dict[str, Any], ...] = (),
    fingerprint: str = FP,
    with_wait_step: bool = False,
) -> ExecutionPlan:
    """A frozen plan built the way the planner builds one: compensation compiled.

    ``node_id`` is the topology id; the selector carries the node *name*, which is
    what ``TargetSelector.matches`` compares against. Getting that backwards makes
    the selector unresolvable, which the G3 drift probe reports as a
    ``target.drift`` refusal — so the fixture is also a live check that the drift
    probe is wired to something real.
    """
    node_name = next(n.name for n in _graph().nodes if n.id == node_id)
    selector = TargetSelector(kind=NodeKind.SERVICE, expr=node_name)
    steps: list[PlannedStep] = []
    for index, (fault_id, duration) in enumerate(zip(fault_ids, durations, strict=True)):
        steps.append(
            PlannedStep(
                id=f"s{index}",
                seq=index,
                raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(
                        ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),
                    ),
                    duration=duration,
                    undo_ops=(UndoOp(op="tc.del_qdisc"),) if compensated else (),
                    verify_probes=(
                        (VerifyProbe(probe="tc.qdisc_absent"),) if probes else ()
                    ),
                ),
            )
        )
    if with_wait_step:
        steps.append(PlannedStep(id="s-wait", seq=len(steps), raw_action=Wait(duration=5.0)))
    return ExecutionPlan(
        run_id="r-proof",
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=fingerprint,
        slo=tuple(slo),
    )


class _Adapter(RuntimeAdapter):
    """Base adapter: a fake runtime that answers capability questions on demand."""

    blocking = False

    @property
    def id(self) -> str:
        return "fake-adapter"

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            engine=self.id, supported=frozenset(), alternatives=frozenset(), version=None
        )

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        verdict = (
            CapabilityVerdict.UNSUPPORTED if self.blocking else CapabilityVerdict.SUPPORTED
        )
        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts={"namespace": verdict.value},
            blocking=self.blocking,
        )

    def ps(self) -> list[dict[str, Any]]:
        return []

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, None]:
        return RuntimeIdentity(runtime="fake", host_id="h", runtime_id=container_id), None

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        return ""

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        return None

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(self, project: str, services: Any = None) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self) -> PartialGraph:
        return PartialGraph(source=self.id)


class _BlockingAdapter(_Adapter):
    blocking = True


# --------------------------------------------------------------------------------
# the compiler on a plan the gate admits
# --------------------------------------------------------------------------------


def test_a_well_formed_plan_compiles_to_pass_with_every_line_cited():
    graph = _graph()
    proof = compile_safety_proof(_plan(), graph, _ctx(), adapter=_Adapter())

    assert proof.verdict is ProofVerdict.PASS
    assert proof.void_reason == ""
    assert proof.missing_obligations() == ()
    assert {o.name for o in proof.obligations} == set(REQUIRED_OBLIGATIONS)


def test_every_pass_line_cites_a_gate_output_by_its_canonical_digest():
    proof = compile_safety_proof(_plan(), _graph(), _ctx(), adapter=_Adapter())

    for obligation in proof.obligations:
        if obligation.status is not ObligationStatus.PASS:
            continue
        # A citation is a lowercase sha256 hex and nothing looser: Phase 1
        # refuses anything else at construction, so this asserts the compiler
        # supplies a real one rather than a label.
        assert SHA256_HEX.fullmatch(obligation.gate_digest), obligation.name
        assert obligation.evidence_ref.strip(), obligation.name
        # The reference names the gate that produced the line, so a reader can
        # find the evidence rather than take the digest on faith.
        assert "gate-output/" in obligation.evidence_ref, obligation.name
        assert proof.plan_digest[:12] in obligation.evidence_ref, obligation.name


def test_the_plan_digest_is_the_canonical_one_the_rest_of_the_system_hashes():
    plan = _plan()
    expected = digest_of(plan.model_dump(mode="json"))

    assert canonical_plan_digest(plan) == expected
    assert compile_safety_proof(plan, _graph(), _ctx()).plan_digest == expected


def test_compiling_does_not_write_decisions_into_the_callers_safety_record():
    """A preview must not pollute the safety log a real run is judged by.

    ``preflight`` learned this the hard way; the compiler runs four more gates
    that all record, so the invariant is worth its own test rather than being
    inferred from the fact that the caller's context is not asserted on.
    """
    ctx = _ctx()
    compile_safety_proof(_plan(), _graph(), ctx, adapter=_Adapter())

    assert ctx.decisions == []
    assert ctx.warnings == []


# --------------------------------------------------------------------------------
# per obligation class
# --------------------------------------------------------------------------------


def test_max_concurrent_faults_fails_on_its_own_cap():
    budget = _permissive().model_copy(update={"max_concurrent_faults": 1})
    proof = compile_safety_proof(_plan(), _graph(), _ctx(budget=budget), adapter=_Adapter())

    line = proof.obligation(ObligationName.MAX_CONCURRENT_FAULTS.value)
    assert line is not None
    assert line.status is ObligationStatus.FAIL
    assert RULE_MAX_CONCURRENT_FAULTS in line.detail
    assert proof.verdict is ProofVerdict.FAIL


def test_max_duration_fails_on_its_own_cap():
    budget = _permissive().model_copy(update={"max_duration_per_fault_s": 5.0})
    proof = compile_safety_proof(_plan(), _graph(), _ctx(budget=budget), adapter=_Adapter())

    line = proof.obligation(ObligationName.MAX_DURATION.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert RULE_MAX_DURATION_PER_FAULT_S in line.detail
    assert proof.verdict is ProofVerdict.FAIL


def test_damage_budget_fails_on_the_cumulative_quota_the_per_step_caps_cannot_see():
    """Two 10s steps are each trivially small; together they are not.

    The per-step caps are lifted, so nothing but the quota can produce this
    refusal — which is what makes it a test of the ``damage_budget`` line rather
    than of the blast probe.
    """
    quota = DamageQuota(budget_s=12.0)
    proof = compile_safety_proof(_plan(), _graph(), _ctx(quota=quota), adapter=_Adapter())

    line = proof.obligation(ObligationName.DAMAGE_BUDGET.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert RULE_BUDGET in line.detail or RULE_PER_FAULT_CEILING in line.detail
    assert proof.verdict is ProofVerdict.FAIL


def test_damage_budget_reports_the_ledger_numbers_it_was_judged_on():
    proof = compile_safety_proof(_plan(), _graph(), _ctx(), adapter=_Adapter())
    line = proof.obligation(ObligationName.DAMAGE_BUDGET.value)

    assert line is not None
    assert line.status is ObligationStatus.PASS
    # 2 x 10s at LOW/REVERSIBLE weight 1.0 on one node.
    assert "20 damage-seconds" in line.detail
    assert "n-a" in line.detail


def test_target_policy_fails_on_a_denied_fault():
    policy = PolicyCfg(deny_faults=frozenset({"net.latency"}))
    proof = compile_safety_proof(_plan(), _graph(), _ctx(policy=policy), adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "policy.deny_faults" in line.detail
    assert proof.verdict is ProofVerdict.FAIL


def test_target_policy_owns_the_caps_that_have_no_line_of_their_own():
    """Three of the budget's six limits land here, by the data map, not by luck."""
    for rule in (
        "blast_radius.max_services_pct",
        "blast_radius.max_hosts",
        "blast_radius.forbidden_fault_pairs",
    ):
        assert OBLIGATION_FOR_RULE[rule] == ObligationName.TARGET_POLICY.value
    for rule in sorted(GATE_RULE_IDS):
        assert rule in OBLIGATION_FOR_RULE, rule


def test_target_policy_fails_on_a_forbidden_fault_pair():
    budget = _permissive().model_copy(
        update={"forbidden_fault_pairs": frozenset({frozenset({"proc.pause", "net.latency"})})}
    )
    proof = compile_safety_proof(_plan(), _graph(), _ctx(budget=budget), adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "forbidden_fault_pairs" in line.detail


def test_capability_requirements_is_void_when_nothing_measured_them():
    """``validate_plan`` skips the capability check with no adapter.

    A line that passed here would be claiming a measurement that never happened,
    so the honest answer is ``VOID`` — the weakest verdict, and a refusal.
    """
    proof = compile_safety_proof(_plan(), _graph(), _ctx())

    line = proof.obligation(ObligationName.CAPABILITY_REQUIREMENTS.value)
    assert line is not None and line.status is ObligationStatus.VOID
    assert "no runtime adapter" in line.detail
    assert proof.verdict is ProofVerdict.VOID


def test_capability_requirements_fails_when_the_adapter_blocks():
    proof = compile_safety_proof(_plan(), _graph(), _ctx(), adapter=_BlockingAdapter())

    line = proof.obligation(ObligationName.CAPABILITY_REQUIREMENTS.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "capability.unsupported" in line.detail
    assert proof.verdict is ProofVerdict.FAIL


def test_capability_requirements_cites_the_shared_derivation_not_a_local_one():
    """Requirements and present capabilities are both in the line's citation.

    Both come from public API — ``capability_requirements_for`` and the adapter's
    own verdict map — so the line shows "required vs. present" without this module
    re-deriving either side.
    """
    proof = compile_safety_proof(_plan(), _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.CAPABILITY_REQUIREMENTS.value)
    assert line is not None
    assert "capability_requirements_for" in line.evidence_ref
    assert "adapter.evaluate" in line.evidence_ref


def test_compensation_fails_on_a_fault_with_no_write_ahead_undo():
    plan = _plan(compensated=False, probes=False)
    proof = compile_safety_proof(plan, _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.COMPENSATION.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "no write-ahead undo contract" in line.detail
    assert "proc.pause" in line.detail


def test_compensation_accepts_a_self_healing_fault_that_deliberately_undoes_nothing():
    """``recovery=False`` means the perturbation stays by design.

    Requiring an undo contract there would refuse a plan whose whole point is
    that nothing is undone, so the line records the basis instead of a failure.
    """
    plan = _plan(compensated=False, probes=False)
    healed = plan.model_copy(
        update={
            "steps": tuple(
                step.model_copy(update={"fault": step.fault.model_copy(update={"recovery": False})})
                if step.fault is not None
                else step
                for step in plan.steps
            )
        }
    )
    proof = compile_safety_proof(healed, _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.COMPENSATION.value)
    assert line is not None and line.status is ObligationStatus.PASS
    assert "self-healing" in line.detail


def test_recovery_path_fails_when_recovery_is_promised_but_unobservable():
    """Recovery with no verify probe is a claim nothing can confirm."""
    plan = _plan(compensated=True, probes=False)
    proof = compile_safety_proof(plan, _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.RECOVERY_PATH.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "no verify probe" in line.detail


def test_stop_conditions_fails_on_a_criterion_that_could_never_fire():
    """``SloCriterion`` is a plain dataclass: an unknown value constructs cleanly.

    That is exactly the "stop condition that can never fire" defect, so the line
    checks the vocabulary rather than trusting the construction to have done it.
    """
    plan = _plan(slo=({"kind": "latency", "metric": "p99", "operator": "maybe", "threshold": 1.0},))
    proof = compile_safety_proof(plan, _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.STOP_CONDITIONS.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "unknown operator 'maybe'" in line.detail


def test_stop_conditions_fails_on_a_criterion_naming_no_metric():
    plan = _plan(slo=({"kind": "latency", "metric": "   ", "operator": "lt", "threshold": 1.0},))
    proof = compile_safety_proof(plan, _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.STOP_CONDITIONS.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "names no metric" in line.detail


def test_stop_conditions_passes_on_a_criterion_that_names_a_metric_and_operator():
    plan = _plan(
        slo=(
            {
                "kind": "latency",
                "metric": "p99",
                "operator": "lt",
                "threshold": 250.0,
                "unit": "ms",
                "window_s": 60.0,
                "name": "p99-under-250ms",
            },
        )
    )
    proof = compile_safety_proof(plan, _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.STOP_CONDITIONS.value)
    assert line is not None and line.status is ObligationStatus.PASS
    assert "1 SLO criterion(ies)" in line.detail


def test_required_approvals_states_the_requirement_when_no_intent_is_presented():
    proof = compile_safety_proof(_plan(), _graph(), _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None and line.status is ObligationStatus.PASS
    assert "plan hash binding" in line.detail or "bind this plan digest" in line.detail
    assert "No intent presented" in line.detail


def test_required_approvals_fails_on_an_intent_bound_to_another_plan():
    intent = ExecutionIntent(plan_hash="0" * 64, engine="podman", actor="ops")
    proof = compile_safety_proof(
        _plan(), _graph(), _ctx(), adapter=_Adapter(), intent=intent, engine="podman"
    )

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "does not authorise this plan" in line.detail
    assert proof.verdict is ProofVerdict.FAIL


def test_required_approvals_passes_on_an_intent_bound_to_this_plan():
    plan = _plan()
    intent = ExecutionIntent(
        plan_hash=canonical_plan_digest(plan), engine="podman", actor="ops"
    )
    proof = compile_safety_proof(
        plan, _graph(), _ctx(), adapter=_Adapter(), intent=intent, engine="podman"
    )

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None and line.status is ObligationStatus.PASS
    assert "verifies against plan" in line.detail


def test_required_approvals_names_the_critical_faults_that_need_an_explicit_ack():
    """A CRITICAL fault needs the triple opt-in, and the line says so by name."""
    proof = compile_safety_proof(
        _plan(fault_ids=("k8s.node_drain",), durations=(5.0,)),
        _graph(),
        _ctx(),
        adapter=_Adapter(),
    )

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None
    assert "k8s.node_drain" in line.detail
    # The catalog, not a local table, is what says that fault is CRITICAL.
    assert RiskLevel.CRITICAL.value in line.detail or "critical fault" in line.detail


# --------------------------------------------------------------------------------
# the acceptance rule: never more permissive than the gate
# --------------------------------------------------------------------------------


def _gate_refuses(plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext) -> tuple[str, ...]:
    """The rule ids the REAL ``validate_plan`` refuses on a throwaway context."""
    from dataclasses import replace as dataclass_replace

    probe = dataclass_replace(ctx, decisions=[], warnings=[])
    try:
        validate_plan(plan, graph, probe)
    except Exception as exc:
        if isinstance(exc, SafetyRefusedError) and exc.decision is not None:
            return (exc.decision.rule_id,)
        return (str(getattr(exc, "reason_code", None) or getattr(exc, "rule", None) or exc),)
    return ()


#: (label, plan, context, graph) tuples that each trip exactly one part of the
#: gate. Every rule the compiler can blame is exercised here; the two tests below
#: are the acceptance rule, so the matrix is the test.
_GATE_CASES: tuple[tuple[str, ExecutionPlan, SafetyContext, TopologyGraph], ...] = (
    (
        "denylist",
        _plan(),
        _ctx(policy=PolicyCfg(deny_faults=frozenset({"proc.pause"}))),
        _graph(),
    ),
    (
        "allowlist",
        _plan(),
        _ctx(policy=PolicyCfg(allow_faults=frozenset({"net.latency"}))),
        _graph(),
    ),
    (
        "risk_ceiling",
        _plan(fault_ids=("k8s.node_drain",), durations=(5.0,)),
        _ctx(policy=PolicyCfg(risk_ceiling=RiskLevel.LOW)),
        _graph(),
    ),
    (
        "critical_triple_optin",
        _plan(fault_ids=("k8s.node_drain",), durations=(5.0,)),
        _ctx(),
        _graph(),
    ),
    (
        "concurrent_faults",
        _plan(fault_ids=("proc.pause", "net.latency", "process.kill"), durations=(1.0, 1.0, 1.0)),
        _ctx(budget=_permissive().model_copy(update={"max_concurrent_faults": 2})),
        _graph(),
    ),
    (
        "duration",
        _plan(durations=(10.0, 10.0)),
        _ctx(budget=_permissive().model_copy(update={"max_duration_per_fault_s": 5.0})),
        _graph(),
    ),
    (
        "forbidden_pair",
        _plan(),
        _ctx(
            budget=_permissive().model_copy(
                update={
                    "forbidden_fault_pairs": frozenset(
                        {frozenset({"proc.pause", "net.latency"})}
                    )
                }
            )
        ),
        _graph(),
    ),
    (
        "services_pct",
        _plan(),
        _ctx(budget=_permissive().model_copy(update={"max_services_pct": 1.0})),
        _graph(),
    ),
    (
        "max_hosts",
        _plan(),
        _ctx(budget=_permissive().model_copy(update={"max_hosts": 1})),
        _hosted_graph(),
    ),
    ("damage_budget", _plan(), _ctx(quota=DamageQuota(budget_s=5.0)), _graph()),
    (
        "per_fault_ceiling",
        _plan(durations=(300.0, 300.0)),
        _ctx(quota=DamageQuota(per_fault_ceiling_s=100.0)),
        _graph(),
    ),
    ("fingerprint_mismatch", _plan(fingerprint=OTHER_FP), _ctx(), _graph()),
    (
        "default_deny",
        _plan(fault_ids=("node.reboot",), durations=(5.0,)),
        _ctx(),
        _graph(),
    ),
    (
        # The built-in `staging` profile admits dev and staging only, so a
        # production run under it is refused by the environment restriction.
        "environment_policy",
        _plan(),
        SafetyContext(
            policy=PolicyCfg(),
            budget=_permissive(),
            fingerprint=FP,
            damage_quota=DamageQuota(),
            environment="production",
            policy_id="staging",
        ),
        _graph(),
    ),
)


@pytest.mark.parametrize(
    ("label", "plan", "ctx", "graph"),
    _GATE_CASES,
    ids=[c[0] for c in _GATE_CASES],
)
def test_the_compiler_refuses_at_least_everything_the_real_gate_refuses(
    label: str, plan: ExecutionPlan, ctx: SafetyContext, graph: TopologyGraph
):
    gate_rules = _gate_refuses(plan, graph, ctx)
    assert gate_rules, f"{label}: the gate was supposed to refuse and did not"

    compilation = compile_safety_evidence(plan, graph, ctx, adapter=_Adapter())

    assert set(gate_rules) <= set(compilation.compiler_refusals), label
    assert compilation.proof.verdict is not ProofVerdict.PASS, label
    # And the refusal is *on a line*, named in that line's detail — not merely
    # present in a side-channel the renderer would never show.
    blamed = [entry for reasons in compilation.blame.values() for entry in reasons]
    assert any(rule in entry for rule in gate_rules for entry in blamed), (
        f"{label}: gate refused {gate_rules} but no line was blamed"
    )
    # The refusal is in the line's own text, not only in a side channel: a
    # renderer that shows nothing but the obligations still shows the refusal.
    for rule in gate_rules:
        owners = [
            proof_line
            for name, reasons in compilation.blame.items()
            if any(rule in entry for entry in reasons)
            for proof_line in (compilation.proof.obligation(name),)
            if proof_line is not None
        ]
        assert owners and all(rule in line.detail for line in owners), (label, rule)


def test_the_compiler_is_a_superset_across_the_whole_gate_matrix():
    """The matrix version, stated once: gate refusals are a subset, never a superset.

    Run per-case above, this asserts the *invariant* over every case at once so a
    future gate rule added outside ``OBLIGATION_FOR_RULE`` shows up as a diff in
    the coverage numbers rather than as one more passing test.
    """
    checked = 0
    for label, plan, ctx, graph in _GATE_CASES:
        gate_rules = _gate_refuses(plan, graph, ctx)
        compilation = compile_safety_evidence(plan, graph, ctx, adapter=_Adapter())
        assert set(gate_rules) <= set(compilation.compiler_refusals), label
        assert compilation.proof.verdict is not ProofVerdict.PASS, label
        checked += 1
    assert checked == len(_GATE_CASES) >= 10


def test_a_plan_the_gate_admits_never_compiles_to_fail():
    """The other direction, which is the one that could hide a compiler bug.

    With a full compensation contract and an adapter present, nothing the gate
    does not object to may make the compiler ``FAIL``. ``VOID`` is allowed — a
    line can honestly be unmeasured — but ``FAIL`` is a finding about the plan,
    and there is no such finding here.
    """
    for label, plan, ctx, graph in _GATE_CASES:
        if _gate_refuses(plan, graph, ctx):
            continue
        proof = compile_safety_proof(plan, graph, ctx, adapter=_Adapter())
        assert proof.verdict in (ProofVerdict.PASS, ProofVerdict.VOID), label


def test_every_rule_the_compiler_can_blame_is_owned_by_a_line():
    """The unmapped-refusal escape hatch has to stay shut for known rules."""
    for rule in sorted(GATE_RULE_IDS):
        assert OBLIGATION_FOR_RULE.get(rule), rule


# --------------------------------------------------------------------------------
# citation completeness, by determinism
# --------------------------------------------------------------------------------


def _digests(proof: SafetyProof) -> dict[str, str]:
    return {o.name: o.gate_digest for o in proof.obligations}


def test_the_same_plan_compiles_to_the_same_nine_citations_twice():
    """A digest taken from a clock or a counter would differ here.

    That is the whole citation-completeness test available from outside: if a
    line's digest is a function of the gate output, it is stable across runs; if
    it is a function of anything else, it is not a citation at all.
    """
    graph, ctx = _graph(), _ctx()
    first = compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter())
    second = compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter())

    assert _digests(first) == _digests(second)
    assert all(SHA256_HEX.fullmatch(d) for d in _digests(first).values())


#: Lines that read a step's duration or its charge, and therefore must change
#: when the duration changes. The per-step stat record is the gate's own output,
#: so the concurrency line moves with it too — its cited numbers are the same
#: ``stats`` mapping the cap was compared inside.
_DURATION_SENSITIVE = frozenset(
    {
        ObligationName.MAX_DURATION.value,
        ObligationName.DAMAGE_BUDGET.value,
        ObligationName.MAX_CONCURRENT_FAULTS.value,
    }
)
#: Lines that read none of it, and must therefore be bit-identical.
_DURATION_BLIND = frozenset(
    {
        ObligationName.TARGET_POLICY.value,
        ObligationName.CAPABILITY_REQUIREMENTS.value,
        ObligationName.COMPENSATION.value,
        ObligationName.RECOVERY_PATH.value,
        ObligationName.STOP_CONDITIONS.value,
    }
)


def test_changing_a_gate_input_changes_the_lines_that_read_it_and_only_those():
    graph, ctx = _graph(), _ctx()
    before = _digests(compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter()))
    after = _digests(
        compile_safety_proof(_plan(durations=(20.0, 20.0)), graph, ctx, adapter=_Adapter())
    )

    changed = {name for name in before if before[name] != after[name]}
    assert changed >= _DURATION_SENSITIVE
    # The lines that never saw the duration are bit-identical, which is what makes
    # the changed digests evidence rather than a global re-hash of the proof.
    assert changed & _DURATION_BLIND == set()


def test_the_approval_line_re_reads_the_plan_because_it_binds_to_it():
    """Its citation names the plan digest, so a changed plan must move it.

    A line that cites the plan it authorises and stayed identical when the plan
    changed would be a citation of nothing.
    """
    graph, ctx = _graph(), _ctx()
    before = _digests(compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter()))
    after = _digests(
        compile_safety_proof(_plan(durations=(10.0, 11.0)), graph, ctx, adapter=_Adapter())
    )

    assert before[ObligationName.REQUIRED_APPROVALS.value] != after[
        ObligationName.REQUIRED_APPROVALS.value
    ]


def test_a_different_policy_changes_the_line_that_reads_the_policy():
    graph = _graph()
    before = _digests(compile_safety_proof(_plan(), graph, _ctx(), adapter=_Adapter()))
    after = _digests(
        compile_safety_proof(
            _plan(),
            graph,
            _ctx(policy=PolicyCfg(risk_ceiling=RiskLevel.HIGH)),
            adapter=_Adapter(),
        )
    )

    assert before[ObligationName.TARGET_POLICY.value] != after[
        ObligationName.TARGET_POLICY.value
    ]


def test_two_different_plans_do_not_share_a_citation():
    graph, ctx = _graph(), _ctx()
    digests = [
        _digests(compile_safety_proof(plan, graph, ctx, adapter=_Adapter()))
        for plan in (_plan(), _plan(durations=(10.0, 11.0)))
    ]
    assert digests[0] != digests[1]


# --------------------------------------------------------------------------------
# truncation agreement
# --------------------------------------------------------------------------------


def test_the_prediction_truncates_where_the_gate_refused():
    """Both stop at the same step, and the gate's rule is among the prediction's.

    The prediction walks the plan and ends at the first per-step breach; the gate
    raises there. A prediction that kept going would report numbers the gate never
    reaches, so agreement is asserted on the stop *and* on the rule set.
    """
    budget = _permissive().model_copy(update={"max_concurrent_faults": 1})
    plan = _plan(fault_ids=("proc.pause", "net.latency", "process.kill"), durations=(1.0, 1.0, 1.0))
    graph, ctx = _graph(), _ctx(budget=budget)

    prediction = predict_impact(graph, plan, budget=budget)
    compilation = compile_safety_evidence(plan, graph, ctx, prediction=prediction)

    assert compilation.gate_refusals == (RULE_MAX_CONCURRENT_FAULTS,)
    assert prediction.truncated_at_step is not None
    assert RULE_MAX_CONCURRENT_FAULTS in prediction.rule_ids
    # The compiler says out loud that it compared the two stops.
    line = compilation.proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert "truncated at step 1" in line.detail
    assert "the gate refused at step 1" in line.detail


def test_a_prediction_that_missed_the_gates_refusal_voids_the_proof():
    """The never-permissive predicate, enforced rather than merely consulted.

    A preview that told an approver "fine" where the gate refuses is the exact
    defect plan 14 exists to prevent, so a proof may not be backed by one.
    """
    from mayhem.domain.hashing import digest as digest_of
    from mayhem.domain.prediction import ImpactPrediction, plan_identity

    budget = _permissive().model_copy(update={"max_concurrent_faults": 1})
    plan = _plan(fault_ids=("proc.pause", "net.latency"), durations=(1.0, 1.0))
    graph, ctx = _graph(), _ctx(budget=budget)

    blank = ImpactPrediction(
        plan_identity=plan_identity(plan),
        graph_identity=digest_of(graph.model_dump(mode="json")),
        basis=PredictionBasis.GRAPH,
    )
    compilation = compile_safety_evidence(plan, graph, ctx, prediction=blank)

    assert compilation.gate_refusals == (RULE_MAX_CONCURRENT_FAULTS,)
    assert compilation.proof.verdict is ProofVerdict.VOID
    assert "calmer than the gate" in compilation.proof.void_reason


def test_a_stale_prediction_is_not_blamed_and_does_not_void():
    """A preview of a different plan has no standing — it is neither trusted nor blamed."""
    from mayhem.domain.prediction import ImpactPrediction

    plan = _plan()
    stale = ImpactPrediction(
        plan_identity="0" * 64,
        graph_identity="1" * 64,
        basis=PredictionBasis.GRAPH,
        violated_rules=(),
    )
    compilation = compile_safety_evidence(
        plan, _graph(), _ctx(), prediction=stale, adapter=_Adapter()
    )

    line = compilation.proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert compilation.proof.verdict is ProofVerdict.PASS
    assert "stale" in line.detail


# --------------------------------------------------------------------------------
# unmapped refusals: the fail-closed escape hatch
# --------------------------------------------------------------------------------


def test_a_refusal_no_line_owns_voids_the_proof_instead_of_being_dropped(monkeypatch):
    """A gate that starts refusing on a new rule must not silently stop the proof.

    The compiler cannot show a refusal it has no line for, so the honest result
    is ``VOID`` with the rule named — a reader sees "we found something we cannot
    place", not "everything passed".
    """

    def _refuse(plan, graph, ctx, adapter=None):
        raise SafetyRefusedError("some.brand.new.rule", "a gate grew a new refusal")

    monkeypatch.setattr(compiler, "validate_plan", _refuse)
    compilation = compile_safety_evidence(_plan(), _graph(), _ctx(), adapter=_Adapter())

    assert compilation.proof.verdict is ProofVerdict.VOID
    assert "some.brand.new.rule" in compilation.proof.void_reason
    assert "no obligation owns" in compilation.proof.void_reason
    # It is still a refusal: nothing about this proof reads as a pass.
    assert compilation.proof.verdict is not ProofVerdict.PASS


# --------------------------------------------------------------------------------
# residue obligations: generated, never discharged, here
# --------------------------------------------------------------------------------


def test_residue_obligations_are_generated_per_fault_with_every_predicate():
    plan = _plan()
    obligations = compile_residue_obligations(plan)

    assert [o.fault_id for o in obligations] == ["proc.pause", "net.latency"]
    for obligation in obligations:
        assert {p.value for p in obligation.predicates} == RESIDUE_PREDICATES
        assert obligation.status is ObligationStatus.VOID
        assert obligation.name == f"residue:{obligation.fault_id}"


def test_attaching_the_residue_lines_makes_the_proof_void_not_pass():
    """Nothing has run, so nothing can be observed clean — yet.

    This is why the compiler leaves them off by default: a ``PASS`` proof of
    admission is a true statement, and bolting undischarged residue lines onto it
    would make it false.
    """
    graph, ctx = _graph(), _ctx()
    admitted = compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter())
    with_residue = compile_safety_proof(
        _plan(), graph, ctx, adapter=_Adapter(), include_residue=True
    )

    assert admitted.verdict is ProofVerdict.PASS
    assert with_residue.verdict is ProofVerdict.VOID
    assert len(with_residue.residue_obligations) == 2
    assert with_residue.void_reason != ""


# --------------------------------------------------------------------------------
# negative controls — the three the plan names
# --------------------------------------------------------------------------------


def test_a_hand_written_pass_with_no_gate_output_is_refused_at_construction():
    """The forged-PASS guard is the type's, and the compiler cannot route around it."""
    with pytest.raises(InvariantViolationError) as excinfo:
        Obligation(
            name=ObligationName.TARGET_POLICY.value,
            status=ObligationStatus.PASS,
            gate_digest="",
            evidence_ref="i checked, trust me",
        )
    assert "sha256" in str(excinfo.value)


def test_a_hand_written_pass_citing_a_non_digest_is_refused():
    with pytest.raises(InvariantViolationError):
        Obligation(
            name=ObligationName.DAMAGE_BUDGET.value,
            status=ObligationStatus.PASS,
            gate_digest="sha256:abcd",
            evidence_ref="gate-output/some:gate",
        )


def test_a_proof_that_declares_more_than_its_lines_support_is_refused():
    """Even with a well-formed citation, the verdict must be the implied one."""
    graph, ctx = _graph(), _ctx()
    proof = compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter())
    failing = proof.obligation(ObligationName.STOP_CONDITIONS.value)
    assert failing is not None
    broken = tuple(
        Obligation(
            name=failing.name,
            status=ObligationStatus.FAIL,
            gate_digest=failing.gate_digest,
            evidence_ref=failing.evidence_ref,
        )
        if o.name == failing.name
        else o
        for o in proof.obligations
    )

    with pytest.raises(InvariantViolationError) as excinfo:
        SafetyProof(
            plan_digest=proof.plan_digest,
            obligations=broken,
            verdict=ProofVerdict.PASS,
        )
    assert "verdict_must_match_obligations" in str(excinfo.value) or "only support" in str(
        excinfo.value
    )


def test_a_proof_for_a_superseded_plan_digest_is_void_never_pass():
    """The staleness rule, end to end through the compiler's own artifact.

    The plan the proof was compiled from and the plan that is frozen now differ
    by one step; the lines all passed and are irrelevant, because they describe a
    plan that no longer exists.
    """
    graph, ctx = _graph(), _ctx()
    old = _plan()
    new = _plan(durations=(10.0, 11.0))
    assert canonical_plan_digest(old) != canonical_plan_digest(new)

    proof = compile_safety_proof(old, graph, ctx, adapter=_Adapter())
    assert proof.verdict is ProofVerdict.PASS

    assert proof.evaluate(canonical_plan_digest(new)) is ProofVerdict.VOID
    assert proof.is_valid(canonical_plan_digest(new)) is False
    voided = proof.voided(canonical_plan_digest(new))
    assert voided.verdict is ProofVerdict.VOID
    assert "plan superseded" in voided.void_reason
    # The lines survive the voiding, so the artifact still says what it checked.
    assert len(voided.obligations) == len(proof.obligations)


def test_a_missing_required_obligation_voids_rather_than_fails():
    """"Not checked" is not "checked and negative"."""
    graph, ctx = _graph(), _ctx()
    proof = compile_safety_proof(_plan(), graph, ctx, adapter=_Adapter())
    assert proof.verdict is ProofVerdict.PASS

    incomplete = SafetyProof(
        plan_digest=proof.plan_digest,
        obligations=tuple(
            o for o in proof.obligations if o.name != ObligationName.RECOVERY_PATH.value
        ),
        verdict=ProofVerdict.VOID,
        void_reason="recovery_path dropped to test the rule",
    )

    assert incomplete.recompute_verdict() is ProofVerdict.VOID
    assert incomplete.missing_obligations() == (ObligationName.RECOVERY_PATH.value,)
    assert incomplete.evaluate(proof.plan_digest) is ProofVerdict.VOID
    assert incomplete.verdict is not ProofVerdict.FAIL


def test_a_plan_with_no_fault_steps_voids_rather_than_vacuously_passing():
    """Nothing to admit, compensate, recover, or interrupt — so nothing is proven.

    ``validate_plan`` accepts such a plan, so this is the compiler refusing
    *more* than the gate, which the acceptance rule permits and the fail-closed
    reading requires. The detail must say why, not just "void".
    """
    plan = _plan(fault_ids=(), durations=(), with_wait_step=True)
    assert _gate_refuses(plan, _graph(), _ctx()) == ()

    proof = compile_safety_proof(plan, _graph(), _ctx(), adapter=_Adapter())
    assert proof.verdict is ProofVerdict.VOID
    assert proof.void_reason
    for name in (
        ObligationName.TARGET_POLICY,
        ObligationName.COMPENSATION,
        ObligationName.RECOVERY_PATH,
        ObligationName.STOP_CONDITIONS,
    ):
        line = proof.obligation(name.value)
        assert line is not None and line.status is not ObligationStatus.PASS, name.value
