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

import ast
import re
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller import safety_proof as compiler
from mayhem.controller.approval_gate import (
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
    RULE_APPROVAL_PROOF_NOT_PASS,
    RULE_APPROVAL_REQUIRED,
    ApprovalGateInputs,
    ApprovalLedger,
)
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.controller.safety_proof import (
    CEILING_RULE_IDS,
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
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
    RuntimeIdentity,
)
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.prediction import (
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_CONCURRENT_FAULTS,
    RULE_MAX_CUSTOMER_FACING_SERVICES,
    RULE_MAX_DEPENDENCY_DEPTH,
    RULE_MAX_DURATION_PER_FAULT_S,
    RULE_PROTECTED_NODE,
    BlastCeilings,
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
    PortBinding,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.topology.providers.base import PartialGraph

if TYPE_CHECKING:
    from mayhem.domain.approval import Approval

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
    approval_gate: ApprovalGateInputs | None = None,
) -> SafetyContext:
    return SafetyContext(
        policy=policy or PolicyCfg(),
        budget=budget or _permissive(),
        fingerprint=FP,
        damage_quota=quota or DamageQuota(),
        approval_gate=approval_gate,
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
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),),
                    duration=duration,
                    undo_ops=(UndoOp(op="tc.del_qdisc"),) if compensated else (),
                    verify_probes=((VerifyProbe(probe="tc.qdisc_absent"),) if probes else ()),
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
        verdict = CapabilityVerdict.UNSUPPORTED if self.blocking else CapabilityVerdict.SUPPORTED
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
    intent = ExecutionIntent(plan_hash=canonical_plan_digest(plan), engine="podman", actor="ops")
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
                    "forbidden_fault_pairs": frozenset({frozenset({"proc.pause", "net.latency"})})
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
# rule-mapping completeness, by reading the gates' own source
# --------------------------------------------------------------------------------
#
# The test above checks the rules the compiler *knows about*. This one checks the
# rules the gates actually *raise*, by parsing the two modules that raise them —
# `controller/safety.py` (authoritative) and `controller/approval_gate.py` (plan
# 09). A gate that grows a new refusal and nobody maps it is then a *test
# failure naming the rule*, not a silent VOID at run time.
#
# Phase 4 exists because this exact check was missing: the approval gate's three
# refusal ids were unmapped for two phases, so an approval-refused run compiled
# to a VOID proof naming a rule nobody owned. The check below would have caught
# it the day the gate landed.

#: The modules whose rule ids the compiler has to be able to place. Both are read
#: as *source*, not as data: there is no registry to forget to update.
BLAMEABLE_SOURCES: tuple[str, ...] = (
    "src/mayhem/controller/safety.py",
    "src/mayhem/controller/approval_gate.py",
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _literal(node: ast.expr) -> str | None:
    """The string a node spells, or ``None`` when it is not a plain literal."""
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _module_string_constants(source: str) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` assignments, as a name->value map."""
    constants: dict[str, str] = {}
    for node in ast.parse(source).body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
            continue
        value = _literal(node.value)
        if value is None:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = value
    return constants


def blameable_rule_ids(source: str) -> frozenset[str]:
    """Every rule id ``source`` can refuse a plan on.

    Three syntactic sites, each of which is a refusal in the code's own words:

    * ``_deny_decision("rule", ...)`` — the deny-decision factory both modules
      build their refusals through, so its first argument *is* the rule id the
      decision records;
    * ``SafetyRefusedError("rule", ...)`` raised **without** a decision — then
      the reason code is the rule id, because there is no decision to read one
      from (with a decision attached, the compiler reads ``decision.rule_id``,
      which site one already covers);
    * ``ApprovalRefusal(rule_id=RULE_X, ...)`` where ``RULE_X`` is a module-level
      string constant — how the plan-09 gate names its three refusals.

    Anything not a plain literal is deliberately *not* resolved (a name defined
    elsewhere, a computed string): those are the dynamic cases the compiler
    handles by kind rather than by enumeration, and inventing a value for them
    would make this test assert something the gate never raises.
    """
    constants = _module_string_constants(source)
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else None
        if node.func.__class__.__name__ == "Attribute":
            name = node.func.attr
        if name == "_deny_decision" and node.args:
            literal = _literal(node.args[0])
            if literal is not None:
                found.add(literal)
        elif name == "SafetyRefusedError" and node.args:
            attaches_decision = len(node.args) >= 3 or any(
                kw.arg == "decision" for kw in node.keywords
            )
            literal = _literal(node.args[0])
            if literal is not None and not attaches_decision:
                found.add(literal)
        elif name == "ApprovalRefusal":
            for keyword in node.keywords:
                if keyword.arg != "rule_id" or not isinstance(keyword.value, ast.Name):
                    continue
                resolved = constants.get(keyword.value.id)
                if resolved is not None:
                    found.add(resolved)
    return frozenset(found)


def _blameable_rule_ids() -> frozenset[str]:
    """The union across both gate modules."""
    found: set[str] = set()
    for relative in BLAMEABLE_SOURCES:
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        found |= blameable_rule_ids(source)
    return frozenset(found)


def test_the_rule_extractor_actually_finds_the_gates_own_rules():
    """The guard is only worth what its extractor finds.

    Without this, a broken extractor would make every completeness test below
    pass vacuously — which is the exact failure mode a coverage test is supposed
    to prevent. It asserts against spelled-out rules from each module rather than
    a count, so it fails if the extractor goes quiet on either file.
    """
    safety = blameable_rule_ids((REPO_ROOT / BLAMEABLE_SOURCES[0]).read_text(encoding="utf-8"))
    approval = blameable_rule_ids((REPO_ROOT / BLAMEABLE_SOURCES[1]).read_text(encoding="utf-8"))

    # Spelled out, not derived from the same table the tests below check.
    assert "policy.deny_faults" in safety
    assert "blast_radius.max_hosts" in safety
    assert "k8s.unsupported" in safety
    assert RULE_APPROVAL_EXECUTOR_UNAUTHORIZED in approval
    assert RULE_APPROVAL_PROOF_NOT_PASS in approval
    assert RULE_APPROVAL_REQUIRED in approval


def test_every_rule_the_gates_can_raise_has_an_owning_proof_line():
    """The completeness guard: each gate's refusals land on a named line.

    This is the assertion the missing approval-gate mapping violated. Read from
    the gates' own source, so a refusal added tomorrow without a mapping fails
    here by name — before any run compiles to an unplaceable VOID.
    """
    unmapped = sorted(rule for rule in _blameable_rule_ids() if not OBLIGATION_FOR_RULE.get(rule))

    assert not unmapped, (
        "these rule ids are raised by a gate but no proof line owns them, so a refusal on "
        f"any of them compiles to a VOID proof naming a rule this compiler cannot place: "
        f"{unmapped}. Add each to OBLIGATION_FOR_RULE (and to "
        "controller.check_gate.RULE_CHECK, which must cover the same set)"
    )


def test_the_completeness_check_fails_on_a_newly_added_unmapped_rule():
    """The negative control: the guard is a real gate, not a tautology.

    Parses a synthetic gate that raises one known rule and one the table does
    not know, and asserts the extractor surfaces the unmapped one. Without this,
    "every rule has an owning line" could pass because the extractor found
    nothing at all — and the next lane would repeat the gap this phase closed.
    """
    synthetic = """
def _new_gate_check(ctx):
    _deny_decision(
        "policy.deny_faults",
        {"fault_id": fault_id},
        "already mapped",
        "",
    )
    raise SafetyRefusedError("brand.new.unmapped.rule", "a gate grew a new refusal")
"""

    found = blameable_rule_ids(synthetic)

    assert "brand.new.unmapped.rule" in found
    unmapped = sorted(rule for rule in found if not OBLIGATION_FOR_RULE.get(rule))
    assert unmapped == ["brand.new.unmapped.rule"], (
        "the extractor must classify the new rule as unowned, or the completeness test "
        f"above cannot fail: got {unmapped}"
    )


def test_the_approval_gate_refusals_are_owned_by_the_approvals_line():
    """The gap this phase closed, asserted directly.

    All three plan-09 refusals are statements about whether *this run* was
    authorised, so they belong to ``required_approvals``. Unmapped, an
    approval-refused run compiled to a VOID proof naming an unplaceable rule —
    fail-closed, but strictly worse than the FAIL the line can now report.
    """
    for rule in (
        RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
        RULE_APPROVAL_PROOF_NOT_PASS,
        RULE_APPROVAL_REQUIRED,
    ):
        assert OBLIGATION_FOR_RULE[rule] == ObligationName.REQUIRED_APPROVALS.value, rule


def test_an_approval_refused_run_fails_the_approvals_line_rather_than_voiding():
    """The honest answer is a FAIL on the line, not a whole-proof VOID.

    Phase 3's author recorded this as "fail-closed and by that module's own
    design", which was true but left the gate's finding unreportable. With the
    mapping in place the refusal is attributable, so the proof is FAIL — a
    finding about this plan — and the rule is named in the line's own detail.
    """
    plan = _plan()
    proof = compile_safety_proof(
        plan,
        _graph(),
        _ctx(approval_gate=_refusing_gate(plan)),
        adapter=_Adapter(),
    )

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None
    assert line.status is ObligationStatus.FAIL
    assert RULE_APPROVAL_REQUIRED in line.detail
    assert proof.verdict is ProofVerdict.FAIL
    assert proof.void_reason == ""


def test_a_configured_approval_gate_that_allows_reports_its_decision_on_the_line():
    """The positive half: the line reads the approval *state*, not just the rule.

    Phase 4's requirement is that ``required_approvals`` actually reads the
    approval state. A refusal proves it is wired; this proves the reading is not
    merely a refusal path — an allowed gate contributes its verdict and its
    approvers to the line's cited output, so the artifact says who authorised
    the run and not merely that nobody objected.
    """
    plan = _plan()
    gate = _refusing_gate(plan)
    approval, approve_grant = _mint_approval(gate.proof, gate)
    allowed = dataclass_replace(gate, approvals=(approval,), grants=(*gate.grants, approve_grant))

    proof = compile_safety_proof(
        plan,
        _graph(),
        _ctx(approval_gate=allowed),
        adapter=_Adapter(),
    )

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None
    assert line.status is ObligationStatus.PASS
    assert "the approval gate authorized plan" in line.detail
    assert "u-approve" in line.detail


# --- the five plan-14 blast-radius ceilings -------------------------------------
#
# ``tests/unit/test_prediction_evidence.py`` records that plan 14's ceilings were
# enforced but unowned, and that the completeness guard was failing by name. The
# rows landed; these tests are the half of the proof that says the mapping is not
# merely present in a table.
#
# Every case runs the real gate twice and compares: once directly through
# ``validate_plan``, to establish that the rule is actually raised rather than
# inferred from the mapping table, and once through the compiler, to establish
# that the compiler reports it as a ``FAIL`` on the line that owns it. A test that
# only read ``OBLIGATION_FOR_RULE`` would pass on a table describing a gate that
# stopped refusing in the last commit, which is the same class of defect this
# whole wave exists to catch.


def _ceiling_graph() -> TopologyGraph:
    """A three-deep dependency chain ending in the front door.

    Every ceiling needs a *different* number to be the tightest one, and a graph
    that only has one measurable quantity can only exercise one of them. So the
    chain is built to have all four measurements at once: faulting ``n-core``
    reaches three nodes over two dependency hops, exactly one of which exposes a
    port — 3 of 4 nodes (75%), depth 2, one customer-facing service. Those are
    read from the graph, not asserted here, because a fixture that states its own
    numbers stops being a fixture the moment the topology changes.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-core", name="core"),
            ServiceNode(id="n-mid", name="mid"),
            ServiceNode(
                id="n-front",
                name="front",
                exposed_ports=(PortBinding(host_port=443, container_port=8443),),
            ),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(
            Edge(src="n-mid", dst="n-core", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-front", dst="n-mid", kind=EdgeKind.DEPENDS_ON, weight=1.0),
        ),
    )


def _ceiling_plan() -> ExecutionPlan:
    """One fault step on ``n-core``, compensated exactly as :func:`_plan` does."""
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="core")
    return ExecutionPlan(
        run_id="r-ceiling",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(fault="net.latency", selectors=(selector,), duration=10.0),
                fault=PlannedFault(
                    fault_id="net.latency",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-core"})),),
                    duration=10.0,
                    undo_ops=(UndoOp(op="tc.del_qdisc"),),
                    verify_probes=(VerifyProbe(probe="tc.qdisc_absent"),),
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


#: ``(label, BlastCeilings, expected rule id)``, one per plan-14 ceiling.
#:
#: Each ceiling is set strictly *inside* the graph's own measurement, so exactly
#: one fires and the gate stops there. A ceiling set at the observed value would
#: breach nothing and prove nothing, which is the same reason
#: ``test_prediction_evidence.py`` builds its cases from measured numbers.
CEILING_PROOF_CASES: tuple[tuple[str, BlastCeilings, str], ...] = (
    (
        "affected nodes",
        BlastCeilings(max_affected_nodes=2),
        RULE_MAX_AFFECTED_NODES,
    ),
    ("affected percentage", BlastCeilings(max_affected_pct=50.0), RULE_MAX_AFFECTED_PCT),
    (
        "dependency depth",
        BlastCeilings(max_dependency_depth=1),
        RULE_MAX_DEPENDENCY_DEPTH,
    ),
    (
        "customer-facing services",
        BlastCeilings(max_customer_facing_services=0),
        RULE_MAX_CUSTOMER_FACING_SERVICES,
    ),
    (
        "protected node list",
        BlastCeilings(protected_node_ids=frozenset({"n-core"})),
        RULE_PROTECTED_NODE,
    ),
)


@pytest.mark.parametrize(
    ("label", "ceilings", "rule_id"),
    CEILING_PROOF_CASES,
    ids=[case[0] for case in CEILING_PROOF_CASES],
)
def test_a_ceiling_refusal_fails_the_target_policy_line_and_never_voids(
    label: str, ceilings: BlastCeilings, rule_id: str
) -> None:
    """The debt's payoff, per ceiling: ``FAIL`` on a named line, not a bare ``VOID``.

    Before the mapping, each of these five ran compiled to a proof that reported
    "no obligation owns this rule" — fail-closed, and useless to whoever had to
    act on it. Now the refusal is attributed: ``target_policy`` is the ``FAIL``,
    its detail carries the gate's own reason with the rule id on it, and
    ``void_reason`` stays empty because the compiler can place everything it was
    told.

    The first assertion is the one that keeps this honest. ``validate_plan`` is
    run directly and must raise ``SafetyRefusedError`` naming ``rule_id``: if the
    gate ever stopped refusing, the mapping could still sit in
    ``OBLIGATION_FOR_RULE`` and this test would keep passing on a table describing
    a refusal nobody can produce.
    """
    graph, plan = _ceiling_graph(), _ceiling_plan()
    ctx = dataclass_replace(_ctx(), blast_ceilings=ceilings)

    with pytest.raises(SafetyRefusedError) as raised:
        validate_plan(plan, graph, ctx)
    assert raised.value.decision.rule_id == rule_id, label

    proof = compile_safety_proof(plan, graph, ctx, adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None, label
    assert line.status is ObligationStatus.FAIL, line.detail
    assert rule_id in line.detail, line.detail
    assert proof.verdict is ProofVerdict.FAIL
    assert proof.void_reason == "", proof.void_reason


@pytest.mark.parametrize(
    ("label", "ceilings", "rule_id"),
    CEILING_PROOF_CASES,
    ids=[case[0] for case in CEILING_PROOF_CASES],
)
def test_a_ceiling_that_holds_reports_what_was_measured_not_that_it_exists(
    label: str, ceilings: BlastCeilings, rule_id: str
) -> None:
    """The positive half: the line reads the ceilings' verdicts, not their presence.

    A line that merely restated "ceilings were configured" would go green here and
    on every run, and would say nothing about whether any limit was close to
    breaking. This asserts the report is a measurement — every ceiling's observed
    value is present, on the allow path, next to the limit it was compared to —
    and that a ``PASS`` here means the gate actually ran the comparison.

    Asserted against ``Obligation.detail`` because that is the whole of what an
    ``Obligation`` carries: ``Obligation`` is a frozen, digest-bearing artifact
    whose fields are ``name``, ``status``, ``gate_digest``, ``evidence_ref``,
    ``evaluated_at`` and ``detail``, and there is no ``output`` on it to read.
    Adding one to satisfy a test would change the schema of a signed proof for
    every consumer at once, so the test reads the surface the artifact really
    has. That is not a downgrade: ``detail`` is what an approver reads, and a
    measurement that never reached it is a measurement nobody acted on.

    The measured values are the gate's own — ``3`` affected nodes, depth ``2``,
    ``75``% of nodes, ``1`` front door, read off ``_ceiling_graph`` — and each
    appears beside the limit it was compared to. Two of the assertions are there
    to catch the two ways this could pass without measuring anything:

    * ``the gate also reported protected_hits 0`` names a stat
      ``_check_blast_ceilings`` emits *unconditionally*. It is on the allow path
      only because the ceilings block ran, so its presence is direct evidence
      the comparison executed rather than a claim in the compiler's own words.
    * ``"protected_node_ids" not in line.detail`` — the list is empty here, so
      the protected ceiling is *unconfigured*. A renderer that folded the
      unconditional ``protected_hits`` stat into the configured list would print
      a fifth pairing for a limit nobody set, and that is exactly the "unchecked
      read as satisfied" defect the sibling test exists to catch.
    """
    graph, plan = _ceiling_graph(), _ceiling_plan()
    # At or above the measured value on every axis, so nothing is breached.
    wide = BlastCeilings(
        max_affected_nodes=3,
        max_affected_pct=100.0,
        max_dependency_depth=2,
        max_customer_facing_services=1,
        protected_node_ids=frozenset(),
    )
    del ceilings, rule_id  # the case table names the refusal; this is its mirror
    ctx = dataclass_replace(_ctx(), blast_ceilings=wide)

    validate_plan(plan, graph, ctx)  # the real gate allows it
    proof = compile_safety_proof(plan, graph, ctx, adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert line.status is ObligationStatus.PASS, line.detail
    # Every configured ceiling, with the gate's own reading beside its limit.
    assert "max_affected_nodes 3 <= 3" in line.detail, line.detail
    assert "max_dependency_depth 2 <= 2" in line.detail, line.detail
    assert "max_affected_pct 75 <= 100" in line.detail, line.detail
    assert "max_customer_facing_services 1 <= 1" in line.detail, line.detail
    assert "1/1 step(s) measured against the 4 configured plan-14 ceiling(s)" in line.detail
    # Proof the ceilings block actually ran, not that it was merely configured.
    assert "the gate also reported protected_hits 0" in line.detail, line.detail
    # The empty protected list is unconfigured, so it must not be reported as a
    # measured ceiling. It is disclosed as a stat instead.
    assert "protected_node_ids" not in line.detail, line.detail
    assert "against no configured ceiling" in line.detail, line.detail


def test_a_configured_protected_list_reports_hits_against_what_it_lists():
    """The one ceiling whose limit is a set, and the pairing that cannot be derived.

    ``_check_blast_ceilings`` measures the protected list by counting what it hit,
    so the gate reports ``ceiling_protected_hits`` where the ceiling it enforces
    is ``protected_node_ids``. No shared word connects the two names, so the
    pairing is written down rather than derived — and this pins that it is paired
    to the *right* one, since a renderer that guessed here would print a front
    door's hit count beside the wrong ceiling and nobody would notice until it
    was wrong in the permissive direction.

    ``n-front`` is in the list and is not a target, so the honest reading is a
    hit count of zero against a list of one: the gate looked, and nothing
    protected was in the blast. Not "the ceiling held" on its own — the count of
    what was protected is what makes the zero meaningful.
    """
    graph, plan = _ceiling_graph(), _ceiling_plan()
    ctx = dataclass_replace(
        _ctx(), blast_ceilings=BlastCeilings(protected_node_ids=frozenset({"n-front"}))
    )

    validate_plan(plan, graph, ctx)
    proof = compile_safety_proof(plan, graph, ctx, adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert line.status is ObligationStatus.PASS, line.detail
    assert "protected_node_ids 0 hit(s) against 1 configured" in line.detail, line.detail
    assert "1/1 step(s) measured against the 1 configured plan-14 ceiling(s)" in line.detail
    # Paired, so it is no longer disclosed as a stat with nothing behind it.
    assert "protected_hits 0 against no configured ceiling" not in line.detail, line.detail


def test_a_ceiling_nobody_could_measure_is_reported_unmeasured_not_held():
    """Configured is not measured, and the empty graph is where the two differ.

    ``max_affected_pct`` is a share of the graph, so on an empty graph there is
    nothing to take a share of and the gate skips it — deliberately, in agreement
    with ``domain.prediction``. The step is admitted, the line ``PASS``es, and
    the artifact would be claiming a check that did not happen if the configured
    ceiling were rendered with the same "held" shape as a measured one. It is
    named as configured *and* unmeasured instead, and the step count drops to
    ``0/1`` so the number of steps that were actually compared is not inflated by
    the one that was not.

    The graph here is empty on purpose, which also means the step is refused on
    target drift first; that is why the assertion is on the ceilings clause of
    the detail rather than on the status alone.
    """
    graph, plan = TopologyGraph(nodes=(), edges=()), _ceiling_plan()
    ctx = dataclass_replace(_ctx(), blast_ceilings=BlastCeilings(max_affected_pct=10.0))

    proof = compile_safety_proof(plan, graph, ctx, adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert "max_affected_pct configured at 10 but unmeasured" in line.detail, line.detail
    assert "0/1 step(s) measured against the 1 configured plan-14 ceiling(s)" in line.detail


def test_no_ceilings_configured_is_reported_as_unmeasured_never_as_satisfied():
    """The absence of a limit must not read as the presence of a pass.

    ``BlastCeilings`` defaults every field to ``None``, and ``None`` means *not
    configured* — a limit nobody asked for. Rendering that as "ceilings checked"
    would let an artifact claim a measurement that was never made, which is the
    specific failure plan 14's own docstring calls out for a prediction that
    cannot evaluate a limit. The line says so in words instead of in a number.

    The negative assertions carry the weight here. ``<=`` is the rendering of a
    ceiling that was *compared against a limit*, so its total absence from the
    detail is the claim: nothing was compared, so no line may present anything as
    having held. The same goes for "measured against", which is the count of
    steps that ran a comparison — reporting ``0/1`` for a context that never
    reached the ceilings at all would still be a measurement count, and would
    still read like a passing measurement of zero.
    """
    graph, plan = _ceiling_graph(), _ceiling_plan()

    proof = compile_safety_proof(plan, graph, _ctx(), adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert line.status is ObligationStatus.PASS
    assert "no plan-14 blast ceilings configured" in line.detail, line.detail
    assert "unchecked rather than satisfied" in line.detail
    assert "measured against" not in line.detail, line.detail
    assert " <= " not in line.detail, line.detail
    assert "unmeasured" not in line.detail.split("no plan-14 blast ceilings", 1)[0], line.detail


def test_a_carried_but_empty_ceiling_block_is_still_reported_as_nothing_compared():
    """``BlastCeilings()`` is a configuration that names no limit, not an absent one.

    ``ctx.blast_ceilings is None`` and ``BlastCeilings()`` are different states
    that both enforce nothing, and the artifact has to keep them apart: the first
    means no ceiling block was ever supplied, the second means one was supplied
    and it was empty. The second is the more dangerous of the two, because the
    gate *does* run it and it *does* return a ``ceiling_*`` stat — so a renderer
    that counted configured fields and paired the stats it found would print a
    measurement. Before this was distinguished, the line said "1/1 step(s)
    measured against the 0 configured plan-14 ceiling(s)", which is a step
    reported as measured against nothing at all.
    """
    graph, plan = _ceiling_graph(), _ceiling_plan()
    ctx = dataclass_replace(_ctx(), blast_ceilings=BlastCeilings())

    proof = compile_safety_proof(plan, graph, ctx, adapter=_Adapter())

    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert line.status is ObligationStatus.PASS
    assert "named no limit" in line.detail, line.detail
    assert "none is reported as satisfied" in line.detail
    assert "measured against" not in line.detail, line.detail
    assert " <= " not in line.detail, line.detail


def test_a_ceiling_breach_reported_only_by_a_prediction_is_still_blamed():
    """``GATE_RULE_IDS`` is the other half of the same mapping.

    Without the five in that set, ``compile_safety_evidence`` filters a
    prediction's findings against it and a prediction that *flagged* a breached
    ceiling contributed no blame at all — the identical gap in the opposite
    direction, and quieter, because the artifact simply did not mention the
    finding. The two assertions are therefore paired with the refusal tests
    above: those prove the gate's refusals are placeable, this proves the
    prediction's findings are too.

    The compilation half stays on ``compilation.blame`` because that *is* the
    rule-level trail and there is nothing to flatten it onto ``Obligation``. The
    proof-level assertions added at the end are the part that has to hold on the
    published artifact: the same breach must read as a ``FAIL`` on
    ``target_policy`` carrying the rule's own reason, and must not become a
    whole-proof ``VOID`` — a ``VOID`` says the compiler could not place the
    refusal, which is a different and much worse claim than "it refused".
    """
    from mayhem.domain.prediction import predict_impact

    graph, plan = _ceiling_graph(), _ceiling_plan()
    breach = BlastCeilings(max_affected_nodes=2)
    # ``predict_impact`` takes the graph first; a prediction of a different graph
    # than the one compiled would be stale and correctly blamed for nothing.
    prediction = predict_impact(graph, plan, ceilings=breach)

    assert prediction.rule_ids & CEILING_RULE_IDS, prediction.rule_ids

    compilation = compile_safety_evidence(
        plan,
        graph,
        dataclass_replace(_ctx(), blast_ceilings=breach),
        adapter=_Adapter(),
    )
    blamed = {
        rule
        for reasons in compilation.blame.get(ObligationName.TARGET_POLICY.value, ())
        for rule in [reasons]
    }
    assert any(RULE_MAX_AFFECTED_NODES in reason for reason in blamed), blamed

    # The same breach on the published artifact: a ``FAIL`` on the owning line
    # carrying the gate's own reason, and no whole-proof ``VOID``.
    proof = compilation.proof
    line = proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert line.status is ObligationStatus.FAIL, line.detail
    assert RULE_MAX_AFFECTED_NODES in line.detail, line.detail
    assert proof.verdict is ProofVerdict.FAIL
    assert proof.void_reason == "", proof.void_reason


def _mint_approval(proof: SafetyProof, gate: ApprovalGateInputs) -> tuple[Approval, RoleGrant]:
    """One approval bound to ``proof``, minted through the plan-09 service.

    Through :meth:`ApprovalLedger.mint` rather than the constructor, so the
    minting path is on the path under test. The ``APPROVE`` grant it needs is
    returned alongside the approval because the gate reads its grants from
    ``ApprovalGateInputs`` — minting against a grant the gate cannot see would
    make the approval look unauthorized at admission, which is a different test.
    """
    approver = Principal(principal_id="u-approve")
    approve_grant = RoleGrant(
        role=Role.APPROVE,
        scope=EnvironmentScope(environment="production"),
        granted_at=datetime(2026, 2, 28, tzinfo=UTC),
        principal=approver,
    )
    ledger = ApprovalLedger(grants=(*gate.grants, approve_grant))
    approval = ledger.mint(
        approval_id="a-proof1",
        proof=proof,
        policy_digest=gate.policy_digest,
        approver=approver,
        environment=EnvironmentScope(environment="production"),
        now=gate.now,
    ).approvals[-1]
    return approval, approve_grant


def test_the_approvals_line_cites_the_approval_state_it_read():
    """The reading is in the citation, so it is evidence rather than prose.

    The line's own output must carry the gate's decision — ``configured``, the
    verdict payload, and the refusal rule ids — because a rendered proof that
    only said "approvals fine" would be a claim with nothing behind it, which is
    the failure Phase 1's forged-PASS guard exists to prevent.
    """
    plan = _plan()
    proof = compile_safety_proof(
        plan,
        _graph(),
        _ctx(approval_gate=_refusing_gate(plan)),
        adapter=_Adapter(),
    )

    line = proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None
    assert SHA256_HEX.fullmatch(line.gate_digest)
    assert "verify_approvals" in line.evidence_ref


def _refusing_gate(plan: ExecutionPlan) -> ApprovalGateInputs:
    """An approval gate configured with no approvals, so it refuses on the quorum.

    The gate's own proof is a PASS over *this* plan's digest. That matters: the
    gate checks the proof before the approvals, so a proof that did not match
    would make ``approval.proof_not_pass`` fire first and mask the quorum
    refusal this test is about.
    """
    obligations = tuple(
        Obligation(
            name=name.value,
            status=ObligationStatus.PASS,
            gate_digest=digest_of({"gate": name.value}),
            evidence_ref=f"evidence://{name.value}",
        )
        for name in ObligationName
    )
    proof = SafetyProof(
        plan_digest=canonical_plan_digest(plan),
        obligations=obligations,
        verdict=ProofVerdict.PASS,
    )
    return ApprovalGateInputs(
        now=datetime(2026, 3, 1, 12, 0, tzinfo=UTC),
        environment=EnvironmentScope(environment="production"),
        executor=Principal(principal_id="u-exec"),
        proof=proof,
        policy_digest=digest_of({"bundle": "test"}),
        approvals=(),
        grants=(
            RoleGrant(
                role=Role.EXECUTE,
                scope=EnvironmentScope(environment="production"),
                granted_at=datetime(2026, 2, 28, tzinfo=UTC),
                principal=Principal(principal_id="u-exec"),
            ),
        ),
    )


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

    assert (
        before[ObligationName.REQUIRED_APPROVALS.value]
        != after[ObligationName.REQUIRED_APPROVALS.value]
    )


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

    assert before[ObligationName.TARGET_POLICY.value] != after[ObligationName.TARGET_POLICY.value]


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
    """ "Not checked" is not "checked and negative"."""
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


# --- the rules mapped ahead of their wiring (plan 30 Phase 4, third pass) --------
#
# Four plans landed refusal rule ids in modules this compiler does not run, and
# each recorded the debt rather than editing this module. Eighteen rows closed it.
#
# The reach half of the guard above is still two modules wide, so none of these
# eighteen rules is *reached* today — they are rows ahead of the wiring. That is
# exactly the state in which a mapping can quietly become fiction, so this section
# asserts the opposite direction: that each row names a rule the code actually
# spells, and that no row anywhere in the table names one it does not. The full
# per-plan ledger, the ids deliberately left unmapped and why, and the negative
# controls live in ``tests/unit/test_owed_rule_mappings.py``; this is the same
# invariant stated from the compiler's side of the boundary, because the compiler
# is what a dead row would misrepresent.

#: Modules whose rule ids the eighteen new rows come from, and the rows each one
#: owns. Written out rather than derived, so a row landing in the wrong family is
#: a failure that names the family instead of passing a set comparison.
OWED_RULE_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "controller/stop_engine.py",
        (
            "stop_for_terminal_run",
            "stop_engine_requires_run_scope",
            "stop_command_stale",
            "stop_stage_skip_refused",
            "stop_stage_not_owed",
            "stop_seal_requires_complete_walk",
            "stop_seal_requires_evidence",
            "stop_seal_digest_mismatch",
        ),
    ),
    (
        "controller/preflight_gate.py",
        ("preflight.refused",),
    ),
    (
        "controller/campaign_dispatch.py",
        ("schedule.campaign_budget", "schedule.no_compilation"),
    ),
    (
        "controller/analytics_service.py",
        (
            "analytics.planner_budget_diverged",
            "analytics.step_unaffordable",
            "analytics.evidence_not_sealed",
            "analytics.search_not_recorded",
        ),
    ),
    (
        "providers/participation.py",
        (
            "provider.fault_undeclared",
            "provider.certification_cell_unpinned",
            "provider.lease_undo_absent",
        ),
    ),
)

#: The two modules that *are* the mapping. Their rows cannot be used as evidence
#: that a rule id exists, or the table certifies itself.
BLAMEABLE_TABLES: frozenset[str] = frozenset(
    {
        "src/mayhem/controller/safety_proof.py",
        "src/mayhem/controller/check_gate.py",
    }
)


def _rule_ids_spelled_by_code(relative: str) -> frozenset[str]:
    """Rule ids a module spells in its *code*: literals, not docstrings, not comments.

    ``ast.parse`` drops comments, so a rule id that survives only in one cannot be
    counted. The one remaining way prose reaches the AST as a string constant is a
    bare string expression, which is what a docstring is — and a rule named only in
    a docstring is precisely the dead row this exists to catch.
    """
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstrings = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    return frozenset(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    )


@pytest.mark.parametrize(
    ("module", "rules"),
    OWED_RULE_FAMILIES,
    ids=[family for family, _ in OWED_RULE_FAMILIES],
)
def test_every_row_mapped_from_a_later_plan_is_a_rule_that_module_raises(
    module: str, rules: tuple[str, ...]
) -> None:
    """Each new row's evidence is its own module, read from that module's source.

    Not "the string appears somewhere in the repository": a rule id spelled only in
    an unrelated module would satisfy a looser check while the row still described
    nothing. This asserts the naming module spells it, and that the rule is mapped.
    """
    spelled = _rule_ids_spelled_by_code(f"src/mayhem/{module}")
    for rule in rules:
        assert rule in spelled, (
            f"{rule} is mapped to a proof line but {module} does not spell it, so the "
            "row describes a refusal that module cannot produce"
        )
        assert OBLIGATION_FOR_RULE.get(rule), rule


def test_no_key_in_the_blame_table_is_a_rule_the_repository_never_spells() -> None:
    """The whole table, checked against the code — the anti-fabrication guard.

    The failure this catches is specific and has already happened once in this
    repository: plan 10's ledger proposed ``stop_resume_skips_owed_stage``, and no
    such rule id exists. Adding that row would have made ``OBLIGATION_FOR_RULE``
    *look* complete while leaving both refusals ``StopEngine._resume`` can raise
    unplaceable — the debt made invisible rather than removed, which is worse than
    the debt because nothing reports it any more.

    Written over the entire table and not just the eighteen new rows, so a row
    added later by a lane that never reads this file is covered too. The two table
    modules are excluded because they spell every row; counting them would make
    this test true by construction.
    """
    spelled: set[str] = set()
    for path in sorted((REPO_ROOT / "src" / "mayhem").rglob("*.py")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative in BLAMEABLE_TABLES:
            continue
        spelled |= _rule_ids_spelled_by_code(relative)

    dead = sorted(rule for rule in OBLIGATION_FOR_RULE if rule not in spelled)
    assert not dead, (
        "these rule ids are mapped to a proof line but no module under src/mayhem "
        "spells them, so each row is coverage of a refusal that cannot occur: "
        f"{dead}. Point each row at the rule the code actually raises, or delete it."
    )


def test_the_stale_rule_id_plan_10_proposed_is_not_in_the_table_and_its_replacement_is() -> None:
    """The correction, pinned so it cannot be reverted by copying the plan back.

    Plan 10's integration table names ``stop_resume_skips_owed_stage`` for
    ``StopEngine._resume``. That rule id is in no module.
    :meth:`StopEngine._resume` raises ``stop_stage_skip_refused``, and one branch
    earlier ``stop_stage_not_owed``. The real ids are mapped — both, because a
    single function raising a pair of which only one is mapped is the same false
    assurance a dead row gives.
    """
    assert "stop_resume_skips_owed_stage" not in OBLIGATION_FOR_RULE
    assert "stop_resume_skips_owed_stage" not in GATE_RULE_IDS
    assert "stop_stage_skip_refused" not in GATE_RULE_IDS, (
        "GATE_RULE_IDS is intersected with prediction.rule_ids, which forecast blast "
        "and damage quantities; a resumed-at-the-wrong-stage stop is a state, not an "
        "estimate, and admitting it would widen the set with an id no prediction can "
        "carry"
    )
    for rule in ("stop_stage_skip_refused", "stop_stage_not_owed"):
        assert OBLIGATION_FOR_RULE.get(rule), rule
