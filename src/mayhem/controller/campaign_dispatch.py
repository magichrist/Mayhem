"""One dispatch core for authored drills *and* scheduled campaigns (plan 13 Phase 4).

Phase 2 (:mod:`mayhem.controller.scheduler`) built the four-stage pipeline a
scheduled run walks -- plan, admit, approve, execute -- as a **port**: four
required callables with no defaults, so no construction path could omit a gate.
That is the right shape for "a scheduled run is not a privileged run", but on its
own it is only a promise that the *caller* kept. Someone still had to bind those
four callables, and a binding written twice -- once for ``mayhem run`` and once
for the scheduler -- is exactly how the two drift apart while both test suites
stay green.

This module is the one binding. :func:`compile_campaign_run` is a single
function with **no origin parameter**: it does not know or care whether the run
was typed by a human at a terminal or reached a fire slot through a cron
expression, because :class:`CampaignRunRequest` has no field that could say so.
An authored drill and a scheduled campaign therefore reach
:func:`~mayhem.controller.planner.plan_drill`,
:func:`~mayhem.controller.safety_proof.compile_safety_evidence`, and
:func:`~mayhem.controller.safety.simulate_plan_policy` through the *same three
statements in the same order*, and there is no branch below this line that could
make one of them acquire something on the way.

How that is proved, and what "proved" means here
------------------------------------------------

Not by comparing outputs. Two paths that produce the same string can have
reached it by different gates, and a test asserting equality would pass if both
paths were wrong in the same way. The property is proved instead by a spy over
the shared compiler: ``compile_safety_evidence`` is imported *into this module's
namespace*, so replacing that one binding and driving a scheduled dispatch
observes the call directly. The negative control removes the admission gate's
use of the compiler and asserts the dispatch still executes -- which is what
makes the positive observation evidence rather than coincidence. Both are in
``tests/unit/test_campaign_dispatch.py``.

What is fail-closed here
------------------------

* **A proof that is not ``PASS`` refuses.** :class:`ProofVerdict` has three
  members and ``VOID`` is the fail-closed third: obligations nobody established.
  ``VOID`` is treated exactly like ``FAIL`` -- the dispatch is refused and the
  reason names the lines that are unproven. There is no advisory mode, because a
  plan whose capability requirements could not be established against a live
  runtime has not been shown to be safe, only unrefuted.
* **A plan with no compilation refuses.** If a planner other than
  :func:`build_dispatch_pipeline`'s produced the plan, the admission gate finds
  no proof to judge and refuses rather than admitting it on the strength of a
  plan nobody checked.
* **A malformed campaign budget refuses.** See :func:`campaign_budget_verdict`.

What is deliberately **not** claimed
------------------------------------

* **No signature verification.** Nothing here verifies a pack signature, a proof
  signature, or an artifact signature;
  :data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` stays
  ``False`` and nothing in this module could make it ``True``.
* **No live-cluster claim.** :class:`DispatchEnvironment` takes a topology graph
  and a :class:`~mayhem.controller.safety.SafetyContext` from its caller and
  compiles against whatever it was handed. A graph from a fixture proves the
  wiring, not the cluster; ``verified-live`` stays ``0`` and this module does not
  move it.
* **No new fault-concurrency cap.** The enforced concurrent-fault budget is
  ``blast_radius.max_concurrent_faults``, read by
  :func:`~mayhem.controller.safety.validate_plan`. This module adds no second
  limit and reads no deprecated one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from mayhem.controller.approval_gate import verify_approvals
from mayhem.controller.planner import plan_drill
from mayhem.controller.policy_gate import plan_faults
from mayhem.controller.safety import simulate_plan_policy, validate_plan
from mayhem.controller.safety_proof import compile_safety_evidence
from mayhem.controller.scheduler import (
    DispatchPipeline,
    DispatchRequest,
    ExecutionReceipt,
    GateVerdict,
    PlannedDispatch,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.quota import damage_weight
from mayhem.domain.safety_proof import ObligationStatus, ProofVerdict

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.controller.approval_gate import ApprovalGateInputs
    from mayhem.controller.policy_gate import PolicyGateResult
    from mayhem.controller.safety import SafetyContext
    from mayhem.controller.safety_proof import SafetyCompilation
    from mayhem.domain.experiments import DrillSpec, ExecutionPlan
    from mayhem.domain.policy import BudgetCharge, BudgetNode
    from mayhem.domain.runtime_adapter import RuntimeAdapter
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "CAMPAIGN_BUDGET_LIMIT",
    "CampaignBudgetVerdict",
    "CampaignDispatch",
    "CampaignRunRequest",
    "DispatchEnvironment",
    "build_dispatch_pipeline",
    "campaign_budget_verdict",
    "compile_campaign_run",
]

#: Rule id the campaign-budget refusal is recorded under. Deliberately **not**
#: spelled like a 07 rule id: this is not a 07 gate refusing on its own terms, it
#: is the scheduler consulting a campaign ledger the caller mounted, and giving it
#: a 07 id would let it be blamed onto a proof line it did not produce. It is
#: also not in ``controller.safety`` or ``controller.approval_gate``, so
#: ``OBLIGATION_FOR_RULE`` and ``RULE_CHECK`` are untouched -- neither table
#: describes a gate that does not live in those two modules.
CAMPAIGN_BUDGET_LIMIT: Final[str] = "schedule.campaign_budget"

#: Rule id for "the planner produced a plan with no safety compilation attached".
#: Same reasoning as above, and it is the reason a bespoke pipeline cannot
#: silently borrow this module's admission gate.
NO_COMPILATION_LIMIT: Final[str] = "schedule.no_compilation"

#: The proof lines a ``PASS`` requires, in the fixed spine's own order.
REQUIRED_PROOF_LINES: Final[tuple[str, ...]] = (
    "max_concurrent_faults",
    "max_duration",
    "damage_budget",
    "target_policy",
    "capability_requirements",
    "compensation",
    "recovery_path",
    "stop_conditions",
    "required_approvals",
)

#: Decimal places a campaign-budget charge is rounded to, matching 07's
#: ``DAMAGE_PRECISION`` by construction rather than by a second constant: the
#: rounding is applied by :meth:`~mayhem.domain.policy.BudgetNode.post_charge`,
#: and this module only rounds the *amount* it hands over, the way 07's
#: ``probe_budget`` does.
_DAMAGE_PRECISION: Final[int] = 6


@dataclass(frozen=True)
class CampaignRunRequest:
    """One campaign run on its way to a plan.

    **There is no origin field, and that is the whole design.** A reader looking
    for ``scheduled=`` or ``generated=`` to branch on will not find one, and
    :func:`compile_campaign_run` reads no environment variable, consults no
    registry, and takes no boolean that would let a caller reach the same three
    compilers by a cheaper route. Two request types therefore cannot describe the
    same run differently.
    """

    run_id: str
    campaign_id: str
    experiment_id: str
    spec: DrillSpec
    #: Directory the spec's relative assets resolve against (``spec_dir`` for
    #: :func:`~mayhem.controller.planner.plan_drill`).
    spec_dir: str | None = None


@dataclass(frozen=True)
class DispatchEnvironment:
    """Everything a dispatch needs that is not the request itself.

    A frozen dataclass of *inputs*, not of decisions: it holds the graph, the
    safety context, and the three callables that supply a spec, the approval
    inputs, and the execution. It holds no clock -- the caller passes ``now``
    through the safety context and the approval inputs, both of which are
    required fields there -- so a dispatch over the same environment and the same
    request produces the same plan digest on any host, on any date.
    """

    graph: TopologyGraph
    ctx: SafetyContext
    #: Resolves one campaign/experiment pair to the drill spec it names. A
    #: refusal to resolve is a planning failure, not a skip.
    spec_for: Callable[[str, str], DrillSpec]
    #: The plan-09 approval inputs for this run. Required rather than optional:
    #: an approval gate whose inputs nobody supplied has authorised nothing, and
    #: a default here would be a default-deny dressed as a default-allow.
    approvals_for: Callable[[ExecutionPlan], ApprovalGateInputs]
    #: Runs the plan. Returns the run id, or raises -- a raising executor is an
    #: unknown outcome, which the scheduler treats as unsettled rather than as a
    #: failure (see :meth:`~mayhem.controller.scheduler.Scheduler.tick`).
    executor: Callable[[ExecutionPlan], ExecutionReceipt]
    adapter: RuntimeAdapter | None = None
    engine: str = "podman"
    config_snapshot_id: str = ""
    topology_snapshot_id: str = ""
    environment_fingerprint: str = ""
    policy_id: str = ""


@dataclass(frozen=True)
class CampaignDispatch:
    """What the shared core produced: a plan and everything said about it."""

    request: CampaignRunRequest
    plan: ExecutionPlan
    plan_digest: str
    compilation: SafetyCompilation
    policy: PolicyGateResult | None

    @property
    def verdict(self) -> ProofVerdict:
        """The proof's own verdict, read on every access rather than cached."""
        return self.compilation.proof.verdict

    @property
    def policy_allowed(self) -> bool:
        """True when no policy bundle refused. ``None`` means no bundle, allowed."""
        return self.policy is None or self.policy.allowed

    @property
    def admissible(self) -> bool:
        """True when the proof is ``PASS`` *and* no policy gate refused.

        Both halves, conjunctively. A ``PASS`` proof with a denying policy
        decision is a plan the safety core liked and the policy core refused;
        admitting it would be picking the half that says yes.
        """
        return self.verdict is ProofVerdict.PASS and self.policy_allowed

    def unproven_lines(self) -> tuple[str, ...]:
        """Proof lines that are not ``PASS``, in the fixed spine's order.

        Named rather than counted, because "the proof is VOID" is not something an
        operator can act on and "capability_requirements and compensation are
        unestablished" is.
        """
        lines = {line.name: line.status for line in self.compilation.proof.obligations}
        return tuple(
            name for name in REQUIRED_PROOF_LINES if lines.get(name) is not ObligationStatus.PASS
        )

    def refusal_reason(self) -> str:
        """One sentence naming why this dispatch is not admissible, or ``""``."""
        if self.admissible:
            return ""
        if self.verdict is not ProofVerdict.PASS:
            unproven = ", ".join(self.unproven_lines()) or "the proof spine"
            detail = (
                f" ({self.compilation.proof.void_reason})" if self.compilation.void_reason else ""
            )
            return (
                f"safety proof is {self.verdict.value}, not PASS: {unproven} not established"
                f"{detail}"
            )
        assert self.policy is not None  # admissible is False and the proof passed
        refusal = self.policy.refusal
        reason = refusal.reason if refusal is not None else self.policy.decision.outcome
        return f"policy gate refused the plan: {reason}"


def compile_campaign_run(
    environment: DispatchEnvironment, request: CampaignRunRequest
) -> CampaignDispatch:
    """Compile one campaign run and take it through proof and policy.

    **The one shared core.** Three statements, in this order, with no branch
    between them and no parameter that could select a different route:

    1. :func:`~mayhem.controller.planner.plan_drill` compiles the frozen
       :class:`~mayhem.domain.experiments.ExecutionPlan`. A spec that will not
       compile raises here, which is upstream of both later steps -- a candidate
       nobody can run never receives a safety case or a policy verdict either.
    2. :func:`~mayhem.controller.safety_proof.compile_safety_evidence` runs the
       real gates and assembles the proof plus its refusal trail.
    3. :func:`~mayhem.controller.safety.simulate_plan_policy` produces the policy
       verdict, and is pure: it mutates nothing on the context.

    Read top to bottom, there is no ``if scheduled:`` here and nowhere below
    :func:`build_dispatch_pipeline`. That is the structural half of "a scheduled
    run faces the identical gate path"; the spy half is in
    ``tests/unit/test_campaign_dispatch.py``.

    Raises:
        mayhem.domain.errors.InvariantViolationError: Propagated from
            ``plan_drill`` when the spec does not compile. It is *not* caught and
            re-labelled here: the planner's own rule ids are more actionable than
            anything this layer could invent, and the scheduler records a raising
            planner as ``schedule.plan_failed`` with the rule id in the reason.
    """
    plan = plan_drill(
        request.run_id,
        request.spec,
        environment.graph,
        config_snapshot_id=environment.config_snapshot_id,
        topology_snapshot_id=environment.topology_snapshot_id,
        environment_fingerprint=environment.environment_fingerprint,
        policy_id=environment.policy_id,
        engine=environment.engine,
        spec_dir=request.spec_dir,
    )
    compilation = compile_safety_evidence(
        plan, environment.graph, environment.ctx, adapter=environment.adapter
    )
    policy = simulate_plan_policy(plan, environment.ctx)
    return CampaignDispatch(
        request=request,
        plan=plan,
        plan_digest=compilation.plan_digest,
        compilation=compilation,
        policy=policy,
    )


def build_dispatch_pipeline(environment: DispatchEnvironment) -> DispatchPipeline:
    """Bind :class:`~mayhem.controller.scheduler.DispatchPipeline` to the real gates.

    All four callables are required by the pipeline's own definition, so this
    function cannot return a pipeline that skips one -- it has nowhere to put a
    default. The bindings, in the order the scheduler calls them:

    ``planner``
        :func:`compile_campaign_run`, carrying the compilation forward on
        :attr:`PlannedDispatch.dispatch` so the admission gate judges *that*
        proof rather than recompiling one and hoping the two agree.
    ``admission``
        :func:`~mayhem.controller.safety.validate_plan`, called bare -- it refuses
        by raising, which is the honest shape of its refusal and is what the
        scheduler's gate wrapper turns into a record -- followed by the
        compilation's own admissibility, which covers the proof and the policy
        gate.
    ``approver``
        :func:`~mayhem.controller.approval_gate.verify_approvals`, also bare.
    ``executor``
        ``environment.executor``, called with the compiled plan.

    The planner's refusals become ``GateVerdict(passed=False)`` rather than
    escaping: the pipeline's gate contract is a verdict, and a caller obliged to
    handle two failure modes to read one gate would eventually handle only the
    convenient one.
    """
    return DispatchPipeline(
        planner=_planner(environment),
        admission=_admission(environment),
        approver=_approver(environment),
        executor=_executor(environment),
    )


def _planner(environment: DispatchEnvironment) -> Callable[[DispatchRequest], PlannedDispatch]:
    """The pipeline's planner: the shared core, with its refusals as verdicts."""

    def plan(request: DispatchRequest) -> PlannedDispatch:
        dispatch = compile_campaign_run(
            environment,
            CampaignRunRequest(
                run_id=request.concurrency.run_id,
                campaign_id=request.campaign_id,
                experiment_id=request.experiment_id,
                spec=environment.spec_for(request.campaign_id, request.experiment_id),
            ),
        )
        return PlannedDispatch(
            plan=dispatch.plan,
            plan_digest=dispatch.plan_digest,
            dispatch=dispatch,
        )

    return plan


def _admission(
    environment: DispatchEnvironment,
) -> Callable[[DispatchRequest, PlannedDispatch], GateVerdict]:
    """The pipeline's admission gate: the safety gate, then the shared proof."""

    def admit(request: DispatchRequest, planned: PlannedDispatch) -> GateVerdict:
        dispatch = planned.dispatch
        if dispatch is None:
            # A planner that did not come from build_dispatch_pipeline produced a
            # plan with no proof attached. Refuse rather than admit it on the
            # strength of a plan nobody checked: the proof is the gate, not a
            # formality, and "no proof" is the fail-closed reading.
            return GateVerdict(
                passed=False,
                reason=(
                    "the planner produced no safety compilation for this plan, so the "
                    "admission gate has nothing to admit; bind the pipeline through "
                    "build_dispatch_pipeline"
                ),
                rule_id=NO_COMPILATION_LIMIT,
            )
        validate_plan(dispatch.plan, environment.graph, environment.ctx, environment.adapter)
        if dispatch.admissible:
            return GateVerdict(passed=True, reason="admitted")
        return GateVerdict(
            passed=False,
            reason=dispatch.refusal_reason(),
            rule_id="schedule.admission_refused",
        )

    return admit


def _approver(
    environment: DispatchEnvironment,
) -> Callable[[DispatchRequest, PlannedDispatch], GateVerdict]:
    """The pipeline's approval gate: plan 09, bound and called bare."""

    def approve(request: DispatchRequest, planned: PlannedDispatch) -> GateVerdict:
        result = verify_approvals(planned.plan, environment.approvals_for(planned.plan))
        if not result.denied:
            return GateVerdict(passed=True, reason="approved")
        refusal = result.refusal
        return GateVerdict(
            passed=False,
            reason=refusal.reason if refusal is not None else "approval gate denied the run",
            rule_id=refusal.rule_id if refusal is not None else "",
        )

    return approve


def _executor(
    environment: DispatchEnvironment,
) -> Callable[[DispatchRequest, PlannedDispatch], ExecutionReceipt]:
    """The pipeline's executor. Bare: a raising executor is an unknown outcome."""

    def execute(request: DispatchRequest, planned: PlannedDispatch) -> ExecutionReceipt:
        return environment.executor(planned.plan)

    return execute


@dataclass(frozen=True)
class CampaignBudgetVerdict:
    """Whether a campaign's hierarchical budget affords the charge it declared."""

    allowed: bool
    #: What a commit would post, widest level first. Empty when nothing was
    #: chargeable, which is the answer for a plan with no fault steps and for a
    #: tree mounted at ``None``.
    charges: tuple[BudgetCharge, ...] = ()
    reason: str = ""
    rule_id: str = ""
    #: The tree with the charge applied, for a caller that commits after the
    #: verdict. Never the tree that was passed in -- ``BudgetNode`` is frozen and
    #: :meth:`~mayhem.domain.policy.BudgetNode.post_charge` returns a new one.
    committed: BudgetNode | None = None

    def describe(self) -> str:
        if not self.allowed:
            return f"campaign budget refuses: {self.reason}"
        spent = ", ".join(f"{charge.scope.value}/{charge.key}" for charge in self.charges)
        if not spent:
            return "campaign budget admits nothing to charge"
        return f"campaign budget admits {spent}"


def campaign_budget_verdict(
    budget: BudgetNode | None, path: tuple[str, ...], plan: ExecutionPlan
) -> CampaignBudgetVerdict:
    """Probe the 07 damage hierarchy for one plan, without spending anything.

    The hierarchy is 07's -- team → environment → service → experiment → fault --
    and so are its semantics: a charge posts to the leaf *and every ancestor*, and
    an exhausted ancestor refuses even when the leaf has headroom. This is a
    **probe**: :meth:`~mayhem.domain.policy.BudgetNode.post_charge` returns new
    trees, so the caller's ``budget`` is never mutated and a refusal costs
    nothing. A caller that wants to commit reads
    :attr:`CampaignBudgetVerdict.committed`.

    ``budget=None`` means no campaign ledger was mounted, which is allowed and
    reports an empty charge list rather than refusing: 07's own damage quota and
    blast-radius budget still apply inside the safety core, and refusing here
    would be inventing a limit nobody configured. A *malformed* ledger is a
    different thing and refuses, carrying the hierarchy's own rule id.

    The damage weight per fault comes from 07's
    :func:`~mayhem.controller.policy_gate.damage_weight`, not from a second
    formula here, so a campaign budget and a policy budget cannot disagree about
    what one fault costs.
    """
    if budget is None:
        return CampaignBudgetVerdict(allowed=True)
    tree = budget
    charges: list[BudgetCharge] = []
    try:
        for fault in plan_faults(plan):
            amount = round(float(fault.duration) * damage_weight(fault.fault_id), _DAMAGE_PRECISION)
            tree, posted = tree.post_charge(_chargeable(tree, (*path, fault.fault_id)), amount)
            charges.extend(posted)
    except InvariantViolationError as exc:
        # A path that resolves at no depth, a scope out of order, a duplicate
        # child: the ledger cannot say who pays, and a charge nobody is
        # accountable for is not a budget. Refuse, naming the hierarchy's rule.
        return CampaignBudgetVerdict(
            allowed=False,
            reason=f"campaign budget at {budget.key!r} cannot attribute this charge: {exc}",
            rule_id=exc.rule,
        )
    spent = next((charge for charge in reversed(charges) if charge.exceeded), None)
    if spent is not None:
        return CampaignBudgetVerdict(
            allowed=False,
            charges=tuple(charges),
            reason=(
                f"{spent.scope.value}/{spent.key} would reach {spent.after_s:g}s against a "
                f"{spent.limit_s:g}s limit"
            ),
            rule_id=CAMPAIGN_BUDGET_LIMIT,
        )
    return CampaignBudgetVerdict(allowed=True, charges=tuple(charges), committed=tree)


def _chargeable(tree: BudgetNode, keys: tuple[str, ...]) -> tuple[str, ...]:
    """The longest prefix of ``keys`` that names real nodes in ``tree``, or raise.

    Same contract as 07's ``_chargeable_path``: a hierarchy authored to three of
    its five levels charges the levels that exist, and a path that names nothing
    at any depth is a misconfiguration rather than a missing budget.

    Resolution delegates to :meth:`~mayhem.domain.policy.BudgetNode.path`, which
    walks the tree by *scope* -- position 0 is the root whatever the key says --
    so a key check is added on top. Without it, ``path(("payments",))`` on a tree
    rooted at ``sre`` would "resolve", and every mistyped team would be charged to
    somebody else's budget. That is precisely the failure
    :func:`campaign_budget_verdict` refuses.
    """
    for length in range(len(keys), 0, -1):
        prefix = keys[:length]
        try:
            resolved = tree.path(prefix)
        except InvariantViolationError:
            continue
        if all(node.key == key for node, key in zip(resolved, prefix, strict=True)):
            return prefix
    msg = (
        f"campaign budget hierarchy under {tree.key!r} holds no level of {list(keys)!r}; "
        "a charge cannot be attributed to any budget"
    )
    raise InvariantViolationError("policy.budget_path_missing", msg)
