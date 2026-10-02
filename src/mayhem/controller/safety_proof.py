"""The safety-proof compiler — Phase 2 of docs/v1.1.0/30_SAFETY_PROOF.md.

Phase 1 gave the proof a *type* (:mod:`mayhem.domain.safety_proof`): nine fixed
obligation names, each PASS line obliged to cite the digest of a gate output.
Phase 2 supplies the thing that can actually fill those lines in: a compiler
that **runs the real gates** against the frozen plan and assembles what they said
into one checkable artifact. It defines no new check. Every refusal it reports
came out of a gate this repository already ships, and every line it passes cites
the digest of the output that produced it.

## The one rule that shapes the whole module

**The compiler may refuse equally or more than executing ``validate_plan`` would.
Never less.** That is not a property the tests hope for; it is structural, and
it is built in two steps:

1. The compiler runs :func:`mayhem.controller.safety.validate_plan` — the
   authoritative gate, unchanged, on a *throwaway clone* of the caller's
   :class:`SafetyContext` — and records the rule id it refused on
   (:func:`_authoritative`).
2. Every rule id any gate can refuse is mapped to the obligation that owns it
   (:data:`OBLIGATION_FOR_RULE`). After all probes have run, the refusals are
   *attributed* centrally (:func:`_blame`): a rule the authoritative gate refused
   downgrades its owning line to ``FAIL`` and names the reason in its detail. A
   rule id with no owning line is not silently dropped — the whole proof comes
   out ``VOID`` with the unmapped rule named, because a refusal this compiler
   cannot place is a refusal it cannot report.

So ``verdict is PASS`` implies ``validate_plan`` passed. Adding refusals later
(prediction, policy bundle, execution intent, compensation, recovery, stop
declarations) can only move a verdict away from PASS, never toward it. The
per-obligation probes in :func:`_blast_probe` and :func:`_admission_probe` run
the same gate functions the authoritative pass runs, on the same inputs, for
attribution and for the numbers a line reports — not to re-derive the verdict.

**Phase 4 added the plan-09 approval gate to both halves.** Its three refusal
rule ids were unmapped until then, so a run the approval gate refused compiled
to a whole-proof ``VOID`` naming a rule no line owned — fail-closed, but a
finding the artifact could not report. They now map to
:data:`ObligationName.REQUIRED_APPROVALS`, and :func:`_approval_probe` reads the
gate's actual verdict into that line rather than only restating what an approval
would have to say. ``tests/unit/test_proof_compiler.py`` parses this module and
``controller/approval_gate.py`` and asserts every rule either can raise is owned
by a line, so the next lane's unmapped refusal fails a test by name instead.

**Phase 4's second half paid the debt plan 14 recorded.** Its five blast-radius
ceilings — affected nodes, affected share, dependency depth, customer-facing
services, and the protected-node list — were enforced by
:func:`mayhem.controller.safety.check_blast_radius` from the moment they landed,
but owned by no line, so a run refused on one compiled to a whole-proof ``VOID``
naming a rule this compiler could not place: fail-closed, and strictly worse than
the ``FAIL`` an operator reading the artifact is actually looking for. All five
now map to :data:`ObligationName.TARGET_POLICY`, beside the two target-side caps
the same function raises, and :data:`GATE_RULE_IDS` gained them so a *prediction*
that flags a breached ceiling is blamed rather than quietly dropped — which was
the same gap in the opposite direction and just as silent.

No tenth obligation name was invented for them. :class:`ObligationName` is the
fixed nine-name spine Phase 1 shipped, and widening what a ``PASS``-shaped proof
must contain is a change to every consumer of the artifact, taken on for a rule
that an existing line already describes accurately: "which targets this plan may
touch, and how much of the system with them". The line *reads* the ceilings rather
than restating them — :func:`_blast_probe` returns the configured limits and the
gate's own per-step measurements, and distinguishes "measured and within" from
"never checked", because a ``None`` ceiling is unchecked and reporting it as
satisfied would be the artifact claiming a pass nobody earned.

## Why the probes clone the context

:func:`mayhem.controller.safety.validate_plan` and
:func:`mayhem.controller.safety.check_blast_radius` *record* a
:class:`~mayhem.domain.decisions.SafetyDecision` on every call, including the
allow path. Compiling a proof must not append preview decisions to the safety
record a real run is judged by — the same reason
:func:`mayhem.controller.preflight._probe_context` clones. So every probe here
runs against :func:`_probe_context`: a copy with fresh ``decisions``/``warnings``
lists and, for the blast probe, the caller's own budget and quota (never a
lifted one — a probe through an unlimited budget could report numbers that pass
a cap the real gate refuses, which is precisely the never-calmer failure this
module exists to prevent).

## Which gate function is used where, and why

* **Capability requirements** come from
  :func:`controller.policy_gate.capability_requirements_for` — the single
  derivation the runtime gate itself uses, which plan 07 moved there verbatim so
  the adapter gate and the policy facts cannot disagree — and the verdicts from
  ``adapter.evaluate`` on the caller's adapter. Only the ``fallback`` branch is
  restated, because ``controller.safety`` states it inline. Nothing is
  re-derived here.
* **The policy gate** is read through
  :func:`controller.safety.simulate_plan_policy`, which is ``simulate_gate``
  with ``simulated=True`` over a scratch decision log. One code path, so the
  verdict compiled here is the verdict admission reaches.
* **One private helper is imported on purpose.** ``_risk_of`` is the gate's own
  catalog-risk resolution, including its ``LOW`` floor for an unknown fault id.
  Re-deriving the risk ladder here would be a second implementation that could
  disagree with admission about which faults need the critical opt-in. It is
  imported from :mod:`mayhem.controller.policy_gate`, which owns it: admission
  (``controller.safety``) and the policy facts both resolve risk through that
  one function, and ``policy_gate`` is the lower of the two modules.
* **The authoritative pass calls ``validate_plan`` without an adapter.** That is
  the same call :func:`controller.preflight.build_preflight` makes and the one
  the repository's gate tests compare against; the adapter branch is the
  capability check this module runs itself, off the shared derivation. Passing
  the adapter as well would evaluate it twice and put a second, redundant copy
  of that verdict in ``gate_refusals``.

## What the nine lines mean, and where each citation lives

============================  =================================================
obligation                    gates that feed it
============================  =================================================
``target_policy``             ``validate_plan``'s identity/environment/k8s/remote
                              checks, ``check_fault_admission``,
                              ``pre_exec_assertion`` (G3 drift), the target-side
                              blast caps and forbidden fault pairs, the five
                              plan-14 blast-radius ceilings with their measured
                              per-step values (Phase 4), and the plan-07 policy
                              gate (or a
                              :class:`~mayhem.domain.policy.PolicyDecision` when
                              one is supplied directly)
``max_concurrent_faults``     ``check_blast_radius`` stat ``concurrent_faults``
``max_duration``              ``check_blast_radius`` stat ``duration_per_fault``
``damage_budget``             ``check_blast_radius``'s
                              :class:`~mayhem.domain.quota.DamageLedger` charge
``capability_requirements``   ``capability_requirements_for`` plus
                              ``adapter.evaluate``
``compensation``              write-ahead ``undo_ops`` on the frozen
                              :class:`~mayhem.domain.experiments.PlannedFault`
``recovery_path``             ``recovery`` flag plus ``verify_probes``
``stop_conditions``           per-fault ``on_failure`` plus ``plan.slo`` parsed
                              through
                              :class:`~mayhem.domain.observations.SloCriterion`
``required_approvals``        the plan-07 gate's ``required_approvals`` (or the
                              critical-fault triple opt-in when no bundle is
                              configured), the plan-09
                              :func:`~mayhem.controller.approval_gate.verify_approvals`
                              verdict when ``SafetyContext.approval_gate`` is
                              configured (Phase 4), plus
                              :func:`mayhem.domain.execution_intent.require_execution_intent`
                              when an :class:`~mayhem.domain.execution_intent.ExecutionIntent`
                              is supplied
============================  =================================================

Three of the budget's six limits (``max_services_pct``, ``max_hosts``,
``forbidden_fault_pairs``) have no line of their own in the nine-name spine, so
they are owned by ``target_policy``: all three are statements about *which
targets this plan may touch and in which combination*. The five plan-14 ceilings
are owned there for the same reason and by the same argument — they bound the same
question from a second direction. The mapping is data (:data:`OBLIGATION_FOR_RULE`),
not folklore, so it can be read and checked in one place.

A line's ``PASS`` means "this line's own gates produced output and nothing in it
was over its cap" — not "the plan is fine". Only the proof verdict says that, and
the verdict is recomputed from all nine.

## What Phase 2 deliberately does not claim

* **Residue obligations are generated, not discharged.** They start ``VOID``
  because nothing has run; Phase 4's residue scan is what moves them. Attaching
  them to a compiled proof therefore makes that proof ``VOID`` — which is
  correct, and the reason :func:`compile_safety_proof` leaves them off by
  default.
* **The capability line reports requirements *and* present capabilities**
  because both are now derivable from public API — the shared requirement
  derivation plus ``adapter.evaluate``'s verdict map. Before plan 07 moved the
  derivation this line could only report the gate's recorded decisions, because
  the requirement set was private to the gate.
* **A plan with no fault steps cannot produce a PASS proof.** There is nothing to
  admit, compensate, recover, or interrupt, so most lines resolve ``VOID``
  ("nothing to check") rather than a vacuous pass. Refusing more than the gate is
  permitted by the acceptance rule; claiming a pass over an empty surface is
  the thing the rule exists to prevent.
* **Residue obligations are still generated here, not discharged.** Phase 4 put
  the scan, the discharge, and the seal in
  :mod:`mayhem.controller.proof_sealing`, which reads the plan-01 residue
  vocabulary. This module still only *asserts* the per-fault lines, because
  asserting them is a plan-time fact and discharging them is an observation about
  a cell that ran — two different jobs, two different modules, and the import
  direction keeps the compiler free of the store and the scan seam.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from typing import TYPE_CHECKING, Any

from mayhem.controller.approval_gate import (
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
    RULE_APPROVAL_PROOF_NOT_PASS,
    verify_approvals,
)
from mayhem.controller.approval_gate import (
    RULE_APPROVAL_REQUIRED as APPROVAL_RULE_REQUIRED,
)
from mayhem.controller.plan_diff import diff_plans
from mayhem.controller.policy_gate import (
    RULE_BUDGET_EXHAUSTED,
    RULE_BUNDLE_DENY,
    RULE_BUNDLE_EXPIRED,
    RULE_COMPAT_CONFLICT,
    RULE_LOCK_CONTENDED,
    _risk_of,
    capability_requirements_for,
)
from mayhem.controller.safety import (
    SafetyRefusedError,
    check_blast_radius,
    check_fault_admission,
    pre_exec_assertion,
    simulate_plan_policy,
    validate_plan,
)
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.execution_intent import require_execution_intent
from mayhem.domain.hashing import digest as digest_of
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.observations import CriterionKind, CriterionOperator, SloCriterion
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
    approval_refusal_reason,
    is_never_permissive,
    is_stale_against,
)
from mayhem.domain.quota import RULE_BUDGET, RULE_PER_FAULT_CEILING, DamageLedger
from mayhem.domain.risks import RiskLevel
from mayhem.domain.runtime_adapter import CapabilityRequirements
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    ResidueObligation,
    SafetyProof,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from mayhem.controller.policy_gate import RequiredApproval
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.execution_intent import ExecutionIntent
    from mayhem.domain.experiments import ExecutionPlan, PlannedFault, PlannedStep
    from mayhem.domain.policy import PolicyDecision
    from mayhem.domain.prediction import ImpactPrediction
    from mayhem.domain.runtime_adapter import RuntimeAdapter
    from mayhem.domain.topology import TopologyGraph

#: Rule ids the blast/damage gates can refuse. Used to decide which of a
#: prediction's findings are attributable to a rule the gate actually knows —
#: a prediction that flags a plan-14 *ceiling* nobody enforces yet is reporting a
#: rule this compiler cannot blame on a line.
#:
#: The five plan-14 ceilings joined this set when the ceiling rules became
#: blameable (Phase 4, second half). Before that they were filtered out here even
#: though :func:`mayhem.controller.safety.validate_plan` refuses on them, which
#: is the mirror image of the ``VOID`` problem and strictly quieter: a prediction
#: that flagged a breached ceiling contributed no blame entry at all, so the
#: artifact simply did not mention it. Both directions of the same gap are now
#: closed — the rules are enforceable (:data:`OBLIGATION_FOR_RULE`) *and*
#: predictable (:data:`GATE_RULE_IDS`).
GATE_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_MAX_SERVICES_PCT,
        RULE_MAX_HOSTS,
        RULE_MAX_CONCURRENT_FAULTS,
        RULE_MAX_DURATION_PER_FAULT_S,
        RULE_FORBIDDEN_FAULT_PAIRS,
        RULE_BUDGET,
        RULE_PER_FAULT_CEILING,
        RULE_MAX_AFFECTED_NODES,
        RULE_MAX_AFFECTED_PCT,
        RULE_MAX_CUSTOMER_FACING_SERVICES,
        RULE_MAX_DEPENDENCY_DEPTH,
        RULE_PROTECTED_NODE,
    }
)

#: The five plan-14 ceilings, narrowed out of :data:`GATE_RULE_IDS`.
#:
#: A subset for one reporting reason: the ceilings and the budget's own caps are
#: enforced by the same function and blamed on the same line, so the only thing
#: that tells them apart in the artifact is the rule id. Without this set the
#: ``target_policy`` line would say a ceiling breach happened somewhere in its
#: blast output and leave the reader to guess which number it was.
CEILING_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_MAX_AFFECTED_NODES,
        RULE_MAX_AFFECTED_PCT,
        RULE_MAX_CUSTOMER_FACING_SERVICES,
        RULE_MAX_DEPENDENCY_DEPTH,
        RULE_PROTECTED_NODE,
    }
)

#: Which obligation owns which refusal. Every rule a gate can raise appears here;
#: a rule id that does not is not ignored, it voids the proof (see
#: :func:`_blame`). Two of the budget's six limits and the whole target/fault-pair
#: family are owned by ``target_policy`` because the nine-name spine has no line
#: of their own and all of them are statements about what the plan may touch.
OBLIGATION_FOR_RULE: dict[str, str] = {
    # -- policy identity and environment ------------------------------------------
    "policy.identity_mismatch": ObligationName.TARGET_POLICY.value,
    "environment.fingerprint_mismatch": ObligationName.TARGET_POLICY.value,
    "environment.mismatch": ObligationName.TARGET_POLICY.value,
    "policy.environment_restriction": ObligationName.TARGET_POLICY.value,
    # -- fault admission ---------------------------------------------------------
    "policy.deny_faults": ObligationName.TARGET_POLICY.value,
    "policy.allow_faults": ObligationName.TARGET_POLICY.value,
    "policy.default_deny": ObligationName.TARGET_POLICY.value,
    "policy.risk_ceiling": ObligationName.TARGET_POLICY.value,
    "policy.critical_triple_optin": ObligationName.TARGET_POLICY.value,
    # -- target-side caps, fault combinations, and target support -----------------
    RULE_MAX_SERVICES_PCT: ObligationName.TARGET_POLICY.value,
    RULE_MAX_HOSTS: ObligationName.TARGET_POLICY.value,
    RULE_FORBIDDEN_FAULT_PAIRS: ObligationName.TARGET_POLICY.value,
    # -- the five plan-14 blast-radius ceilings -----------------------------------
    # Phase 4, second half, closing the debt plan 14 recorded. Same owner as the
    # two target-side caps above and for the reason that block already gives: the
    # nine-name spine has no line of its own for *how much of the system may this
    # plan touch*, and these five are exactly that question — a node count, a
    # dependency depth, a share of the fleet, a count of front doors, and a
    # protected list of ids this plan may not be pointed at. They are also raised
    # by the same function (``check_blast_radius``), so they belong beside
    # ``RULE_MAX_HOSTS`` rather than beside the three budget lines, which are
    # about concurrency, duration and damage and would misdescribe all five.
    #
    # A tenth obligation name was considered and rejected on the type, not the
    # taste: :class:`~mayhem.domain.safety_proof.ObligationName` is the *fixed*
    # nine-name spine Phase 1 shipped, and adding a line to it changes what a
    # ``PASS``-shaped proof must contain for every consumer of the artifact, for
    # a rule that is already perfectly describable on an existing line.
    RULE_MAX_AFFECTED_NODES: ObligationName.TARGET_POLICY.value,
    RULE_MAX_AFFECTED_PCT: ObligationName.TARGET_POLICY.value,
    RULE_MAX_CUSTOMER_FACING_SERVICES: ObligationName.TARGET_POLICY.value,
    RULE_MAX_DEPENDENCY_DEPTH: ObligationName.TARGET_POLICY.value,
    RULE_PROTECTED_NODE: ObligationName.TARGET_POLICY.value,
    "k8s.unsupported": ObligationName.TARGET_POLICY.value,
    "remote.unsupported": ObligationName.TARGET_POLICY.value,
    "target.drift": ObligationName.TARGET_POLICY.value,
    # -- the two budget limits that own a line -----------------------------------
    RULE_MAX_CONCURRENT_FAULTS: ObligationName.MAX_CONCURRENT_FAULTS.value,
    RULE_MAX_DURATION_PER_FAULT_S: ObligationName.MAX_DURATION.value,
    RULE_BUDGET: ObligationName.DAMAGE_BUDGET.value,
    RULE_PER_FAULT_CEILING: ObligationName.DAMAGE_BUDGET.value,
    # -- capability and execution locus -------------------------------------------
    "capability.unsupported": ObligationName.CAPABILITY_REQUIREMENTS.value,
    "execution_context.compatibility": ObligationName.CAPABILITY_REQUIREMENTS.value,
    "execution_context.refused": ObligationName.CAPABILITY_REQUIREMENTS.value,
    # -- the plan-09 approval gate -------------------------------------------------
    # Phase 4. All three refusals the approval gate can raise are statements about
    # whether *this run* was authorised, so ``required_approvals`` owns all of
    # them. They were unmapped until now, which by :func:`_blame`'s own design
    # meant an approval-refused run compiled to a ``VOID`` proof naming the rule
    # it could not place — fail-closed, but strictly less useful than the answer
    # the gate itself gives, and it hid a real ``FAIL`` behind a ``VOID``.
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED: ObligationName.REQUIRED_APPROVALS.value,
    RULE_APPROVAL_PROOF_NOT_PASS: ObligationName.REQUIRED_APPROVALS.value,
    APPROVAL_RULE_REQUIRED: ObligationName.REQUIRED_APPROVALS.value,
    # -- the plan-07 policy gate ---------------------------------------------------
    RULE_BUNDLE_EXPIRED: ObligationName.TARGET_POLICY.value,
    RULE_BUNDLE_DENY: ObligationName.TARGET_POLICY.value,
    RULE_LOCK_CONTENDED: ObligationName.TARGET_POLICY.value,
    RULE_COMPAT_CONFLICT: ObligationName.TARGET_POLICY.value,
    RULE_BUDGET_EXHAUSTED: ObligationName.DAMAGE_BUDGET.value,
}

#: The refusal the policy gate raises for an adapter block, in the gate's own
#: words (``controller.safety`` records it under this id).
RULE_CAPABILITY_UNSUPPORTED = "capability.unsupported"

#: Which line owns a policy-gate refusal whose rule id is an arbitrary
#: ``PolicyRule.rule_id``. A bundle's own rule names are chosen by whoever
#: authored the bundle, so they cannot be enumerated here; what *is* knowable is
#: which refusal it is, and only the damage budget is about damage. Everything
#: else a bundle can refuse on is a statement about what the plan may touch.
POLICY_REFUSAL_OWNER: dict[str, str] = {
    RULE_BUDGET_EXHAUSTED: ObligationName.DAMAGE_BUDGET.value,
}
DEFAULT_POLICY_REFUSAL_OWNER: str = ObligationName.TARGET_POLICY.value


@dataclass(frozen=True, slots=True)
class _Line:
    """One proof line under construction, before its digest is taken.

    ``output`` is the gate output the line is computed *from*; the digest the
    obligation cites is taken over exactly this, which is what makes
    "every PASS line traces to a gate output" checkable rather than asserted.
    """

    name: str
    gates: tuple[str, ...]
    output: dict[str, Any]
    status: ObligationStatus
    detail: str

    def with_refusals(self, reasons: tuple[str, ...]) -> _Line:
        """Downgrade to ``FAIL`` and name ``reasons`` — used by :func:`_blame`."""
        if not reasons:
            return self
        merged = f"{self.detail}; refused: {'; '.join(reasons)}" if self.detail else (
            f"refused: {'; '.join(reasons)}"
        )
        return dataclass_replace(
            self,
            output={**self.output, "refusals": list(reasons)},
            status=(
                ObligationStatus.FAIL
                if self.status is not ObligationStatus.FAIL
                else self.status
            ),
            detail=merged,
        )

    def as_obligation(self, plan_digest: str) -> Obligation:
        return Obligation(
            name=self.name,
            status=self.status,
            gate_digest=digest_of(self.output),
            evidence_ref=(
                f"gate-output/{'+'.join(self.gates)}:{self.name}@plan={plan_digest[:12]}"
            ),
            detail=self.detail,
        )


@dataclass(frozen=True, slots=True)
class SafetyCompilation:
    """A compiled proof plus the machine-readable trail that produced it.

    The proof alone cannot answer the agreement question — it carries digests,
    not rule ids — so the compiler returns the refusal sets beside it. The
    acceptance test compares ``gate_refusals`` against ``compiler_refusals``.
    """

    proof: SafetyProof
    plan_digest: str
    #: Rule ids ``validate_plan`` refused on this plan, in the gate's own words.
    gate_refusals: tuple[str, ...]
    #: Rule ids this compiler refused, i.e. the gate's plus everything the extra
    #: checks added. ``gate_refusals <= set(compiler_refusals)`` always holds.
    compiler_refusals: tuple[str, ...]
    #: Obligation name -> the rules blamed on that line.
    blame: Mapping[str, tuple[str, ...]]
    #: Non-empty when the proof was forced to ``VOID`` by something no single
    #: line can carry (an unmapped refusal, a prediction calmer than the gate).
    void_reason: str = ""


@dataclass(frozen=True, slots=True)
class _BlastProbe:
    """What one gate-shaped pass over the plan's fault steps observed."""

    steps: tuple[dict[str, Any], ...] = ()
    refusals: tuple[tuple[str, str], ...] = ()  # (rule_id, reason)
    ledger: DamageLedger | None = None
    first_refused_step: int | None = None
    #: Approval levels the plan-07 gate surfaced, carried so the approval probe
    #: can raise the quorum the same way :func:`validate_plan` does rather than
    #: re-deriving the requirements from a second bundle evaluation.
    requirements: tuple[RequiredApproval, ...] = ()
    #: The plan-14 blast ceilings the caller's context carried, or ``None`` when
    #: it carried none. Separate from the ``steps`` because it is the difference
    #: between "these limits were measured and held" and "these limits were never
    #: looked at", and an artifact that cannot tell those apart is claiming a
    #: pass it did not earn.
    ceilings: dict[str, Any] | None = None
    #: Per-step ``ceiling_*`` stats as :func:`mayhem.controller.safety
    #.check_blast_radius` returned them. These are the gate's own measurements,
    #: not a second computation: the ceilings are enforced *inside* that call, so
    #: a step either carries them or raised instead.
    ceiling_observations: tuple[dict[str, Any], ...] = ()

    @property
    def rule_ids(self) -> frozenset[str]:
        return frozenset(rule for rule, _ in self.refusals)

    def refusal_for(self, *rules: str) -> str:
        for rule, reason in self.refusals:
            if rule in rules:
                return reason
        return ""

    def worst(self, stat: str) -> float:
        return max((float(s.get(stat, 0.0)) for s in self.steps), default=0.0)


# --------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------


def canonical_plan_digest(plan: ExecutionPlan) -> str:
    """The plan's canonical digest, taken through ``plan_diff``'s definition.

    ``diff_plans`` hashes ``plan.model_dump(mode="json")`` through
    ``canonical_json``; diffing the plan against itself and reading
    ``authored_hash`` is that same hash, obtained without duplicating it. It is
    also the value :func:`mayhem.domain.prediction.plan_identity` computes, so a
    sealed prediction and a proof can be compared directly.
    """
    return str(diff_plans(plan, plan)["authored_hash"])


def _fault_steps(plan: ExecutionPlan) -> tuple[PlannedStep, ...]:
    return tuple(s for s in plan.steps if s.fault is not None)


def _probe_context(ctx: SafetyContext) -> SafetyContext:
    """A copy of ``ctx`` whose decision log starts empty.

    See the module docstring: compiling a proof must not write preview decisions
    into the safety record a real run is judged by.
    """
    return dataclass_replace(ctx, decisions=[], warnings=[])


def _decisions(ctx: SafetyContext) -> list[dict[str, Any]]:
    return [d.model_dump(mode="json") for d in ctx.decisions]


def _rule_of(exc: Exception) -> str:
    """The rule id an exception refuses on, or a marker that it refuses on none.

    ``unmapped:`` is a real answer, not a shrug: a gate raising something this
    compiler cannot place is a refusal it cannot report on a line, and
    :func:`_blame` turns that into a ``VOID`` proof rather than a silent pass.
    """
    if isinstance(exc, SafetyRefusedError):
        return exc.decision.rule_id if exc.decision is not None else exc.reason_code
    if isinstance(exc, InvariantViolationError):
        return exc.rule
    return f"unmapped:{type(exc).__name__}"


def _describe(exc: Exception) -> str:
    if isinstance(exc, SafetyRefusedError) and exc.decision is not None:
        return exc.decision.reason
    return str(exc)


# --------------------------------------------------------------------------------
# gate probes
# --------------------------------------------------------------------------------


def _authoritative(
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
) -> tuple[tuple[str, str], ...]:
    """Run the real ``validate_plan`` and return the ``(rule, reason)`` it refused.

    One pass, unchanged, on a clone. This is the ground truth the compiler is
    measured against: everything else in this module exists to explain it, and
    the acceptance rule is that explaining it may never conclude anything weaker.

    Called without an ``adapter`` — the same call
    :func:`mayhem.controller.preflight.build_preflight` makes and the one the
    repository's own gate tests compare against. The adapter branch of
    ``validate_plan`` is the capability check this module runs itself in
    :func:`_capability_probe`, off the same shared derivation, so routing it
    through here as well would evaluate the adapter twice and report one refusal
    from a function whose failure is not the compiler's to interpret.
    """
    probe = _probe_context(ctx)
    try:
        validate_plan(plan, graph, probe)
    except DomainError as exc:
        return ((_rule_of(exc), _describe(exc)),)
    return ()


def _admission_probe(plan: ExecutionPlan, ctx: SafetyContext) -> _BlastProbe:
    """``check_fault_admission`` per fault step, on a clone.

    Shares the :class:`_BlastProbe` shape with :func:`_blast_probe` so both can
    feed the blame pass uniformly; the ``ledger`` is ``None`` because admission
    charges no damage.
    """
    probe = _probe_context(ctx)
    refusals: list[tuple[str, str]] = []
    steps: list[dict[str, Any]] = []
    first: int | None = None
    for index, step in enumerate(_fault_steps(plan)):
        fault = step.fault
        assert fault is not None  # narrowed by _fault_steps
        risk = _risk_of(fault.fault_id)
        try:
            check_fault_admission(fault.fault_id, risk, probe)
        except DomainError as exc:
            if first is None:
                first = index
            refusals.append((_rule_of(exc), _describe(exc)))
            continue
        steps.append({"step": index, "fault_id": fault.fault_id, "risk": risk.value})
    return _BlastProbe(
        steps=tuple(steps),
        refusals=tuple(refusals),
        ledger=None,
        first_refused_step=first,
    )


def _drift_probe(plan: ExecutionPlan, graph: TopologyGraph) -> _BlastProbe:
    """G3: every frozen target must still resolve on the live graph.

    :func:`pre_exec_assertion` needs no ``SafetyContext`` — it re-resolves each
    frozen selector against the graph and reports ids that vanished since
    planning — so nothing here is probed against a context at all.
    """
    pairs = tuple(
        (t.selector, t.node_ids) for s in _fault_steps(plan) if s.fault for t in s.fault.targets
    )
    if not pairs:
        return _BlastProbe()
    try:
        pre_exec_assertion(pairs, graph)
    except DomainError as exc:
        return _BlastProbe(refusals=((_rule_of(exc), _describe(exc)),), first_refused_step=0)
    return _BlastProbe(
        steps=tuple({"target": str(sel), "node_ids": sorted(ids)} for sel, ids in pairs)
    )


def _capability_probe(
    plan: ExecutionPlan,
    adapter: RuntimeAdapter | None,
) -> _BlastProbe:
    """The adapter's own answers to the plan's capability requirements.

    The requirements come from :func:`controller.policy_gate.capability_requirements_for`
    — the single derivation the runtime gate itself uses, moved there verbatim so
    two copies cannot disagree about what a plan requires — and the verdicts come
    from ``adapter.evaluate`` on the same ``RuntimeAdapter`` the runtime gate
    would use. Only the ``fallback`` branch is restated, because the gate states
    it inline: when a plan requires none of the three families the gate consults,
    it evaluates a fixed probe requirement rather than an empty one.

    With no adapter the gate skips this check entirely, so nothing was measured
    and the line it feeds resolves ``VOID`` rather than passing.
    """
    if adapter is None:
        return _BlastProbe()
    requirements = capability_requirements_for(plan)
    if not (requirements.namespaces or requirements.tools or requirements.permissions):
        requirements = CapabilityRequirements(
            namespaces=frozenset({"network"}),
            tools=frozenset({"tool"}),
            permissions=frozenset({"limit"}),
        )
    result = adapter.evaluate(requirements)
    verdicts = (
        {
            "adapter": adapter.id,
            "required": {
                "namespaces": sorted(requirements.namespaces),
                "tools": sorted(requirements.tools),
                "permissions": sorted(requirements.permissions),
            },
            "present": dict(sorted(result.verdicts.items())),
        },
    )
    if not result.blocking:
        return _BlastProbe(steps=tuple(verdicts))
    message = result.refuse_with_message() or "unsupported capability requirements"
    return _BlastProbe(
        steps=tuple(verdicts),
        refusals=(
            (
                RULE_CAPABILITY_UNSUPPORTED,
                f"{adapter.id}: {message} [capability.unsupported]",
            ),
        ),
        first_refused_step=0,
    )


def _policy_probe(plan: ExecutionPlan, ctx: SafetyContext) -> _BlastProbe:
    """The plan-07 policy gate, read-only, through its own simulation entry point.

    :func:`simulate_plan_policy` is ``simulate_gate`` with ``simulated=True`` and
    a scratch decision log, so the verdict here is the verdict admission reaches
    — there is one code path, not a preview that can drift. It returns ``None``
    when the context carries no bundle, which is the same "no policy configured"
    answer :func:`validate_plan` gives.
    """
    try:
        result = simulate_plan_policy(plan, ctx)
    except DomainError as exc:
        return _BlastProbe(refusals=((_rule_of(exc), _describe(exc)),), first_refused_step=0)
    if result is None:
        return _BlastProbe()
    requirements = tuple(result.required_approvals)
    if result.refusal is not None:
        return _BlastProbe(
            steps=(dict(result.inputs()),),
            refusals=(
                (result.refusal.rule_id, result.refusal.reason),
                *((rule, result.refusal.reason) for rule in result.refusal.rule_ids()),
            ),
            first_refused_step=0,
            requirements=requirements,
        )
    return _BlastProbe(steps=(dict(result.inputs()),), requirements=requirements)


def _approval_probe(
    plan: ExecutionPlan,
    ctx: SafetyContext,
    *,
    requirements: Sequence[RequiredApproval] = (),
) -> _BlastProbe:
    """The plan-09 approval gate, read-only, through its own entry point.

    Phase 4. :func:`mayhem.controller.approval_gate.verify_approvals` is pure —
    ``now`` is a field on its inputs, no store is opened, and nothing is mutated —
    so this probe runs the same gate ``validate_plan`` runs and reads the verdict
    off the result. That is what lets the ``required_approvals`` line *read the
    approval state* instead of only restating the requirements: with no gate
    configured nothing was evaluated and the line says so, and with one
    configured the refusal is reported through its own rule id (now mapped to
    this line in :data:`OBLIGATION_FOR_RULE`) rather than arriving as an
    unplaceable refusal that voids the whole proof.

    The result is a *probe*, not a decision: it runs on the caller's own gate
    inputs without recording anything on ``ctx``, because compiling a proof must
    not append preview decisions to the safety record a real run is judged by.
    """
    inputs = ctx.approval_gate
    if inputs is None:
        return _BlastProbe()
    try:
        result = verify_approvals(plan, inputs, requirements=tuple(requirements))
    except DomainError as exc:
        return _BlastProbe(refusals=((_rule_of(exc), _describe(exc)),), first_refused_step=0)
    evidence = result.evidence()
    refusals: tuple[tuple[str, str], ...] = ()
    if result.refusal is not None:
        refusals = ((result.refusal.rule_id, result.refusal.reason),)
    return _BlastProbe(
        steps=(evidence,),
        refusals=refusals,
        first_refused_step=0 if refusals else None,
    )


def _blast_probe(plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext) -> _BlastProbe:
    """``check_blast_radius`` once per fault step, through the real budget.

    Not through a lifted one. ``preflight`` uses an unrestricted probe to show an
    operator how far over a cap a step is, and that is right for a preview; it
    would be wrong here, because a step refused by the real budget produces no
    ``stats`` and probing it through an unlimited budget would let this module
    report a passing number for a cap the gate refuses.

    **The plan-14 ceilings are read off this same call, not off a second one.**
    :func:`mayhem.controller.safety.check_blast_radius` enforces them internally,
    after the budget's caps and before the damage charge, so a ceiling breach
    arrives here as an ordinary refusal with the gate's own rule id and reason and
    is attributable to ``target_policy`` by :data:`OBLIGATION_FOR_RULE`. Probing
    them separately would mean calling the gate twice on the same step and
    reporting whichever answer came back second — and a second call is a second
    chance to disagree with the run the proof is about.
    """
    probe = _probe_context(ctx)
    ledger = DamageLedger()
    steps: list[dict[str, Any]] = []
    refusals: list[tuple[str, str]] = []
    seen: list[str] = []
    first: int | None = None
    for index, step in enumerate(_fault_steps(plan)):
        fault = step.fault
        assert fault is not None
        target_ids = frozenset().union(*(t.node_ids for t in fault.targets))
        try:
            stats = check_blast_radius(
                graph,
                target_ids,
                float(fault.duration),
                tuple(seen),
                fault.fault_id,
                ctx=probe,
                ledger=ledger,
            )
        except DomainError as exc:
            if first is None:
                first = index
            refusals.append((_rule_of(exc), _describe(exc)))
            seen.append(fault.fault_id)
            continue
        steps.append(
            {"step": index, "fault_id": fault.fault_id, "targets": sorted(target_ids), **stats}
        )
        seen.append(fault.fault_id)
    return _BlastProbe(
        steps=tuple(steps),
        refusals=tuple(refusals),
        ledger=ledger,
        first_refused_step=first,
        ceilings=_ceilings_configured(ctx),
        ceiling_observations=tuple(_ceiling_observation(s) for s in steps),
    )


#: ``stats`` keys :func:`mayhem.controller.safety._check_blast_ceilings` returns.
#: Matched by prefix rather than enumerated because the gate owns that spelling: a
#: sixth ceiling added there is reported on ``target_policy`` without this module
#: being edited, and editing this module to enumerate them is exactly how the two
#: would drift.
_CEILING_STAT_PREFIX = "ceiling_"


def _ceiling_observation(step: dict[str, Any]) -> dict[str, Any]:
    """One step's ``ceiling_*`` stats, as the gate returned them.

    An empty observation is meaningful and is kept rather than filtered out: a
    step with no ceiling keys is a step the ceilings did not measure, and dropping
    it would make "measured nothing" indistinguishable from "not a step".
    """
    return {
        "step": step["step"],
        "fault_id": step["fault_id"],
        **{
            key: value
            for key, value in step.items()
            if key.startswith(_CEILING_STAT_PREFIX)
        },
    }


def _ceilings_configured(ctx: SafetyContext) -> dict[str, Any] | None:
    """The plan-14 ceilings admission will enforce, as the context carries them.

    ``None`` — not an empty dict — when nothing is configured, because that
    difference is the entire reason this is reported. ``BlastCeilings()`` with
    every field ``None`` *is* a configuration that names no limit, and the gate
    then checks none; rendering it as ``{}`` would let a reader mistake "no
    ceilings" for "every ceiling satisfied", which is the failure mode plan 14's
    own docstring calls out for a prediction that cannot measure a limit.
    """
    ceilings = ctx.blast_ceilings
    if ceilings is None:
        return None
    return {
        "max_affected_nodes": ceilings.max_affected_nodes,
        "max_dependency_depth": ceilings.max_dependency_depth,
        "max_customer_facing_services": ceilings.max_customer_facing_services,
        "max_affected_pct": ceilings.max_affected_pct,
        "protected_node_ids": sorted(ceilings.protected_node_ids),
    }


def _names_a_limit(value: Any) -> bool:
    """Whether a configured ceiling field asks for a limit at all.

    Two shapes say "nobody asked for this" and neither is a satisfied ceiling: a
    ``None`` — the model default for every field — and an *empty* collection,
    which is what ``protected_node_ids`` looks like when nothing is protected.

    Deliberately not ``bool(value)``. ``bool(0)`` is ``False``, and a zero is a
    real and very tight limit: ``max_customer_facing_services=0`` is the
    front-doors-must-not-fall-over ceiling, and treating it as unconfigured would
    drop the one configured ceiling most likely to have just been measured
    against. The count of configured ceilings is a safety claim about what was
    checked, so it is not allowed to be wrong in the flattering direction.
    """
    if value is None:
        return False
    if isinstance(value, (str, bytes)):
        return bool(value)
    if isinstance(value, (frozenset, set, list, tuple, dict)):
        return len(value) > 0
    return True


#: ``ceiling_*`` stat name -> the configured field it was compared against, for
#: the one pair whose two names share no words.
#:
#: Four of the five are paired by :func:`_ceiling_field`'s word test without
#: being written down here, and that is the point: this is a record of the
#: *exception*, not an enumeration of the ceilings. The gate measures the
#: protected list by counting what it hit, so it reports ``ceiling_protected_hits``
#: where the ceiling it enforces is ``protected_node_ids`` — no shared word, so
#: no derivation can recover it, and a derivation that guessed instead would risk
#: pairing a measurement with the wrong limit. A sixth ceiling added to the gate
#: still needs no entry here: its stat reaches :func:`_ceiling_field` first, and
#: if it also cannot be derived it lands in the disclosed-unpaired clause rather
#: than disappearing.
_CEILING_STAT_FIELD: dict[str, str] = {"protected_hits": "protected_node_ids"}


def _ceiling_field(limits: dict[str, Any], stat: str) -> str | None:
    """The configured ceiling a ``ceiling_<stat>`` observation was compared to.

    Matched by shared words rather than by an enumerated table, because the two
    sides do not spell the same ceiling the same way — the gate reports
    ``ceiling_dependency_depth`` and ``ceiling_affected_pct`` where the ceilings
    it enforces are ``max_dependency_depth`` and ``max_affected_pct`` — and
    pairing them positionally would be a second vocabulary for the same five
    ceilings that would drift silently the moment the gate reordered or inserted
    one.

    A stat that shares *no* word with a field is not paired by guessing; only
    :data:`_CEILING_STAT_FIELD` may pair it. An ambiguous match is likewise
    refused rather than resolved by sort order, because reporting a number next
    to the wrong limit is worse than reporting it next to none.

    ``None`` when no configured ceiling claims the stat, which is a real case and
    not an error: ``_check_blast_ceilings`` emits ``ceiling_protected_hits``
    unconditionally, so an empty ``protected_node_ids`` yields a measurement with
    no configured limit behind it. The caller reports that separately rather than
    folding it into the configured list, because "0 hits" against a limit nobody
    set is not a ceiling that held.

    Returns ``None`` rather than raising so an unpaired stat stays *disclosed*
    (see :func:`_ceilings_note`) instead of vanishing.
    """
    aliased = _CEILING_STAT_FIELD.get(stat)
    if aliased is not None and aliased in limits:
        return aliased
    stat_words = set(stat.split("_"))
    matches = [
        field for field in sorted(limits) if stat_words <= set(field.split("_"))
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _ceilings_note(blast: _BlastProbe) -> str:
    """The plan-14 ceilings, each beside the number the gate measured against it.

    Counts alone are not a measurement. "4 ceiling(s) configured" would render
    identically for a plan that ran every comparison, for one where a single
    measurement was taken, and for one where the ceilings were configured and
    then skipped because the graph was empty — so the note pairs every
    configured ceiling with the observed value the gate returned for it, on the
    allow path, where nothing is refusing and the artifact is the only evidence
    the check ran.

    The three shapes it can report are the three things that are true:

    * **No ceilings carried at all.** ``ctx.blast_ceilings is None``. Nothing was
      compared, and the note says so in words rather than in a count, because a
      count of zero here reads as "nothing breached".
    * **A ceiling block that names no limit.** Every field ``None`` or empty.
      Distinct from the case above, and *not* a measurement either: the gate ran
      its block and the block contained no limits. Rendering it as "0 configured
      ceiling(s)" would be true and useless; rendering it as "all ceilings held"
      would be a pass nobody earned.
    * **At least one limit.** Then each one is rendered as observed-against-limit,
      and anything the gate reported with no configured limit behind it is named
      separately so it cannot be mistaken for a ceiling that held.

    Numbers come from :attr:`_BlastProbe.ceiling_observations`, which is the
    ``check_blast_radius`` call's own ``stats``. Nothing here recomputes a blast
    measurement: a second computation is a second chance to disagree with the
    run the proof is about.
    """
    if blast.ceilings is None:
        return (
            "; no plan-14 blast ceilings configured, so those five limits were "
            "unchecked rather than satisfied"
        )
    limits = {name: value for name, value in blast.ceilings.items() if _names_a_limit(value)}
    if not limits:
        return (
            "; a plan-14 blast-ceiling block was carried but named no limit, so no "
            "ceiling was compared against anything and none is reported as satisfied"
        )

    worst: dict[str, float] = {}
    unpaired: dict[str, float] = {}
    measured_steps = 0
    for observation in blast.ceiling_observations:
        paired_here = False
        for key, value in observation.items():
            if not key.startswith(_CEILING_STAT_PREFIX):
                continue
            stat = key[len(_CEILING_STAT_PREFIX) :]
            field = _ceiling_field(limits, stat)
            if field is None:
                unpaired[stat] = _worst(unpaired.get(stat), value)
                continue
            paired_here = True
            worst[field] = _worst(worst.get(field), value)
        # A step counts as measured only if a *configured* ceiling was actually
        # compared on it. ``_ceiling_observation`` always carries ``step`` and
        # ``fault_id``, so testing the observation for truth would count every
        # step as measured and report a number that cannot be 0 — including for
        # the step whose one configured ceiling was unmeasurable, which is the
        # step an operator most needs counted honestly.
        measured_steps += paired_here

    pairings = ", ".join(
        _ceiling_pairing(name, limit, worst.get(name)) for name, limit in sorted(limits.items())
    )
    note = (
        f"; {measured_steps}/{len(blast.ceiling_observations)} step(s) measured against the "
        f"{len(limits)} configured plan-14 ceiling(s): {pairings}"
    )
    if unpaired:
        note += (
            "; the gate also reported "
            + ", ".join(
                f"{stat} {_ceiling_number(value)}" for stat, value in sorted(unpaired.items())
            )
            + " against no configured ceiling"
        )
    return note


def _worst(seen: float | None, value: Any) -> float:
    """The larger of a running maximum and a new observation.

    Every admitted step was compared and none exceeded its limit, so the largest
    value across steps is the tightest comparison the ceilings actually faced.
    Reporting that number is reporting what was measured; reporting a per-step
    list instead would imply the aggregate was one step's reading.
    """
    as_float = float(value)
    return as_float if seen is None else max(seen, as_float)


def _ceiling_pairing(name: str, limit: Any, observed: float | None) -> str:
    """One configured ceiling and the number it was compared against.

    Three renderings, because three things can be true and the difference is the
    whole report: the ceiling was measured and held, the ceiling was configured
    but nothing on any admitted step could measure it, or — for the protected
    list, whose "limit" is a set rather than a number — it was measured as a
    count of hits against a count of configured entries.
    """
    if isinstance(limit, (frozenset, set, list, tuple)):
        # A list limit has no single number to compare against, so the
        # "unmeasured" half of this branch names what was configured instead of
        # trying to render the set as a scalar.
        if observed is None:
            return (
                f"{name} configured with {len(limit)} protected node(s) but "
                "unmeasured on every admitted step"
            )
        return f"{name} {_ceiling_number(observed)} hit(s) against {len(limit)} configured"
    if observed is None:
        return (
            f"{name} configured at {_ceiling_number(limit)} but unmeasured on every "
            "admitted step"
        )
    return f"{name} {_ceiling_number(observed)} <= {_ceiling_number(limit)}"


def _ceiling_number(value: Any) -> str:
    """A ceiling reading as a short number.

    ``:g`` because every ``ceiling_*`` stat is a ``dict[str, float]`` the gate
    typed as float, and ``3.0`` next to a configured ``3`` reads like two
    different numbers in an artifact whose entire job is to show that they were
    compared.
    """
    return f"{float(value):g}"


# --------------------------------------------------------------------------------
# line builders
# --------------------------------------------------------------------------------


def _cap_line(
    probe: _BlastProbe,
    *,
    name: str,
    cap: str,
    stat: str,
    budget: float,
    observed_key: str,
    noun: str,
) -> _Line:
    """A blast line of the shape "worst ``stat`` over measured steps vs. a cap".

    One builder for ``max_concurrent_faults`` and ``max_duration`` because they
    are the same check with different numbers, and a divergence between two
    hand-written copies of the same comparison is a bug waiting for a review to
    miss it.
    """
    worst = probe.worst(stat)
    over = worst > float(budget)
    output = {
        "gate": "controller.safety.check_blast_radius",
        "cap": cap,
        "budget": float(budget),
        "observed": {
            observed_key: worst,
            "measured_steps": len(probe.steps),
            "truncated_at_step": probe.first_refused_step,
        },
        "steps": [dict(s) for s in probe.steps],
    }
    if not probe.steps:
        # No step produced stats. Either a per-step cap fired first (so the
        # blame pass will FAIL this line by name) or the plan has no fault steps
        # at all — in which case nothing was measured and the line is VOID, not a
        # vacuous pass.
        return _Line(
            name=name,
            gates=("controller.safety.check_blast_radius",),
            output=output,
            status=(
                ObligationStatus.FAIL if probe.rule_ids else ObligationStatus.VOID
            ),
            detail=(
                f"no fault step produced blast stats, so the {cap} limit was never "
                f"evaluated: "
                f"{'; '.join(r for _, r in probe.refusals) or 'no fault step to measure'}"
            ),
        )
    return _Line(
        name=name,
        gates=("controller.safety.check_blast_radius",),
        output=output,
        status=ObligationStatus.FAIL if over else ObligationStatus.PASS,
        detail=(
            f"worst {noun} {worst:g} against cap {float(budget):g} over "
            f"{len(probe.steps)} measured step(s)"
        ),
    )


def _line_damage_budget(
    probe: _BlastProbe,
    quota: dict[str, Any],
    extra: Iterable[str] = (),
) -> _Line:
    ledger = probe.ledger
    total = ledger.total_s if ledger is not None else 0.0
    worst_node = ledger.worst_node if ledger is not None else ""
    worst_s = ledger.worst_node_s if ledger is not None else 0.0
    by_node = ledger.by_node() if ledger is not None else {}
    budget_s = float(quota.get("budget_s", 0.0))
    over = bool(worst_s > budget_s)
    charged = ledger.steps if ledger is not None else 0
    if charged == 0:
        return _Line(
            name=ObligationName.DAMAGE_BUDGET.value,
            gates=("controller.safety.check_blast_radius", "domain.quota.DamageLedger"),
            output={
                "gate": "controller.safety.check_blast_radius",
                "quota": quota,
                "observed": {"charged_steps": 0, "truncated_at_step": probe.first_refused_step},
                "also_blamed": list(extra),
            },
            status=ObligationStatus.FAIL if probe.rule_ids else ObligationStatus.VOID,
            detail=(
                "no fault step reached the damage ledger: the cumulative budget "
                "was never evaluated"
            ),
        )
    return _Line(
        name=ObligationName.DAMAGE_BUDGET.value,
        gates=("controller.safety.check_blast_radius", "domain.quota.DamageLedger"),
        output={
            "gate": "controller.safety.check_blast_radius",
            "quota": quota,
            "observed": {
                "total_damage_s": round(total, 3),
                "worst_node": worst_node,
                "worst_node_damage_s": round(worst_s, 3),
                "worst_node_headroom_s": round(budget_s - worst_s, 3),
                "charged_steps": charged,
                "truncated_at_step": probe.first_refused_step,
            },
            "by_node": {node: round(value, 3) for node, value in by_node.items()},
            "steps": [dict(s) for s in probe.steps],
            "also_blamed": list(extra),
        },
        status=ObligationStatus.FAIL if over else ObligationStatus.PASS,
        detail=(
            f"worst target {worst_node or '(none)'} accumulated {worst_s:g} damage-seconds "
            f"against budget {budget_s:g} over {charged} charged step(s); "
            f"plan total {total:g}"
        ),
    )


def _line_capability(probe: _BlastProbe, adapter: RuntimeAdapter | None) -> _Line:
    output = {
        "gate": "controller.policy_gate.capability_requirements_for + adapter.evaluate",
        "adapter": adapter.id if adapter is not None else "",
        "verdicts": [dict(s) for s in probe.steps],
    }
    if adapter is None:
        return _Line(
            name=ObligationName.CAPABILITY_REQUIREMENTS.value,
            gates=("controller.policy_gate.capability_requirements_for", "adapter.evaluate"),
            output=output,
            status=ObligationStatus.VOID,
            detail=(
                "no runtime adapter supplied: validate_plan skips the capability check, so "
                "capability requirements were not evaluated and this line cannot pass"
            ),
        )
    return _Line(
        name=ObligationName.CAPABILITY_REQUIREMENTS.value,
        gates=("controller.policy_gate.capability_requirements_for", "adapter.evaluate"),
        output=output,
        status=ObligationStatus.FAIL if probe.rule_ids else ObligationStatus.PASS,
        detail=(
            f"adapter {adapter.id} answered the plan's capability requirements; "
            f"{len(probe.steps)} requirement set(s) evaluated"
        ),
    )


def _line_target_policy(
    plan: ExecutionPlan,
    ctx: SafetyContext,
    *,
    admission: _BlastProbe,
    drift: _BlastProbe,
    blast: _BlastProbe,
    policy_decision: PolicyDecision | None,
    policy: _BlastProbe,
    prediction: ImpactPrediction | None,
    prediction_notes: tuple[str, ...] = (),
) -> _Line:
    faults = _fault_steps(plan)
    output: dict[str, Any] = {
        "gate": "controller.safety.validate_plan",
        "admission": [dict(s) for s in admission.steps],
        "target_drift": [dict(s) for s in drift.steps],
        "target_side_blast": [
            {
                "step": s["step"],
                "fault_id": s["fault_id"],
                "services_pct": s.get("services_pct"),
                "hosts": s.get("hosts"),
            }
            for s in blast.steps
        ],
        # The plan-14 ceilings, reported from the same ``check_blast_radius``
        # call that enforced them. Two keys and a basis, because the question a
        # reader of this line actually has is "what was checked", and "configured"
        # and "measured" answer different halves of it: a ceiling left at ``None``
        # is *unchecked*, not satisfied, so the two cannot be collapsed into one
        # number without the artifact claiming a pass nobody earned.
        "plan14_blast_ceilings": {
            "configured": blast.ceilings,
            "measured": [dict(o) for o in blast.ceiling_observations],
            "refused_on": sorted(blast.rule_ids & CEILING_RULE_IDS),
            "basis": (
                "no ceilings configured: controller.safety.check_blast_radius checked "
                "none, so these limits are unmeasured rather than satisfied"
                if blast.ceilings is None
                else "controller.safety._check_blast_ceilings, per fault step, through "
                "the same check_blast_radius call that refused on them"
            ),
        },
        "forbidden_fault_pairs": sorted(
            sorted(pair) for pair in ctx.budget.forbidden_fault_pairs
        ),
        "policy_decision": (
            policy_decision.model_dump(mode="json") if policy_decision is not None else None
        ),
        "policy_config": ctx.policy.model_dump(mode="json"),
        "allow_critical_cli": ctx.allow_critical_cli,
        "policy_id": plan.policy_id,
        "context_policy_id": ctx.policy_id,
        "environment_fingerprint": plan.environment_fingerprint,
        "context_fingerprint": ctx.fingerprint,
        "environment": ctx.environment,
        "fault_count": len(faults),
        "policy_gate": [dict(s) for s in policy.steps],
        "policy_refusals": [rule for rule, _ in policy.refusals],
        "prediction_rule_ids": sorted(prediction.rule_ids) if prediction is not None else None,
        "prediction_notes": list(prediction_notes),
    }
    note = f" ({'; '.join(prediction_notes)})" if prediction_notes else ""
    if not faults:
        return _Line(
            name=ObligationName.TARGET_POLICY.value,
            gates=("controller.safety.validate_plan", "controller.safety.check_fault_admission"),
            output=output,
            status=ObligationStatus.VOID,
            detail=(
                "plan has no fault steps: no target or fault was admitted, so this line "
                f"has no admission decision to cite{note}"
            ),
        )
    if policy_decision is not None and policy_decision.denied:
        return _Line(
            name=ObligationName.TARGET_POLICY.value,
            gates=(
                "controller.safety.validate_plan",
                "controller.safety.check_fault_admission",
                "controller.policy_gate.evaluate_gate",
            ),
            output=output,
            status=ObligationStatus.FAIL,
            detail=(
                f"policy decision {policy_decision.describe()} denied the plan: "
                f"{'; '.join(policy_decision.reasons) or 'no reason recorded'}{note}"
            ),
        )
    if policy.rule_ids:
        return _Line(
            name=ObligationName.TARGET_POLICY.value,
            gates=(
                "controller.safety.validate_plan",
                "controller.safety.check_fault_admission",
                "controller.policy_gate.evaluate_gate",
            ),
            output=output,
            status=ObligationStatus.FAIL,
            detail=(
                f"the plan-07 policy gate refused on "
                f"{', '.join(sorted(policy.rule_ids))}{note}"
            ),
        )
    ceilings_note = _ceilings_note(blast)
    return _Line(
        name=ObligationName.TARGET_POLICY.value,
        gates=("controller.safety.validate_plan", "controller.safety.check_fault_admission"),
        output=output,
        status=ObligationStatus.PASS,
        detail=(
            f"{len(faults)} fault step(s) admitted under policy {ctx.policy_id or '(default)'}; "
            f"{len(admission.steps)} admission decision(s), "
            f"{len(drift.steps)} frozen target(s) re-resolved, "
            f"{len(blast.steps)} step(s) within the target-side caps"
            f"{ceilings_note}"
            f"{', policy bundle permits the plan' if policy.steps else ''}{note}"
        ),
    )


def _line_compensation(plan: ExecutionPlan) -> _Line:
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    for step in _fault_steps(plan):
        fault: PlannedFault = step.fault  # type: ignore[assignment]
        scope = fault.target
        kubernetes = scope is not None and scope.runtime == RuntimeLabel.KUBERNETES
        if kubernetes:
            basis = "kubernetes driver carries the compensation contract"
        elif not fault.recovery:
            basis = "self-healing mode: the perturbation is left in place by design"
        elif fault.undo_ops and fault.verify_probes:
            basis = "write-ahead undo ops and verify probes compiled at plan time"
        else:
            basis = "no write-ahead undo contract"
            missing.append(fault.fault_id)
        rows.append(
            {
                "step": step.seq,
                "fault_id": fault.fault_id,
                "undo_ops": len(fault.undo_ops),
                "verify_probes": len(fault.verify_probes),
                "recovery": fault.recovery,
                "runtime": scope.runtime.value if scope is not None else "",
                "basis": basis,
            }
        )
    output = {
        "gate": "experiments.PlannedFault.undo_ops",
        "faults": rows,
        "uncompensated": missing,
    }
    if not rows:
        return _Line(
            name=ObligationName.COMPENSATION.value,
            gates=("experiments.PlannedFault.undo_ops",),
            output=output,
            status=ObligationStatus.VOID,
            detail="plan has no fault steps: there is nothing to compensate",
        )
    if missing:
        return _Line(
            name=ObligationName.COMPENSATION.value,
            gates=("experiments.PlannedFault.undo_ops",),
            output=output,
            status=ObligationStatus.FAIL,
            detail=(
                f"{len(missing)} fault(s) carry no write-ahead undo contract: "
                f"{', '.join(sorted(set(missing)))}"
            ),
        )
    return _Line(
        name=ObligationName.COMPENSATION.value,
        gates=("experiments.PlannedFault.undo_ops",),
        output=output,
        status=ObligationStatus.PASS,
        detail=(
            f"{len(rows)} fault step(s) carry a compensation contract "
            f"({sum(1 for r in rows if r['undo_ops'])} with write-ahead undo ops, "
            f"{sum(1 for r in rows if not r['recovery'])} in self-healing mode)"
        ),
    )


def _line_recovery_path(plan: ExecutionPlan) -> _Line:
    rows: list[dict[str, Any]] = []
    unverifiable: list[str] = []
    for step in _fault_steps(plan):
        fault: PlannedFault = step.fault  # type: ignore[assignment]
        needs_probes = bool(fault.recovery)
        if needs_probes and not fault.verify_probes:
            unverifiable.append(fault.fault_id)
        rows.append(
            {
                "step": step.seq,
                "fault_id": fault.fault_id,
                "recovery": fault.recovery,
                "on_failure": fault.on_failure.value,
                "verify_probes": len(fault.verify_probes),
            }
        )
    output = {
        "gate": "experiments.PlannedFault.verify_probes",
        "faults": rows,
        "unverifiable": sorted(set(unverifiable)),
    }
    if not rows:
        return _Line(
            name=ObligationName.RECOVERY_PATH.value,
            gates=("experiments.PlannedFault.verify_probes",),
            output=output,
            status=ObligationStatus.VOID,
            detail="plan has no fault steps: there is no recovery path to state",
        )
    if unverifiable:
        return _Line(
            name=ObligationName.RECOVERY_PATH.value,
            gates=("experiments.PlannedFault.verify_probes",),
            output=output,
            status=ObligationStatus.FAIL,
            detail=(
                f"{len(set(unverifiable))} fault(s) promise recovery with no verify probe, so "
                f"recovered is unobservable: {', '.join(sorted(set(unverifiable)))}"
            ),
        )
    return _Line(
        name=ObligationName.RECOVERY_PATH.value,
        gates=("experiments.PlannedFault.verify_probes",),
        output=output,
        status=ObligationStatus.PASS,
        detail=(
            f"{len(rows)} fault step(s) declare a failure policy and a recovery signal; "
            f"{sum(1 for r in rows if r['on_failure'] == 'abort_and_recover')} abort and recover"
        ),
    )


def _criterion_problems(criterion: SloCriterion) -> tuple[str, ...]:
    """Why this stop criterion could never fire as written, if that is the case."""
    problems: list[str] = []
    if not str(criterion.metric).strip():
        problems.append("names no metric, so it can never be evaluated")
    kind = str(criterion.kind)
    if kind not in {member.value for member in CriterionKind}:
        problems.append(f"unknown criterion kind {kind!r}")
    operator = str(criterion.operator)
    if operator not in {member.value for member in CriterionOperator}:
        problems.append(f"unknown operator {operator!r}")
    return tuple(problems)


def _line_stop_conditions(plan: ExecutionPlan) -> _Line:
    rows: list[dict[str, Any]] = []
    malformed: list[str] = []
    for step in _fault_steps(plan):
        fault: PlannedFault = step.fault  # type: ignore[assignment]
        try:
            on_failure = fault.on_failure.value
        except AttributeError:
            on_failure = str(fault.on_failure)
        rows.append({"step": step.seq, "fault_id": fault.fault_id, "on_failure": on_failure})
    criteria: list[dict[str, Any]] = []
    for index, raw in enumerate(plan.slo):
        try:
            parsed = SloCriterion(**raw)
        except (TypeError, ValueError) as exc:
            malformed.append(f"slo[{index}]: {exc}")
            continue
        # ``SloCriterion`` is a plain dataclass, so an unknown key raises but an
        # unknown *value* does not: ``operator="maybe"`` constructs cleanly and
        # then fails at evaluation time, which is the "stop condition that can
        # never fire" defect this module's siblings already refuse. The check
        # below is the authoring-time twin of that refusal.
        problems = _criterion_problems(parsed)
        if problems:
            malformed.extend(f"slo[{index}]: {problem}" for problem in problems)
            continue
        criteria.append(
            {
                "index": index,
                "criterion_id": parsed.criterion_id,
                "kind": str(parsed.kind),
                "metric": parsed.metric,
                "operator": str(parsed.operator),
                "threshold": parsed.threshold,
                "unit": parsed.unit,
                "window_s": parsed.window_s,
            }
        )
    output = {
        "gate": "experiments.PlannedFault.on_failure + observations.SloCriterion",
        "fault_stop_policies": rows,
        "slo_criteria": criteria,
        "malformed_criteria": malformed,
    }
    if not rows and not criteria:
        return _Line(
            name=ObligationName.STOP_CONDITIONS.value,
            gates=("experiments.PlannedFault.on_failure", "observations.SloCriterion"),
            output=output,
            status=ObligationStatus.VOID,
            detail=(
                "plan declares no stop surface: no fault failure policy and no SLO criterion, "
                "so nothing can interrupt it and nothing can be checked"
            ),
        )
    if malformed:
        return _Line(
            name=ObligationName.STOP_CONDITIONS.value,
            gates=("experiments.PlannedFault.on_failure", "observations.SloCriterion"),
            output=output,
            status=ObligationStatus.FAIL,
            detail=(
                f"{len(malformed)} declared stop condition(s) do not parse into a criterion: "
                f"{'; '.join(malformed)}"
            ),
        )
    return _Line(
        name=ObligationName.STOP_CONDITIONS.value,
        gates=("experiments.PlannedFault.on_failure", "observations.SloCriterion"),
        output=output,
        status=ObligationStatus.PASS,
        detail=(
            f"{len(rows)} fault-level stop policy(ies) and {len(criteria)} SLO criterion(ies) "
            f"parsed and named a metric"
        ),
    )


def _line_required_approvals(
    plan: ExecutionPlan,
    ctx: SafetyContext,
    plan_digest: str,
    policy: _BlastProbe,
    approval: _BlastProbe,
    *,
    intent: ExecutionIntent | None,
    engine: str,
    target_identity: str,
) -> _Line:
    """Approval *requirements* for this plan, the approval gate's own verdict, and
    any presented intent's verdict.

    The requirements come from the plan-07 policy gate when a bundle is
    configured — the gate's own :class:`RequiredApproval` records, which are the
    levels a decision says must be approved before the plan may stand — and from
    the critical-fault triple opt-in when it is not.

    Phase 4 adds the middle term: when ``ctx.approval_gate`` is configured, the
    line reports the plan-09 gate's actual verdict and the sealed evidence
    payload it produced, so ``required_approvals`` reads *the approval state*
    rather than only restating what an approval would have to say. With no gate
    configured nothing was evaluated, and the line says exactly that — a
    requirement restated is not an authorization read.
    """
    try:
        gate_result = simulate_plan_policy(plan, ctx)
    except DomainError:
        gate_result = None
    required = (
        [
            {
                "approval_level": approval_level.approval_level,
                "policy_rule_id": approval_level.rule_id,
                "reason": approval_level.reason,
                "remediation": approval_level.remediation,
            }
            for approval_level in (
                gate_result.required_approvals if gate_result is not None else ()
            )
        ]
        if gate_result is not None
        else []
    )
    critical = sorted(
        {
            f.fault_id
            for f in (step.fault for step in _fault_steps(plan))
            if f is not None and _risk_of(f.fault_id) is RiskLevel.CRITICAL
        }
    )
    requirements = {
        "plan_digest": plan_digest,
        "plan_hash_binding": "required: an approval that names no plan authorises nothing",
        "policy_approvals": required,
        "critical_faults_requiring_explicit_ack": critical,
        "policy_allow_critical": ctx.policy.allow_critical,
        "critical_fault_acks": sorted(ctx.policy.critical_fault_acks),
        "engine": engine,
        "target_identity": target_identity,
        "intent_supplied": intent is not None,
        "intent_actor": intent.actor if intent is not None else "",
        "intent_break_glass": intent.break_glass if intent is not None else False,
        "intent_expired": intent.is_expired() if intent is not None else None,
        # Phase 4: the approval *state*, as the plan-09 gate itself reported it.
        # ``configured`` is separate from ``steps`` on purpose — an empty evidence
        # list would be indistinguishable from "the gate ran and said nothing".
        "approval_gate_configured": ctx.approval_gate is not None,
        "approval_gate_verdict": [dict(step) for step in approval.steps],
        "approval_gate_refusals": [rule for rule, _ in approval.refusals],
    }
    output = {
        "gate": "controller.policy_gate.required_approvals + "
        "controller.approval_gate.verify_approvals + "
        "domain.execution_intent.require_execution_intent",
        "requirements": requirements,
        "policy_gate_recorded": [rule for rule, _ in policy.refusals],
    }
    wanted = (
        f"{len(required)} policy approval level(s) required"
        if required
        else f"{len(critical)} critical fault(s) need an explicit ack: {', '.join(critical)}"
    )
    if ctx.approval_gate is not None:
        return _approval_line(
            output=output,
            approval=approval,
            wanted=wanted,
            plan_digest=plan_digest,
        )
    if intent is None:
        return _Line(
            name=ObligationName.REQUIRED_APPROVALS.value,
            gates=("controller.policy_gate.required_approvals",),
            output=output,
            status=ObligationStatus.PASS,
            detail=(
                f"approval requirements established for plan {plan_digest[:12]}: {wanted}, "
                f"and any approval must bind this plan digest. No intent presented at compile "
                f"time — the grant itself is bound in a later phase, against the proof digest"
            ),
        )
    try:
        require_execution_intent(
            intent,
            plan_hash=plan_digest,
            engine=engine,
            target_identity=target_identity,
            allow_implicit=None,
        )
    except DomainError as exc:
        return _Line(
            name=ObligationName.REQUIRED_APPROVALS.value,
            gates=("domain.execution_intent.require_execution_intent",),
            output={**output, "refusals": [str(exc)]},
            status=ObligationStatus.FAIL,
            detail=f"the presented execution intent does not authorise this plan: {exc}",
        )
    return _Line(
        name=ObligationName.REQUIRED_APPROVALS.value,
        gates=("domain.execution_intent.require_execution_intent",),
        output=output,
        status=ObligationStatus.PASS,
        detail=(
            f"approval requirements established ({wanted}) and the presented intent "
            f"(actor {intent.actor or '(unnamed)'}) verifies against plan {plan_digest[:12]}"
        ),
    )


def _approval_line(
    *,
    output: dict[str, Any],
    approval: _BlastProbe,
    wanted: str,
    plan_digest: str,
) -> _Line:
    """The ``required_approvals`` line once the plan-09 gate has actually run.

    Split out of :func:`_line_required_approvals` because the two cases answer
    different questions. Without a gate the line can only state a requirement;
    with one it can report a decision, and a decision has exactly two honest
    shapes here — the gate refused (a finding, so ``FAIL``) or it allowed (a
    reading, so ``PASS`` with the approvers named).
    """
    gates = (
        "controller.approval_gate.verify_approvals",
        "controller.policy_gate.required_approvals",
    )
    if approval.rule_ids:
        return _Line(
            name=ObligationName.REQUIRED_APPROVALS.value,
            gates=gates,
            output=output,
            status=ObligationStatus.FAIL,
            detail=(
                f"the approval gate refused on "
                f"{', '.join(sorted(approval.rule_ids))}: {wanted}"
            ),
        )
    state = approval.steps[0] if approval.steps else {}
    approvers = list((state.get("approvals") or {}).get("approvers") or []) if state else []
    return _Line(
        name=ObligationName.REQUIRED_APPROVALS.value,
        gates=gates,
        output=output,
        status=ObligationStatus.PASS,
        detail=(
            f"the approval gate authorized plan {plan_digest[:12]}: {wanted}; "
            f"{len(approvers)} approval(s) bound to the compiled proof digest"
            + (f" from {', '.join(approvers)}" if approvers else "")
        ),
    )


# --------------------------------------------------------------------------------
# blame and assembly
# --------------------------------------------------------------------------------


def _blame(
    lines: dict[str, _Line],
    refusals: Iterable[tuple[str, str]],
    extra_owners: Mapping[str, str] | None = None,
) -> tuple[dict[str, _Line], dict[str, tuple[str, ...]], tuple[str, ...]]:
    """Downgrade every line a refusal belongs to. The acceptance rule, in code.

    ``refusals`` carries the authoritative gate's rules first and the compiler's
    own after, so anything ``validate_plan`` refused lands on a line here — which
    is why ``verdict is PASS`` implies the gate passed. A rule with no owning
    line is returned as unmapped and voids the proof.
    """
    per_line: dict[str, list[str]] = {}
    unmapped: list[str] = []
    owners = dict(extra_owners or {})
    for rule, reason in refusals:
        owner = OBLIGATION_FOR_RULE.get(rule) or owners.get(rule)
        if owner is None:
            unmapped.append(f"{rule}: {reason}")
            continue
        per_line.setdefault(owner, []).append(f"[{rule}] {reason}")
    blamed = {name: tuple(reasons) for name, reasons in per_line.items()}
    updated = {name: line.with_refusals(blamed.get(name, ())) for name, line in lines.items()}
    return updated, blamed, tuple(unmapped)


def _void_summary(obligations: tuple[Obligation | ResidueObligation, ...]) -> str:
    unproven = [o.name for o in obligations if o.status is not ObligationStatus.PASS]
    return f"lines not established: {', '.join(unproven)}" if unproven else "proof is void"


def compile_residue_obligations(plan: ExecutionPlan) -> tuple[ResidueObligation, ...]:
    """The per-fault residue obligations this plan owes, asserted and undischarged.

    Generated at plan time from the fault steps and discharged post-run by the
    residue scan (gap 65). They start ``VOID``: nothing has run, so "nothing left
    behind" has not been observed — and Phase 1's type refuses to call an
    unobserved line a pass. Each carries the full predicate set by construction,
    so a fault whose family cannot be scanned for one of the six conditions still
    gets all six asserted rather than a weakened line.
    """
    obligations: list[ResidueObligation] = []
    for step in _fault_steps(plan):
        fault: PlannedFault = step.fault  # type: ignore[assignment]
        obligations.append(
            ResidueObligation(
                fault_id=fault.fault_id,
                status=ObligationStatus.VOID,
                gate_digest=digest_of(
                    {
                        "source": "compile_residue_obligations",
                        "plan_step": step.seq,
                        "fault_id": fault.fault_id,
                        "undo_ops": len(fault.undo_ops),
                        "verify_probes": len(fault.verify_probes),
                    }
                ),
                evidence_ref=f"plan-time assertion for step {step.seq}",
                detail=(
                    "asserted at plan time; the post-run residue scan discharges this line "
                    "and nothing else may"
                ),
            )
        )
    return tuple(obligations)


def compile_safety_evidence(
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
    *,
    adapter: RuntimeAdapter | None = None,
    prediction: ImpactPrediction | None = None,
    policy_decision: PolicyDecision | None = None,
    intent: ExecutionIntent | None = None,
    engine: str = "",
    target_identity: str = "",
    include_residue: bool = False,
) -> SafetyCompilation:
    """Run every gate and assemble the proof plus its refusal trail.

    See the module docstring for the obligation-to-gate map and for why the
    compiler can only ever refuse more than ``validate_plan``. This is the
    informative entry point; :func:`compile_safety_proof` is the same run
    reduced to the artifact.
    """
    plan_digest = canonical_plan_digest(plan)

    authoritative = _authoritative(plan, graph, ctx)
    admission = _admission_probe(plan, ctx)
    drift = _drift_probe(plan, graph)
    policy = _policy_probe(plan, ctx)
    approval = _approval_probe(plan, ctx, requirements=policy.requirements)
    capability = _capability_probe(plan, adapter)
    blast = _blast_probe(plan, graph, ctx)

    prediction_notes: list[str] = []
    predicted: tuple[tuple[str, str], ...] = ()
    never_permissive = True
    if prediction is not None:
        if is_stale_against(prediction, graph=graph, plan=plan):
            # A prediction of a different plan or graph has no standing here at
            # all, so it is neither blamed nor held to agreement: reporting that
            # it "missed" the gate's refusal would be measuring a preview of
            # something else.
            prediction_notes.append(
                "prediction is stale against this graph/plan, so its findings were not blamed"
            )
        else:
            never_permissive = is_never_permissive(
                prediction, [rule for rule, _ in authoritative]
            )
            unusable = approval_refusal_reason(prediction, graph=graph, plan=plan)
            if unusable:
                prediction_notes.append(
                    f"prediction is not usable for approval, so its findings were not blamed: "
                    f"{unusable}"
                )
            else:
                predicted = tuple(
                    (rule, f"predicted breach: {rule}")
                    for rule in sorted(prediction.rule_ids & GATE_RULE_IDS)
                )
        if prediction.truncated_at_step is not None:
            prediction_notes.append(
                f"prediction truncated at step {prediction.truncated_at_step}"
                + (
                    f"; the gate refused at step {blast.first_refused_step}"
                    if blast.first_refused_step is not None
                    else "; the gate refused nothing"
                )
            )

    lines: dict[str, _Line] = {
        ObligationName.TARGET_POLICY.value: _line_target_policy(
            plan,
            ctx,
            admission=admission,
            drift=drift,
            blast=blast,
            policy_decision=policy_decision,
            policy=policy,
            prediction=prediction,
            prediction_notes=tuple(prediction_notes),
        ),
        ObligationName.MAX_CONCURRENT_FAULTS.value: _cap_line(
            blast,
            name=ObligationName.MAX_CONCURRENT_FAULTS.value,
            cap=RULE_MAX_CONCURRENT_FAULTS,
            stat="concurrent_faults",
            budget=float(ctx.budget.max_concurrent_faults),
            observed_key="worst_concurrent_faults",
            noun="concurrent fault count",
        ),
        ObligationName.MAX_DURATION.value: _cap_line(
            blast,
            name=ObligationName.MAX_DURATION.value,
            cap=RULE_MAX_DURATION_PER_FAULT_S,
            stat="duration_per_fault",
            budget=float(ctx.budget.max_duration_per_fault_s),
            observed_key="worst_duration_per_fault_s",
            noun="per-fault duration (s)",
        ),
        ObligationName.DAMAGE_BUDGET.value: _line_damage_budget(
            blast, ctx.damage_quota.model_dump(mode="json")
        ),
        ObligationName.CAPABILITY_REQUIREMENTS.value: _line_capability(capability, adapter),
        ObligationName.COMPENSATION.value: _line_compensation(plan),
        ObligationName.RECOVERY_PATH.value: _line_recovery_path(plan),
        ObligationName.STOP_CONDITIONS.value: _line_stop_conditions(plan),
        ObligationName.REQUIRED_APPROVALS.value: _line_required_approvals(
            plan,
            ctx,
            plan_digest,
            policy,
            approval,
            intent=intent,
            engine=engine,
            target_identity=target_identity,
        ),
    }

    refusals: list[tuple[str, str]] = [*authoritative, *admission.refusals, *drift.refusals]
    refusals.extend(policy.refusals)
    refusals.extend(approval.refusals)
    refusals.extend(capability.refusals)
    refusals.extend(blast.refusals)
    refusals.extend(predicted)
    # A bundle authors its own rule names, so the policy gate's rule ids are
    # placed by *which refusal it is* rather than by enumeration. Without this a
    # policy-denied plan would come out VOID (an unmapped refusal) instead of
    # FAIL on the line that caused it — a weaker, less useful answer than the
    # gate itself gives.
    policy_owners = {
        rule: POLICY_REFUSAL_OWNER.get(rule, DEFAULT_POLICY_REFUSAL_OWNER)
        for rule in policy.rule_ids
    }
    lines, blamed, unmapped = _blame(lines, refusals, policy_owners)

    obligations: list[Obligation | ResidueObligation] = [
        lines[name.value].as_obligation(plan_digest) for name in ObligationName
    ]
    if include_residue:
        obligations.extend(compile_residue_obligations(plan))

    void_reasons: list[str] = []
    if unmapped:
        void_reasons.append(
            "a gate refused on a rule no obligation owns, so the refusal cannot be shown: "
            + "; ".join(unmapped)
        )
    if prediction is not None and not never_permissive:
        void_reasons.append(
            "the supplied prediction is calmer than the gate: it does not flag a rule "
            "validate_plan refused on, so it cannot back this proof"
        )

    provisional = SafetyProof(
        plan_digest=plan_digest,
        obligations=tuple(obligations),
        verdict=ProofVerdict.VOID,
        void_reason="provisional assembly",
    )
    implied = provisional.recompute_verdict()
    verdict = ProofVerdict.VOID if void_reasons else implied
    reason = "; ".join(void_reasons) or (
        "" if implied is not ProofVerdict.VOID else _void_summary(tuple(obligations))
    )
    proof = SafetyProof.model_validate(
        {
            **provisional.model_dump(),
            "obligations": tuple(obligations),
            "verdict": verdict,
            "void_reason": reason,
        }
    )
    return SafetyCompilation(
        proof=proof,
        plan_digest=plan_digest,
        gate_refusals=tuple(rule for rule, _ in authoritative),
        compiler_refusals=tuple(dict.fromkeys(rule for rule, _ in refusals)),
        blame={name.value: blamed.get(name.value, ()) for name in ObligationName},
        void_reason=reason,
    )


def compile_safety_proof(
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
    *,
    adapter: RuntimeAdapter | None = None,
    prediction: ImpactPrediction | None = None,
    policy_decision: PolicyDecision | None = None,
    intent: ExecutionIntent | None = None,
    engine: str = "",
    target_identity: str = "",
    include_residue: bool = False,
) -> SafetyProof:
    """Compile the frozen plan's safety case. See :func:`compile_safety_evidence`.

    The same run, reduced to the artifact an approver or a renderer reads. Use
    :func:`compile_safety_evidence` when the rule-level trail is wanted too.
    """
    return compile_safety_evidence(
        plan,
        graph,
        ctx,
        adapter=adapter,
        prediction=prediction,
        policy_decision=policy_decision,
        intent=intent,
        engine=engine,
        target_identity=target_identity,
        include_residue=include_residue,
    ).proof
