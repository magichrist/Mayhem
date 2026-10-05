"""Plan 07 Phase 2 — policy evaluation wired *into* the plan-time gate.

Phase 1 gave :mod:`mayhem.domain.policy` a vocabulary and no call site: the
rules existed, nothing read them, and ``controller/safety.py`` still evaluated
only the older ``PolicyCfg`` denylist/allowlist/risk-ceiling checks. This module
is the call site.

Three shapes, and the differences between them are the point of the phase:

- :func:`evaluate_gate` is what ``safety.validate_plan`` calls. It is a **pure
  function** of ``(plan, inputs, environment)``. It reads budgets, asks about
  locks, and reads the collision graph; it never charges a budget, never takes
  a lock, and never writes to a caller-owned object. That is why simulation
  needs no second implementation.
- :func:`simulate_gate` is ``evaluate_gate`` with ``simulated=True``. Not a
  parallel code path that happens to be careful — the *same* function — so a
  preview cannot drift from what admission would decide.
- :class:`PolicyGateInputs` carries everything the gate needs that is not on
  the plan, including ``now``. ``now`` is a required field rather than a
  default, because ``evaluate_bundle`` refuses an ambient clock and the only
  way to keep that promise here is to make the clock impossible to omit.

The fourth shape arrived later and is **not** one of these three:
:func:`commit_budget` is the write. It posts a plan's damage to the
hierarchical ledger after admission, and it is deliberately unreachable from
the three above — see its own section at the foot of this module.

**Refusal order is deliberate and most-actionable-first**: an expired bundle,
then the operational preconditions (resource lock, damage budget, fault-pair
compatibility), then the bundle's own verdict. A plan that breaks four things
at once is refused for the thing a human can unblock soonest, and the reason
string names the holder, the budget level, or the pair rather than saying only
"denied". Both are hard refusals, so the order is a *reporting* preference, not
a ranking: no outcome can be reached by skipping a step.

**The compatibility graph is additive.** An undeclared pair is permitted,
because ``BlastRadiusBudget.forbidden_fault_pairs`` — enforced per
``{earlier, new}`` pair by ``safety._first_forbidden_pair`` — remains the
authoritative refusal for a forbidden pair. The graph can only add conflicts
and conditions on top of that, so it can never be the only thing standing
between a plan and an incompatible pair, and it can never quietly turn a
passing plan into a failing one.

**Approvals are surfaced here and enforced next door.** :func:`required_approvals`
reads what a decision says is required and puts it in the result (and in the
refusal reason, as the plan's example output shows). This module still does not
mint, bind, or check an approval — it cannot, and it stays a pure function of
``(plan, inputs, environment)``. Enforcement is
:mod:`mayhem.controller.approval_gate`, which ``controller.safety.validate_plan``
runs immediately after this gate and hands the outstanding levels to: a level
this gate names raises the quorum there. Which *named group* satisfies which
level is still unbound, because nothing on an approval says so.

Phase 4 — two budget systems, one answer, and no exceptions
----------------------------------------------------------

**Two budget systems, reconciled.** ``BlastRadiusBudget.damage_quota``
(:class:`mayhem.domain.quota.DamageQuota`, enforced per step by
``safety.check_blast_radius`` against a per-target ledger) and the hierarchical
:class:`mayhem.domain.policy.BudgetNode` tree are independent, measure different
things over different horizons, and until now knew nothing about each other.
:func:`reconcile_budgets` is the single authoritative answer to "is this plan
within budget?" and it is a **pure conjunction**: the plan is within budget if and
only if *both* systems permit it. Neither wins, because there is nothing to win —
see :func:`reconcile_budgets` for why arithmetic reconciliation is not merely
unnecessary but wrong here. Reporting precedence (hierarchy first) is a
*reporting* preference and is fixed so the refusal reads in the order the
refusal is about.

**A broken policy config refuses; it does not raise.** Phase 2's contract was that
a drifted pin, a missing parent, an inheritance cycle, and an unmappable budget
path all raise :class:`~mayhem.domain.errors.InvariantViolationError`. That is
still true of the primitives — :func:`effective_rules` and :func:`probe_budget`
raise, and their own callers and tests depend on it. What changed is that the
*gate* no longer lets those exceptions escape: a malformed bundle is an operator
error, and the useful answer to it is a typed, named refusal carrying the fix,
not a traceback that ends somebody's run. :func:`detect_config_defect` converts
each one to a :class:`PolicyConfigDefect` — the refusal reason is preserved
verbatim, the defect is classified, and the remediation is authored per defect.

Phase 4b — spending the ledger
------------------------------

The other half of Phase 4 landed afterwards: **budget charges now post to the
ledger hierarchically.** :func:`commit_budget` writes every charge a plan would
have made — the leaf and every ancestor above it — to a
:class:`HierarchicalBudgetLedger`, and judges the result *after* writing, so a
refused charge stays on the ledger. That last half is the whole design: a run
that attempted the damage did it, whatever the gate said, and a ledger that
refunded a refusal would report more headroom to the next run than the system
actually has.

The gate is untouched by this and stayed pure. The commit is a separate call a
caller makes after admission, it reuses :func:`_charge_plan` — the same walk
:func:`probe_budget` uses — so the numbers a preview reports and the numbers a
commit writes cannot come from two implementations, and it reuses
:func:`_budget_refusal`, so the refusal it produces is the gate's refusal
byte-for-byte and carries the same rule id. Persisted state lives in the existing
``observations`` table through :class:`ObservationBudgetLedger`; the reasoning,
including what that choice costs, is in that class's docstring.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_context import ExecutionContext
from mayhem.domain.faults import FaultCategory
from mayhem.domain.policy import (
    BUDGET_SCOPE_ORDER,
    DAMAGE_PRECISION,
    BudgetLedgerEntry,
    BudgetScope,
    PolicyDecision,
    PolicyDimension,
    PolicyFacts,
    ResourceLock,
    acquire_lock,
    effective_rules,
    evaluate_bundle,
    evaluate_compatibility,
    fold_spend,
    resolve_precedence,
)
from mayhem.domain.quota import DamageLedger, damage_weight
from mayhem.domain.risks import RiskLevel
from mayhem.domain.runtime_adapter import CapabilityRequirements

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from mayhem.domain.experiments import ExecutionPlan, PlannedFault
    from mayhem.domain.policy import (
        BudgetCharge,
        BudgetNode,
        CompatibilityEdge,
        CompatibilityOutcome,
        LockVerdict,
        PolicyBundle,
        PolicyRule,
    )
    from mayhem.domain.quota import DamageQuota, QuotaCharge

# -- rule ids ---------------------------------------------------------------------
# The existing gate names each refusal by the rule that produced it
# ("policy.deny_faults", "blast_radius.max_hosts", ...). A policy refusal is
# named the same way so a log line reads uniformly whichever half spoke, and
# so a refusal is traceable to a rule id rather than to a call site.

RULE_BUNDLE_EXPIRED = "policy.bundle_expired"
RULE_BUNDLE_DENY = "policy.bundle_deny"
RULE_LOCK_CONTENDED = "policy.resource_lock_contended"
RULE_BUDGET_EXHAUSTED = "policy.damage_budget_exhausted"
RULE_COMPAT_CONFLICT = "policy.compatibility_conflict"
RULE_BUNDLE_ALLOW = "policy.bundle_allow"
RULE_APPROVAL_REQUIRED = "policy.approval_required"

#: A bundle or budget hierarchy that cannot be evaluated at all. Phase 4: every
#: authoring defect the Phase 1 contract said would raise now arrives here as a
#: refusal instead, so a malformed policy layer ends a run with a remediation
#: rather than a traceback. See :func:`detect_config_defect`.
RULE_POLICY_CONFIG = "policy.config_invalid"

_LOCK_CHARS = frozenset(string.ascii_lowercase + string.digits + "._:-")
_LOCK_LEAD = frozenset(string.ascii_lowercase + string.digits)


# =============================================================================
# Broken configuration (Phase 4)
#
# The domain primitives still raise — ``PolicyBundle.verify_pin``,
# ``inherited_rules``, ``BudgetNode.post_charge`` are all documented to, and
# their direct callers depend on it. What Phase 4 changes is the *gate's* edge:
# nothing raised by evaluating a policy configuration escapes ``evaluate_gate``
# as an exception. Each one is classified, named, and given a remediation here,
# and the gate returns a refusal carrying it.
# =============================================================================


class ConfigDefect(StrEnum):
    """What is wrong with the policy configuration, at the granularity a fix needs."""

    #: ``content_digest`` no longer matches the content it is pinning.
    PIN_DRIFTED = "pin_drifted"
    #: ``parents`` names a bundle the index does not hold.
    PARENT_MISSING = "parent_missing"
    #: ``parents`` forms a loop.
    INHERITANCE_CYCLE = "inheritance_cycle"
    #: ``budget_path`` names no level of the budget tree, so no charge could be
    #: attributed to any budget.
    BUDGET_PATH_UNMAPPABLE = "budget_path_unmappable"
    #: Any other ``InvariantViolationError`` raised while reading the bundle's
    #: own structure. Exists so an unforeseen authoring error refuses with a
    #: named defect instead of escaping as an exception.
    MALFORMED = "malformed"


@dataclass(frozen=True)
class PolicyConfigDefect:
    """One authoring defect, classified, with the reason preserved and a fix.

    ``reason`` is the raised invariant's own message, verbatim — the evidence
    somebody needs to find the typo is the one the primitive produced, not a
    paraphrase. ``defect`` is what the gate can act on and ``remediation`` is the
    fix, written for whoever authored the bundle rather than for whoever ran it.
    """

    defect: ConfigDefect
    reason_code: str
    reason: str
    remediation: str
    inputs: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        return f"{self.defect.value}: {self.reason}"


#: ``reason_code`` of the raised invariant -> (defect, remediation). Keyed on the
#: code rather than the message so a rewording upstream cannot silently reclassify
#: a defect or drop it into the :attr:`ConfigDefect.MALFORMED` bucket.
_CONFIG_DEFECTS: dict[str, tuple[ConfigDefect, str]] = {
    "policy.bundle_digest_mismatch": (
        ConfigDefect.PIN_DRIFTED,
        "re-pin the bundle: rebuild it from its authored content and set "
        "content_digest with PolicyBundle.pin(); a bundle whose content no longer "
        "matches its pin cannot decide anything, and no rule of it can be trusted "
        "to still be the rule that was reviewed",
    ),
    "policy.bundle_parent_missing": (
        ConfigDefect.PARENT_MISSING,
        "publish the named parent bundle into the policy index this bundle is "
        "resolved against, or drop the dangling entry from `parents`; a bundle "
        "that inherits from a bundle nobody can load has an unknown rule set",
    ),
    "policy.bundle_cycle": (
        ConfigDefect.INHERITANCE_CYCLE,
        "break the inheritance cycle in `parents` — inheritance has to be a "
        "partial order, and a cycle has no last writer, so no version can be "
        "resolved or pinned",
    ),
    "policy.budget_path_missing": (
        ConfigDefect.BUDGET_PATH_UNMAPPABLE,
        "correct budget_path so every level it names exists in the budget tree, "
        "or widen the tree to that depth; a charge that cannot be attributed to "
        "any budget is damage nobody is accountable for, so the gate refuses "
        "rather than skip the charge",
    ),
    "budget.path_missing": (
        ConfigDefect.BUDGET_PATH_UNMAPPABLE,
        "correct budget_path so every level it names exists in the budget tree, "
        "or widen the tree to that depth; a charge that cannot be attributed to "
        "any budget is damage nobody is accountable for, so the gate refuses "
        "rather than skip the charge",
    ),
    "budget.path_order": (
        ConfigDefect.BUDGET_PATH_UNMAPPABLE,
        "author budget_path in hierarchy order (team → environment → service → "
        "experiment); the budget tree is walked by scope, so a path whose levels "
        "are out of order names no budget",
    ),
    "budget.scope_order": (
        ConfigDefect.MALFORMED,
        "rebuild the budget tree so each node holds only children of the next "
        "scope down; the hierarchy is team → environment → service → experiment "
        "→ fault and a node cannot hold a child out of order",
    ),
    "budget.duplicate_child": (
        ConfigDefect.MALFORMED,
        "give each budget node one child per key; two siblings with the same name "
        "make the spend ambiguous and the charge unaccountable",
    ),
    "budget.negative_charge": (
        ConfigDefect.MALFORMED,
        "author only non-negative fault durations; a negative charge is a typo, "
        "and posting one would refund a budget nobody agreed to give back",
    ),
}


def _defect_from_exception(
    exc: InvariantViolationError, context: dict[str, Any]
) -> PolicyConfigDefect:
    """Classify a raised invariant as a named, fixable configuration defect."""
    defect, remediation = _CONFIG_DEFECTS.get(
        exc.rule,
        (
            ConfigDefect.MALFORMED,
            "repair the policy bundle or budget hierarchy named above so it can be "
            "read; the gate refuses a configuration it cannot evaluate rather than "
            "deciding against an unreadable rule set",
        ),
    )
    return PolicyConfigDefect(
        defect=defect,
        reason_code=exc.rule,
        reason=str(exc),
        remediation=remediation,
        inputs={**context, "reason_code": exc.rule},
    )


def detect_config_defect(inputs: PolicyGateInputs) -> PolicyConfigDefect | None:
    """Classify whatever makes this bundle unreadable, or ``None`` when it is fine.

    Covers the two defects that make the *rule set* unreachable — a drifted pin
    and an inheritance that cannot be resolved — and it is total: it returns a
    defect instead of propagating the :class:`InvariantViolationError` its
    primitives raise. The budget-path defect is found later, by
    :func:`probe_budget_safely`, because it needs the plan's fault ids to be
    answerable at all.

    ``PolicyGateInputs`` itself still raises in ``__post_init__`` for a naive
    clock, a lock request with no experiment identity, and a non-positive lock
    window. Those are *caller* errors in the wiring, not authoring errors in the
    policy, they are raised at construction where the traceback points at the
    call site that made the mistake, and no bundle is involved. Phase 4 narrows
    "refuse rather than raise" to the bundle, where the mistake is somebody's
    authored YAML rather than the line above.
    """
    context = {"bundle": inputs.bundle.describe(), "bundle_id": inputs.bundle.bundle_id}
    try:
        inputs.bundle.verify_pin()
    except InvariantViolationError as exc:
        return _defect_from_exception(exc, context)
    try:
        effective_rules(inputs.bundle, inputs.index)
    except InvariantViolationError as exc:
        return _defect_from_exception(exc, context)
    return None


# =============================================================================
# Inputs and outputs
# =============================================================================


@dataclass(frozen=True)
class PolicyGateInputs:
    """Everything the gate needs that the plan does not carry.

    ``index`` supplies the ancestor bundles named by ``bundle.parents`` for
    inheritance; an empty one is correct for a bundle with no parents. ``locks``
    is the caller's live lock set and ``compatibility`` the caller's own
    collision edges — both are read, never written. A bundle's *own* graph
    (:meth:`~mayhem.domain.policy.PolicyBundle.graph`) is always consulted as
    well, and wins a pair both declare; see :func:`effective_compatibility`.
    ``budget_path`` names the run's place in the
    five-level hierarchy (team → environment → service → experiment); the gate
    appends the fault id for the leaf.
    """

    bundle: PolicyBundle
    now: datetime
    index: Mapping[str, PolicyBundle] = field(default_factory=dict)
    locks: tuple[ResourceLock, ...] = ()
    lock_resources: tuple[str, ...] = ()
    lock_window_s: float = 3600.0
    experiment_id: str = ""
    run_id: str = ""
    budget: BudgetNode | None = None
    budget_path: tuple[str, ...] = ()
    #: Collision edges the *caller* supplies on top of the bundle's own graph.
    #: Merged by :func:`effective_compatibility`, where the bundle's declaration
    #: wins a pair both claim.
    compatibility: tuple[CompatibilityEdge, ...] = ()
    #: The per-target cumulative damage quota, so the gate can answer "is this
    #: plan within budget?" without deferring half the question to the per-step
    #: loop in ``safety.check_blast_radius``. ``None`` — the default — means this
    #: gate is not configured with the quota system at all, and that loop stays
    #: its sole enforcer, byte-for-byte as before. Supplying it is what makes
    #: :func:`reconcile_budgets` a conjunction of two live systems rather than a
    #: conjunction of one and a silence; see :func:`probe_quota` for exactly what
    #: a gate-side probe can and cannot see.
    damage_quota: DamageQuota | None = None
    # Dimensions the gate cannot read off a plan — team, schedule, cloud cost,
    # deployment/incident state, approval level. Fills only what the gate does
    # not derive; a derived dimension is never overridden (see
    # :func:`derive_facts`).
    observed: Mapping[PolicyDimension, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            msg = (
                "policy gate requires a timezone-aware `now`; a naive clock makes "
                "bundle expiry and lock windows unreproducible"
            )
            raise InvariantViolationError("policy.gate_naive_clock", msg)
        if self.lock_resources and not self.experiment_id:
            msg = (
                "policy gate lock checks need an experiment_id: without one, a "
                "lock cannot be recognised as this experiment's own reservation"
            )
            raise InvariantViolationError("policy.gate_lock_identity", msg)
        if self.lock_window_s <= 0.0:
            msg = f"policy gate lock_window_s must be positive, got {self.lock_window_s}"
            raise InvariantViolationError("policy.gate_lock_window", msg)

    def with_now(self, now: datetime) -> PolicyGateInputs:
        """The same gate as of a different instant — a replay, not a re-plan."""
        return replace(self, now=now)


@dataclass(frozen=True)
class MutationSink:
    """The declared boundary a commit writes through.

    The gate is read-only by construction, so nothing here is ever written and a
    simulation's sink is provably empty — the purity test asserts
    ``len(sink) == 0`` against a real object rather than against a comment. The
    type exists so the boundary is a name in the API: the only writes this
    engine's gate will ever make are budget posting and lock granting.

    **Budget posting now has its commit path (:func:`commit_budget`) and it does
    not come through here.** That is a deliberate split, not an inconsistency.
    A sink is a callback into the caller's process: whatever a ``record()`` did
    was in memory until the caller did something else with it. A damage charge
    has to be durable, ordered against the other charges, and re-readable by the
    next run, and none of those is a property a returned tuple can have. So the
    commit takes a :class:`HierarchicalBudgetLedger` and writes to it directly,
    and the sink stays the *evaluation* boundary — the one place the purity claim
    has to be true, and the one place an empty sink is evidence.

    Lock granting still has no commit path at all. :func:`check_locks` returns a
    :class:`~mayhem.domain.policy.LockVerdict` and taking the lock is a write
    against a live lock set with an expiry and an owner, which is a different
    operation from spending a ledger.
    """

    calls: tuple[tuple[str, str], ...] = ()

    def record(self, kind: str, detail: str) -> MutationSink:
        """A sink with one more recorded mutation. Never called."""
        return replace(self, calls=(*self.calls, (kind, detail)))

    def __len__(self) -> int:
        return len(self.calls)


@dataclass(frozen=True)
class RequiredApproval:
    """One approval a decision says the plan needs. Requirement only."""

    approval_level: str
    rule_id: str
    reason: str
    remediation: str

    def describe(self) -> str:
        return f"{self.approval_level} (required by {self.rule_id})"


@dataclass(frozen=True)
class PolicyRefusal:
    """The first-fatal refusal, in the shape ``SafetyRefusedError`` records."""

    rule_id: str
    reason: str
    remediation: str
    inputs: dict[str, Any]

    def rule_ids(self) -> tuple[str, ...]:
        """Every policy rule the refusal rests on, not just its own id."""
        named = self.inputs.get("policy_rule_ids")
        if isinstance(named, list):
            return tuple(str(rule) for rule in named)
        return ()


@dataclass(frozen=True)
class PolicyGateResult:
    """The verdict plus every intermediate the verdict was reached through.

    Carried whole rather than reduced to a boolean so a later phase can bind a
    decision to evidence (Phase 4) and a later one can explain it (Phase 3)
    without re-running the gate and hoping the inputs still agree.
    """

    decision: PolicyDecision
    facts: PolicyFacts
    refusal: PolicyRefusal | None = None
    lock_verdicts: tuple[LockVerdict, ...] = ()
    # What a commit *would* post to the hierarchical budget, widest level first.
    # Produced by probing copies of the tree, so nothing has been spent.
    pending_charges: tuple[BudgetCharge, ...] = ()
    compatibility: tuple[CompatibilityOutcome, ...] = ()
    required_approvals: tuple[RequiredApproval, ...] = ()
    simulated: bool = False
    #: Both budget systems' answers and the verdict they combine into. Phase 4.
    #: Carried whole so a reader never has to re-derive which system said what,
    #: and so the conjunction survives into the evidence record.
    budget: BudgetReconciliation | None = None
    #: Non-empty only when the policy configuration could not be evaluated. Its
    #: presence is what makes ``decision``'s empty digests honest rather than
    #: missing: nothing was read, so nothing could be digested.
    config_defect: PolicyConfigDefect | None = None
    #: The bundle this decision was reached under. Carried so a decision can
    #: never be separated from the thing it was decided about:
    #: :mod:`mayhem.controller.policy_evidence` re-derives the bundle's digest and
    #: refuses any record whose ``policy_digest`` disagrees with it, and a
    #: hand-built :class:`PolicyDecision` paired with the wrong bundle cannot slip
    #: past that check by omitting it.
    bundle: PolicyBundle | None = None
    #: The instant this verdict was reached as of — ``inputs.now``, never a clock
    #: read. Carried so the evidence layer can re-check currency
    #: (:func:`verify_decision_binding`) without the caller having to remember
    #: which clock the gate used, and so a record says *when* it was decided
    #: rather than leaving an auditor to infer it.
    now: datetime | None = None

    @property
    def allowed(self) -> bool:
        # ``decision.allowed`` is necessary but not sufficient: a bundle can
        # permit these facts while a lock, a budget, or a collision edge still
        # refuses the plan. Only the gate's own verdict counts.
        return self.refusal is None and self.decision.allowed

    @property
    def denied(self) -> bool:
        return not self.allowed

    def decision_digest(self) -> str:
        """The replay comparison key — see :meth:`PolicyDecision.decision_digest`."""
        return self.decision.decision_digest()

    def inputs(self) -> dict[str, Any]:
        return {
            **self.decision.inputs(),
            "refusal_rule_id": self.refusal.rule_id if self.refusal else "",
            "required_approvals": [a.approval_level for a in self.required_approvals],
            "compatibility": [outcome.describe() for outcome in self.compatibility],
            "pending_charges": [
                f"{charge.scope.value}:{charge.key}={charge.after_s}"
                for charge in self.pending_charges
            ],
            "simulated": self.simulated,
            "budget": self.budget.inputs() if self.budget is not None else {},
            "config_defect": self.config_defect.defect.value if self.config_defect else "",
        }

    def describe(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        body = self.refusal.reason if self.refusal else (self.decision.reasons or ("allow",))[0]
        return f"{verdict} {body}"


# =============================================================================
# Facts
# =============================================================================


def plan_faults(plan: ExecutionPlan) -> tuple[PlannedFault, ...]:
    """The plan's fault steps in order, ignoring wait/check steps."""
    faults: list[PlannedFault] = []
    for step in plan.steps:
        if step.fault is not None:
            faults.append(step.fault)
    return tuple(faults)


def capability_requirements_for(plan: ExecutionPlan) -> CapabilityRequirements:
    """The capability families the runtime gate consults, derived from a plan.

    This is ``controller.safety._validate_capability_requirements``' derivation,
    moved here verbatim so the adapter gate and the policy facts cannot drift
    apart about what a plan requires — two copies of this shape would eventually
    disagree, and a policy that denies a capability the gate never asked for is
    a policy that refuses valid plans for an invisible reason.

    Only ``namespaces``, ``tools``, and ``permissions`` are derived: they are
    the three families the gate has always consulted, and the remaining
    ``CapabilityRequirements`` fields stay empty because nothing in the codebase
    populates them.
    """
    namespaces: set[str] = set()
    tools: set[str] = set()
    permissions: set[str] = set()
    for fault in plan_faults(plan):
        if fault.execution_loci is not None:
            target = fault.execution_loci.get("target")
            if isinstance(target, str) and target.startswith("network_namespace"):
                namespaces.add(target)
        if fault.execution_context is not None and (
            fault.execution_context.context
            in (ExecutionContext.NETWORK_NAMESPACE, ExecutionContext.PROCESS)
        ):
            namespaces.add(fault.execution_context.context.value)
        for resolved in fault.targets:
            for node_id in resolved.node_ids:
                if node_id.startswith("net"):
                    namespaces.add(node_id)
                if node_id.startswith(("p-", "proc")):
                    permissions.add("limit")
    return CapabilityRequirements(
        namespaces=frozenset(namespaces),
        tools=frozenset(tools),
        permissions=frozenset(permissions),
    )


def _risk_of(fault_id: str) -> RiskLevel:
    """Risk for ``fault_id``, mirroring ``controller.safety._risk_of``.

    The ``LOW`` floor is carried over deliberately. That function prices an
    unresolvable fault at the *bottom* of the ladder because it gates admission,
    where over-pricing refuses valid plans; a policy fact that priced the same
    fault at the top would refuse a plan the gate permits. ``domain.quota``
    documents the opposite choice for damage; this is admission, not damage.
    """
    try:
        return definition_for(fault_id).risk
    except Exception:
        return RiskLevel.LOW


def _family_of(fault_id: str) -> str:
    """Fault family for ``fault_id``, falling back to its id prefix."""
    try:
        return FaultCategory.from_fault_id(fault_id).value
    except Exception:
        return fault_id.split(".", 1)[0]


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _capability_values(plan: ExecutionPlan) -> tuple[str, ...]:
    """Capability facts, namespaced by family so ``network`` and ``net-x`` differ."""
    reqs = capability_requirements_for(plan)
    return _sorted_unique(
        [
            *(f"namespace:{name}" for name in reqs.namespaces),
            *(f"tool:{name}" for name in reqs.tools),
            *(f"permission:{name}" for name in reqs.permissions),
        ]
    )


def _target_values(plan: ExecutionPlan) -> tuple[str, ...]:
    ids: set[str] = set()
    for fault in plan_faults(plan):
        for resolved in fault.targets:
            ids |= resolved.node_ids
    return _sorted_unique(ids)


def projected_damage_s(plan: ExecutionPlan) -> float:
    """Total damage-seconds the plan would charge, at the quota's own prices.

    Same arithmetic as ``DamageLedger.charge``'s per-node term
    (``duration_s x damage_weight``) and rounded at
    :data:`~mayhem.domain.policy.DAMAGE_PRECISION` so a fact derived from it
    cannot drift on the last binary digit between two runs.
    """
    total = sum(
        float(fault.duration) * damage_weight(fault.fault_id) for fault in plan_faults(plan)
    )
    return round(total, DAMAGE_PRECISION)


def derive_facts(
    plan: ExecutionPlan, inputs: PolicyGateInputs, *, environment: str | None = None
) -> PolicyFacts:
    """The observed facts this decision is made *from*.

    Dimensions the gate can read off a plan, the environment, and the target
    set it derives. Dimensions that name the world rather than the plan — team,
    schedule, maintenance window, cloud cost, approval level, deployment and
    incident state — come from ``inputs.observed``.

    Derived values win over supplied ones: a caller can fill a dimension the
    gate is blind to, but cannot talk the facts into a different target set or
    fault family than the plan actually carries. A derived dimension with no
    values is left *unobserved* rather than recorded as observed-empty, because
    an unobserved dimension is what makes a deny-shaped ``not_in`` rule decline
    to match (see ``PolicyPredicate.matches``).
    """
    faults = plan_faults(plan)
    derived: dict[PolicyDimension, tuple[str, ...]] = {
        PolicyDimension.ENVIRONMENT: (environment,) if environment is not None else (),
        PolicyDimension.TARGET: _target_values(plan),
        PolicyDimension.FAULT_FAMILY: _sorted_unique(_family_of(f.fault_id) for f in faults),
        PolicyDimension.RISK: _sorted_unique(_risk_of(f.fault_id).value for f in faults),
        PolicyDimension.CAPABILITY: _capability_values(plan),
        # Always observed, including for a plan with no fault steps: "this plan
        # runs zero faults concurrently" is a fact a ceiling rule can ask about.
        PolicyDimension.CONCURRENCY: (str(len(faults)),),
        PolicyDimension.DAMAGE_BUDGET: (str(projected_damage_s(plan)),)
        if inputs.budget is not None
        else (),
    }
    values: dict[PolicyDimension, tuple[str, ...]] = {
        dimension: tuple(supplied) for dimension, supplied in inputs.observed.items()
    }
    for dimension, observed in derived.items():
        if observed:
            values[dimension] = observed
    return PolicyFacts(values=values)


# =============================================================================
# The three preconditions
# =============================================================================


def _lock_token(raw: str) -> str:
    """Coerce an arbitrary id into the ``ResourceLock.lock_id`` pattern.

    Run ids, experiment ids, and resource names are all free-form; the lock id
    is not. Losing information here would be harmless, emitting an invalid id
    would raise in the middle of a refusal, so the token is sanitised rather
    than trusted.
    """
    cleaned = "".join(ch if ch in _LOCK_CHARS else "-" for ch in raw.lower())
    cleaned = cleaned.lstrip("._:-")
    if not cleaned:
        return "policy-lock"
    if cleaned[0] not in _LOCK_LEAD:
        cleaned = f"lock-{cleaned}"
    return cleaned[:128]


def check_locks(plan: ExecutionPlan, inputs: PolicyGateInputs) -> tuple[LockVerdict, ...]:
    """Ask whether each resource this run wants is free, before admission.

    Expired locks are dropped by :func:`acquire_lock` before the conflict test,
    so a lock held by a dead run fences nothing once its window closes, and a
    re-entrant request from the same experiment is never its own blocker.
    """
    if not inputs.lock_resources:
        return ()
    owner = inputs.run_id or plan.run_id
    window = timedelta(seconds=inputs.lock_window_s)
    verdicts = []
    for resource in sorted(set(inputs.lock_resources)):
        requested = ResourceLock(
            lock_id=_lock_token(f"{inputs.experiment_id}.{owner}.{resource}"),
            resource=resource,
            experiment_id=inputs.experiment_id,
            owner_run_id=owner,
            acquired_at=inputs.now,
            expires_at=inputs.now + window,
            reason="policy gate admission",
        )
        verdicts.append(acquire_lock(inputs.locks, requested, now=inputs.now))
    return tuple(verdicts)


def _scope_at(depth: int) -> BudgetScope:
    for scope, order in BUDGET_SCOPE_ORDER.items():
        if order == depth:
            return scope
    msg = f"budget hierarchy has no scope at depth {depth}"
    raise InvariantViolationError("policy.budget_depth", msg)


def _descend(root: BudgetNode, keys: tuple[str, ...]) -> BudgetNode | None:
    """The node ``keys`` names under ``root``, or ``None`` if the path is absent."""
    node = root
    for depth, key in enumerate(keys):
        if depth == 0:
            if node.key != key:
                return None
            continue
        child = node.child(_scope_at(depth), key)
        if child is None:
            return None
        node = child
    return node


def _chargeable_path(tree: BudgetNode, keys: tuple[str, ...], leaf: str) -> tuple[str, ...]:
    """The longest prefix of ``keys + (leaf,)`` that exists in ``tree``.

    A hierarchy authored to three of its five levels still charges the levels
    that exist rather than refusing every plan against it. A path that exists
    at no depth is a misconfiguration, not a missing budget: raising is the
    same choice ``BudgetNode.post_charge`` makes when handed a path it cannot
    resolve, because silently skipping the charge would turn a typo'd team name
    into damage nobody is accountable for.
    """
    candidate = (*keys, leaf)
    for length in range(len(candidate), 0, -1):
        prefix = candidate[:length]
        if _descend(tree, prefix) is not None:
            return prefix
    msg = (
        f"budget hierarchy under {tree.key!r} holds no level of "
        f"{list(candidate)!r}; a charge cannot be attributed to any budget"
    )
    raise InvariantViolationError("policy.budget_path_missing", msg)


def _charge_plan(
    plan: ExecutionPlan, inputs: PolicyGateInputs, tree: BudgetNode
) -> tuple[BudgetNode, tuple[BudgetCharge, ...]]:
    """``tree`` with every step's charge posted, and every charge, in step order.

    The one walk both :func:`probe_budget` and :func:`commit_budget` use. That
    sharing is the point: the numbers a preview reports and the numbers a commit
    writes come from one implementation, so "the preview said it would fit" and
    "the commit charged that much" cannot be two calculations that agree today
    and drift tomorrow. A second copy of this loop is the one thing that would
    make plan 07's preview meaningless.

    Still pure. ``BudgetNode`` is frozen and ``post_charge`` returns a new tree,
    so the rebinding below is local and ``tree`` — the caller's tree, mounted or
    rebuilt — is never spent. The caller decides what to do with the returned
    tree: :func:`probe_budget` throws it away, :func:`commit_budget` persists
    what was charged and hands the new tree back.
    """
    charges: list[BudgetCharge] = []
    for fault in plan_faults(plan):
        amount = round(float(fault.duration) * damage_weight(fault.fault_id), DAMAGE_PRECISION)
        path = _chargeable_path(tree, inputs.budget_path, fault.fault_id)
        tree, posted = tree.post_charge(path, amount)
        charges.extend(posted)
    return tree, tuple(charges)


def probe_budget(plan: ExecutionPlan, inputs: PolicyGateInputs) -> tuple[BudgetCharge, ...]:
    """Charge every step against a *copy* of the budget and return the charges.

    ``BudgetNode`` is frozen and ``post_charge`` returns a new tree, so the
    running tree inside :func:`_charge_plan` is a local rebinding and
    ``inputs.budget`` is never spent — the probe-then-commit shape
    ``check_blast_radius`` already uses with ``DamageQuota.unrestricted()``. The
    returned charges are what a commit *would* post, in the order a refusal
    would read them: widest level first, per step.

    This is the raising form and it stays raising: an unmappable ``budget_path``
    is an :class:`InvariantViolationError` here, exactly as
    :meth:`BudgetNode.post_charge` is, because silently skipping the charge is
    the failure mode both are written against. :func:`probe_budget_safely` is
    the gate's edge over it.
    """
    if inputs.budget is None:
        return ()
    return _charge_plan(plan, inputs, inputs.budget)[1]


def _charge_plan_safely(
    plan: ExecutionPlan, inputs: PolicyGateInputs, tree: BudgetNode
) -> tuple[BudgetNode, tuple[BudgetCharge, ...], PolicyConfigDefect | None]:
    """:func:`_charge_plan`, with a misconfiguration returned instead of raised.

    Returns ``(tree, charges, defect)``. On a defect the tree comes back
    **untouched** and ``charges`` is empty, because the walk raised part-way
    through and a partial charge list would be a lie: the caller is about to
    persist these, and persisting half a plan's damage while reporting a refusal
    would leave the ledger describing a run that never happened.

    ``BudgetNode``'s own ``InvariantViolationError`` covers more than the path
    lookup (a scope order the tree was authored against, a duplicate child, a
    negative charge), so the whole exception is classified rather than just the
    one case :func:`probe_budget` documents. Any invariant raised while walking
    the tree is a malformed hierarchy, and a malformed hierarchy refuses.
    """
    try:
        charged, charges = _charge_plan(plan, inputs, tree)
    except InvariantViolationError as exc:
        context: dict[str, Any] = {
            "budget_root": tree.key,
            "budget_path": list(inputs.budget_path),
        }
        return tree, (), _defect_from_exception(exc, context)
    return charged, charges, None


def probe_budget_safely(
    plan: ExecutionPlan, inputs: PolicyGateInputs
) -> tuple[tuple[BudgetCharge, ...], PolicyConfigDefect | None]:
    """:func:`probe_budget`, with a misconfiguration returned instead of raised.

    Returns ``(charges, defect)``. Exactly one is meaningful: a non-empty
    ``defect`` means nothing was charged and nothing was spent, because the path
    could not be resolved at all — there is no partial answer to give.

    A gate mounted with no budget at all is **not** a defect: an absent
    hierarchy is a system nobody configured one for, and the reconciliation below
    already reports it as ``none`` rather than inventing a refusal.
    """
    if inputs.budget is None:
        return (), None
    return _charge_plan_safely(plan, inputs, inputs.budget)[1:]


# =============================================================================
# The two budget systems, and the one answer
#
# Phase 2 left these unreconciled: ``probe_budget`` answered "has this run's
# hierarchy exhausted?" and ``safety.check_blast_radius`` answered "is this
# target over its quota?", each over its own arithmetic, neither knowing the other
# existed. Everything below is the reconciliation.
# =============================================================================


class BudgetAuthority(StrEnum):
    """Which system decided the combined answer, and by what rule.

    The values are a truth table, not a ranking. ``NONE`` is the only answer that
    means "nobody spoke"; everything else either permitted or refused, and a
    refusal never has a *winner* because a refusal is not contested.
    """

    #: Neither system is configured with this plan.
    NONE = "none"
    #: Both configured systems permitted the plan.
    BOTH_PERMIT = "both_permit"
    #: Only the hierarchical tree was configured and it permitted the plan.
    HIERARCHY_PERMITS = "hierarchy_permits"
    #: Only the per-target quota was configured and it permitted the plan.
    QUOTA_PERMITS = "quota_permits"
    #: The hierarchical budget refused.
    HIERARCHY = "hierarchy"
    #: The per-target quota refused.
    QUOTA = "quota"
    #: Both refused. Reported as the hierarchy's refusal, with both in the inputs.
    BOTH_REFUSE = "both_refuse"


@dataclass(frozen=True)
class HierarchyBudgetView:
    """What the five-level budget tree says about this plan."""

    configured: bool
    charges: tuple[BudgetCharge, ...] = ()
    breached: tuple[BudgetCharge, ...] = ()

    @property
    def refused(self) -> bool:
        return bool(self.breached)


@dataclass(frozen=True)
class QuotaBudgetView:
    """What the per-target cumulative damage quota says about this plan.

    ``charges`` is the ledger's running record, one entry per charged step, and
    ``refusal`` is the *first* charge that exceeded — which is the one
    ``check_blast_radius`` would have raised on, since it stops at the first
    breach.
    """

    configured: bool
    charges: tuple[QuotaCharge, ...] = ()
    refusal: QuotaCharge | None = None

    @property
    def refused(self) -> bool:
        return self.refusal is not None


@dataclass(frozen=True)
class BudgetReconciliation:
    """Both systems' answers, and the one verdict they combine into."""

    authority: BudgetAuthority
    hierarchy: HierarchyBudgetView
    quota: QuotaBudgetView
    refusal: PolicyRefusal | None = None

    @property
    def within_budget(self) -> bool:
        """The one answer. ``True`` only when nothing refused."""
        return self.refusal is None

    def inputs(self) -> dict[str, Any]:
        """The machine-readable half, for ``PolicyGateResult``."""
        breach = self.hierarchy.breached[0] if self.hierarchy.breached else None
        return {
            "budget_authority": self.authority.value,
            "hierarchy_configured": self.hierarchy.configured,
            "quota_configured": self.quota.configured,
            "hierarchy_scope": breach.scope.value if breach is not None else "",
            "hierarchy_key": breach.key if breach is not None else "",
            "hierarchy_after_s": breach.after_s if breach is not None else 0.0,
            "hierarchy_limit_s": breach.limit_s if breach is not None else None,
            "quota_rule_id": self.quota.refusal.rule_id if self.quota.refusal else "",
            "quota_worst_target": self.quota.refusal.worst_node if self.quota.refusal else "",
            "quota_after_s": self.quota.refusal.worst_node_s if self.quota.refusal else 0.0,
            "quota_limit_s": self.quota.refusal.limit_s if self.quota.refusal else 0.0,
        }

    def describe(self) -> str:
        if self.within_budget:
            return f"budget: within ({self.authority.value})"
        return f"budget: refused ({self.authority.value})"


def probe_quota(plan: ExecutionPlan, inputs: PolicyGateInputs) -> QuotaBudgetView:
    """The per-target quota system's answer, probed on a fresh ledger.

    **Why the gate can answer this without a topology graph.**
    ``safety.check_blast_radius`` charges the target set unioned with its
    dependents closure, and compares the *worst single target's* accumulated
    damage against the budget.
    The closure widens *which* nodes are charged, never *how much* each one is:
    every affected node accrues the same ``duration_s x damage_weight`` for that
    step. So the worst node's running total is a sum over steps that does not
    depend on the closure at all, and the per-fault ceiling compares one step's
    per-node term, which does not depend on it either. Both comparisons are
    reproducible from the plan alone.

    **The one-way invariant that makes this safe.** Because the closure is a
    superset of the plan's own resolved targets, every node's accumulated total
    under the authoritative ledger is at least the total this probe computes, so
    ``worst_node_s`` there is at least ``worst_node_s`` here. Therefore:

    * a *refusal* from this probe is final — ``check_blast_radius`` will reach the
      same verdict with the closure-exact numbers, and refuses sooner;
    * a *permit* from this probe is not by itself sufficient, because the
      authoritative ledger can refuse on closure-widened damage.

    Neither half loses a refusal, which is the property that matters: this probe
    can only move a refusal earlier, never past one. ``tests/unit/
    test_policy_evidence.py`` pins the direction against the real ledger.

    A step whose targets resolved to nothing charges nothing here, which is what
    ``check_blast_radius`` does too — it passes the affected set straight
    through, and an empty set accrues nothing.
    """
    if inputs.damage_quota is None:
        return QuotaBudgetView(configured=False)
    ledger = DamageLedger()
    charges: list[QuotaCharge] = []
    for fault in plan_faults(plan):
        node_ids = frozenset().union(*(target.node_ids for target in fault.targets))
        if not node_ids:
            continue
        charge = ledger.charge(
            fault_id=fault.fault_id,
            duration_s=float(fault.duration),
            node_ids=node_ids,
            quota=inputs.damage_quota,
        )
        charges.append(charge)
        if charge.exceeded:
            # ``check_blast_radius`` raises on the first breach, so nothing after
            # it would ever be charged by the authoritative ledger either.
            break
    return QuotaBudgetView(
        configured=True,
        charges=tuple(charges),
        refusal=next((charge for charge in charges if charge.exceeded), None),
    )


def reconcile_budgets(
    hierarchy: HierarchyBudgetView, quota: QuotaBudgetView
) -> BudgetReconciliation:
    """The single authoritative answer to "is this plan within budget?".

    **Neither system wins, because there is nothing to win.** The plan is within
    budget if and only if both systems permit it — the conjunction is the whole
    rule, and it is symmetric on purpose. The two are not two measurements of one
    quantity:

    * the hierarchy answers "has this *team / service / experiment* spent its
      window?", over spend that is **persisted across runs**;
    * the quota answers "has *this target* been impaired for too long inside
      this plan?", over a ledger that ``validate_plan`` starts fresh on every
      pass.

    Summing them, taking the minimum, or letting either relax the other would all
    be wrong: the two count overlapping damage-seconds at different horizons, so
    any arithmetic combination double-counts, and "whichever is stricter" would
    let a system that cannot see the other's scope answer for it. A plan refused
    by either is refused; a plan allowed by both is allowed. There is no
    configuration of limits under which those two sentences are false.

    **Which one reports.** A refusal is reported by the hierarchy when both
    refused (:attr:`BudgetAuthority.BOTH_REFUSE`), for two reasons that are about
    the reader rather than the arithmetic. It is the plan-level aggregate, so it
    names the scope whose limit an operator would go and change; and it is
    evaluated first inside ``evaluate_gate``, which keeps the refusal ordering
    Phase 2 established. The other system's numbers travel in the refusal's
    inputs, so a reader is told what the quota thought too.

    Both refusals are retained on the result, so nothing here is lost by
    reporting only one of them.
    """
    breached_hierarchy = hierarchy.breached
    quota_refusal = quota.refusal
    if hierarchy.refused and quota.refused:
        authority = BudgetAuthority.BOTH_REFUSE
    elif hierarchy.refused:
        authority = BudgetAuthority.HIERARCHY
    elif quota_refusal is not None:
        authority = BudgetAuthority.QUOTA
    elif not hierarchy.configured and not quota.configured:
        authority = BudgetAuthority.NONE
    elif hierarchy.configured and quota.configured:
        authority = BudgetAuthority.BOTH_PERMIT
    elif quota.configured:
        authority = BudgetAuthority.QUOTA_PERMITS
    else:
        authority = BudgetAuthority.HIERARCHY_PERMITS
    return BudgetReconciliation(
        authority=authority,
        hierarchy=hierarchy,
        quota=quota,
        refusal=_budget_refusal(breached_hierarchy, quota_refusal),
    )


def effective_compatibility(inputs: PolicyGateInputs) -> tuple[CompatibilityEdge, ...]:
    """The collision graph this gate consults: the bundle's, then the caller's.

    Phase 3 moved the graph *into* the bundle, so it is covered by the policy
    digest an approval binds. A caller may still supply edges of its own — an
    operator's local denylist, a provider's declared incompatibilities — and the
    union is what gets consulted.

    **The bundle wins a disputed pair.** Two edges for the same unordered pair
    are collapsed to one here, before
    :func:`~mayhem.domain.policy.evaluate_compatibility` is ever asked, because
    that function returns the first edge it finds in a sorted walk and two
    disagreeing declarations would otherwise be resolved by fault-id ordering —
    a fact about spelling, not about policy. The rule is the one the rest of
    plan 07 already uses for rules: the nearer, versioned, digest-pinned
    declaration wins.
    """
    declared = inputs.bundle.graph()
    if not inputs.compatibility:
        return declared
    claimed = {edge.pair() for edge in declared}
    return (*declared, *(edge for edge in inputs.compatibility if edge.pair() not in claimed))


def check_compatibility(
    plan: ExecutionPlan, inputs: PolicyGateInputs, facts: PolicyFacts
) -> tuple[CompatibilityOutcome, ...]:
    """Consult the collision graph once per ``{earlier, new}`` pair.

    The same reading ``safety._first_forbidden_pair`` uses — every earlier
    step paired with the new one, never "all of them plus the new one" — so a
    three-fault plan is checked as completely as a two-fault one, and the pair
    is caught on whichever of its two members runs second. Undeclared pairs
    come back permitted; see the module docstring for why that is safe.

    Consults :func:`effective_compatibility`, so the graph the *bundle* pins is
    consulted as well as whatever the caller supplied.
    """
    edges = effective_compatibility(inputs)
    outcomes = []
    seen: list[str] = []
    for fault in plan_faults(plan):
        new = fault.fault_id
        for earlier in sorted({prior for prior in seen if prior != new}):
            outcomes.append(evaluate_compatibility(edges, earlier, new, facts))
        seen.append(new)
    return tuple(outcomes)


# =============================================================================
# Approval requirements (surfaced only — plan 09 implements approvals)
# =============================================================================


def required_approvals(
    rules: Iterable[PolicyRule], facts: PolicyFacts
) -> tuple[RequiredApproval, ...]:
    """What a decision says must be approved before the plan may stand.

    An ``APPROVAL_LEVEL`` rule *is* the approval statement: a bundle that means
    "this needs SRE plus the service owner" authors
    ``approval_level in ("sre", "service_owner")``. Two rules govern whether it
    speaks. It must have **matched these facts** — an unmatched rule is a
    statement about some other plan, not a requirement of this one. Matching is
    read off the rule rather than off ``decision.matched_rules`` on purpose: a
    denied decision reports only the rules that *refused*, and the plan's own
    example output puts the requirement on a denial ("production policy forbids
    critical faults without two approvals / Required: service owner + SRE" — the
    levels render sorted, because the same requirement set must render the same
    string every time it is read).
    Reading only the deny rules would report nothing exactly when a reader most
    needs to know.

    The levels it names are reported as *outstanding*: a level the facts already
    carry (supplied by the caller as ``observed[APPROVAL_LEVEL]``) is dropped,
    because a requirement that is already met is not something a human still has
    to go and do. With nothing on hand the result is the full list, which is the
    shape the plan's example renders.

    Nothing is requested, bound, or enforced here: this function's whole
    obligation is that the requirement is *visible* on the refusal, so a reader
    sees what would change the verdict instead of only learning that it
    changed. ``controller.approval_gate`` is where the requirement is answered
    — it takes the levels this returns and turns them into a quorum.
    """
    held = facts.observed(PolicyDimension.APPROVAL_LEVEL) or frozenset()
    found: list[RequiredApproval] = []
    for rule in resolve_precedence(rules):
        if rule.dimension is not PolicyDimension.APPROVAL_LEVEL:
            continue
        if not rule.matches(facts):
            continue
        for level in rule.predicate.values:
            if level in held:
                continue
            found.append(
                RequiredApproval(
                    approval_level=level,
                    rule_id=rule.rule_id,
                    reason=rule.reason or rule.explain(facts),
                    remediation=rule.remediation or f"obtain {level} approval for this plan",
                )
            )
    return tuple(sorted(found, key=lambda approval: (approval.approval_level, approval.rule_id)))


# =============================================================================
# Refusals
# =============================================================================


def _with_requirements(text: str, approvals: tuple[RequiredApproval, ...]) -> str:
    if not approvals:
        return text
    levels = ", ".join(approval.approval_level for approval in approvals)
    return f"{text} Required: {levels}."


def _expiry_refusal(inputs: PolicyGateInputs, decision: PolicyDecision) -> PolicyRefusal | None:
    if inputs.bundle.authorizes(inputs.now):
        return None
    reason = (
        decision.reasons[0]
        if decision.reasons
        else (f"policy bundle {inputs.bundle.describe()} cannot authorize a run")
    )
    return PolicyRefusal(
        rule_id=RULE_BUNDLE_EXPIRED,
        reason=reason,
        remediation="pin a newer bundle version; an expired policy version cannot authorize a run",
        inputs={
            "bundle": inputs.bundle.describe(),
            "expires_at": inputs.bundle.expires_at.isoformat() if inputs.bundle.expires_at else "",
            "now": inputs.now.isoformat(),
        },
    )


def _lock_refusal(verdicts: tuple[LockVerdict, ...]) -> PolicyRefusal | None:
    blocked = [verdict for verdict in verdicts if not verdict.granted]
    if not blocked:
        return None
    holder = blocked[0]
    return PolicyRefusal(
        rule_id=RULE_LOCK_CONTENDED,
        reason=f"{holder.reason} [{RULE_LOCK_CONTENDED}]",
        remediation=(
            "queue behind the holder, narrow the target set, or wait for the lock to expire"
        ),
        inputs={
            "resource": holder.resource,
            "requested_by": holder.requested_by,
            "blockers": list(holder.blockers),
            "holder_experiment_id": holder.holder_experiment_id,
            "holder_run_id": holder.holder_run_id,
            "holder_expires_at": holder.holder_expires_at.isoformat()
            if holder.holder_expires_at
            else "",
        },
    )


def _budget_refusal(
    breached: tuple[BudgetCharge, ...], quota_refusal: QuotaCharge | None
) -> PolicyRefusal | None:
    """The single budget refusal, reported by the hierarchy when both fired.

    Phase 4 replaced "the hierarchy's answer" with "both systems' answers". The
    hierarchy's rule id, wording, and remediation are unchanged, so a refusal that
    only the hierarchy produces reads byte-for-byte as it did in Phase 2; what is
    new is the quota's numbers in ``inputs`` and the two rule ids in
    ``budget_rule_ids``, which is what lets a reader see that the other system
    agreed rather than that the other system was never consulted.
    """
    offenders = [charge for charge in breached if charge.exceeded]
    if not offenders and quota_refusal is None:
        return None
    rule_ids = []
    inputs: dict[str, Any] = {}
    if offenders:
        first = offenders[0]
        rule_ids.append(RULE_BUDGET_EXHAUSTED)
        inputs |= {
            "scope": first.scope.value,
            "key": first.key,
            "before_s": first.before_s,
            "after_s": first.after_s,
            "limit_s": first.limit_s,
            "headroom_s": first.headroom_s,
        }
        reason = (
            f"damage budget: {first.scope.value} budget {first.key!r} reaches "
            f"{first.after_s:.0f}s of damage, over its {first.limit_s:.0f}s budget "
            f"[{RULE_BUDGET_EXHAUSTED}]"
        )
        remediation = (
            "split the plan across more runs, shorten the faults, or raise the "
            f"limit at {first.scope.value} level {first.key!r}"
        )
    else:
        # Narrowed by the guard at the top: no hierarchy breach and a quota
        # refusal is the only way to reach here.
        assert quota_refusal is not None
        rule_ids.append(quota_refusal.rule_id)
        inputs |= dict(quota_refusal.inputs())
        reason = quota_refusal.reason
        remediation = quota_refusal.remediation
    if offenders and quota_refusal is not None:
        # Both refused. The hierarchy reports — see ``reconcile_budgets`` — and
        # the quota's own numbers and rule id ride along so the record shows a
        # conjunction rather than a single system's opinion.
        rule_ids.append(quota_refusal.rule_id)
        inputs |= {
            "also_refused_by": quota_refusal.rule_id,
            "quota_fault_id": quota_refusal.fault_id,
            "quota_step_index": quota_refusal.step_index,
            "quota_worst_node": quota_refusal.worst_node,
            "quota_worst_node_s": round(quota_refusal.worst_node_s, 3),
            "quota_budget_s": quota_refusal.limit_s,
        }
    return PolicyRefusal(
        rule_id=rule_ids[0],
        reason=reason,
        remediation=remediation,
        inputs={**inputs, "budget_rule_ids": rule_ids},
    )


def _config_refusal(defect: PolicyConfigDefect) -> PolicyRefusal:
    """The refusal for a policy configuration that cannot be evaluated at all.

    Its own rule id, distinct from every other refusal here, because no bundle
    rule spoke and none could: the refusal is about the *policy layer*, not about
    this plan. A reader who sees ``policy.config_invalid`` knows the answer is
    "fix the configuration", not "change the plan".
    """
    return PolicyRefusal(
        rule_id=RULE_POLICY_CONFIG,
        reason=f"policy config: {defect.reason} [{RULE_POLICY_CONFIG}]",
        remediation=defect.remediation,
        inputs={**defect.inputs, "config_defect": defect.defect.value},
    )


def _config_decision(inputs: PolicyGateInputs, defect: PolicyConfigDefect) -> PolicyDecision:
    """The deny a broken configuration reaches, with no rule set behind it.

    ``rule_digest``, ``policy_digest`` and ``facts_digest`` are all empty, and
    that is the honest value rather than a placeholder: the bundle could not be
    read, so no rule set was resolved, no bundle content was digested, and no
    facts were compared against anything. A consumer that requires a non-empty
    ``policy_digest`` before it will seal a decision — which is what
    :mod:`mayhem.controller.policy_evidence` does — refuses this record for free,
    and correctly: there is nothing here to attest.
    """
    return PolicyDecision(
        outcome="deny",
        reasons=(f"{defect.reason} [{RULE_POLICY_CONFIG}]",),
        matched_rules=(),
        bundle_id=inputs.bundle.bundle_id,
        bundle_version=inputs.bundle.version,
        rule_digest="",
        policy_digest="",
        facts_digest="",
    )


def _compatibility_refusal(outcomes: tuple[CompatibilityOutcome, ...]) -> PolicyRefusal | None:
    unsafe = [outcome for outcome in outcomes if not outcome.safe]
    if not unsafe:
        return None
    first = unsafe[0]
    return PolicyRefusal(
        rule_id=RULE_COMPAT_CONFLICT,
        reason=f"compatibility: {first.describe()} [{RULE_COMPAT_CONFLICT}]",
        remediation="drop one fault of the pair, or satisfy the edge's conditions",
        inputs={
            "left_fault": first.left_fault,
            "right_fault": first.right_fault,
            "verdict": first.verdict.value,
            "declared": first.declared,
            "reason": first.reason,
            "unsatisfied": list(first.unsatisfied),
        },
    )


def _decision_refusal(
    rules: Iterable[PolicyRule],
    decision: PolicyDecision,
    approvals: tuple[RequiredApproval, ...],
) -> PolicyRefusal | None:
    if decision.allowed:
        return None
    matched = set(decision.matched_rules)
    fixes = [
        rule.remediation
        for rule in resolve_precedence(rules)
        if rule.rule_id in matched and rule.remediation
    ]
    reason = "; ".join(decision.reasons) or "policy bundle denied these facts"
    return PolicyRefusal(
        rule_id=RULE_BUNDLE_DENY,
        reason=_with_requirements(reason, approvals),
        remediation="; ".join(fixes) or "use a bundle version whose rules permit these facts",
        # ``PolicyDecision.inputs`` is the machine-readable half, plus the rule
        # ids it was reached by so :meth:`PolicyRefusal.rule_ids` can answer
        # "which policy rules refused this?" without parsing the reason.
        inputs={**decision.inputs(), "policy_rule_ids": list(decision.matched_rules)},
    )


# =============================================================================
# The gate
# =============================================================================


def evaluate_gate(
    plan: ExecutionPlan,
    inputs: PolicyGateInputs,
    *,
    environment: str | None = None,
    sink: MutationSink | None = None,
) -> PolicyGateResult:
    """Evaluate ``inputs`` against ``plan`` and return the verdict with its evidence.

    Pure, and **total over broken configurations**: a drifted pin, an unresolvable
    inheritance, and an unmappable budget path all return a refusal named by
    :data:`RULE_POLICY_CONFIG` instead of raising. Phase 2's contract was that
    these raise, and that is still true of the primitives — ``verify_pin``,
    ``effective_rules`` and ``probe_budget`` all raise, and their direct callers
    and tests depend on it. What Phase 4 removed is the *gate's* willingness to
    let them escape: an operator's typo in a policy bundle ends a run with a
    remediation somebody can act on, not with a traceback. The defect, the
    primitive's own reason string, and the fix are all on the result
    (:attr:`PolicyGateResult.config_defect`).

    A broken configuration refuses *first*, before expiry, locks, and the bundle's
    own verdict, because none of those can be evaluated without a readable rule
    set. That is the only ordering change from Phase 2 and it can only move a
    refusal earlier onto a more fundamental cause.

    ``sink`` is accepted and never written — see :class:`MutationSink`.
    """
    defect = detect_config_defect(inputs)
    if defect is None:
        charges, defect = probe_budget_safely(plan, inputs)
    else:
        charges = ()
    if defect is not None:
        return _refused_by_config(plan, inputs, defect, environment=environment)
    rules = effective_rules(inputs.bundle, inputs.index)
    facts = derive_facts(plan, inputs, environment=environment)
    decision = evaluate_bundle(inputs.bundle, facts, now=inputs.now, index=inputs.index)
    approvals = required_approvals(rules, facts)
    verdicts = check_locks(plan, inputs)
    outcomes = check_compatibility(plan, inputs, facts)
    budget = reconcile_budgets(
        HierarchyBudgetView(
            configured=inputs.budget is not None,
            charges=charges,
            breached=tuple(charge for charge in charges if charge.exceeded),
        ),
        probe_quota(plan, inputs),
    )
    for candidate in (
        _expiry_refusal(inputs, decision),
        _lock_refusal(verdicts),
        budget.refusal,
        _compatibility_refusal(outcomes),
        _decision_refusal(rules, decision, approvals),
    ):
        if candidate is not None:
            return PolicyGateResult(
                decision=decision,
                facts=facts,
                refusal=candidate,
                lock_verdicts=verdicts,
                pending_charges=charges,
                compatibility=outcomes,
                required_approvals=approvals,
                budget=budget,
                bundle=inputs.bundle,
                now=inputs.now,
            )
    return PolicyGateResult(
        decision=decision,
        facts=facts,
        refusal=None,
        lock_verdicts=verdicts,
        pending_charges=charges,
        compatibility=outcomes,
        required_approvals=approvals,
        budget=budget,
        bundle=inputs.bundle,
        now=inputs.now,
    )


def _refused_by_config(
    plan: ExecutionPlan,
    inputs: PolicyGateInputs,
    defect: PolicyConfigDefect,
    *,
    environment: str | None = None,
) -> PolicyGateResult:
    """The whole result for a policy configuration that cannot be evaluated.

    Facts are still derived: they come from the plan and the caller's ``observed``
    and never from the bundle, so a reader can see what *would* have been
    evaluated once the configuration is repaired. Everything that needed a
    readable rule set is empty — the decision's digests, the approval
    requirements, the lock verdicts, the compatibility outcomes, the budget
    reconciliation — and the decision itself is the deny from
    :func:`_config_decision`.

    ``facts_digest`` on that deny is deliberately empty too, even though the facts
    were derived: a digest there would claim the facts were *compared* against a
    rule set, and no rule set was read. The facts are on the result for a human;
    the digests are for machines, and a machine is told "nothing was evaluated".
    """
    return PolicyGateResult(
        decision=_config_decision(inputs, defect),
        facts=derive_facts(plan, inputs, environment=environment),
        refusal=_config_refusal(defect),
        config_defect=defect,
        bundle=inputs.bundle,
        now=inputs.now,
    )


def simulate_gate(
    plan: ExecutionPlan,
    inputs: PolicyGateInputs,
    *,
    environment: str | None = None,
    sink: MutationSink | None = None,
) -> PolicyGateResult:
    """Evaluate a frozen plan and return the decision, mutating nothing.

    Deliberately *not* a second implementation: this is
    :func:`evaluate_gate` with ``simulated=True`` set on the result. Purity is
    therefore structural rather than a promise — the plan is a frozen model,
    budgets are probed on copies, ``acquire_lock`` returns a verdict instead of
    taking the lock, and ``sink`` receives nothing. A preview and an admission
    cannot disagree because there is only one code path.
    """
    return replace(evaluate_gate(plan, inputs, environment=environment, sink=sink), simulated=True)


# =============================================================================
# The commit path: budget charges post to the ledger hierarchically
#
# Plan 07 Phase 4's other half, and the last thing the plan listed as not done.
# :func:`evaluate_gate` stays what it has always been — a pure function that reads
# a tree and answers "would this charge fit". Nothing below is reachable from it,
# from :func:`probe_budget`, or from :func:`simulate_gate`. The commit is a
# *separate, explicit* operation a caller makes after admission, and it is the
# only thing in this module that writes anything.
#
# Three properties are load-bearing, and each one is a decision rather than an
# implementation detail.
#
# * **A charge posts to the leaf and to every ancestor above it.** Damage inside
#   a team spends the team's window whether or not the team's own node ran
#   anything; :meth:`BudgetNode.post_charge` has always had that arithmetic and
#   :func:`commit_budget` persists all of it rather than the leaf alone. A ledger
#   holding only leaves would answer "has this fault been over its limit" and
#   never "has this team", which is the question the team-level node exists for.
# * **An exhausted ancestor refuses even when the leaf has headroom.** The
#   judgement reads *every* posted charge, so the widest level that went over is
#   what the refusal names, and the tree can be exhausted at any one of five
#   levels without the leaf ever noticing.
# * **Charge, then judge — and a refused charge stays charged.** The same
#   discipline :class:`~mayhem.domain.quota.DamageLedger` charges with, for the
#   same reason: a run that attempted the damage did it, whatever a gate said
#   about it. Rolling the number back would leave the ledger disagreeing with the
#   world in the one direction that flatters the next run, because the headroom a
#   refund creates is exactly what the following run plans against. A budget that
#   refunds a refusal is not a budget anybody can reason about.
#
# **What this path does not do, stated rather than left to be discovered.** It does
# not merge with the per-target ``DamageQuota``. That ledger answers spend inside
# one plan on a fresh ledger each pass; this one answers spend persisted across
# runs. :func:`reconcile_budgets` remains the pure conjunction of the two and
# remains the only answer to "is this plan within budget" — a commit does not
# consult the quota and a quota charge does not consult this ledger, so no
# damage-second is ever counted by both.
# =============================================================================


class HierarchicalBudgetLedger(Protocol):
    """Where posted damage-budget charges are written, and read back from.

    Two operations, because that is all a hierarchical budget needs: append one
    charge, and read every charge ever appended. **Spend is not stored as a
    running total** — it is the sum of the entries — so a stored total can never
    disagree with the charges that produced it, and a reader can always show the
    arithmetic rather than a number nobody can account for.

    Append-only is the interface, not a convention: there is deliberately no
    ``update`` and no ``delete``. The correction for a charge that should not have
    been made is a new record written by whoever owns the hierarchy, which is the
    same discipline ``infra.audit_stream`` enforces in SQL triggers and the same
    one :func:`fold_spend`'s docstring relies on.
    """

    def append(self, entry: BudgetLedgerEntry) -> None:
        """Record one charge durably.

        A failure here must propagate. A commit that reported success while a
        charge was lost would leave the ledger understating damage and the gate
        over-admitting against it forever after.
        """

    def entries(self) -> tuple[BudgetLedgerEntry, ...]:
        """Every charge on the ledger, in the order it was appended."""


KIND_BUDGET_CHARGE = "policy.budget_charge"
"""The ``observations.kind`` every persisted damage-budget charge is written under."""


def persisted_budget(tree: BudgetNode, ledger: HierarchicalBudgetLedger) -> BudgetNode:
    """``tree`` with everything the ledger says has already been spent.

    The read half of the commit path, and the reason "persisted across runs" is a
    claim this module can make rather than an aspiration. A caller mounts the
    *authored* hierarchy — shape and authored limits, never spend — and this
    returns the same tree carrying the history, which is what the gate then probes
    and the commit then extends.
    """
    return fold_spend(tree, ledger.entries())


@dataclass(frozen=True)
class BudgetCommit:
    """What a commit posted to the ledger, and what posting it judged.

    ``charges`` is *everything* that was posted, widest level first per step, and
    ``breached`` is the subset whose ``after_s`` passed its own limit. ``tree`` is
    the post-charge tree including every run's prior spend, which is what a caller
    mounts next time so the window carries forward rather than resetting.

    ``entries`` counts ledger rows written. It is the field that answers "did this
    run spend anything", and it is separate from ``charges`` only so a caller can
    see the difference between "charged nothing" and "had nothing to charge".
    """

    charges: tuple[BudgetCharge, ...] = ()
    tree: BudgetNode | None = None
    breached: tuple[BudgetCharge, ...] = ()
    entries: int = 0
    config_defect: PolicyConfigDefect | None = None
    refusal: PolicyRefusal | None = None

    @property
    def posted(self) -> bool:
        """True when anything reached the ledger."""
        return self.entries > 0

    @property
    def within_budget(self) -> bool:
        return self.refusal is None

    @property
    def refused(self) -> bool:
        return self.refusal is not None

    def inputs(self) -> dict[str, Any]:
        """The machine-readable half, shaped like :meth:`PolicyGateResult.inputs`."""
        return {
            "budget_posted_entries": self.entries,
            "budget_posted": [
                f"{charge.scope.value}:{charge.key}={charge.after_s}" for charge in self.charges
            ],
            "budget_posted_breached": [
                f"{charge.scope.value}:{charge.key}" for charge in self.breached
            ],
            "budget_post_refusal": self.refusal.rule_id if self.refusal else "",
            "budget_post_config_defect": (
                self.config_defect.defect.value if self.config_defect else ""
            ),
        }

    def describe(self) -> str:
        if self.refusal is not None:
            return f"budget commit refused: {self.refusal.reason}"
        if not self.posted:
            return "budget commit posted nothing (no budget mounted)"
        return f"budget commit posted {self.entries} charge(s) to the damage ledger"


def commit_budget(
    plan: ExecutionPlan,
    inputs: PolicyGateInputs,
    ledger: HierarchicalBudgetLedger,
) -> BudgetCommit:
    """Post this plan's damage to the hierarchical ledger, then judge the result.

    **Call this after admission, never inside it.** The gate's own answer is
    :func:`probe_budget`, and it is what decides whether the plan may run; this is
    the operation that makes the answer cost something. Keeping them apart is not
    tidiness — it is the only way ``simulate_gate`` can stay provably free of
    writes, because a preview and a commit that shared a code path could not.

    **The charge is computed against the ledger, not against the mounted tree.**
    The mounted tree carries the *authored* limits; the spend comes from
    :func:`persisted_budget`, so a plan that a previous run pushed an ancestor over
    is refused here even though the leaf has room left. This is what makes the
    hierarchy a budget over time rather than a per-run ceiling.

    **The charges are recomputed here rather than taken from a gate result.** A
    result handed in was reached against a ledger as it stood then, and this call
    may be the one that follows somebody else's commit in between. The numbers
    posted are the numbers judged *here*, on the ledger as it stands now — from
    the same :func:`_charge_plan` the gate probes with, so the two cannot disagree
    about arithmetic while still agreeing about when.

    **No budget mounted is allowed, and posts nothing.** That is the reading
    :func:`mayhem.controller.campaign_dispatch.campaign_budget_verdict` gives an
    unmounted campaign budget: a limit nobody configured is not a limit, and
    refusing here would invent one. A *malformed* hierarchy is a different thing
    and refuses, with the same ``policy.config_invalid`` refusal and the same
    per-defect remediation the gate produces — this path reuses
    :func:`_config_refusal` rather than authoring a second wording.

    **The refusal reuses :func:`_budget_refusal`,** so the rule id
    (:data:`RULE_BUDGET_EXHAUSTED`), the reason, the remediation and the inputs
    are byte-identical whether the gate or the commit refused. One id for one
    failure is what keeps a proof's obligation mapping honest, and it is why this
    path introduces no rule id of its own.

    Refusals here are :class:`PolicyRefusal` values, not exceptions: a commit that
    overspends is an operational outcome somebody needs to read and reconcile, not
    a crash. A ledger that *cannot be read* does raise
    (``budget.ledger_entry_invalid``), because in that case the module does not
    know what the budget has already spent and must not guess.
    """
    if inputs.budget is None:
        return BudgetCommit()
    tree = persisted_budget(inputs.budget, ledger)
    charged, charges, defect = _charge_plan_safely(plan, inputs, tree)
    if defect is not None:
        # Nothing was posted. The walk raised before it could say who pays, so
        # there is no damage to record — and posting "what we could work out so
        # far" would leave the ledger describing damage for a plan the gate never
        # charged at all.
        return BudgetCommit(tree=tree, config_defect=defect, refusal=_config_refusal(defect))
    run_id = inputs.run_id or plan.run_id
    for charge in charges:
        ledger.append(BudgetLedgerEntry.from_charge(charge, run_id=run_id, charged_at=inputs.now))
    breached = tuple(charge for charge in charges if charge.exceeded)
    # Judged *after* every append, and nothing above this line can undo one. That
    # ordering is the charge-then-judge rule stated as control flow rather than
    # as a promise: there is no code path from a breach back to a refund.
    return BudgetCommit(
        charges=charges,
        tree=charged,
        breached=breached,
        entries=len(charges),
        refusal=_budget_refusal(breached, None),
    )
