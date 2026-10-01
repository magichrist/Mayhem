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
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_context import ExecutionContext
from mayhem.domain.faults import FaultCategory
from mayhem.domain.policy import (
    BUDGET_SCOPE_ORDER,
    DAMAGE_PRECISION,
    BudgetScope,
    PolicyDimension,
    PolicyFacts,
    ResourceLock,
    acquire_lock,
    effective_rules,
    evaluate_bundle,
    evaluate_compatibility,
    resolve_precedence,
)
from mayhem.domain.quota import damage_weight
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
        PolicyDecision,
        PolicyRule,
    )

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

_LOCK_CHARS = frozenset(string.ascii_lowercase + string.digits + "._:-")
_LOCK_LEAD = frozenset(string.ascii_lowercase + string.digits)


# =============================================================================
# Inputs and outputs
# =============================================================================


@dataclass(frozen=True)
class PolicyGateInputs:
    """Everything the gate needs that the plan does not carry.

    ``index`` supplies the ancestor bundles named by ``bundle.parents`` for
    inheritance; an empty one is correct for a bundle with no parents. ``locks``
    is the caller's live lock set and ``compatibility`` the collision graph —
    both are read, never written. ``budget_path`` names the run's place in the
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
    compatibility: tuple[CompatibilityEdge, ...] = ()
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

    Phase 2's gate is read-only by construction, so nothing here is ever
    written and a simulation's sink is provably empty — the purity test asserts
    ``len(sink) == 0`` against a real object rather than against a comment.
    The type exists so the boundary is a name in the API: Phase 4's budget
    posting and lock granting are the calls that will appear here, and they are
    the only writes the gate will ever make.
    """

    calls: tuple[tuple[str, str], ...] = ()

    def record(self, kind: str, detail: str) -> MutationSink:
        """A sink with one more recorded mutation. Never called in Phase 2."""
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
        [*(f"namespace:{name}" for name in reqs.namespaces),
         *(f"tool:{name}" for name in reqs.tools),
         *(f"permission:{name}" for name in reqs.permissions)]
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


def probe_budget(plan: ExecutionPlan, inputs: PolicyGateInputs) -> tuple[BudgetCharge, ...]:
    """Charge every step against a *copy* of the budget and return the charges.

    ``BudgetNode`` is frozen and ``post_charge`` returns a new tree, so the
    running tree below is a local rebinding and ``inputs.budget`` is never
    spent — the probe-then-commit shape ``check_blast_radius`` already uses
    with ``DamageQuota.unrestricted()``. The returned charges are what a commit
    (Phase 4) would post, in the order a refusal would read them: widest level
    first, per step.
    """
    if inputs.budget is None:
        return ()
    tree = inputs.budget
    charges: list[BudgetCharge] = []
    for fault in plan_faults(plan):
        amount = round(float(fault.duration) * damage_weight(fault.fault_id), DAMAGE_PRECISION)
        path = _chargeable_path(tree, inputs.budget_path, fault.fault_id)
        tree, posted = tree.post_charge(path, amount)
        charges.extend(posted)
    return tuple(charges)


def check_compatibility(
    plan: ExecutionPlan, inputs: PolicyGateInputs, facts: PolicyFacts
) -> tuple[CompatibilityOutcome, ...]:
    """Consult the collision graph once per ``{earlier, new}`` pair.

    The same reading ``safety._first_forbidden_pair`` uses — every earlier
    step paired with the new one, never "all of them plus the new one" — so a
    three-fault plan is checked as completely as a two-fault one, and the pair
    is caught on whichever of its two members runs second. Undeclared pairs
    come back permitted; see the module docstring for why that is safe.
    """
    outcomes = []
    seen: list[str] = []
    for fault in plan_faults(plan):
        new = fault.fault_id
        for earlier in sorted({prior for prior in seen if prior != new}):
            outcomes.append(
                evaluate_compatibility(inputs.compatibility, earlier, new, facts)
            )
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
    critical faults without two approvals / Required: SRE + service owner").
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


def _expiry_refusal(
    inputs: PolicyGateInputs, decision: PolicyDecision
) -> PolicyRefusal | None:
    if inputs.bundle.authorizes(inputs.now):
        return None
    reason = decision.reasons[0] if decision.reasons else (
        f"policy bundle {inputs.bundle.describe()} cannot authorize a run"
    )
    return PolicyRefusal(
        rule_id=RULE_BUNDLE_EXPIRED,
        reason=reason,
        remediation="pin a newer bundle version; an expired policy version cannot authorize a run",
        inputs={
            "bundle": inputs.bundle.describe(),
            "expires_at": inputs.bundle.expires_at.isoformat()
            if inputs.bundle.expires_at
            else "",
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


def _budget_refusal(charges: tuple[BudgetCharge, ...]) -> PolicyRefusal | None:
    breached = [charge for charge in charges if charge.exceeded]
    if not breached:
        return None
    first = breached[0]
    return PolicyRefusal(
        rule_id=RULE_BUDGET_EXHAUSTED,
        reason=(
            f"damage budget: {first.scope.value} budget {first.key!r} reaches "
            f"{first.after_s:.0f}s of damage, over its {first.limit_s:.0f}s budget "
            f"[{RULE_BUDGET_EXHAUSTED}]"
        ),
        remediation=(
            "split the plan across more runs, shorten the faults, or raise the "
            f"limit at {first.scope.value} level {first.key!r}"
        ),
        inputs={
            "scope": first.scope.value,
            "key": first.key,
            "before_s": first.before_s,
            "after_s": first.after_s,
            "limit_s": first.limit_s,
            "headroom_s": first.headroom_s,
        },
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
        remediation="; ".join(fixes)
        or "use a bundle version whose rules permit these facts",
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

    Pure, and refused configurations raise rather than degrade: a bundle whose
    pin has drifted, one that inherits from a missing parent, and one caught in
    an inheritance cycle all raise :class:`InvariantViolationError`, matching the
    phase-1 contract that a broken policy layer is never silently dropped. Those
    are authoring errors; the *decisions* a bundle reaches are what the gate
    returns.

    ``sink`` is accepted and never written — see :class:`MutationSink`.
    """
    inputs.bundle.verify_pin()
    rules = effective_rules(inputs.bundle, inputs.index)
    facts = derive_facts(plan, inputs, environment=environment)
    decision = evaluate_bundle(inputs.bundle, facts, now=inputs.now, index=inputs.index)
    approvals = required_approvals(rules, facts)
    verdicts = check_locks(plan, inputs)
    charges = probe_budget(plan, inputs)
    outcomes = check_compatibility(plan, inputs, facts)
    for candidate in (
        _expiry_refusal(inputs, decision),
        _lock_refusal(verdicts),
        _budget_refusal(charges),
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
            )
    return PolicyGateResult(
        decision=decision,
        facts=facts,
        refusal=None,
        lock_verdicts=verdicts,
        pending_charges=charges,
        compatibility=outcomes,
        required_approvals=approvals,
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
    return replace(
        evaluate_gate(plan, inputs, environment=environment, sink=sink), simulated=True
    )
