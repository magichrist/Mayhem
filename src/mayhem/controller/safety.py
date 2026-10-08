from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.controller.approval_gate import (
    RULE_APPROVAL_ALLOW,
    RULE_APPROVAL_OVERRIDE,
    ApprovalGateInputs,
    ApprovalGateResult,
    verify_approvals,
)
from mayhem.domain.decisions import SafetyDecision, SafetySeverity
from mayhem.domain.errors import InvariantViolationError, TargetResolutionError
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.policy_gate import (
    RULE_APPROVAL_REQUIRED,
    RULE_BUNDLE_ALLOW,
    PolicyGateInputs,
    RequiredApproval,
    _risk_of,
    capability_requirements_for,
    evaluate_gate,
    simulate_gate,
)
from mayhem.domain.prediction import (
    customer_facing_node_ids,
    dependency_fan_out,
)
from mayhem.domain.provider import ProviderError, ProviderRegistration
from mayhem.domain.quota import DamageLedger, DamageQuota, QuotaCharge, is_catalog_fault
from mayhem.domain.risks import RiskLevel
from mayhem.domain.runtime_adapter import (
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
)
from mayhem.domain.target_selector import select_many

if TYPE_CHECKING:
    from collections.abc import Iterable

    from mayhem.config import PolicyCfg
    from mayhem.controller.k8s_admission import K8sAdmissionInput
    from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan, PlannedFault
    from mayhem.domain.policy_gate import PolicyGateResult
    from mayhem.domain.prediction import BlastCeilings
    from mayhem.domain.topology import NodeKind, TargetSelector, TopologyGraph

from mayhem.providers.participation import (
    ProviderAction,
    ProviderParticipationError,
    charge_provider_blast,
)
from mayhem.providers.sandbox import SandboxEnforcer, select_profile


class SafetyRefusedError(InvariantViolationError):
    def __init__(
        self, reason_code: str, message: str, decision: SafetyDecision | None = None
    ) -> None:
        super().__init__(reason_code, message)
        self.reason_code = reason_code
        self.decision = decision


def environment_fingerprint(
    *,
    host_names: Iterable[str],
    compose_digest: str,
    profile: str | None = None,
    policy_id: str | None = None,
    target_profile: str | None = None,
) -> str:
    payload = "|".join(
        (
            ",".join(sorted(host_names)),
            compose_digest,
            profile or "default",
            policy_id or "",
            target_profile or "",
        )
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class SafetyContext:
    policy: PolicyCfg
    budget: BlastRadiusBudget
    fingerprint: str
    allow_critical_cli: bool = False
    warnings: list[str] = field(default_factory=list)
    policy_id: str = ""
    decisions: list[SafetyDecision] = field(default_factory=list)
    environment: str | None = None
    target_profile: str | None = None
    # Cumulative damage budget. Deliberately *not* on ``BlastRadiusBudget``: the
    # five per-step caps live there because they are the spec's five caps, and
    # this is a sixth thing the gate checks. It defaults to an active budget
    # rather than ``None`` — a quota nobody configures is a quota nobody gets,
    # and the default is deliberately loose enough that ordinary drills never
    # meet it.
    damage_quota: DamageQuota = field(default_factory=DamageQuota)
    # Plan 09 Phase 2: the approval gate. ``None`` — the default — means this
    # context knows nothing about approvals, and admission is byte-for-byte what
    # it was before the field existed. It is independent of ``policy_gate`` on
    # purpose: a run must be approval-gated whether or not a policy bundle
    # exists, and a bundle may demand approvals without being the thing that
    # enforces them.
    #
    # Declared *before* ``policy_gate`` because ``tests/unit/test_policy_gate.py``
    # asserts that field is last on the dataclass. That assertion is that suite's
    # statement about its own addition, not a semantic claim about ordering, and
    # every construction of this context in the tree passes keywords.
    approval_gate: ApprovalGateInputs | None = None
    # v1.1.0 plan 02 Phase 2: the workload-aware Kubernetes admission — the
    # cluster client, the injected authorization predicate, and the resolver's
    # per-step records. ``None`` — the default — means this context knows
    # nothing about Kubernetes admission, and ``validate_plan`` skips it as a
    # single ``is not None`` test, so no existing decision, refusal, message, or
    # ordering moves. Configured, it can only *add* a refusal before any
    # mutation; it never relaxes one. Nothing in the CLI constructs one yet
    # (see the ledger in docs/v1.1.0/02_KUBERNETES_RUNTIME.md).
    #
    # Declared before ``policy_gate`` for the same reason ``approval_gate`` is:
    # ``tests/unit/test_policy_gate.py`` pins ``policy_gate`` as the last field
    # on this dataclass, and every construction in the tree passes keywords, so
    # the constraint is about that suite's own statement rather than about
    # semantics.
    k8s_admission: K8sAdmissionInput | None = None
    # v1.1.0 plan 14 Phase 4: the five plan-14 §"Controls" ceilings — protected
    # service list, maximum dependency depth, maximum customer-facing services,
    # maximum percentage, blast-radius ceiling. ``None`` — the default — means
    # this context knows nothing about them, and admission is byte-for-byte what
    # it was before the field existed: the five checks are behind one
    # ``is not None`` test, they run *after* all five of the budget's per-step
    # caps and the forbidden-pair check and *before* the damage ledger charge,
    # and they refuse only when a limit is actually configured. With no ceiling
    # configured a plan cannot reach them, so no decision, refusal, message,
    # recorded ``stats`` key, or ordering moves.
    #
    # Additive in the same sense ``policy_gate`` is: it can only *add* a
    # refusal. A context carrying ceilings never loses one the config-policy or
    # budget half would have made — the ceilings are checked after those, so
    # they are the later, more specific objection and the earlier one still
    # speaks first.
    #
    # Declared before ``policy_gate`` for the same reason ``approval_gate`` and
    # ``k8s_admission`` are.
    blast_ceilings: BlastCeilings | None = None
    # Plan 07 Phase 2: the versioned policy bundle, plus the locks, budgets,
    # and collision graph it is evaluated against. ``None`` — the default —
    # means this context knows nothing about policy bundles, and every gate
    # below behaves exactly as it did before the field existed. Bundles are
    # additive to ``policy``/``budget``, never a replacement for them: with a
    # bundle configured the gate speaks *in addition*, so configuring one can
    # add a refusal but can never lose a refusal the config-policy half would
    # have made.
    policy_gate: PolicyGateInputs | None = None

    def record(self, decision: SafetyDecision) -> None:
        self.decisions.append(decision)
        if decision.severity == SafetySeverity.warning:
            self.warnings.append(decision.reason)


DEFAULT_DENY = frozenset({"node.reboot"})


def _deny_decision(
    rule_id: str, inputs: dict[str, object], reason: str, remediation: str
) -> SafetyDecision:
    return SafetyDecision(
        rule_id=rule_id,
        inputs=dict(inputs),
        outcome="deny",
        reason=reason,
        remediation=remediation,
        severity=SafetySeverity.error,
    )


def check_fault_admission(fault_id: str, definition_risk: RiskLevel, ctx: SafetyContext) -> None:
    if fault_id in ctx.policy.deny_faults:
        dec = _deny_decision(
            "policy.deny_faults",
            {"fault_id": fault_id, "risk": definition_risk.value},
            f"{fault_id}: denied by policy denylist [policy.deny_faults]",
            f"remove {fault_id!r} from policy.deny_faults or use a different policy",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if ctx.policy.allow_faults is not None:
        if fault_id not in ctx.policy.allow_faults:
            dec = _deny_decision(
                "policy.allow_faults",
                {"fault_id": fault_id, "allow_faults": sorted(ctx.policy.allow_faults)},
                f"{fault_id}: not present in policy allowlist [policy.allow_faults]",
                f"add {fault_id!r} to policy.allow_faults or relax the allowlist",
            )
            ctx.record(dec)
            raise SafetyRefusedError("safety.refused", dec.reason, dec)
    elif fault_id in DEFAULT_DENY:
        dec = _deny_decision(
            "policy.default_deny",
            {"fault_id": fault_id},
            f"{fault_id}: denied by default; add it to policy.allow_faults to opt in [policy.default_deny]",
            f"add {fault_id!r} to policy.allow_faults",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ceiling = ctx.policy.risk_ceiling
    if ceiling is not None and definition_risk.at_least(ceiling.next_higher()):
        dec = _deny_decision(
            "policy.risk_ceiling",
            {"fault_id": fault_id, "risk": definition_risk.value, "ceiling": ceiling.value},
            f"{fault_id}: risk {definition_risk.value} exceeds policy ceiling {ceiling.value} [policy.risk_ceiling]",
            f"raise policy.risk_ceiling to {definition_risk.value} or use lower-risk fault",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if definition_risk is RiskLevel.CRITICAL and not (
        ctx.policy.allow_critical
        and ctx.allow_critical_cli
        and fault_id in ctx.policy.critical_fault_acks
    ):
        dec = _deny_decision(
            "policy.critical_triple_optin",
            {
                "fault_id": fault_id,
                "allow_critical": ctx.policy.allow_critical,
                "allow_critical_cli": ctx.allow_critical_cli,
            },
            f"{fault_id}: critical risk requires config policy.allow_critical, the CLI-level --allow-critical, and a per-fault ack in policy.critical_fault_acks [policy.critical_triple_optin]",
            f"set policy.allow_critical=true, acknowledge {fault_id!r} in policy.critical_fault_acks, and pass --allow-critical",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ctx.record(
        SafetyDecision(
            rule_id="policy.allow",
            inputs={"fault_id": fault_id, "risk": definition_risk.value},
            outcome="allow",
            reason=f"{fault_id}: admitted",
            remediation="",
            severity=SafetySeverity.info,
        )
    )


def _affected_node_ids(graph: TopologyGraph, targets: Iterable[str]) -> frozenset[str]:
    affected: set[str] = set()
    for node_id in targets:
        affected.add(node_id)
        affected |= graph.dependents_closure(node_id)
    return frozenset(affected)


@dataclass(frozen=True)
class ProviderRunScope:
    """Admission proof a run carries for provider steps (plan 17 Phase 4 wiring).

    A non-catalog fault id is a provider fault id, and the safety gate cannot
    admit one on its own: it has no loader, no grant and no sandbox profile.
    The scope supplies what the gate would otherwise have to invent — the
    registrations the loader admitted (the single enforcement point for
    loading, unchanged) — so the run path can charge the step through the
    participation API and refuse what the loader never admitted.

    ``None`` (the default on every gate below) means the run carries no
    provider admissions, and admission is byte-for-byte what it was before this
    field existed. Fail-closed applies the moment a scope *is* supplied: a
    provider step with no declaring registration, no sandbox admission, or no
    chargeable action is refused, never defaulted.
    """

    registrations: tuple[ProviderRegistration, ...] = ()
    owner_agent: str = "mayhem.run"


def _provider_registration_for_fault(
    scope: ProviderRunScope, fault_id: str
) -> ProviderRegistration | None:
    """The loaded registration declaring *fault_id*, or ``None``.

    Read off the loader's own ``declared_fault_ids`` — the gate does not
    re-derive declarations, re-check digests, or re-evaluate grants. The loader
    stays the single enforcement point; this is a membership read, not a
    second gate.
    """
    for registration in scope.registrations:
        if fault_id in registration.metadata.declared_fault_ids:
            return registration
    return None


def _charge_provider_step(
    *,
    ledger: DamageLedger,
    fault_id: str,
    node_ids: frozenset[str],
    duration_s: float,
    quota: DamageQuota,
    scope: ProviderRunScope,
    run_id: str,
    ctx: SafetyContext,
) -> QuotaCharge:
    """Charge one provider step to *ledger*, or refuse it before it is charged.

    The one call Phase 4 was missing: the run path charges a provider step
    through :func:`~mayhem.providers.participation.charge_provider_blast` —
    the same ledger call a native step makes, on the caller's own ledger — so
    a provider step and a native step cannot disagree about what a run costs,
    and a breach refuses with the ledger's own ``damage_quota.*`` rule ids.

    Fail-closed, in order: (1) no loaded registration declares the fault, so
    there is nothing to charge it *as* — refused with
    ``provider.fault_undeclared``; (2) the sandbox profile the declaration
    earns is not admittable under enforcement, so executing it would run
    unconfined third-party code — refused before any charge is made (loading
    unconfined is the loader's opt-in; *executing* unconfined is never
    admitted here); (3) the action itself is malformed — refused rather than
    defaulted. A quota breach is returned, not raised: the charge has landed
    and the caller judges it, exactly as for a native step.
    """
    registration = _provider_registration_for_fault(scope, fault_id)
    if registration is None:
        dec = _deny_decision(
            "provider.fault_undeclared",
            {"fault_id": fault_id},
            f"{fault_id}: no loaded provider declares this fault, so mayhem will not "
            "charge, lease or execute it [provider.fault_undeclared]",
            "load the provider that declares this fault through the provider loader first",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    metadata = registration.metadata
    try:
        SandboxEnforcer(select_profile(metadata), require_enforced=True).admit()
    except ProviderError as exc:
        dec = _deny_decision(
            "provider.fault_undeclared",
            {"fault_id": fault_id, "provider_id": metadata.provider_id},
            f"{fault_id}: provider {metadata.provider_id!r} is not admittable for "
            f"execution ({exc}); an unconfined third-party runtime may be loaded "
            "but it may not run [provider.fault_undeclared]",
            "load the provider without sandbox enforcement only for inspection, "
            "or declare no permissions so there is nothing to confine",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec) from exc
    try:
        action = ProviderAction(
            provider_id=metadata.provider_id,
            fault_id=fault_id,
            run_id=run_id,
            owner_agent=scope.owner_agent,
            node_ids=tuple(sorted(node_ids)),
            duration_s=duration_s,
        )
    except ProviderParticipationError as exc:
        dec = _deny_decision(
            "provider.fault_undeclared",
            {"fault_id": fault_id, "provider_id": metadata.provider_id},
            f"{fault_id}: {exc} [provider.fault_undeclared]",
            "supply a non-empty target set, a positive duration, and the run id",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec) from exc
    return charge_provider_blast(ledger, action, quota).charge


def check_blast_radius(
    graph: TopologyGraph,
    target_node_ids: Iterable[str],
    duration_s: float,
    fault_ids_so_far: tuple[str, ...],
    new_fault_id: str,
    *,
    ctx: SafetyContext,
    ledger: DamageLedger | None = None,
    provider_scope: ProviderRunScope | None = None,
    run_id: str = "",
) -> dict[str, float]:
    """Enforce every blast-radius limit for one fault step.

    **Six limits, not five.** The first five are the per-step ones
    (``max_services_pct``, ``max_hosts``, ``max_concurrent_faults``,
    ``max_duration_per_fault_s``, ``forbidden_fault_pairs``); the sixth is the
    *cumulative* damage quota, which is the only one that can see the sequence.

    Plan 14 Phase 4 added a seventh thing, on a seventh optional input: the five
    plan-14 §"Controls" ceilings, checked by :func:`_check_blast_ceilings` after
    the six above and before the damage charge. They are *additional* in the same
    one-directional sense — a context with no ``blast_ceilings`` never reaches
    them, and a context with them can only lose a refusal the six above would
    have made, never gain one that makes a plan more acceptable.

    The relationship between them is deliberate and one-directional:

    - **The quota is additional, never a replacement.** The five per-step
      checks run first, unchanged, in the same order, with the same messages.
      The quota can only add a refusal; it can never make a plan more
      acceptable. A step that breaches a per-step cap is still refused on that
      cap, with the same rule id and the same reason as before.
    - **Stricter wins.** Both are hard refusals, so there is no value that
      lets one side outrank the other: whenever the two disagree the plan is
      refused, by whichever fires, and preflight reports *both*. The only
      asymmetry is which one gets to speak first when a single step breaks both
      — the per-step rule does, because a per-step breach is a defect in the
      step on its own and is the more actionable message.
    - **It fires before the step runs.** This whole function is the plan-time
      gate: ``executor.execute`` calls ``validate_plan`` over every step before
      it opens a run, so a refusal here happens before any injection.

    ``ledger`` is the plan's cumulative damage account. ``validate_plan``
    creates one and threads it through every step; passing ``None`` gives a
    single-step ledger, which is the right answer for a one-off call.
    """
    budget = ctx.budget
    affected = _affected_node_ids(graph, target_node_ids)
    services_total = len(graph.of_kind(_service_kind()))
    services_hit = sum(1 for n in graph.of_kind(_service_kind()) if n.id in affected)
    hosts_hit = sum(1 for n in graph.of_kind(_host_kind()) if n.id in affected)
    pct = (services_hit / services_total * 100.0) if services_total else 0.0
    stats = {
        "services_pct": round(pct, 1),
        "hosts": float(hosts_hit),
        "concurrent_faults": float(len(fault_ids_so_far) + 1),
        "duration_per_fault": duration_s,
    }
    if pct > budget.max_services_pct:
        dec = _deny_decision(
            "blast_radius.max_services_pct",
            {"fault_id": new_fault_id, "pct": pct, "budget": budget.max_services_pct},
            f"blast radius: {new_fault_id} would affect {pct:.0f}% of services > budget {budget.max_services_pct}% [blast_radius.max_services_pct]",
            "reduce blast or raise blast_radius.max_services_pct",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if hosts_hit > budget.max_hosts:
        dec = _deny_decision(
            "blast_radius.max_hosts",
            {"fault_id": new_fault_id, "hosts_hit": hosts_hit, "budget": budget.max_hosts},
            f"blast radius: {new_fault_id} touches {hosts_hit} hosts > budget {budget.max_hosts} [blast_radius.max_hosts]",
            "reduce blast or raise blast_radius.max_hosts",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if len(fault_ids_so_far) + 1 > budget.max_concurrent_faults:
        dec = _deny_decision(
            "blast_radius.max_concurrent_faults",
            {
                "fault_id": new_fault_id,
                "concurrent": len(fault_ids_so_far) + 1,
                "budget": budget.max_concurrent_faults,
            },
            "blast radius: max_concurrent_faults exceeded [blast_radius.max_concurrent_faults]",
            "reduce concurrent faults or raise blast_radius.max_concurrent_faults",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if duration_s > budget.max_duration_per_fault_s:
        dec = _deny_decision(
            "blast_radius.max_duration_per_fault_s",
            {
                "fault_id": new_fault_id,
                "duration": duration_s,
                "budget": budget.max_duration_per_fault_s,
            },
            f"{new_fault_id} duration {duration_s:.0f}s exceeds per-fault cap {budget.max_duration_per_fault_s:.0f}s [blast_radius.max_duration_per_fault_s]",
            "shorten duration or raise blast_radius.max_duration_per_fault_s",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    forbidden = _first_forbidden_pair(fault_ids_so_far, new_fault_id, budget.forbidden_fault_pairs)
    if forbidden is not None:
        dec = _deny_decision(
            "blast_radius.forbidden_fault_pairs",
            {"pair": sorted(forbidden)},
            f"blast radius: forbidden fault pair {sorted(forbidden)} [blast_radius.forbidden_fault_pairs]",
            "remove the forbidden pair from blast_radius or change fault set",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    # Plan 14 Phase 4: the five §"Controls" ceilings, checked here for the same
    # reason the budget's caps are — per-step, per-fault, before any injection.
    # Placement is load-bearing rather than cosmetic: this runs *after* all five
    # budget checks and the forbidden-pair check and *before* the cumulative
    # damage charge, which is exactly the order
    # ``mayhem.domain.prediction._per_step_rules`` evaluates the same five rule
    # ids in. The preview and the gate therefore raise the *same* rule id on the
    # *same* step, which is what makes ``is_never_permissive`` checkable rather
    # than aspirational.
    #
    # With no ``ctx.blast_ceilings`` this is one ``is None`` test and no stats
    # key is added, so a context that configures nothing behaves exactly as
    # before the field existed.
    if ctx.blast_ceilings is not None:
        stats.update(
            _check_blast_ceilings(
                ceilings=ctx.blast_ceilings,
                graph=graph,
                affected=affected,
                target_ids=frozenset(target_node_ids),
                new_fault_id=new_fault_id,
                ctx=ctx,
            )
        )
    # Cumulative. The per-step checks above have all passed, so this is the
    # only way a step that is individually tiny can still be refused — which is
    # the entire point of a sequence-level limit.
    #
    # Plan 17 Phase 4: a non-catalog fault id is a provider fault id, and when
    # the run carries provider admissions it is charged through the
    # participation API on this same ledger — one ledger, one implementation —
    # with sandbox admission checked fail-closed before the charge. With no
    # scope this branch is not reached and the native charge below is
    # byte-for-byte what it was.
    active_ledger = ledger if ledger is not None else DamageLedger()
    if provider_scope is not None and not is_catalog_fault(new_fault_id):
        charge = _charge_provider_step(
            ledger=active_ledger,
            fault_id=new_fault_id,
            node_ids=affected,
            duration_s=duration_s,
            quota=ctx.damage_quota,
            scope=provider_scope,
            run_id=run_id,
            ctx=ctx,
        )
    else:
        charge = active_ledger.charge(
            fault_id=new_fault_id,
            duration_s=duration_s,
            node_ids=affected,
            quota=ctx.damage_quota,
        )
    stats.update(_damage_stats(charge))
    if charge.exceeded:
        dec = _deny_decision(charge.rule_id, charge.inputs(), charge.reason, charge.remediation)
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ctx.record(
        SafetyDecision(
            rule_id="blast_radius.allow",
            inputs={"fault_id": new_fault_id, "stats": stats},
            outcome="allow",
            reason=f"{new_fault_id}: blast radius within budget",
            remediation="",
            severity=SafetySeverity.info,
        )
    )
    return stats


#: The plan-14 §"Controls" ceiling rule ids — the gate's side of the vocabulary
#: ``mayhem.domain.prediction`` owns.
#:
#: **These names are deliberately NOT used as the first argument to the
#: ``_deny_decision`` calls in :func:`_check_blast_ceilings`; the string literals
#: are spelled out inline there instead, and the duplication is deliberate.** The
#: reason is that ``tests/unit/test_proof_compiler.py`` reads this module *as
#: source* and extracts a rule id only from a ``_deny_decision`` call whose first
#: argument is a plain literal — a bare ``Name`` is skipped as one of the module's
#: "dynamic" refusals, precisely so the extractor does not invent values it
#: cannot see. Passing the constants would therefore hide these five rules from
#: ``test_every_rule_the_gates_can_raise_has_an_owning_proof_line``, which is the
#: guard that exists so "a gate refusal no proof line owns" fails *by name*
#: rather than compiling to a whole-proof ``VOID`` at run time. Inlining the
#: literals puts them back inside that guard; these names exist so
#: ``tests/unit/test_prediction_evidence.py`` can pin the two spellings equal, so
#: the duplication cannot drift.
#:
#: The inlining bought the guard its chance to fire, and it did: when this phase
#: landed, ``test_every_rule_the_gates_can_raise_has_an_owning_proof_line`` failed
#: naming all five, which is the only reason the missing mapping was a failing
#: test rather than a latent ``VOID``. Those five rows now exist in
#: ``safety_proof.OBLIGATION_FOR_RULE`` (owned by ``target_policy``, beside the
#: two target-side caps this gate raises alongside them) and in
#: ``check_gate.RULE_CHECK``, and the guard is green because the mapping is there.
#: The duplication stays: it is what keeps the next gate's new refusal inside
#: that guard instead of outside it.
RULE_CEILING_MAX_AFFECTED_NODES = "blast_radius.max_affected_nodes"
RULE_CEILING_MAX_DEPENDENCY_DEPTH = "blast_radius.max_dependency_depth"
RULE_CEILING_MAX_CUSTOMER_FACING_SERVICES = "blast_radius.max_customer_facing_services"
RULE_CEILING_MAX_AFFECTED_PCT = "blast_radius.max_affected_pct"
RULE_CEILING_PROTECTED_NODE = "blast_radius.protected_node"


def _check_blast_ceilings(
    *,
    ceilings: BlastCeilings,
    graph: TopologyGraph,
    affected: frozenset[str],
    target_ids: frozenset[str],
    new_fault_id: str,
    ctx: SafetyContext,
) -> dict[str, float]:
    """Enforce the five plan-14 ceilings for one fault step, or refuse it.

    Additive and per-step, exactly like the budget's caps above: every ceiling is
    optional, an unconfigured one is *unchecked* rather than satisfied, and the
    checks can only add a refusal.

    Two deliberate details, both about agreeing with the preview rather than
    about taste:

    * **The measurements are borrowed, not re-derived.** Dependency depth comes
      from :func:`mayhem.domain.prediction.dependency_fan_out` and the
      customer-facing set from
      :func:`~mayhem.domain.prediction.customer_facing_node_ids` — the same two
      functions ``domain.prediction`` uses to *predict* these breaches. A second
      implementation here could disagree with the preview about a depth or a
      front door, and that disagreement is precisely the failure
      :func:`~mayhem.domain.prediction.is_never_permissive` exists to rule out.
    * **The protected list is matched against the step's *targets*, not the
      blast.** An unavoidable dependent of a protected service is a fact to
      surface, not a reason to refuse; refusing on it would make the rule
      un-satisfiable for any plan that touches anything upstream of a front door.

    Returns the observed numbers to fold into the step's ``stats``, so an
    operator sees what was measured on the allow path as well as on the refusal
    path. Each key is named after the ceiling and is a plain float, matching the
    ``dict[str, float]`` contract ``check_blast_radius`` documents.

    Raises:
        SafetyRefusedError: On the first ceiling breached, carrying the decision
            that named the rule and the observed value.
    """
    observed: dict[str, float] = {}
    if ceilings.max_affected_nodes is not None:
        node_count = float(len(affected))
        observed["ceiling_max_affected_nodes"] = node_count
        if node_count > ceilings.max_affected_nodes:
            dec = _deny_decision(
                "blast_radius.max_affected_nodes",
                {
                    "fault_id": new_fault_id,
                    "affected_nodes": len(affected),
                    "ceiling": ceilings.max_affected_nodes,
                },
                f"blast radius: {new_fault_id} affects {len(affected)} node(s) > "
                f"plan-14 ceiling {ceilings.max_affected_nodes} "
                f"[{RULE_CEILING_MAX_AFFECTED_NODES}]",
                "narrow the target set or raise the affected-node ceiling",
            )
            ctx.record(dec)
            raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if ceilings.max_dependency_depth is not None:
        depth = float(dependency_fan_out(graph, sorted(target_ids)).max_depth)
        observed["ceiling_dependency_depth"] = depth
        if depth > ceilings.max_dependency_depth:
            dec = _deny_decision(
                "blast_radius.max_dependency_depth",
                {
                    "fault_id": new_fault_id,
                    "depth": depth,
                    "ceiling": ceilings.max_dependency_depth,
                },
                f"blast radius: {new_fault_id} reaches {depth:g} dependency hop(s) > "
                f"plan-14 ceiling {ceilings.max_dependency_depth} "
                f"[{RULE_CEILING_MAX_DEPENDENCY_DEPTH}]",
                "target a shallower dependency, or raise the depth ceiling",
            )
            ctx.record(dec)
            raise SafetyRefusedError("safety.refused", dec.reason, dec)
    node_total = len(graph.nodes)
    # An empty graph has no share to divide by, so the percentage is
    # unmeasurable rather than zero — and an unmeasurable ceiling is unchecked,
    # which is not the same as satisfied. ``domain.prediction`` skips the rule on
    # an empty graph for the same reason, so the two agree.
    if ceilings.max_affected_pct is not None and node_total:
        pct = round(len(affected) / node_total * 100.0, 3)
        observed["ceiling_affected_pct"] = pct
        if pct > ceilings.max_affected_pct:
            dec = _deny_decision(
                "blast_radius.max_affected_pct",
                {
                    "fault_id": new_fault_id,
                    "pct": pct,
                    "ceiling": ceilings.max_affected_pct,
                },
                f"blast radius: {new_fault_id} affects {len(affected)} of {node_total} "
                f"nodes ({pct:g}%) > plan-14 ceiling {ceilings.max_affected_pct}% "
                f"[{RULE_CEILING_MAX_AFFECTED_PCT}]",
                "narrow the target set or raise the affected-percentage ceiling",
            )
            ctx.record(dec)
            raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if ceilings.max_customer_facing_services is not None:
        facing = tuple(sorted(customer_facing_node_ids(graph).intersection(affected)))
        observed["ceiling_customer_facing_services"] = float(len(facing))
        if len(facing) > ceilings.max_customer_facing_services:
            dec = _deny_decision(
                "blast_radius.max_customer_facing_services",
                {
                    "fault_id": new_fault_id,
                    "customer_facing": list(facing),
                    "ceiling": ceilings.max_customer_facing_services,
                },
                f"blast radius: {new_fault_id} affects {len(facing)} customer-facing "
                f"service(s) {list(facing)} > plan-14 ceiling "
                f"{ceilings.max_customer_facing_services} "
                f"[{RULE_CEILING_MAX_CUSTOMER_FACING_SERVICES}]",
                "target an internal dependency, or raise the customer-facing ceiling",
            )
            ctx.record(dec)
            raise SafetyRefusedError("safety.refused", dec.reason, dec)
    hit_protected = tuple(sorted(ceilings.protected_node_ids.intersection(target_ids)))
    observed["ceiling_protected_hits"] = float(len(hit_protected))
    if hit_protected:
        dec = _deny_decision(
            "blast_radius.protected_node",
            {"fault_id": new_fault_id, "protected": list(hit_protected)},
            f"blast radius: {new_fault_id} targets protected node(s) {list(hit_protected)} "
            f"[{RULE_CEILING_PROTECTED_NODE}]",
            "remove the protected node from the target set",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    return observed


def _first_forbidden_pair(
    fault_ids_so_far: tuple[str, ...],
    new_fault_id: str,
    forbidden: frozenset[frozenset[str]],
) -> frozenset[str] | None:
    """The forbidden pair this step completes, or ``None``.

    A "pair" is two faults. The new step completes one with each *earlier*
    step, so the candidates are exactly ``{earlier, new}`` — not "every fault
    so far plus the new one". Building a single set of all of them (the bug
    this replaces) produced a set of size ``len(fault_ids_so_far) + 1``, which
    matches a two-element forbidden pair on a two-fault plan and matches
    *nothing* on a three-fault plan: ``forbidden_fault_pairs`` was silently
    inert for every plan longer than two steps.

    Checking ``(earlier, new)`` for each earlier step is also *complete*: the
    pair ``{a, b}`` is caught on whichever of the two comes second, so a plan
    containing a forbidden pair cannot get past the gate no matter where the
    pair sits in the ordering. Iteration is over sorted unique earlier ids so
    the refusal names the same pair on every run.
    """
    if not forbidden or not fault_ids_so_far:
        return None
    for earlier in sorted({f for f in fault_ids_so_far if f != new_fault_id}):
        pair = frozenset({earlier, new_fault_id})
        if pair in forbidden:
            return pair
    return None


def _damage_stats(charge: QuotaCharge) -> dict[str, float]:
    """The cumulative numbers ``check_blast_radius`` reports for one step.

    Floats only: the returned mapping is documented as ``dict[str, float]`` and
    preflight folds every key into a numeric max. The offending *node* is a
    string, so it travels on the ledger / ``QuotaCharge`` instead.
    """
    return {
        "damage_step_s": charge.step_damage_s,
        "damage_total_s": charge.total_s,
        "damage_worst_target_s": charge.worst_node_s,
        "damage_headroom_s": charge.limit_s - charge.worst_node_s,
    }


def _check_execution_context(fault: PlannedFault, graph: TopologyGraph) -> None:
    if fault.execution_context is None:
        return
    node_kinds: set[NodeKind] = set()
    for target in fault.targets:
        for node_id in target.node_ids:
            node = graph.by_id(node_id)
            if node is not None:
                node_kinds.add(node.kind)
    if not node_kinds:
        return
    try:
        fault.execution_context.assert_compatible(frozenset(node_kinds))
    except InvariantViolationError as exc:
        dec = _deny_decision(
            "execution_context.compatibility",
            {"fault_id": fault.fault_id, "node_kinds": sorted(k.value for k in node_kinds)},
            f"{fault.fault_id}: {exc} [execution_context.compatibility]",
            "change execution_context or target kinds",
        )
        raise SafetyRefusedError("execution_context.refused", dec.reason, dec) from exc


_K8S_NODE_KIND_VALUES: frozenset[str] = frozenset({"pod", "k8s_node"})
_K8S_REFUSE_MSG = (
    "kubernetes execution not yet supported; see the RuntimeAdapter contract at ADR-M7-1"
)
_K8S_UNSUPPORTED_REMEDIATION_DETAIL = (
    "k8s.unsupported: kubernetes execution not yet supported or capability-gated; "
    "see ADR-M7-1; missing capability or cluster context; check --context/--namespace and "
    "adapter capability (NODE_CONTROL/NETNS/DNS_CONTROL); manifest mode remains usable for planning"
)
_REMOTE_NODE_KIND_VALUES: frozenset[str] = frozenset({"external_dependency"})
_REMOTE_REFUSE_MSG = "remote execution not yet supported; ADR-M3-5 ships only the RemoteAgentInterface contract — no transport is wired in this milestone"


def k8s_unsupported_remediation(
    fault_id: str, capability: str | None = None, context: str | None = None
) -> str:
    parts = [f"{fault_id}: {_K8S_UNSUPPORTED_REMEDIATION_DETAIL}"]
    if capability:
        parts.append(f"missing capability: {capability}")
    if context:
        parts.append(f"context: {context}")
    return " — ".join(parts)


def _check_k8s_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        from mayhem.domain.target import ResourceKind

        scope = getattr(fault, "target", None)
        is_node_scope = (
            scope is not None
            and scope.runtime == RuntimeLabel.KUBERNETES
            and scope.kind == ResourceKind.K8S_NODE
        )
        if scope is not None and scope.runtime == RuntimeLabel.KUBERNETES:
            if is_node_scope:
                continue
            select_many(graph, scope)
        for target in fault.targets:
            for node_id in target.node_ids:
                node = graph.by_id(node_id)
                if node is not None and node.kind in _K8S_NODE_KIND_VALUES:
                    if is_node_scope:
                        continue
                    raise SafetyRefusedError(
                        "k8s.unsupported",
                        k8s_unsupported_remediation(
                            fault.fault_id,
                            capability="Kubernetes capability",
                            context=(
                                str(scope.authority.get("namespace")) if scope is not None else None
                            ),
                        ),
                    )


def _check_remote_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        for target in fault.targets:
            for node_id in target.node_ids:
                node = graph.by_id(node_id)
                if node is not None and node.kind in _REMOTE_NODE_KIND_VALUES:
                    raise SafetyRefusedError(
                        "remote.unsupported",
                        f"{fault.fault_id}: {_REMOTE_REFUSE_MSG} [remote.unsupported]",
                    )


def _check_environment_policy(ctx: SafetyContext) -> None:
    if ctx.environment is None:
        return
    from mayhem.domain.policy import BUILTIN_PROFILES

    profile = BUILTIN_PROFILES.get(ctx.policy_id) if ctx.policy_id else None
    if profile is None:
        return
    if not profile.allowed_environments and not profile.denied_environments:
        return
    from mayhem.domain.policy import is_environment_allowed

    if not is_environment_allowed(profile, ctx.environment):
        dec = _deny_decision(
            "policy.environment_restriction",
            {"environment": ctx.environment, "policy_id": ctx.policy_id},
            f"environment {ctx.environment!r} denied by policy {ctx.policy_id!r} [policy.environment_restriction]",
            "use --policy with allowed environment or adjust policy allowed_environments",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)


def _check_k8s_admission(plan: ExecutionPlan, ctx: SafetyContext) -> None:
    """Plan 02 Phase 2: refuse an unsafe Kubernetes workload plan before mutation.

    Additive in the same way the policy bundle is, and for the same reason: one
    optional field on the context, so a context without it never reaches the
    function body and every existing decision keeps its place in the order.

    What it adds is a refusal that names the violated rule and the observed
    numbers (the PDB arithmetic, the StatefulSet rollout budget, the DaemonSet
    node coverage, the anti-affinity domains, the topology skew, the cluster
    health) plus the two admission refusals no pure rule can make: a target the
    run is not authorized to touch, and a step with no resolved live target.

    Decisions are recorded as the steps are walked, and the walk stops at the
    first refusal — so a refusal recorded here is the same shape (and reachable
    through the same ``explain_fault_refusal``) as every other gate refusal.
    """
    from mayhem.controller.k8s_admission import admit_k8s_plan

    admission = ctx.k8s_admission
    if admission is None:
        return
    for outcome in admit_k8s_plan(plan, admission):
        for rule_id in outcome.warnings:
            ctx.record(
                SafetyDecision(
                    rule_id=rule_id,
                    inputs=dict(outcome.inputs),
                    outcome="warn",
                    reason=f"{outcome.workload}: {rule_id}",
                    remediation=outcome.remediation,
                    severity=SafetySeverity.warning,
                )
            )
        if outcome.admitted:
            ctx.record(
                SafetyDecision(
                    rule_id=outcome.rule_id,
                    inputs=dict(outcome.inputs),
                    outcome="allow",
                    reason=outcome.reason,
                    remediation="",
                    severity=SafetySeverity.info,
                )
            )
            continue
        dec = _deny_decision(
            outcome.rule_id,
            dict(outcome.inputs),
            outcome.reason,
            outcome.remediation,
        )
        ctx.record(dec)
        raise SafetyRefusedError("k8s.admission_refused", dec.reason, dec)


def validate_plan(
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
    adapter: RuntimeAdapter | None = None,
    provider_scope: ProviderRunScope | None = None,
) -> None:
    if plan.policy_id and ctx.policy_id and plan.policy_id != ctx.policy_id:
        dec = _deny_decision(
            "policy.identity_mismatch",
            {"plan_policy": plan.policy_id, "ctx_policy": ctx.policy_id},
            f"policy identity mismatch: plan {plan.policy_id!r} vs context {ctx.policy_id!r} [policy.identity_mismatch]",
            "re-plan with matching --policy",
        )
        ctx.record(dec)
        raise SafetyRefusedError("environment.mismatch", dec.reason, dec)
    if plan.environment_fingerprint != ctx.fingerprint:
        dec = _deny_decision(
            "environment.fingerprint_mismatch",
            {"plan_fp": plan.environment_fingerprint[:12], "ctx_fp": ctx.fingerprint[:12]},
            "plan fingerprint does not match current environment identity; re-plan against live topology [environment.fingerprint_mismatch]",
            "re-plan",
        )
        ctx.record(dec)
        raise SafetyRefusedError("environment.mismatch", dec.reason, dec)
    _check_environment_policy(ctx)
    # Plan 02 Phase 2. Placed after the identity/environment checks — which are
    # statements about *this run* and outrank anything about one workload — and
    # before ``_check_k8s_targets``, because a refusal that names a violated
    # rule and its observed numbers is strictly more actionable than the
    # generic "kubernetes execution not yet supported" placeholder, and a plan
    # already refused for a real reason has no use for the placeholder one.
    # With no ``ctx.k8s_admission`` this is a single ``is not None`` test, so
    # the refusal order of every check below is byte-for-byte what it was.
    _check_k8s_admission(plan, ctx)
    _check_k8s_targets(plan, graph)
    _check_remote_targets(plan, graph)
    if adapter is not None:
        _validate_capability_requirements(plan, adapter, ctx)
    # Plan 07 Phase 2. Placed after the identity/environment/unsupported-target
    # checks and *before* the per-step admission loop, so the existing refusals
    # keep their precedence and the bundle still gets to speak before any
    # injection: locks, budgets, and the collision graph are all plan-level
    # questions that "before admission" answers in one pass.
    #
    # One optional field is the entire integration surface. With no bundle
    # configured this is a single ``is not None`` test and the function below
    # is never reached, so every existing gate, refusal, message, and decision
    # ordering is untouched.
    requirements: tuple[RequiredApproval, ...] = ()
    if ctx.policy_gate is not None:
        policy_result = evaluate_gate(plan, ctx.policy_gate, environment=ctx.environment)
        _apply_policy_result(policy_result, ctx)
        # Handed to the approval gate below: a decision that names outstanding
        # approval levels raises the quorum there. The policy gate *surfaces*
        # them; plan 09 Phase 2 enforces them.
        requirements = policy_result.required_approvals
    # Plan 09 Phase 2, same placement rationale and the same additive contract:
    # with no approval gate configured nothing below runs and admission is
    # unchanged. After the policy gate, because "may this plan exist at all" is
    # answered before "is this particular run approved" — an approval cannot
    # legalize a plan the policy half refuses.
    if ctx.approval_gate is not None:
        _apply_approval_result(
            verify_approvals(plan, ctx.approval_gate, requirements=requirements), ctx
        )
    seen_faults: list[str] = []
    # One ledger per validation pass, not one per context: a context is reused
    # (preflight validates the same plan it previews, the executor validates a
    # plan the caller already validated), and a ledger that survived between
    # passes would charge the same plan twice and refuse it for damage it never
    # caused. Local state also makes validate_plan deterministic — the same
    # plan always produces the same verdict.
    ledger = DamageLedger()
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        definition_risk = _risk_of(fault.fault_id)
        check_fault_admission(fault.fault_id, definition_risk, ctx)
        target_ids = frozenset().union(*(t.node_ids for t in fault.targets))
        check_blast_radius(
            graph,
            target_ids,
            float(fault.duration),
            tuple(seen_faults),
            fault.fault_id,
            ctx=ctx,
            ledger=ledger,
            provider_scope=provider_scope,
            run_id=plan.run_id,
        )
        seen_faults.append(fault.fault_id)
        if fault.execution_context is not None:
            _check_execution_context(fault, graph)


def _apply_policy_result(result: PolicyGateResult, ctx: SafetyContext) -> None:
    """Record a policy verdict on ``ctx`` and refuse the plan if it denied.

    Approvals are recorded as warnings, never as refusals *here*: a bundle that
    merely *asks* for an approval must not refuse the plan by itself, which
    would be implementing approvals badly and early. Plan 09 Phase 2 is what
    enforces the requirement, in :func:`_apply_approval_result`, which
    :func:`validate_plan` runs immediately after this one and feeds the
    outstanding levels through. The split is deliberate: this half says what
    would change the verdict, that half requires the answer.
    """
    for approval in result.required_approvals:
        ctx.record(
            SafetyDecision(
                rule_id=RULE_APPROVAL_REQUIRED,
                inputs={
                    "approval_level": approval.approval_level,
                    "policy_rule_id": approval.rule_id,
                    "bundle": result.decision.describe(),
                },
                outcome="warn",
                reason=f"policy requires {approval.approval_level} approval: {approval.reason}",
                remediation=approval.remediation,
                severity=SafetySeverity.warning,
            )
        )
    if result.refusal is not None:
        dec = _deny_decision(
            result.refusal.rule_id,
            result.refusal.inputs,
            result.refusal.reason,
            result.refusal.remediation,
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ctx.record(
        SafetyDecision(
            rule_id=RULE_BUNDLE_ALLOW,
            inputs=result.inputs(),
            outcome="allow",
            reason=f"policy {result.decision.describe()} permits this plan",
            remediation="",
            severity=SafetySeverity.info,
        )
    )


def _apply_approval_result(result: ApprovalGateResult, ctx: SafetyContext) -> None:
    """Record an approval verdict on ``ctx`` and refuse the plan if it denied.

    This is the enforcement half of what :func:`_apply_policy_result` only
    surfaces: a policy decision may *ask* for an approval, and this is where the
    answer is required. The two are additive — a bundle can add a refusal here
    never gets to make, and a configured approval gate can refuse a plan a
    bundle was happy with, which is the point of an approval.

    On the allow path the whole sealed record
    (:meth:`ApprovalGateResult.evidence`) is attached to the decision, and an
    emergency override additionally gets its own decision under
    :data:`~mayhem.controller.approval_gate.RULE_APPROVAL_OVERRIDE` — a distinct
    rule id, a warning severity, and the overriding principal and reason in the
    text, so a run that executed under an override is never mistakable for a run
    that was approved outright once the decision reaches the evidence envelope's
    ``safety_decisions``.
    """
    evidence = result.evidence()
    if result.refusal is not None:
        dec = _deny_decision(
            result.refusal.rule_id,
            evidence,
            result.refusal.reason,
            result.refusal.remediation,
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    for override in result.overrides:
        ctx.record(
            SafetyDecision(
                rule_id=RULE_APPROVAL_OVERRIDE,
                inputs=override.evidence(),
                outcome="allow",
                reason=f"{override.describe()} [{RULE_APPROVAL_OVERRIDE}]",
                remediation="file the post-hoc review for this emergency override",
                severity=SafetySeverity.warning,
            )
        )
    ctx.record(
        SafetyDecision(
            rule_id=RULE_APPROVAL_ALLOW,
            inputs=evidence,
            outcome="allow",
            reason=f"approvals verified: {result.state.describe()}",
            remediation="",
            severity=SafetySeverity.info,
        )
    )


def simulate_plan_policy(plan: ExecutionPlan, ctx: SafetyContext) -> PolicyGateResult | None:
    """Evaluate a frozen plan's policy bundle, mutating nothing — Phase 2 preview.

    Returns ``None`` when the context carries no bundle, which is the same
    "no policy bundle configured" answer :func:`validate_plan` gives.

    Purity is structural. The gate is a pure function (see
    :mod:`mayhem.domain.policy_gate`) and this helper is the only thing
    that could have recorded into ``ctx`` — it does not. The caller's
    ``ctx.decisions`` and ``ctx.warnings`` are therefore byte-for-byte
    unchanged, which is exactly the property plan 14's preview and the 30 proof
    depend on.
    """
    if ctx.policy_gate is None:
        return None
    return simulate_gate(plan, ctx.policy_gate, environment=ctx.environment)


def _validate_capability_requirements(
    plan: ExecutionPlan,
    adapter: RuntimeAdapter,
    ctx: SafetyContext,
) -> None:
    # The derivation moved to ``controller.policy_gate`` unchanged so the
    # adapter gate and the policy facts read the same requirement off the same
    # plan; two copies of this shape would eventually disagree.
    reqs = capability_requirements_for(plan)
    fallback = CapabilityRequirements(
        namespaces=frozenset({"network"}),
        tools=frozenset({"tool"}),
        permissions=frozenset({"limit"}),
    )
    if not (reqs.namespaces or reqs.tools or reqs.permissions):
        result = adapter.evaluate(fallback)
    else:
        result = adapter.evaluate(reqs)
    if result.blocking:
        message = result.refuse_with_message() or "unsupported capability requirements"
        dec = _deny_decision(
            "capability.unsupported",
            {"adapter": adapter.id, "verdicts": result.verdicts},
            f"{adapter.id}: {message} [capability.unsupported]",
            "use adapter with required capability or change fault",
        )
        ctx.record(dec)
        raise SafetyRefusedError("capability.unsupported", dec.reason, dec)
    for key, verdict in result.verdicts.items():
        if verdict == CapabilityVerdict.ALTERNATIVE:
            ctx.warnings.append(
                f"{adapter.id}: capability '{key}' satisfied via ALTERNATIVE path [capability.alternative]"
            )
            ctx.record(
                SafetyDecision(
                    rule_id="capability.alternative",
                    inputs={"adapter": adapter.id, "key": key},
                    outcome="warn",
                    reason=f"{adapter.id}: capability '{key}' satisfied via ALTERNATIVE path",
                    remediation="",
                    severity=SafetySeverity.warning,
                )
            )


def pre_exec_assertion(
    target_selector_pairs: Iterable[tuple[TargetSelector, frozenset[str] | tuple[str, ...]]],
    live_graph: TopologyGraph,
) -> None:
    for selector, expected_ids in target_selector_pairs:
        try:
            live = live_graph.resolve(selector)
        except TargetResolutionError as exc:
            raise SafetyRefusedError(
                "target.drift", f"G3 drift refusal for {selector}: {exc} [target.drift]"
            ) from None
        live_ids = frozenset(n.id for n in live)
        missing = set(expected_ids) - live_ids
        if missing:
            raise SafetyRefusedError(
                "target.drift",
                f"G3 drift refusal: nodes vanished since planning: {sorted(missing)} [target.drift]",
            )


def dry_run_policy_evaluation(
    plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext
) -> list[SafetyDecision]:
    decisions: list[SafetyDecision] = []
    try:
        validate_plan(plan, graph, ctx)
        decisions.extend(list(ctx.decisions))
        decisions.append(
            SafetyDecision(
                rule_id="dry_run.allow",
                inputs={"plan_id": plan.run_id},
                outcome="allow",
                reason="dry-run: plan would be allowed",
                remediation="",
                severity=SafetySeverity.info,
            )
        )
    except SafetyRefusedError as exc:
        if exc.decision is not None:
            decisions.append(exc.decision)
        else:
            decisions.append(
                SafetyDecision(
                    rule_id=exc.reason_code,
                    inputs={},
                    outcome="deny",
                    reason=str(exc),
                    remediation="",
                    severity=SafetySeverity.error,
                )
            )
    return decisions


def explain_fault_refusal(exc: SafetyRefusedError) -> dict[str, str]:
    dec = exc.decision
    if dec is None:
        return {"rule_id": exc.reason_code, "reason": str(exc), "remediation": ""}
    return {
        "rule_id": dec.rule_id,
        "reason": dec.reason,
        "remediation": dec.remediation,
        "inputs": str(dec.inputs),
    }


# ``_risk_of`` is re-exported from :mod:`mayhem.domain.policy_gate` (see the
# import at the top of this module) rather than reimplemented here. Admission and
# the policy facts both resolve a fault's risk through it, including the ``LOW``
# floor for an unresolvable fault id, and those two answers must never disagree:
# a fact priced above admission's answer would refuse a plan the gate admits.
# ``policy_gate`` is the lower module — this one already imports from it — so it
# is the only direction a shared implementation can travel. Consumers that want
# the helper should import it from ``policy_gate``: this module is not an
# explicit re-export (``no_implicit_reexport`` is on under ``strict``), and
# ``controller.safety_proof`` does exactly that.
def _service_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.SERVICE


def _host_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.HOST
