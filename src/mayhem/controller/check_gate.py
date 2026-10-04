"""Check evaluation and release gating — the engine behind a PR check and a
release gate (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 2; gaps 43, 46,
47, 103).

Phase 1 (:mod:`mayhem.domain.pipeline`) supplied the vocabulary. This module is
the thing that produces it: it evaluates a pull request's checks, decides
whether a change may open a release, and dispatches a ChatOps command.

## The one rule that shapes the whole module

**No check may implement its own shortcut version of a gate.** Every
gate-shaped answer this module gives is *read off* the normal compile → proof →
policy path, which runs exactly once per evaluation:

    mayhem.controller.safety.validate_plan          (authoritative, unchanged)
      └── controller.safety_proof.compile_safety_evidence
            ├── the per-obligation probes the compiler already owns
            └── the plan-07 policy gate, simulate_gate, via simulate_plan_policy
    mayhem.controller.policy_gate.plan_faults
    mayhem.domain.catalog.definition_for            (syntax: what exists)
    mayhem.domain.certification.CertificationRecord (what is certified)

:func:`evaluate_pr_checks` makes **one** call to
:func:`~mayhem.controller.safety_proof.compile_safety_evidence` and then *projects*
its result onto checks. There is no second copy of "is this blast radius too
big" here: :data:`OBLIGATION_CHECK` and :data:`RULE_CHECK` are lookup tables
saying which check *reports* which proof line and which gate rule, and the
outcome itself is always the proof's own status. A check that re-derived its own
verdict would agree with the gate on the happy path and drift on the first rule
it forgot, and the drift would be invisible, because both answers would be
labelled "check passed".

That is also why the attribution tables must cover *every* rule the compiler
can blame, and :func:`check_for_rule` is total by construction. An unmapped rule
is not silently dropped: it falls to :data:`DEFAULT_RULE_CHECK`, which is the
same conservative default the proof compiler uses for the same reason
(:data:`~mayhem.controller.safety_proof.DEFAULT_POLICY_REFUSAL_OWNER`) — a
bundle authors its own rule names, so "which check does ``checkout.blocklist_v3``
belong to" has no table answer, and defaulting it to "nobody reports it" would
be the one default that loses a refusal.

## Fail-closed, in five places

The doc's acceptance criteria are all *negative* statements, so most of this
module is about what it refuses:

* **An unreachable control plane reports ``UNKNOWN``, never ``PASS`` and never
  ``FAIL``.** :func:`evaluate_pr_checks` does not run a single gate when
  :attr:`CheckInputs.control_plane` is
  :data:`~mayhem.domain.pipeline.ControlPlaneReach.UNREACHABLE`; it returns
  checks that all report unknown and say why. ``PRCheck`` refuses any other
  outcome structurally, so the engine cannot produce one even by accident. A DNS
  timeout is a fact about the network, not an incident, and manufacturing an
  incident out of one is how a fleet ends up with a red board for a bad gateway.
* **A coverage number cannot be printed without its denominator.** See below.
* **A release gate decision fails closed.** :func:`release_gate` blocks when
  evidence is unavailable, when a required resilience suite did not run, and
  when any check is unknown. :class:`ReleaseGateDecision` additionally refuses
  to *construct* an ``ALLOW`` without cited evidence and without every required
  suite passed-with-a-run, so "allow" is not a value a caller can reach by
  leaving a field empty.
* **A gate cannot allow without evidence.** Same rule, plus the delegation: the
  release gate reads :func:`~mayhem.domain.pipeline.blocking_reasons` rather
  than re-deciding, so "may this open a release" has one answer in the codebase.
* **ChatOps refuses an unauthorized principal before validation runs.**
  :func:`dispatch_chatops` resolves the requester's roles first and raises
  :class:`ChatOpsRefusedError` without ever calling the injected validator. An
  approval typed into a chat channel by somebody without the ``approve`` role
  must not reach the same validation a CLI invocation reaches *and then* be
  refused downstream — the refusal belongs at the door.

## Coverage numbers carry their denominator

Plan 22's rule, enforced here rather than stated in a doc: a coverage finding's
message always renders ``N of M``, where ``M`` is the declared landscape
(:attr:`CoverageSurface.denominator`), never a bare fraction and never a bare
count. :class:`CoverageSurface` refuses an empty landscape outright — a
"coverage number" with nothing to divide by is the thing the rule exists to
stop, and "none of nothing covered" is how an untested service reports 100%.

A gap rides on a *passing* check as a warning (a known gap is not a new
failure, and failing every PR that carries one would train people to ignore the
check); coverage that was **lost** is an error and fails, because a cell that
was passed and no longer is a regression rather than a gap.

## Certification states a check may report

:class:`RuntimeFaultState` is the vocabulary a check reports a fault's runtime
standing in, and it is deliberately a subset-with-one-extension of
:data:`~mayhem.domain.certification.CertificationState` — the states the record
store can actually hold — plus ``UNVERIFIED`` for "no record exists at all". A
check that could only say ``certified`` would have to say it about a
catalog-only fault; naming the absence is what keeps it honest.
:class:`FaultClaim` refuses to be *constructed* with a live claim that no record
backs, and the claim for a ``catalog_only`` definition is ``UNVERIFIED`` by
construction. :data:`REPORTABLE_STATES` is the machine-checkable statement of
the rule, and ``tests/unit/test_check_gate.py`` asserts it against the
certification module rather than against a copy of it.

What a check *does* with a claim is a separate question, and the split follows
the coverage one: a **catalog-only** planned fault is an error (it cannot run
here), while a fault with **no live certification record** is a warning on an
otherwise passing check. A check red on every PR until the whole catalog is
certified is a check people learn to ignore; a fault silently reported as
certified is a lie. The first is fixed by not gating on it, the second by making
it unconstructible.

## The ChatOps seam, and what Phase 2 does not do

:func:`dispatch_chatops` takes a :class:`ChatOpsTransport` — one method,
``send`` — and a **required** ``validate`` callable. There is no Slack client
here and no default validator: the caller passes the same validation entry point
its CLI path uses, and the tests prove the property that matters (the requester
is bound, and an unauthorized requester never reaches validation) with fakes
rather than with a transport. Phase 3 owns the bots; this module owns the seam.

## Determinism

Nothing here reads a clock, a store, or an environment. ``now`` is an argument
where a decision needs one (ChatOps role resolution), coverage states are passed
in, and :func:`compile_safety_evidence` probes on throwaway clones of the
caller's :class:`~mayhem.controller.safety.SafetyContext`, so evaluating a PR
never appends preview decisions to the safety record a real run is judged by.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, Self

from pydantic import BaseModel, ConfigDict, model_validator

from mayhem.controller.approval_gate import (
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
    RULE_APPROVAL_PROOF_NOT_PASS,
    RULE_APPROVAL_REQUIRED,
)
from mayhem.controller.policy_gate import (
    RULE_BUDGET_EXHAUSTED,
    RULE_BUNDLE_DENY,
    RULE_BUNDLE_EXPIRED,
    RULE_COMPAT_CONFLICT,
    RULE_LOCK_CONTENDED,
    plan_faults,
)
from mayhem.controller.safety_proof import SafetyCompilation, compile_safety_evidence
from mayhem.domain.catalog import definition_for
from mayhem.domain.certification import CertificationState

# ``RunPin`` stays runtime-visible despite being annotation-only at first
# glance: ``ResilienceSuite`` is a plain dataclass that is nested in
# ``ReleaseGateDecision.suites``, so pydantic has to resolve ``RunPin`` to
# build this module's schema. Moving it under ``TYPE_CHECKING`` compiles
# and then raises at first ``ReleaseGateDecision(...)``.
from mayhem.domain.comparison import RunPin  # noqa: TC001
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
    TeamMembership,
    effective_roles,
)
from mayhem.domain.pipeline import (
    CONTROL_PLANE_UNREACHABLE,
    ChangeLink,
    CheckFinding,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    FindingSeverity,
    PipelineVerdict,
    PlanMerge,
    PRCheck,
    blocking_reasons,
)
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
)
from mayhem.domain.quota import RULE_BUDGET, RULE_PER_FAULT_CEILING
from mayhem.domain.safety_proof import ObligationName, ObligationStatus, ProofVerdict

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.certification import CertificationRecord
    from mayhem.domain.coverage import CellState, CoverageCell
    from mayhem.domain.decisions import DecisionRef
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.faults import FaultDefinition
    from mayhem.domain.policy import PolicyDecision
    from mayhem.domain.runtime_adapter import RuntimeAdapter
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "CHATOPS_REQUIRED_ROLE",
    "CHECK_NAME",
    "CHECK_ORDER",
    "DEFAULT_RULE_CHECK",
    "GATE_ALLOW",
    "GATE_BLOCK",
    "OBLIGATION_CHECK",
    "REPORTABLE_STATES",
    "REQUIRED_SUITES",
    "RULE_ALLOW_WITHOUT_EVIDENCE",
    "RULE_BLOCK_WITHOUT_REASON",
    "RULE_CHATOPS_NOT_AUTHORIZED",
    "RULE_CHATOPS_VALIDATION_REFUSED",
    "RULE_CHECK",
    "RULE_CLAIM_WITHOUT_RECORD",
    "RULE_COVERAGE_EMPTY_DENOMINATOR",
    "RULE_COVERAGE_UNKNOWN_KEY",
    "RULE_SUITE_UNKNOWN_UNEXPLAINED",
    "RULE_SUITE_WITHOUT_EVIDENCE",
    "RULE_SUITE_WITHOUT_RUN",
    "RULE_SYNTAX_UNRESOLVED",
    "ChangeKind",
    "ChatOpsCommand",
    "ChatOpsReceipt",
    "ChatOpsRefusedError",
    "ChatOpsRequest",
    "ChatOpsTransport",
    "CheckInputs",
    "CheckReport",
    "CoverageSurface",
    "FaultClaim",
    "ReleaseGateDecision",
    "ReleaseGateRequest",
    "ResilienceSuite",
    "RuntimeFaultState",
    "check_for_rule",
    "claim_for_fault",
    "coverage_check",
    "dispatch_chatops",
    "evaluate_pr_checks",
    "release_gate",
    "required_suites_for",
]

# ── refusal codes ─────────────────────────────────────────────────────────────
# Stable strings, because they end up in a commit status and in a chat
# transcript and somebody greps for them.

RULE_CHATOPS_NOT_AUTHORIZED = "chatops.principal_not_authorized"
RULE_CHATOPS_VALIDATION_REFUSED = "chatops.validation_refused"
RULE_ALLOW_WITHOUT_EVIDENCE = "release_gate.allow_without_evidence"
RULE_BLOCK_WITHOUT_REASON = "release_gate.block_without_reason"
RULE_SUITE_WITHOUT_EVIDENCE = "release_gate.suite_without_evidence"
RULE_SUITE_WITHOUT_RUN = "release_gate.suite_without_run"
RULE_SUITE_UNKNOWN_UNEXPLAINED = "release_gate.unknown_suite_unexplained"
RULE_COVERAGE_EMPTY_DENOMINATOR = "coverage.empty_denominator"
RULE_COVERAGE_UNKNOWN_KEY = "coverage.key_outside_landscape"
RULE_CLAIM_WITHOUT_RECORD = "fault_claim.live_without_record"
RULE_SYNTAX_UNRESOLVED = "syntax.unresolved_fault"
RULE_UNKNOWN_UNEXPLAINED = "check_gate.unknown_unexplained"


# =============================================================================
# Attribution tables — which check reports which proof line and which rule
# =============================================================================
#
# These are *reporting* tables, not decision tables. Nothing here decides
# anything: an outcome is always read off the proof or the refusal set the
# normal path produced. They exist so a refusal lands on the check an operator
# is already looking at, and so the coverage of the table is testable — every
# rule :data:`~mayhem.controller.safety_proof.OBLIGATION_FOR_RULE` can blame
# appears in exactly one row here, and the test suite asserts it.

#: Proof line -> the check that reports it.
#:
#: Three of the nine lines have no Phase-2 check of their own. ``compensation``,
#: ``recovery_path``, and ``stop_conditions`` are reported on ``safety_policy``,
#: which is defined as "the safety case the normal path compiled for this plan"
#: rather than "the policy bundle's verdict". A missing undo op is a safety
#: finding, and hiding it because the plan's Phase-2 check list has no row for
#: it would be the exact failure this engine exists to prevent.
OBLIGATION_CHECK: Final[dict[str, CheckScope]] = {
    ObligationName.TARGET_POLICY.value: CheckScope.TARGET,
    ObligationName.MAX_CONCURRENT_FAULTS.value: CheckScope.BLAST_RADIUS,
    ObligationName.MAX_DURATION.value: CheckScope.BLAST_RADIUS,
    ObligationName.DAMAGE_BUDGET.value: CheckScope.DAMAGE_BUDGET,
    ObligationName.CAPABILITY_REQUIREMENTS.value: CheckScope.FAULT_COMPATIBILITY,
    ObligationName.REQUIRED_APPROVALS.value: CheckScope.SAFETY_POLICY,
    ObligationName.COMPENSATION.value: CheckScope.SAFETY_POLICY,
    ObligationName.RECOVERY_PATH.value: CheckScope.SAFETY_POLICY,
    ObligationName.STOP_CONDITIONS.value: CheckScope.SAFETY_POLICY,
}

#: Gate rule id -> the check that reports it.
#:
#: Enumerated, and total against
#: :data:`~mayhem.controller.safety_proof.OBLIGATION_FOR_RULE`: every rule the
#: proof compiler can blame appears in exactly one row here, every row here is a
#: rule the compiler can blame, and **no row is dead** — each rule id is one the
#: code under ``src/mayhem`` actually spells, which
#: ``tests/unit/test_owed_rule_mappings.py`` asserts by reading the source rather
#: than by trusting this table's own shape. A row for a rule nothing raises would
#: pass every test that only compares the two tables to each other, which is why
#: the dead-row check reads the code.
#:
#: Two obligations are deliberately split from their check: the five plan-14
#: ceilings are blamed on ``target_policy`` and reported on ``blast_radius``. That
#: split is a choice about which question a reader is asking — *which line owns this
#: rule* and *which check should show it* are not the same question — and it is
#: written out at both rows rather than left to be inferred. Every row added since,
#: including the provider lease refused for a missing write-ahead undo (blamed on
#: ``compensation``, reported on ``safety_policy`` because ``OBLIGATION_CHECK``
#: already maps that line there), agrees with its own obligation's check.
RULE_CHECK: Final[dict[str, CheckScope]] = {
    # -- blast radius: the five per-step caps plus the forbidden pairs ---------
    RULE_MAX_SERVICES_PCT: CheckScope.BLAST_RADIUS,
    RULE_MAX_HOSTS: CheckScope.BLAST_RADIUS,
    RULE_MAX_CONCURRENT_FAULTS: CheckScope.BLAST_RADIUS,
    RULE_MAX_DURATION_PER_FAULT_S: CheckScope.BLAST_RADIUS,
    RULE_FORBIDDEN_FAULT_PAIRS: CheckScope.BLAST_RADIUS,
    # -- plan-14 blast-radius ceilings -------------------------------------------
    # The five ceilings `check_blast_radius` enforces on a seventh, optional
    # input. They are enumerated here rather than left to `DEFAULT_RULE_CHECK`
    # even though the default would resolve them: the default is the right answer
    # for a *bundle-authored* rule name, whose scope nobody can know, and the
    # wrong answer here — these are the gate's own rule ids, raised by the same
    # function as the five above, and their blast radius is not a safety-policy
    # finding. Note that the obligation that owns them is `target_policy` while
    # the check that reports them is `blast_radius`; that split is already how
    # `RULE_MAX_SERVICES_PCT` and `RULE_MAX_HOSTS` work, and it is deliberate —
    # the check an operator reads is the one about the quantity that broke.
    RULE_MAX_AFFECTED_NODES: CheckScope.BLAST_RADIUS,
    RULE_MAX_AFFECTED_PCT: CheckScope.BLAST_RADIUS,
    RULE_MAX_CUSTOMER_FACING_SERVICES: CheckScope.BLAST_RADIUS,
    RULE_MAX_DEPENDENCY_DEPTH: CheckScope.BLAST_RADIUS,
    RULE_PROTECTED_NODE: CheckScope.BLAST_RADIUS,
    # -- cumulative damage: the quota, the only sequence-level limit ------------
    RULE_BUDGET: CheckScope.DAMAGE_BUDGET,
    RULE_PER_FAULT_CEILING: CheckScope.DAMAGE_BUDGET,
    RULE_BUDGET_EXHAUSTED: CheckScope.DAMAGE_BUDGET,
    # -- fault compatibility: capabilities, loci, and fault-on-fault pairs -----
    RULE_COMPAT_CONFLICT: CheckScope.FAULT_COMPATIBILITY,
    "capability.unsupported": CheckScope.FAULT_COMPATIBILITY,
    "execution_context.compatibility": CheckScope.FAULT_COMPATIBILITY,
    "execution_context.refused": CheckScope.FAULT_COMPATIBILITY,
    # -- target validity: identity, environment, and supportable targets -------
    "policy.identity_mismatch": CheckScope.TARGET,
    "environment.fingerprint_mismatch": CheckScope.TARGET,
    "environment.mismatch": CheckScope.TARGET,
    "k8s.unsupported": CheckScope.TARGET,
    "remote.unsupported": CheckScope.TARGET,
    "target.drift": CheckScope.TARGET,
    # -- safety policy: the policy half of the gate, and the plan's contracts ---
    "policy.environment_restriction": CheckScope.SAFETY_POLICY,
    "policy.deny_faults": CheckScope.SAFETY_POLICY,
    "policy.allow_faults": CheckScope.SAFETY_POLICY,
    "policy.default_deny": CheckScope.SAFETY_POLICY,
    "policy.risk_ceiling": CheckScope.SAFETY_POLICY,
    "policy.critical_triple_optin": CheckScope.SAFETY_POLICY,
    RULE_BUNDLE_EXPIRED: CheckScope.SAFETY_POLICY,
    RULE_BUNDLE_DENY: CheckScope.SAFETY_POLICY,
    RULE_LOCK_CONTENDED: CheckScope.SAFETY_POLICY,
    # -- the plan-09 approval gate: the checks that report `required_approvals` --
    # Added in plan 30 Phase 4, when the approval gate's refusal rule ids became
    # blameable (they are mapped to `ObligationName.REQUIRED_APPROVALS` in
    # `OBLIGATION_FOR_RULE`, which is what this table must cover). `SAFETY_POLICY`
    # is where `required_approvals` is already reported, so the rules that blame
    # it land on the same check rather than a new one.
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED: CheckScope.SAFETY_POLICY,
    RULE_APPROVAL_PROOF_NOT_PASS: CheckScope.SAFETY_POLICY,
    RULE_APPROVAL_REQUIRED: CheckScope.SAFETY_POLICY,
    # -- the stop and preflight refusals (plan 10) ----------------------------------
    # Enumerated for the reason :data:`DEFAULT_RULE_CHECK` gives as its *default*
    # and not its rule: the default is right for a bundle-authored rule name, whose
    # check nobody can know, and wrong for a gate's own id — these are refusals mayhem
    # raises about a specific run at a specific moment, and "safety-policy" is the
    # check that reports them. The two scopes are not interchangeable in the other
    # direction either: a stop that refuses to act is a finding about whether the
    # run may proceed (`safety_policy`), not about which targets the plan named
    # (`target`).
    "preflight.refused": CheckScope.SAFETY_POLICY,
    "stop_for_terminal_run": CheckScope.SAFETY_POLICY,
    "stop_engine_requires_run_scope": CheckScope.SAFETY_POLICY,
    "stop_command_stale": CheckScope.SAFETY_POLICY,
    # The stop-ladder structural refusals: a walk that will not resume in order, and
    # a seal that will not close over it. All `SAFETY_POLICY` because
    # `OBLIGATION_CHECK` already reports `recovery_path` there — see the note on
    # `provider.lease_undo_absent` below for why that split (line here, check there)
    # is deliberate rather than an oversight.
    "stop_stage_skip_refused": CheckScope.SAFETY_POLICY,
    "stop_stage_not_owed": CheckScope.SAFETY_POLICY,
    "stop_seal_requires_complete_walk": CheckScope.SAFETY_POLICY,
    "stop_seal_requires_evidence": CheckScope.SAFETY_POLICY,
    "stop_seal_digest_mismatch": CheckScope.SAFETY_POLICY,
    # -- the campaign dispatch stage (plan 13) --------------------------------------
    # `campaign_budget` is `DAMAGE_BUDGET` and not `SAFETY_POLICY`: the refusal
    # measures the same cumulative damage-seconds against the same quota the
    # `damage_quota.*` rows report, and an operator reading it wants the budget
    # check. `no_compilation` is `SAFETY_POLICY`, whose check is defined as "the
    # safety case the normal path compiled for this plan" — which is the thing
    # missing.
    "schedule.campaign_budget": CheckScope.DAMAGE_BUDGET,
    "schedule.no_compilation": CheckScope.SAFETY_POLICY,
    # -- the analytics service (plan 15) --------------------------------------------
    # Two budget refusals and two evidence refusals, mirroring the two obligations
    # they land on in `safety_proof.OBLIGATION_FOR_RULE`. `evidence_not_sealed` and
    # `search_not_recorded` are `SAFETY_POLICY` because `required_approvals` is
    # reported there; they are not coverage refusals and `target` would misreport
    # them as statements about what the plan may touch.
    "analytics.planner_budget_diverged": CheckScope.DAMAGE_BUDGET,
    "analytics.step_unaffordable": CheckScope.DAMAGE_BUDGET,
    "analytics.evidence_not_sealed": CheckScope.SAFETY_POLICY,
    "analytics.search_not_recorded": CheckScope.SAFETY_POLICY,
    # -- the provider participation surface (plan 17) ------------------------------
    # `lease_undo_absent` is `SAFETY_POLICY`, which is where `compensation` is
    # already reported, so the line and the check agree. The refusal is a mutation
    # whose write-ahead undo cannot be recorded; `target` would misreport it as a
    # statement about what the plan may touch. The other two *are* `TARGET` — a
    # fault the declaration does not contain and a matrix cell that cannot carry a
    # provider version are both statements about what this plan may act on, which is
    # what `target_policy` and `target` are for.
    # `provider.quota_exceeded` is absent on purpose: an exceeded charge is refused
    # with the ledger's own `damage_quota.*` rule id, so it already has a row and a
    # second one could disagree with it.
    "provider.fault_undeclared": CheckScope.TARGET,
    "provider.certification_cell_unpinned": CheckScope.TARGET,
    "provider.lease_undo_absent": CheckScope.SAFETY_POLICY,
}

#: Where a refusal goes when its rule id is not in :data:`RULE_CHECK`.
#:
#: Only the rules above are enumerable — a :class:`~mayhem.domain.policy.
#: PolicyBundle` authors its own ``rule_id`` strings. The default is the same one
#: the proof compiler uses for the same reason: everything a bundle can refuse on
#: is a statement about what the plan may touch. Defaulting to "nobody reports
#: it" would be the one default that loses a refusal.
DEFAULT_RULE_CHECK: Final[CheckScope] = CheckScope.SAFETY_POLICY


def check_for_rule(rule_id: str) -> CheckScope:
    """The check that reports ``rule_id``. Total: never "nobody"."""
    return RULE_CHECK.get(rule_id, DEFAULT_RULE_CHECK)


#: The scopes :func:`evaluate_pr_checks` emits from the proof, in report order.
#: ``COVERAGE`` is absent because a coverage surface is supplied by the caller
#: (:class:`CoverageSurface`), and ``RESILIENCE`` because a suite is evidence
#: from outside the plan (:class:`ResilienceSuite`). Neither is derivable from a
#: plan, so neither is invented here.
CHECK_ORDER: Final[tuple[CheckScope, ...]] = (
    CheckScope.SYNTAX,
    CheckScope.TARGET,
    CheckScope.SAFETY_POLICY,
    CheckScope.BLAST_RADIUS,
    CheckScope.DAMAGE_BUDGET,
    CheckScope.FAULT_COMPATIBILITY,
)

#: Check name per scope. Names must be unique within a verdict — ``PRCheck``
#: refuses a duplicate, and so does :class:`PipelineVerdict` — and stable,
#: because a commit status is keyed on them.
CHECK_NAME: Final[dict[CheckScope, str]] = {
    CheckScope.SYNTAX: "syntax",
    CheckScope.TARGET: "target",
    CheckScope.SAFETY_POLICY: "safety-policy",
    CheckScope.BLAST_RADIUS: "blast-radius",
    CheckScope.DAMAGE_BUDGET: "damage-budget",
    CheckScope.FAULT_COMPATIBILITY: "fault-compatibility",
    CheckScope.COVERAGE: "coverage",
    CheckScope.RESILIENCE: "resilience",
}

_REMEDIATION: Final[dict[CheckScope, str]] = {
    CheckScope.SYNTAX: "fix the authored fault id or parameters and re-plan",
    CheckScope.TARGET: (
        "re-plan against the live topology, or target a runtime this build supports"
    ),
    CheckScope.SAFETY_POLICY: (
        "satisfy the plan's safety contracts (compensate, recover, stop, approve) "
        "or change the policy"
    ),
    CheckScope.BLAST_RADIUS: "reduce the blast or raise the blast-radius budget",
    CheckScope.DAMAGE_BUDGET: "shorten the run or raise the damage quota",
    CheckScope.FAULT_COMPATIBILITY: (
        "target a supported locus, and certify the fault before relying on it"
    ),
    CheckScope.COVERAGE: "add an experiment covering the named cell",
}


def _finding_code(scope: CheckScope) -> str:
    """The ``CheckFinding.code`` for a failed check of ``scope``."""
    return (
        RULE_SYNTAX_UNRESOLVED
        if scope is CheckScope.SYNTAX
        else f"check.{scope.value.replace('_', '-')}.refused"
    )


# =============================================================================
# Certification vocabulary — the states a check may report
# =============================================================================


class RuntimeFaultState(StrEnum):
    """What a check may report about a fault's runtime standing.

    Every member except :data:`UNVERIFIED` is a
    :data:`~mayhem.domain.certification.CertificationState` value, i.e. a state
    the certification record store can actually hold; :data:`REPORTABLE_STATES`
    asserts that against the certification module rather than a copy of it, and
    the test suite makes the assertion part of the suite.

    ``UNVERIFIED`` is the one addition, and it is the honest one: "no
    certification record exists for this fault". Without it, a check that found
    nothing would have to report the *last* state it saw, which is how an
    uncertified fault gets printed as ``stale`` — as though it had once been
    certified and lapsed, which is a different and more alarming claim.
    """

    CERTIFIED = CertificationState.CERTIFIED.value
    EXPIRING = CertificationState.EXPIRING.value
    PENDING = CertificationState.PENDING.value
    STALE = CertificationState.STALE.value
    FAILED = CertificationState.FAILED.value
    INCOMPATIBLE = CertificationState.INCOMPATIBLE.value
    UNVERIFIED = "unverified"

    @property
    def has_live_claim(self) -> bool:
        """True only for the two states that are a *current* claim."""
        return self in (RuntimeFaultState.CERTIFIED, RuntimeFaultState.EXPIRING)

    @property
    def record_backed(self) -> bool:
        """False for :data:`UNVERIFIED`, which no record backs because none exists."""
        return self is not RuntimeFaultState.UNVERIFIED


#: The states a PR check is allowed to print.
REPORTABLE_STATES: Final[frozenset[str]] = frozenset(state.value for state in RuntimeFaultState)


class FaultClaim(BaseModel):
    """What one fault's certification record says, as a check reports it.

    The load-bearing refusal is :meth:`_live_needs_a_record`: a live claim
    without a record behind it is not a weak claim, it is a malformed one. That
    is the same rule :mod:`mayhem.domain.safety_proof` applies to a forged
    ``PASS`` line, for the same reason — the failure this module must make
    unrepresentable is "a PR check certified a fault nothing certified", plus its
    two catalog-only corollaries, which would otherwise need a caller to
    remember.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fault_id: str
    state: RuntimeFaultState
    live: bool = False
    catalog_only: bool = False
    evidence_refs: tuple[str, ...] = ()
    detail: str = ""

    @model_validator(mode="after")
    def _live_needs_a_record(self) -> Self:
        if self.state.has_live_claim != self.live:
            raise InvariantViolationError(
                RULE_CLAIM_WITHOUT_RECORD,
                f"{self.fault_id} is reported as {self.state.value!r} with "
                f"live={self.live}: a live certification claim and a current "
                "record state are the same statement and cannot disagree",
            )
        if self.catalog_only and self.live:
            raise InvariantViolationError(
                RULE_CLAIM_WITHOUT_RECORD,
                f"{self.fault_id} is catalog-only and cannot hold a live "
                "certification claim: the fault refuses to execute here, so there "
                "is no runtime for a record to certify",
            )
        if self.catalog_only and self.state.has_live_claim:
            raise InvariantViolationError(
                RULE_CLAIM_WITHOUT_RECORD,
                f"{self.fault_id} is catalog-only but reported as {self.state.value!r}",
            )
        if self.live and not self.evidence_refs:
            raise InvariantViolationError(
                RULE_CLAIM_WITHOUT_RECORD,
                f"{self.fault_id} carries a live certification claim with no "
                "evidence reference: a claim nobody can re-derive is a badge",
            )
        return self

    @property
    def runtime_certified(self) -> bool:
        """True only for a live claim on a fault that actually executes."""
        return self.live and not self.catalog_only

    def describe(self) -> str:
        return f"{self.fault_id} is {self.state.value}"

    def to_dict(self) -> dict[str, object]:
        return {
            "fault_id": self.fault_id,
            "state": self.state.value,
            "live": self.live,
            "runtime_certified": self.runtime_certified,
            "catalog_only": self.catalog_only,
            "evidence_refs": list(self.evidence_refs),
            "detail": self.detail,
        }


def claim_for_fault(
    definition: FaultDefinition,
    records: Sequence[CertificationRecord] = (),
) -> FaultClaim:
    """The claim a check reports for ``definition``, from its records.

    Order of authority, and the reason for it:

    1. a ``catalog_only`` definition is :data:`RuntimeFaultState.UNVERIFIED`
       whatever the records say — the fault refuses to execute, so there is no
       runtime for a record to have certified, and a record claiming otherwise
       is describing a machine this build cannot reach;
    2. otherwise the live records decide, because
       :attr:`~mayhem.domain.certification.CertificationRecord.grants_live_verification`
       is the repository's own "is this a current claim" predicate and is not
       re-derived here;
    3. otherwise the last record's own state is reported verbatim;
    4. otherwise :data:`RuntimeFaultState.UNVERIFIED` — no record, which is not
       ``stale``.

    ``records`` is the caller's certification store in the shape
    :func:`mayhem.infra.promotion.evaluate_maturity` consumes. An empty sequence
    means "nothing is certified", which is an assertion rather than an absence,
    and yields :data:`RuntimeFaultState.UNVERIFIED` for every fault.
    """
    if definition.catalog_only:
        return FaultClaim(
            fault_id=definition.id,
            state=RuntimeFaultState.UNVERIFIED,
            live=False,
            catalog_only=True,
            detail=definition.refusal_reason or "catalog-only: the fault refuses to execute",
        )
    live = [record for record in records if record.grants_live_verification]
    if live:
        # Deterministic pick: latest ``certified_at``, then latest expiry, then
        # the record label. Set order would make the claim depend on iteration
        # order, and this claim goes into a commit status.
        chosen = max(
            live,
            key=lambda record: (
                record.certified_at or datetime.min.replace(tzinfo=UTC),
                record.expires_at,
                record.label,
            ),
        )
        state = (
            RuntimeFaultState.EXPIRING
            if chosen.state is CertificationState.EXPIRING
            else RuntimeFaultState.CERTIFIED
        )
        return FaultClaim(
            fault_id=definition.id,
            state=state,
            live=True,
            evidence_refs=(f"certification:{chosen.label}",),
            detail=f"certified on {chosen.cell.label}",
        )
    if records:
        last = records[-1]
        return FaultClaim(
            fault_id=definition.id,
            state=RuntimeFaultState(last.state.value),
            live=False,
            evidence_refs=(f"certification:{last.label}",),
            detail=last.reason or last.state.value,
        )
    return FaultClaim(
        fault_id=definition.id,
        state=RuntimeFaultState.UNVERIFIED,
        live=False,
        detail="no certification record exists for this fault",
    )


# =============================================================================
# Coverage — a number with its denominator
# =============================================================================


@dataclass(frozen=True, slots=True)
class CoverageSurface:
    """One service's declared resilience landscape and what is covered in it.

    ``cells`` is the **denominator**: the cells this service is measured
    against. It is a constructor argument rather than something computed later
    because a coverage number whose denominator arrived afterwards is a number
    somebody chose.

    Three refusals at construction:

    * a blank service name, or an empty landscape
      (:data:`RULE_COVERAGE_EMPTY_DENOMINATOR`) — "0 of 0 covered" is not a
      coverage number, and rendering it is how an untested service ends up
      reporting a clean 100%;
    * a repeated cell key (:data:`RULE_COVERAGE_UNKNOWN_KEY`) — a cell has one
      state and one place in the denominator;
    * a ``covered`` or ``states`` key outside the landscape
      (:data:`RULE_COVERAGE_UNKNOWN_KEY`) — a key the landscape does not contain
      cannot be one of its covered cells, and counting it would push the
      numerator past the denominator.
    """

    service: str
    cells: tuple[CoverageCell, ...]
    covered: frozenset[str] = frozenset()
    lost: tuple[CoverageCell, ...] = ()
    states: Mapping[str, CellState] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.service.strip():
            raise InvariantViolationError(
                RULE_COVERAGE_EMPTY_DENOMINATOR,
                "a coverage surface must name its service",
            )
        if not self.cells:
            raise InvariantViolationError(
                RULE_COVERAGE_EMPTY_DENOMINATOR,
                f"coverage for {self.service!r} was reported with no declared "
                "landscape: a fraction with no denominator is not a coverage "
                "number, and 'none of nothing covered' is how an untested "
                "service reports 100%",
            )
        keys = {cell.key for cell in self.cells}
        if len(keys) != len(self.cells):
            raise InvariantViolationError(
                RULE_COVERAGE_UNKNOWN_KEY,
                f"coverage landscape for {self.service!r} repeats a cell: a cell "
                "has one state and one place in the denominator",
            )
        stray = sorted(set(self.covered) - keys)
        if stray:
            raise InvariantViolationError(
                RULE_COVERAGE_UNKNOWN_KEY,
                f"coverage for {self.service!r} counts {stray} as covered, but "
                "those cells are not in the declared landscape",
            )
        unknown_states = sorted(set(self.states) - keys)
        if unknown_states:
            raise InvariantViolationError(
                RULE_COVERAGE_UNKNOWN_KEY,
                f"coverage for {self.service!r} reports states for "
                f"{unknown_states}, which are not in the declared landscape",
            )

    @property
    def denominator(self) -> int:
        """The declared cell count. The number every coverage claim divides by."""
        return len(self.cells)

    @property
    def numerator(self) -> int:
        return sum(1 for cell in self.cells if cell.key in self.covered)

    @property
    def gaps(self) -> tuple[CoverageCell, ...]:
        """Declared but uncovered cells, in declared order."""
        return tuple(cell for cell in self.cells if cell.key not in self.covered)

    @property
    def fraction(self) -> float:
        return self.numerator / self.denominator

    def describe(self) -> str:
        """``service: N of M declared resilience cells covered``.

        The denominator is in the sentence, always. That is the whole rule from
        plan 22, and it is why this is a method on the surface rather than
        string-building at each call site.
        """
        return (
            f"{self.service}: {self.numerator} of {self.denominator} declared "
            "resilience cells covered"
        )

    @property
    def evidence_ref(self) -> str:
        """A stable reference naming the number and its denominator together."""
        return f"coverage/{self.service}@{self.numerator}of{self.denominator}"

    def to_dict(self) -> dict[str, object]:
        return {
            "service": self.service,
            "covered": self.numerator,
            "denominator": self.denominator,
            "fraction": self.fraction,
            "gaps": [cell.key for cell in self.gaps],
            "lost": [cell.key for cell in self.lost],
            "statement": self.describe(),
        }


def coverage_check(surface: CoverageSurface, *, name: str | None = None) -> PRCheck:
    """The ``coverage`` check for ``surface``, with the gap or the loss named.

    A gap is a **warning** on a passing check: "checkout has no experiment
    covering PostgreSQL failure" is a true and useful thing to say about a PR
    that is otherwise fine. Lost coverage is different — a cell that was passed
    and no longer is a regression, not a gap — so it is an error and fails.

    ``PRCheck`` carries at most one finding, so a surface with several gaps
    reports the first and lets :meth:`CoverageSurface.describe` carry the count.
    A finding is a triage sentence, not a table; the full gap list stays on the
    surface, which is what a renderer reads.
    """
    label = name or CHECK_NAME[CheckScope.COVERAGE]
    lost = surface.lost
    if lost:
        cell = lost[0]
        return PRCheck(
            name=label,
            scope=CheckScope.COVERAGE,
            outcome=CheckOutcome.FAIL,
            evidence_refs=(surface.evidence_ref,),
            finding=CheckFinding(
                code="coverage.lost",
                message=(
                    f"{surface.service} lost coverage on {cell.fault_kind} for "
                    f"{cell.target}: {surface.describe()}"
                ),
                remediation=(
                    "restore the experiment that covered this cell, or record why "
                    "the cell is no longer covered"
                ),
                severity=FindingSeverity.ERROR,
                cell=cell,
            ),
            detail=f"{len(lost)} of {surface.denominator} declared cells lost coverage",
        )
    gaps = surface.gaps
    if not gaps:
        return PRCheck(
            name=label,
            scope=CheckScope.COVERAGE,
            outcome=CheckOutcome.PASS,
            evidence_refs=(surface.evidence_ref,),
            detail=surface.describe(),
        )
    cell = gaps[0]
    return PRCheck(
        name=label,
        scope=CheckScope.COVERAGE,
        outcome=CheckOutcome.PASS,
        evidence_refs=(surface.evidence_ref,),
        finding=CheckFinding(
            code="coverage.gap",
            message=(
                f"{surface.service} has no experiment covering {cell.fault_kind} "
                f"for {cell.target}: {surface.describe()}"
            ),
            remediation=(
                f"add an experiment covering {cell.key}, or record the cell as "
                "blocked with a reason"
            ),
            severity=FindingSeverity.WARNING,
            cell=cell,
        ),
        detail=(
            f"{len(gaps)} of {surface.denominator} declared cells uncovered "
            f"({surface.describe()})"
        ),
    )


# =============================================================================
# Inputs and the report they produce
# =============================================================================


@dataclass(frozen=True, slots=True)
class CheckInputs:
    """Everything :func:`evaluate_pr_checks` reads. Nothing else.

    ``control_plane`` is the one field that changes what the engine *does*
    rather than what it reports: unreachable means no gate runs at all, so a
    check cannot pass by accident because a half-reachable plane happened to
    answer the cheap half.
    """

    plan: ExecutionPlan
    graph: TopologyGraph
    safety: SafetyContext
    change: ChangeLink
    cited_run: RunPin | None = None
    adapter: RuntimeAdapter | None = None
    policy_decision: PolicyDecision | None = None
    certifications: Mapping[str, Sequence[CertificationRecord]] | None = None
    coverage: tuple[CoverageSurface, ...] = ()
    control_plane: ControlPlaneReach = ControlPlaneReach.REACHABLE
    control_plane_detail: str = ""

    def __post_init__(self) -> None:
        if self.control_plane is ControlPlaneReach.UNREACHABLE and not (
            self.control_plane_detail.strip()
        ):
            raise InvariantViolationError(
                RULE_UNKNOWN_UNEXPLAINED,
                f"an unreachable control plane must say why: {CONTROL_PLANE_UNREACHABLE}",
            )


@dataclass(frozen=True, slots=True)
class CheckReport:
    """The checks one evaluation produced, plus what they were read from.

    ``compilation`` is ``None`` exactly when the control plane was unreachable
    and no gate ran. Carrying that distinction is the point: a report *with* a
    compilation has a safety case behind it; a report without one has seven
    ``UNKNOWN`` checks and nothing else.
    """

    checks: tuple[PRCheck, ...]
    change: ChangeLink
    cited_run: RunPin | None
    plan_digest: str
    control_plane: ControlPlaneReach
    claims: tuple[FaultClaim, ...] = ()
    compilation: SafetyCompilation | None = None
    #: The compiled proof's own ``void_reason``, empty when it compiled clean.
    #: Carried rather than spread across the checks on purpose — see
    #: :func:`_findings_for_scope`. A renderer shows it once; a check reports only
    #: what it owns.
    void_reason: str = ""

    def check(self, name: str) -> PRCheck | None:
        return next((check for check in self.checks if check.name == name), None)

    def by_scope(self, scope: CheckScope) -> tuple[PRCheck, ...]:
        return tuple(check for check in self.checks if check.scope is scope)

    @property
    def blocking(self) -> tuple[PRCheck, ...]:
        return tuple(check for check in self.checks if check.blocking)

    @property
    def proven(self) -> bool:
        """True when a safety case was compiled *and* it passed for this plan."""
        return self.compilation is not None and (
            self.compilation.proof.verdict is ProofVerdict.PASS
        )

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        """Every check's citations, de-duplicated, in check order."""
        return tuple(
            dict.fromkeys(ref for check in self.checks for ref in check.evidence_refs)
        )

    def verdict(
        self,
        *,
        decision_refs: Sequence[DecisionRef] = (),
        decided_at: datetime | None = None,
    ) -> PipelineVerdict:
        """Grade these checks into a :class:`PipelineVerdict`.

        Raises:
            InvariantViolationError: When the checks carry no evidence at all,
                which is what an unreachable control plane produces. There is no
                verdict to build in that case, and inventing an evidence reference
                to get one is exactly the forgery Phase 1 refuses. The caller
                reads :attr:`checks` and sees seven ``UNKNOWN``s.
        """
        return PipelineVerdict.decide(
            self.change,
            self.checks,
            cited_run=self.cited_run,
            decision_refs=tuple(decision_refs),
            decided_at=decided_at,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "control_plane": self.control_plane.value,
            "plan_digest": self.plan_digest,
            "proven": self.proven,
            "void_reason": self.void_reason,
            "checks": [check.to_dict() for check in self.checks],
            "claims": [claim.to_dict() for claim in self.claims],
        }


# =============================================================================
# The engine
# =============================================================================


def evaluate_pr_checks(inputs: CheckInputs) -> CheckReport:
    """Evaluate a pull request's checks through the normal compile → proof → policy path.

    One call to :func:`~mayhem.controller.safety_proof.compile_safety_evidence`
    runs ``validate_plan`` unchanged plus every probe the compiler owns; the
    checks are then *projections* of that result. Nothing here re-derives a
    verdict, so the engine can only ever be as strict as the path it reads — and
    a check cannot report something the proof does not also report, because the
    detail it quotes *is* the obligation's detail.

    The caller's :class:`~mayhem.controller.safety.SafetyContext` decision log is
    untouched (the compiler probes on clones), so evaluating a PR never appends
    preview decisions to the safety record a real run is judged by.

    An unreachable control plane short-circuits before any gate runs and returns
    checks that all report unknown, each carrying the reason. That is not a
    degraded pass path; it is the only answer a network that cannot be reached
    can honestly give.
    """
    if inputs.control_plane is ControlPlaneReach.UNREACHABLE:
        return _unreachable_report(inputs)

    compilation = compile_safety_evidence(
        inputs.plan,
        inputs.graph,
        inputs.safety,
        adapter=inputs.adapter,
        policy_decision=inputs.policy_decision,
    )
    claims = _claims_for(inputs)
    checks = [_check_from_scope(inputs, compilation, scope, claims) for scope in CHECK_ORDER]
    checks.extend(
        coverage_check(surface, name=f"coverage:{surface.service}")
        for surface in inputs.coverage
    )
    return CheckReport(
        checks=tuple(checks),
        change=inputs.change,
        cited_run=inputs.cited_run,
        plan_digest=compilation.plan_digest,
        control_plane=inputs.control_plane,
        claims=claims,
        compilation=compilation,
        void_reason=compilation.void_reason,
    )


#: How much of a catalog refusal may be quoted into a check finding.
#:
#: :class:`~mayhem.domain.pipeline.CheckFinding` caps ``message`` at 2000
#: characters, and the catalog's own ``not in catalog`` refusal enumerates every
#: id it holds — 2911 characters at this catalog's size. Pasting that in full
#: would not produce a *long* finding; it would raise
#: :class:`pydantic.ValidationError` out of the middle of
#: :func:`evaluate_pr_checks`, so a PR with one misspelled fault id would crash
#: the check rather than fail it. The head of the message is kept, because the
#: fault id is the first thing it says and that is what an operator needs; the
#: tail is a list of 145 ids nobody reads.
_SYNTAX_REPORT_CHARS: Final[int] = 400


def _syntax_problems(inputs: CheckInputs) -> tuple[str, ...]:
    """What the authored plan does not resolve against the catalog.

    Deliberately *not* a gate: nothing here decides whether a fault may run. It
    asks the two questions the catalog alone answers — does this fault id exist,
    and do its parameters satisfy the declared grammar — through
    :func:`mayhem.domain.catalog.definition_for` and the definition's own
    ``validate_params``, so a PR check cannot hold a different parameter grammar
    than the planner does.

    Each refusal is bounded (see :data:`_SYNTAX_REPORT_CHARS`). The bound is a
    fix for a crash, not a style preference: an unbounded catalog refusal is
    longer than the finding that has to carry it, and a finding that is too long
    to construct is not a finding.
    """
    problems: list[str] = []
    faults = plan_faults(inputs.plan)
    for fault in faults:
        try:
            definition = definition_for(fault.fault_id)
        except LookupError as exc:
            problems.append(_bounded(str(exc)))
            continue
        if definition.catalog_only:
            problems.append(
                f"{fault.fault_id} is catalog-only: "
                f"{definition.refusal_reason or 'it refuses to execute here'}"
            )
            continue
        try:
            definition.validate_params(fault.params)
        except DomainError as exc:
            problems.append(_bounded(f"{fault.fault_id} params do not validate: {exc}"))
    if not faults:
        problems.append("the plan names no fault step, so there is nothing to check")
    return tuple(problems)


def _bounded(message: str) -> str:
    """A refusal short enough for a finding, saying how much was dropped.

    The "and N more characters of catalog listing" tail is deliberate: a silent
    truncation would let a reader believe they had seen the whole refusal, which
    is the same failure mode as a truncated ticket.
    """
    if len(message) <= _SYNTAX_REPORT_CHARS:
        return message
    return (
        f"{message[:_SYNTAX_REPORT_CHARS].rstrip()} "
        f"(+{len(message) - _SYNTAX_REPORT_CHARS} more characters of catalog listing)"
    )


def _obligation_problems(compilation: SafetyCompilation, scope: CheckScope) -> tuple[str, ...]:
    """Why ``scope``'s proof lines are not all passing, in the proof's own words."""
    problems: list[str] = []
    for name, owning in OBLIGATION_CHECK.items():
        if owning is not scope:
            continue
        obligation = compilation.proof.obligation(name)
        if obligation is None:
            problems.append(f"the proof carries no {name} line for this plan")
            continue
        if obligation.status is ObligationStatus.PASS:
            continue
        problems.append(f"{name}: {obligation.detail or obligation.status.value}")
    return tuple(problems)


def _scope_refusals(compilation: SafetyCompilation, scope: CheckScope) -> tuple[str, ...]:
    """Gate rules refused on, filtered to the ones ``scope`` owns."""
    return tuple(
        dict.fromkeys(
            rule for rule in compilation.compiler_refusals if check_for_rule(rule) is scope
        )
    )


def _scope_evidence(compilation: SafetyCompilation, scope: CheckScope) -> tuple[str, ...]:
    """The proof lines' own evidence refs, for the lines ``scope`` reports.

    May be empty, and the caller must then fail the check rather than pass it.
    There is deliberately no fallback reference: a scope whose proof lines cite
    no gate output has produced no gate output, and a synthesised
    ``gate-output/...`` string would read as cited while leading nowhere — which
    is worse than a missing one, because a missing one is visible.
    """
    return tuple(
        dict.fromkeys(
            obligation.evidence_ref
            for name, owning in OBLIGATION_CHECK.items()
            if owning is scope
            for obligation in (compilation.proof.obligation(name),)
            if obligation is not None and obligation.evidence_ref.strip()
        )
    )


def _findings_for_scope(
    inputs: CheckInputs,
    compilation: SafetyCompilation,
    scope: CheckScope,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(problems, evidence_refs)`` for one scope, off the compiled proof."""
    if scope is CheckScope.SYNTAX:
        return _syntax_problems(inputs), (f"plan-digest/{compilation.plan_digest}",)
    # Deliberately *not* the proof's global ``void_reason``. Blaming every
    # check for it would make "capability requirements were not established"
    # read as a blast-radius failure, which is the kind of misattribution that
    # teaches an operator to ignore the check that matters. Each scope reports
    # its own lines (above) and its own refused rules (above); a refusal no line
    # can carry still lands somewhere, because :func:`check_for_rule` is total
    # and routes it to :data:`DEFAULT_RULE_CHECK`. The proof's own verdict is
    # on :attr:`CheckReport.void_reason` for a renderer to show once.
    problems = [
        *_obligation_problems(compilation, scope),
        *_scope_refusals(compilation, scope),
    ]
    evidence = _scope_evidence(compilation, scope)
    if not evidence:
        problems.append(
            f"no proof line reporting {CHECK_NAME[scope]} cites a gate output, so "
            "this check has no evidence behind it and cannot pass"
        )
    return tuple(dict.fromkeys(problems)), evidence


def _claims_for(inputs: CheckInputs) -> tuple[FaultClaim, ...]:
    """One claim per distinct planned fault, in first-appearance order."""
    certifications = inputs.certifications or {}
    claims: dict[str, FaultClaim] = {}
    for fault in plan_faults(inputs.plan):
        if fault.fault_id in claims:
            continue
        try:
            definition = definition_for(fault.fault_id)
        except LookupError:
            # No definition means no claim can be made about it. The syntax check
            # is where that is reported, with the catalog's own message.
            continue
        claims[fault.fault_id] = claim_for_fault(
            definition, tuple(certifications.get(fault.fault_id, ()))
        )
    return tuple(claims.values())


def _claim_errors(claims: tuple[FaultClaim, ...]) -> tuple[str, ...]:
    """Catalog-only planned faults. These *fail* the compatibility check.

    A catalog-only fault cannot run here, so a plan naming one is refused by the
    planner and refused again here. The syntax check says so too, and
    deliberately: "the plan names a fault this build refuses" and "the plan's
    faults are not certified" are different facts, and a reviewer needs both.
    """
    blocked = tuple(claim for claim in claims if claim.catalog_only)
    if not blocked:
        return ()
    return (
        f"{len(blocked)} of {len(claims)} planned fault(s) are catalog-only and cannot "
        f"run here: {', '.join(claim.fault_id for claim in blocked)}",
    )


def _claim_warnings(claims: tuple[FaultClaim, ...]) -> tuple[str, ...]:
    """Planned faults with no live certification record. These only *warn*.

    A warning, deliberately, and for the same reason a coverage gap is one: a PR
    that touches an uncertified fault is not thereby broken, and a check that is
    red on every PR until the entire catalog is certified is a check people learn
    to ignore. What must never happen is the opposite — an uncertified fault
    *reported as certified* — and that is unrepresentable in :class:`FaultClaim`
    rather than merely discouraged here.

    The states are spelled out rather than collapsed into "not certified",
    because ``stale``, ``failed``, and ``incompatible`` are three different
    operational stories and a reader cannot tell them apart from an absence.
    Folded into one sentence: "nothing here is certified" is one fact about the
    plan, not five facts about five faults.
    """
    unverified = tuple(
        claim for claim in claims if not claim.runtime_certified and not claim.catalog_only
    )
    if not unverified:
        return ()
    states = ", ".join(sorted({claim.state.value for claim in unverified}))
    return (
        f"{len(unverified)} of {len(claims)} planned fault(s) hold no live "
        f"certification record ({states}): "
        f"{', '.join(claim.fault_id for claim in unverified)}",
    )


def _check_from_scope(
    inputs: CheckInputs,
    compilation: SafetyCompilation,
    scope: CheckScope,
    claims: tuple[FaultClaim, ...],
) -> PRCheck:
    """One check, graded from the proof and the claims. Never from its own logic."""
    problems, evidence = _findings_for_scope(inputs, compilation, scope)
    warnings: tuple[str, ...] = ()
    if scope is CheckScope.FAULT_COMPATIBILITY:
        problems = (*problems, *_claim_errors(claims))
        warnings = _claim_warnings(claims)
    if problems:
        # Bounded as well as the individual refusals: a plan with several
        # unresolvable faults joins into one message, and each of those is
        # comfortably under the finding's 2000-character cap while their sum is
        # not. See :data:`_SYNTAX_REPORT_CHARS` for why this is a crash fix.
        detail = _bounded("; ".join(dict.fromkeys(problems)))
        return PRCheck(
            name=CHECK_NAME[scope],
            scope=scope,
            outcome=CheckOutcome.FAIL,
            evidence_refs=evidence,
            finding=CheckFinding(
                code=_finding_code(scope),
                message=detail,
                remediation=_REMEDIATION.get(scope, "see the finding for what to change"),
                severity=FindingSeverity.ERROR,
            ),
            detail=detail,
        )
    detail = _pass_detail(scope, compilation, claims, warnings)
    if warnings:
        return PRCheck(
            name=CHECK_NAME[scope],
            scope=scope,
            outcome=CheckOutcome.PASS,
            evidence_refs=evidence,
            finding=CheckFinding(
                code="check.fault-compatibility.uncertified",
                message="; ".join(warnings),
                remediation=_REMEDIATION[CheckScope.FAULT_COMPATIBILITY],
                severity=FindingSeverity.WARNING,
            ),
            detail=detail,
        )
    return PRCheck(
        name=CHECK_NAME[scope],
        scope=scope,
        outcome=CheckOutcome.PASS,
        evidence_refs=evidence,
        detail=detail,
    )


def _pass_detail(
    scope: CheckScope,
    compilation: SafetyCompilation,
    claims: tuple[FaultClaim, ...],
    warnings: tuple[str, ...] = (),
) -> str:
    """What a passing check says. Never the proof's global verdict.

    A PASS whose detail reads "proof verdict FAIL" is a check confusing the
    reader about a *different* line's problem. A scope reports the lines it owns
    and how many of them passed; the proof's own verdict belongs on
    :attr:`CheckReport.void_reason` and ``proven``, once, for a renderer.
    """
    if scope is CheckScope.SYNTAX:
        return (
            f"plan {compilation.plan_digest[:12]}: every planned fault resolves in "
            "the catalog with valid parameters"
        )
    if scope is CheckScope.FAULT_COMPATIBILITY and claims:
        live = sum(1 for claim in claims if claim.runtime_certified)
        suffix = f"; {len(warnings)} certification warning(s)" if warnings else ""
        return (
            f"{live} of {len(claims)} planned faults hold a live certification "
            f"record ({', '.join(sorted({c.state.value for c in claims}))}){suffix}"
        )
    owned = tuple(
        name for name, owning in OBLIGATION_CHECK.items() if owning is scope
    )
    passing = sum(
        1
        for name in owned
        for obligation in (compilation.proof.obligation(name),)
        if obligation is not None and obligation.status is ObligationStatus.PASS
    )
    return (
        f"{CHECK_NAME[scope]}: {passing} of {len(owned)} proof lines pass for plan "
        f"{compilation.plan_digest[:12]}"
    )


def _unreachable_report(inputs: CheckInputs) -> CheckReport:
    """One unknown check per scope and no compilation. See the module docstring."""
    detail = inputs.control_plane_detail.strip()
    checks = tuple(
        PRCheck(
            name=CHECK_NAME[scope],
            scope=scope,
            outcome=CheckOutcome.UNKNOWN,
            control_plane=ControlPlaneReach.UNREACHABLE,
            detail=f"{detail} — {CONTROL_PLANE_UNREACHABLE}",
        )
        for scope in CHECK_ORDER
    )
    checks = checks + tuple(
        coverage_check(surface, name=f"coverage:{surface.service}")
        for surface in inputs.coverage
    )
    return CheckReport(
        checks=checks,
        change=inputs.change,
        cited_run=inputs.cited_run,
        plan_digest="",
        control_plane=ControlPlaneReach.UNREACHABLE,
        claims=(),
        compilation=None,
    )


# =============================================================================
# Resilience suites and the release gate
# =============================================================================


class ChangeKind(StrEnum):
    """What changed, which is what decides which suites are owed.

    Plan 16's release gate is "attach resilience suites to deployments,
    dependency changes, and infrastructure changes" — three triggers, three
    different suites. The enum is the closed form of that sentence, so a fourth
    trigger cannot be spelled at a call site as free text and quietly gate on
    nothing.
    """

    DEPLOYMENT = "deployment"
    DEPENDENCY = "dependency"
    INFRASTRUCTURE = "infrastructure"


#: The suites owed per trigger, read rather than branched over, so "which suites
#: does this change owe" has one answer.
REQUIRED_SUITES: Final[dict[ChangeKind, tuple[str, ...]]] = {
    ChangeKind.DEPLOYMENT: ("resilience.post-deploy",),
    ChangeKind.DEPENDENCY: ("resilience.dependency-failure",),
    ChangeKind.INFRASTRUCTURE: ("resilience.infrastructure-drift",),
}


def required_suites_for(kind: ChangeKind) -> tuple[str, ...]:
    """The suite names a change of ``kind`` owes before it may open a release."""
    return REQUIRED_SUITES[kind]


@dataclass(frozen=True, slots=True)
class ResilienceSuite:
    """One resilience suite's result, as a release gate reads it.

    Three refusals, all in service of "a gate never allows without evidence":

    * a ``PASS`` with no evidence refs is refused (:data:`RULE_SUITE_WITHOUT_EVIDENCE`);
    * a ``PASS`` with no cited run is refused (:data:`RULE_SUITE_WITHOUT_RUN`) —
      resilience nobody can attribute to a run is a feeling, and it cannot be
      compared across a release either;
    * an ``UNKNOWN`` with no explanation is refused
      (:data:`RULE_SUITE_UNKNOWN_UNEXPLAINED`) — a suite that could not conclude
      must say why, or the reader is left to guess whether it was a timeout or a
      skip.

    An ``UNKNOWN`` reports with the control plane marked **reachable**: the suite
    reached the evidence store and the evidence store had nothing. That is a
    different fact from a suite that could not reach the store, and conflating
    them is how "the runner was down" gets recorded as "the service is fine".
    """

    name: str
    outcome: CheckOutcome
    evidence_refs: tuple[str, ...] = ()
    run: RunPin | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvariantViolationError(
                RULE_SUITE_WITHOUT_EVIDENCE, "a resilience suite must be named"
            )
        if self.outcome is CheckOutcome.PASS:
            if not self.evidence_refs:
                raise InvariantViolationError(
                    RULE_SUITE_WITHOUT_EVIDENCE,
                    f"resilience suite {self.name!r} reports pass with no evidence "
                    "reference: a gate that opens on an uncited suite opens on "
                    "nothing",
                )
            if self.run is None:
                raise InvariantViolationError(
                    RULE_SUITE_WITHOUT_RUN,
                    f"resilience suite {self.name!r} reports pass while citing no "
                    "run: resilience that cannot be attributed to a run cannot be "
                    "compared across a release either",
                )
        if self.outcome is CheckOutcome.UNKNOWN and not self.detail.strip():
            raise InvariantViolationError(
                RULE_SUITE_UNKNOWN_UNEXPLAINED,
                f"resilience suite {self.name!r} reported unknown without saying "
                "whether the runner was unreachable or had nothing to report",
            )

    @property
    def conclusive(self) -> bool:
        return self.outcome is not CheckOutcome.UNKNOWN

    def as_check(self) -> PRCheck:
        """The suite as a :class:`PRCheck`, so it joins a verdict like any other."""
        if self.outcome is CheckOutcome.PASS:
            return PRCheck(
                name=self.name,
                scope=CheckScope.RESILIENCE,
                outcome=CheckOutcome.PASS,
                evidence_refs=self.evidence_refs,
                detail=self.detail or f"suite passed on {self.run.label if self.run else ''}",
            )
        if self.outcome is CheckOutcome.FAIL:
            return PRCheck(
                name=self.name,
                scope=CheckScope.RESILIENCE,
                outcome=CheckOutcome.FAIL,
                evidence_refs=self.evidence_refs,
                finding=CheckFinding(
                    code="resilience.suite_failed",
                    message=f"{self.name} reported fail: {self.detail}".rstrip(": "),
                    remediation="fix the regression the suite found and re-run it",
                    severity=FindingSeverity.ERROR,
                ),
                detail=self.detail,
            )
        return PRCheck(
            name=self.name,
            scope=CheckScope.RESILIENCE,
            outcome=CheckOutcome.UNKNOWN,
            detail=f"{self.name} reported unknown: {self.detail}",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "outcome": self.outcome.value,
            "run": None if self.run is None else self.run.label,
            "evidence_refs": list(self.evidence_refs),
            "detail": self.detail,
        }


#: The only two answers a release gate can give. Module-level rather than class
#: attributes because :class:`ReleaseGateDecision` is a pydantic model and a bare
#: class attribute there is not part of the schema — a reader would reasonably
#: assume ``decision=GATE_ALLOW`` were validated against it, and it is only
#: validated because :meth:`ReleaseGateDecision._check_invariants` says so.
GATE_ALLOW: Final[str] = "allow"
GATE_BLOCK: Final[str] = "block"


@dataclass(frozen=True, slots=True)
class ReleaseGateRequest:
    """A release-gate question: this change, this trigger, the suites owed."""

    change: ChangeLink
    kind: ChangeKind
    subject: str
    suites: tuple[str, ...] = ()
    merge: PlanMerge | None = None

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise InvariantViolationError(
                RULE_BLOCK_WITHOUT_REASON,
                "a release gate must name the deployment, dependency, or "
                "infrastructure change it is deciding about",
            )

    @property
    def required_suites(self) -> tuple[str, ...]:
        """The suites owed: the caller's, or the trigger's default."""
        return self.suites or required_suites_for(self.kind)


class ReleaseGateDecision(BaseModel):
    """Whether a change may open a release, and what it rests on.

    The refusals here carry the fail-closed rule:

    * ``allow`` with no ``evidence_refs`` is refused
      (:data:`RULE_ALLOW_WITHOUT_EVIDENCE`) — not warned about, *refused*, so
      there is no code path that produces an allow without a citation behind it;
    * ``allow`` while naming reasons is refused, for the same reason;
    * ``allow`` while a required suite has not passed *with a cited run* is
      refused — checked here rather than left to the caller, because a decision
      object that can be built in an inconsistent state is one a later reader
      cannot trust;
    * ``block`` with no ``reasons`` is refused (:data:`RULE_BLOCK_WITHOUT_REASON`),
      because a closed gate that does not say what closed it is indistinguishable
      from a gate that was never wired up.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ChangeKind
    subject: str
    decision: str
    reasons: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    required_suites: tuple[str, ...] = ()
    suites: tuple[ResilienceSuite, ...] = ()
    verdict_digest: str = ""
    gate_reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.decision not in (GATE_ALLOW, GATE_BLOCK):
            raise InvariantViolationError(
                RULE_BLOCK_WITHOUT_REASON,
                f"release-gate decision must be {GATE_ALLOW!r} or {GATE_BLOCK!r}, "
                f"got {self.decision!r}",
            )
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise InvariantViolationError(
                RULE_ALLOW_WITHOUT_EVIDENCE,
                f"release gate for {self.subject!r} repeats an evidence reference",
            )
        if self.decision == GATE_BLOCK:
            if not self.reasons:
                raise InvariantViolationError(
                    RULE_BLOCK_WITHOUT_REASON,
                    f"a release gate for {self.subject!r} blocked without saying "
                    "what blocked it",
                )
            return self
        if not self.evidence_refs:
            raise InvariantViolationError(
                RULE_ALLOW_WITHOUT_EVIDENCE,
                f"a release gate for {self.subject!r} was allowed with no cited "
                "evidence: an allow with nothing behind it is not a decision, it "
                "is a default",
            )
        if self.reasons:
            raise InvariantViolationError(
                RULE_ALLOW_WITHOUT_EVIDENCE,
                f"a release gate for {self.subject!r} was allowed while naming "
                f"blocking reasons: {list(self.reasons)}",
            )
        unrun = tuple(
            name for name in self.required_suites if not _suite_passed(name, self.suites)
        )
        if unrun:
            raise InvariantViolationError(
                RULE_ALLOW_WITHOUT_EVIDENCE,
                f"a release gate for {self.subject!r} was allowed while "
                f"{list(unrun)} had not passed with a cited run",
            )
        return self

    @property
    def opens_release(self) -> bool:
        return self.decision == GATE_ALLOW

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "decision": self.decision,
            "opens_release": self.opens_release,
            "reasons": list(self.reasons),
            "evidence_refs": list(self.evidence_refs),
            "required_suites": list(self.required_suites),
            "suites": [suite.to_dict() for suite in self.suites],
            "verdict_digest": self.verdict_digest,
            "gate_reasons": list(self.gate_reasons),
        }


def _suite_passed(name: str, suites: tuple[ResilienceSuite, ...]) -> bool:
    return any(
        suite.name == name
        and suite.outcome is CheckOutcome.PASS
        and suite.run is not None
        and bool(suite.evidence_refs)
        for suite in suites
    )


def release_gate(
    verdict: PipelineVerdict,
    request: ReleaseGateRequest,
    *,
    suites: Sequence[ResilienceSuite] = (),
) -> ReleaseGateDecision:
    """Decide whether ``request``'s change may open a release. Fails closed.

    The pipeline half is *delegated*:
    :func:`mayhem.domain.pipeline.blocking_reasons` is called, never
    re-implemented, so "may this open a release" has one answer in this codebase
    and the gate cannot drift from the verdict predicate Phase 1 shipped.

    The suite half is the gap-103 half, and every branch of it blocks:

    * a required suite with no result at all blocks — a suite that did not run is
      not a suite that passed;
    * an ``UNKNOWN`` suite blocks and is named with its reason;
    * a ``FAIL`` suite blocks and is named with the finding;
    * a ``PASS`` suite with no cited run blocks (and, at construction of the
      suite, cannot exist).

    So the only path to ``allow`` is: no blocking reason from the verdict, no
    merge invalidation, every required suite passed with a run and evidence, and
    a non-empty evidence set on the decision itself.
    """
    # Kept separate rather than merged: "the pipeline itself blocks" and "the
    # suites this change owes did not report" are different diagnoses, and a
    # gate that conflates them tells an operator to re-run a suite when the
    # pipeline never passed in the first place.
    pipeline_reasons = blocking_reasons(verdict, request.merge)
    reasons: list[str] = [*pipeline_reasons]
    supplied = {suite.name: suite for suite in suites}
    evidence: list[str] = list(verdict.evidence_refs)
    for name in request.required_suites:
        suite = supplied.get(name)
        if suite is None:
            reasons.append(
                f"required resilience suite {name!r} did not report: no evidence "
                f"is available for the {request.kind.value} of {request.subject!r}, "
                "and a gate with no evidence blocks"
            )
            continue
        if suite.outcome is CheckOutcome.UNKNOWN:
            reasons.append(f"resilience suite {name!r} did not conclude: {suite.detail}")
            continue
        if suite.outcome is CheckOutcome.FAIL:
            reasons.append(f"resilience suite {name!r} reported fail: {suite.detail}")
        evidence.extend(suite.evidence_refs)
        if suite.run is not None:
            evidence.append(f"run/{suite.run.label}")

    ordered = tuple(dict.fromkeys(reasons))
    if not ordered:
        return ReleaseGateDecision(
            kind=request.kind,
            subject=request.subject,
            decision=GATE_ALLOW,
            evidence_refs=tuple(dict.fromkeys(evidence)),
            required_suites=request.required_suites,
            suites=tuple(suites),
            verdict_digest=verdict.verdict_digest(),
        )
    return ReleaseGateDecision(
        kind=request.kind,
        subject=request.subject,
        decision=GATE_BLOCK,
        reasons=ordered,
        evidence_refs=tuple(dict.fromkeys(evidence)),
        required_suites=request.required_suites,
        suites=tuple(suites),
        verdict_digest=verdict.verdict_digest(),
        gate_reasons=pipeline_reasons,
    )


# =============================================================================
# ChatOps
# =============================================================================


class ChatOpsCommand(StrEnum):
    """The three commands the doc names.

    Closed for the same reason :class:`~mayhem.domain.pipeline.CheckScope` is
    closed: a command that cannot be named is a command nobody can write an
    authorization row for.
    """

    RUN = "run"
    APPROVE = "approve"
    STOP = "stop"


#: Command -> the role that authorizes it. Data, so "who may approve" has one
#: answer and the test suite can iterate it rather than restate it.
CHATOPS_REQUIRED_ROLE: Final[dict[ChatOpsCommand, Role]] = {
    ChatOpsCommand.RUN: Role.EXECUTE,
    ChatOpsCommand.APPROVE: Role.APPROVE,
    ChatOpsCommand.STOP: Role.EMERGENCY_STOP,
}


class ChatOpsRefusedError(InvariantViolationError):
    """A chat command was refused.

    An :class:`~mayhem.domain.errors.InvariantViolationError` so the existing CLI
    error surface renders it unchanged, carrying the requester, the required
    role, and the roles actually held — the three things an operator needs to
    decide whether to fix a grant or to go away.
    """

    def __init__(
        self,
        rule_id: str,
        message: str,
        *,
        requester: str = "",
        command: str = "",
        required: str = "",
        held: tuple[str, ...] = (),
    ) -> None:
        super().__init__(rule_id, message)
        self.requester = requester
        self.command = command
        self.required = required
        self.held = held


@dataclass(frozen=True, slots=True)
class ChatOpsRequest:
    """One chat command, bound to the identity that typed it.

    ``requester`` is never inferred from a transport: it is the authenticated
    principal, and it is what the role resolution in :func:`dispatch_chatops`
    reads. A seam that let the transport supply the identity would be a seam
    where a channel name is an authorization decision.

    ``plan`` is carried rather than looked up, for the same reason: the validator
    the caller injects is handed the plan the *requester* named, so a chat command
    cannot be validated against a different plan than the one that was typed.
    """

    command: ChatOpsCommand
    requester: Principal
    environment: EnvironmentScope
    text: str
    run_id: str = ""
    plan: ExecutionPlan | None = None


@dataclass(frozen=True, slots=True)
class ChatOpsReceipt:
    """What the chat surface says back. Bound to the requester, always."""

    command: ChatOpsCommand
    requester: str
    environment: str
    roles: tuple[str, ...]
    verdict_digest: str = ""
    evidence_refs: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "command": self.command.value,
            "requester": self.requester,
            "environment": self.environment,
            "roles": list(self.roles),
            "verdict_digest": self.verdict_digest,
            "evidence_refs": list(self.evidence_refs),
            "detail": self.detail,
        }


class ChatOpsTransport(Protocol):
    """The seam a Slack or Teams client implements. One method.

    Deliberately this small, and deliberately unimplemented here: Phase 3 owns
    the bots. What the tests must prove — the requester is bound, and an
    unauthorized requester never reaches validation — is a property of
    :func:`dispatch_chatops`, and a three-line fake transport proves it without a
    network, a token, or a third-party dependency.
    """

    def send(self, receipt: ChatOpsReceipt) -> None: ...


def dispatch_chatops(
    request: ChatOpsRequest,
    *,
    transport: ChatOpsTransport,
    validate: Callable[[ChatOpsRequest], PipelineVerdict],
    grants: Sequence[RoleGrant] = (),
    memberships: Sequence[TeamMembership] = (),
    now: datetime,
) -> ChatOpsReceipt:
    """Authorize, validate, then dispatch — in that order, and only that order.

    ``validate`` is required and has no default. It is the caller's own CLI
    validation entry point, passed in rather than re-implemented here, which is
    what "dispatch through identical validation as the CLI" means concretely:
    the ChatOps path has no second validator to drift from the first. Its return
    type is a :class:`~mayhem.domain.pipeline.PipelineVerdict` rather than a
    boolean, so a caller cannot smuggle ``True`` past the gate's own evidence
    requirements — the verdict carries the checks and the citations, and this
    function reads them.

    The order is the security property:

    1. resolve the requester's roles with
       :func:`~mayhem.domain.identity.effective_roles` at ``now``, and refuse
       unless the command's required role is among them. Default-deny: no grants
       means no roles, so an empty ``grants`` refuses everything.
    2. only then call ``validate``. An unauthorized principal never reaches the
       validation a CLI invocation reaches.
    3. refuse when the verdict does not gate — delegated to
       :func:`~mayhem.domain.pipeline.blocking_reasons`, so "may this run" has
       one answer.
    4. send the receipt, bound to the requester.

    Raises:
        ChatOpsRefusedError: If the requester holds no required role, or the
            validation returned a verdict that does not gate.
    """
    required = CHATOPS_REQUIRED_ROLE[request.command]
    roles = effective_roles(
        grants,
        principal=request.requester,
        scope=request.environment,
        memberships=memberships,
        now=now,
    )
    if required not in roles:
        held = tuple(sorted(role.value for role in roles))
        raise ChatOpsRefusedError(
            RULE_CHATOPS_NOT_AUTHORIZED,
            f"{request.requester.principal_id} may not {request.command.value} in "
            f"{request.environment.describe()}: this command needs "
            f"{required.value!r} and the principal holds {list(held) or ['no roles']}",
            requester=request.requester.principal_id,
            command=request.command.value,
            required=required.value,
            held=held,
        )

    verdict = validate(request)
    gate_reasons = blocking_reasons(verdict)
    if gate_reasons:
        raise ChatOpsRefusedError(
            RULE_CHATOPS_VALIDATION_REFUSED,
            f"chat {request.command.value} by {request.requester.principal_id} was "
            "refused by the same validation the CLI uses: " + "; ".join(gate_reasons),
            requester=request.requester.principal_id,
            command=request.command.value,
            required=required.value,
            held=tuple(sorted(role.value for role in roles)),
        )

    receipt = ChatOpsReceipt(
        command=request.command,
        requester=request.requester.principal_id,
        environment=request.environment.describe(),
        roles=tuple(sorted(role.value for role in roles)),
        verdict_digest=verdict.verdict_digest(),
        evidence_refs=verdict.evidence_refs,
        detail=f"{request.command.value} authorized on verdict {verdict.verdict_digest()[:12]}",
    )
    transport.send(receipt)
    return receipt
