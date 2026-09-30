# Plan 07 — Policy-as-Code Safety Engine

**Priority:** P0. Gap items 7, 66, 67, 86.

## Objective
Turn Mayhem's safety rules into a centrally managed, explainable policy system — and fold in the collision graph (66), hierarchical damage budgets (67), and environment locking (86).

## Builds on (extend, do not duplicate)
- `controller/safety.py`: `SafetyContext`, `check_fault_admission`, `check_blast_radius`, `DamageLedger`, `validate_plan` (G1+G2), `pre_exec_assertion` (G3 drift).
- `domain/quota.py`: real-definition pricing, dependents-closure charging, active-by-default quota.
- `BlastRadiusBudget` five per-step caps plus `forbidden_fault_pairs` (now load-bearing since 1.0.0).
- `config.py` policy block (allow/deny, risk ceiling, critical triple opt-in) and target profiles.

## Policy dimensions
Environment, team, fault family, risk, target, capability, schedule,
maintenance window, damage budget, cloud cost, approval level,
concurrency, deployment/incident state.

## Requirements
Deny/allow rules, policy precedence, inheritance, policy versioning,
simulation mode, human-readable explanations, audit trail.

## Rego/OPA
Support optional OPA/Rego evaluation but keep a native policy model for simple deployments.

## Phase 1 — Domain model: policy vocabulary
Add `domain/policy.py`: `PolicyRule` (dimension, predicate, effect), `PolicyBundle` (versioned, digest-pinned), `PolicyDecision` (allow/deny + reasons + digests), `BudgetNode` (team → environment → service → experiment → fault hierarchy for gap 67), `ResourceLock` (experiment-scoped reservations for gap 86), `CompatibilityEdge` (fault-pair compatibility graph for gap 66: permitted, conflicting with reason, conditionally-safe). Pure types; precedence and inheritance as pure functions. Acceptance: decision determinism tests; budget-exhaustion arithmetic tests.

## Phase 2 — Engine: evaluation inside the real gate
Policy evaluation runs inside `validate_plan`, not beside it: the native model first, OPA/Rego as an optional delegate for complex estates. Simulation mode evaluates a frozen plan and returns the decision with zero mutation (plan 14's preview and the 30 proof consume this). Collision graph consulted per `{earlier, new}` pair (the 1.0.0 fix generalized); resource locks checked before admission. Acceptance: a policy change alters decisions only through a versioned bundle — no ambient behavior drift.

## Phase 3 — Surface: policy authoring and explanation
Policy CRUD plus `explain` output: every denial names the rule, the observed values, and the values that would have passed (the promotion-refusal style). Approval requirements surface as part of the decision. Acceptance: the DENY example in this file is produced by the engine verbatim, not hand-written.

## Phase 4 — Safety and evidence integration
Every mutating run records its `PolicyDecision` (rule versions, digests) into the evidence envelope; approval binds to the exact plan+policy digest pair so either changing invalidates approval (09 consumes this). Budget charges post to the ledger hierarchically. Acceptance: replaying a decision from evidence reproduces it bit-for-bit.

## Phase 5 — Tests, regression guards, negative controls
Forbidden-pair regression suite (3+ fault plans, the historical inertness case), quota and budget tests, lock-contention tests (two experiments, one postgres-primary → second queues with the lock owner named). Negative controls: an expired policy version cannot authorize a run; a lock held by a dead run is fenced, never inherited. Acceptance: all green; policy simulation covered by tests asserting no mutation occurred.

## Phase 6 — Docs, honesty gates, rollout
Policy authoring guide, precedence documentation, migration from the current config-policy block (which stays valid; bundles are additive). Rollout: native model first, OPA delegate second, hierarchical budgets third. Acceptance: no doc describes a policy dimension the evaluator does not enforce.

## Example result
```text
DENY
Reason: production policy forbids critical faults without two approvals.
Required: SRE + service owner.
Plan digest: abc123
```

## Dependencies
09 (approvals bound to digests), 12 (decision records sealed), 20
(environment definitions the policy dimensions reference), 30 (proof
consumes evaluation).

## STATUS
- Phase 1 (domain model): DONE — `domain/policy.py` was extended in place with `PolicyRule`, `PolicyFacts`, `PolicyBundle`, `PolicyDecision`, precedence and inheritance as pure functions (`resolve_precedence`, `inherited_rules`, `effective_rules`, `evaluate_rules`, `evaluate_bundle`), the five-level `BudgetNode` hierarchy (team → environment → service → experiment → fault), `ResourceLock` with `lock_conflicts`/`acquire_lock`/`blocking_locks`, and `CompatibilityEdge`; 57 new tests.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.

Known limitation: **nothing reads any of it yet.** `controller/safety.py` still evaluates the older `PolicyCfg` denylist/allowlist/risk-ceiling checks and never imports `mayhem.domain.policy`'s new types. Phase 1 put the rules in the domain; Phase 2 is what wires evaluation to them, so until then this is vocabulary with no call site.
