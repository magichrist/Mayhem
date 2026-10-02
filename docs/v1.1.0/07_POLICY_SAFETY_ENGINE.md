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
- Phase 2 (engine): DONE — `controller/policy_gate.py` evaluates a `PolicyBundle` against plan-derived `PolicyFacts` inside `validate_plan` (one optional `SafetyContext.policy_gate` field; a DENY refuses naming the rule, an ALLOW records a decision); resource locks, hierarchical budget charges, and the fault-pair compatibility graph are consulted at admission, approval requirements are surfaced without being enforced, and `simulate_gate` returns the same decision with provably zero mutation; 36 tests.
- Phase 3: not started
- Phase 4 (safety and evidence integration): DONE — see the ledger below.
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.

## Phase 4 ledger (safety and evidence integration)

**Reconciled the two budget systems.** `reconcile_budgets(hierarchy, quota)` in `controller/policy_gate.py` is the single authoritative answer to "is this plan within budget?", and it is a pure conjunction: the plan is within budget **iff both systems permit it**. Neither system wins, because there is nothing to win — they are not two measurements of one quantity. The hierarchical `BudgetNode` tree answers "has this team/service/experiment spent its window?" over spend **persisted across runs**; the per-target `DamageQuota` answers "has this target been impaired too long inside this plan?" over a ledger `validate_plan` starts fresh on every pass. Summing, minimising, or letting either relax the other would all double-count overlapping damage-seconds at different horizons. On disagreement (both refuse) the **hierarchy reports** — it is the plan-level aggregate and names the scope an operator would change — and the quota's rule id and numbers ride along in the refusal's `inputs` under `also_refused_by`, so a reader is told the other system agreed rather than that it was never consulted. `PolicyGateInputs.damage_quota` is the new (default-absent) field that lets the gate hold both halves at once; the field defaults to `None`, which keeps `check_blast_radius` the sole enforcer of the quota and the no-bundle golden byte-identical.

**The gate re-derives the quota verdict without a topology graph.** `probe_quota` is allowed to be approximate in one direction only, and that direction is the safe one: the dependents closure `check_blast_radius` charges can only widen *which* nodes accrue a step's `duration_s x damage_weight`, never how much each accrues, so every node's authoritative total is at least the gate's. A gate-side **refusal is therefore final**; a gate-side **permit may be overturned** by the authoritative ledger, which still refuses. `tests/unit/test_policy_evidence.py` pins that direction against the real ledger over a quota/plan matrix.

**Broken policy configs refuse rather than raise.** Phase 2's four raising configs — drifted pin, missing parent, inheritance cycle, unmappable budget path — now return a typed refusal named `policy.config_invalid` and classified by `ConfigDefect`, with the primitive's own `reason_code` and message preserved verbatim and a per-defect remediation authored for whoever wrote the bundle. The raising contract is *not* withdrawn from the primitives: `PolicyBundle.verify_pin`, `effective_rules` and `probe_budget` all still raise, and `tests/unit/test_policy_gate.py` now asserts both halves. The conversion is also total — any `InvariantViolationError` from reading the bundle becomes `ConfigDefect.MALFORMED` rather than escaping. Two things still raise, deliberately: `PolicyGateInputs.__post_init__` (naive clock, lock check with no experiment identity, non-positive window), because those are wiring errors in the calling line rather than authoring errors in a bundle, and a non-`InvariantViolationError`, which is a bug rather than a configuration.

**The decision is sealed.** `controller/policy_evidence.py` is new. `verify_decision_binding` re-derives the bundle's digest and refuses a decision whose `policy_digest` disagrees with it, whose bundle id/version differs, whose `rule_digest` is empty (nothing was resolved), or whose bundle has since expired. `build_authorization` additionally refuses a denied result, a config defect, and a result carrying no bundle at all. `seal_policy_decision` then hands a `RunAuthorization` to plan 12's own `seal_run_evidence_at_run_close`, so the run's attested chain gains a `policy_decided` event carrying the decision, rule, policy, and facts digests, the decision digest, and the bundle **version** (`policy_bundle`) — plan 12's machinery reused unchanged, no second event type, digest, manifest, or seal. `PolicyGateResult` gained `bundle`, `now`, `budget` and `config_defect` so a decision can never be separated from the bundle it was reached under. `policy_evidence(result)` produces the whole verdict as one payload with a recomputable `sealed_digest`.

**Policy version changes go to the audit stream.** `record_policy_bundle_change` appends `audit.policy.version_changed` to `infra/audit_stream.py`'s `AuditStream`, with both the previous and current version and content digest, because one alone cannot show that a *change* happened. It refuses a "change" with identical id, version and digest, and every entry goes through `AuditStream.record` — append-only, chain re-verified before extension, the same evidence-boundary secret gate. `KIND_POLICY_VERSION_CHANGED` is declared in `policy_evidence.py` rather than added to `audit_stream.py`'s `KIND_*` table, because that module was not this phase's to edit; it is still the single definition and folding it in is a one-line move (see the limitation below).

**Tests:** `tests/unit/test_policy_evidence.py` (38 tests, new) — the full 7-row budget reconciliation matrix, purity, the neither-overrides case, both-end-to-end budget paths, the one-way quota-probe invariant, the four broken-config refusals each naming its own remediation, four-distinct-remediations, refusal through `validate_plan`, the sealing round trip (chain + manifest verification + exact reload), budget conjunction in the evidence, tamper-detectable `sealed_digest`, four audit-stream cases, and the negative controls (drifted pin refuses instead of raising; expired bundle cannot authorize at the gate *or* the seal; a decision whose digest disagrees with its bundle is refused; a denied decision and an unbound result cannot be sealed; a replay from recorded inputs reproduces the decision and the `sealed_digest` bit-for-bit; a replay after a version bump does **not**). `tests/unit/test_policy_gate.py` extended with 8 gate-surface tests. Suite total for the seven policy/safety/approval/quota files: 310 passing.

**Deviation from Phase 2, deliberate:** `test_unmappable_budget_path_raises_rather_than_skipping_the_charge` asserted that `evaluate_gate` raises. Requirement 2 forbids exactly that, so the test was rewritten to assert the typed refusal *and* that `probe_budget` still raises directly. It is the one pre-existing assertion this phase changed, and the behaviour it was protecting — a charge is never silently skipped — is asserted in both places.

**Still not landed, and Phase 4 does not claim it:**

- **Budget charges are still computed, never posted.** `probe_budget` returns what a commit *would* write and spends nothing. Phase 4 reconciled the two systems' *verdicts*; it did not add the commit path that spends a ledger, because spending is a write and the gate is pure by construction (`MutationSink` is still never written). The plan's "budget charges post to the ledger hierarchically" is **not** done.
- **Nothing calls the evidence seam.** `policy_evidence.py` is a complete, tested seam with no production call site: no store, `SafetyContext`, or CLI path constructs a `RunAuthorization` from a gate result yet. The run-close call site is `cli/lifecycle.py::_write_evidence_after_run`, which plan 12 already documents, and `cli/**` was not this phase's to edit.
- **`KIND_POLICY_VERSION_CHANGED` lives in `policy_evidence.py`**, not in `audit_stream.py`'s closed `KIND_*` table. One definition, greppable, but it is an edit that table's owner should make.
- **The `OPA/Rego` delegate is still not wired** (Phase 2's gap, unchanged).
- **The gate reads bundles but nothing authors, stores, or selects one yet.** There is no policy store, no bundle loader, and no CLI surface: a `SafetyContext` gets a `PolicyGateInputs` only if a caller constructs one, so in production today every run still reaches the gate with `policy_gate=None` and the config-policy path alone decides. Phase 3 owns authoring and the `explain` output.
- **`safety_proof.POLICY_REFUSAL_OWNER` is unchanged and still a heuristic.** `RULE_BUDGET_EXHAUSTED` maps to `DAMAGE_BUDGET`; the quota's own rule ids (`damage_quota.budget`, `damage_quota.per_fault_ceiling`) are *not* in that table, so a quota refusal now arriving from the policy gate rather than from `check_blast_radius` is placed by kind via `DEFAULT_POLICY_REFUSAL_OWNER` = `TARGET_POLICY`. Phase 4 made that path reachable where it was not before, so the heuristic now covers a case it did not. It still lands on a real obligation, but it is placed by kind and not by rule id, and `safety_proof.py` was not this phase's to edit. Recorded as a limitation for whoever owns that table.

