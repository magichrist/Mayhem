# Plan 14 — Topology Intelligence and Blast-Radius Prediction

**Priority:** P1. Gap items 19, 26, 54, 62, 72.

## Objective
Use discovered dependencies to predict and constrain experiment impact before execution — folding in predictive blast simulation (26), the no-mutation preview (62/72), and the resilience graph substrate (54).

## Builds on
- `topology/service.py` merge plus drift reporting and `domain/topology.py` graph types stay the discovery core; new edge kinds extend them.
- The v1.0.0 preflight (real-gate evaluation, all five limits rendered) stays the enforcement point; prediction here is its read-only twin — same math, no mutation, never a parallel gate.
- Existing blast accounting (`dependents_closure`, damage ledger) is what predictions are computed with, so preview and gate cannot disagree.

## Graph
Nodes: service, workload, pod, node, database, queue, dependency, SLO,
experiment, incident. Edges: depends_on, calls, stores_in,
publishes_to, affects, tested_by, failed_under. Experiments and
incidents as nodes (gap 54) make coverage and history graph queries,
not report joins.

## Prediction
Before running a fault estimate: targets affected, dependency fan-out,
replica loss, expected capacity change, policy violations, likely SLO
impact, cloud cost.

## Controls
Blast-radius ceiling, maximum dependency depth, maximum
customer-facing services, maximum percentage, protected service list.

## Phase 1 — Domain model: graph and prediction types
Extend `domain/topology.py` with new node/edge kinds; add `domain/prediction.py`: `ImpactPrediction` (affected set, fan-out, capacity delta, violated rules with observed values, cost estimate) as pure computation over a frozen graph plus a frozen plan. Pure functions; prediction determinism tests (same graph plus plan yields same prediction). Acceptance: prediction-vs-gate agreement tests — the preview may be conservative, never permissive, relative to `validate_plan`.

## Phase 2 — Engine: prediction service and no-mutation simulate
Prediction service evaluates the frozen plan against live topology without touching targets (`mayhem simulate` semantics for gap 72: target selection, blast radius, expected changes, capabilities, policy result, cost estimate, expected evidence — zero mutation by construction, enforced by running with the mutation backend detached). Acceptance: simulate-then-run agreement tests; a test asserting simulate performed no mutation (mock mutation backend, zero calls).

## Phase 3 — Surface: risk preview and dependency views
Every plan display carries the resolvable target set plus the risk preview (inside/outside policy with reasons); topology views show services with blast radius, health, coverage, and incident history per node. Acceptance: preview output stored with the plan and rendered identically in CLI and UI (08).

## Phase 4 — Safety and evidence integration
Predictions sealed with the plan (so post-run analysis can score prediction accuracy); protected-service and depth/percentage ceilings enforced in admission (07 dimensions); fan-out facts feed 05 dependency-fault scoping. Acceptance: a run whose actual blast exceeded prediction opens a finding, not a silent pass.

## Phase 5 — Tests, regression guards, negative controls
Prediction-accuracy tests on fixture graphs, agreement tests with the real gate, simulate-purity tests, protected-list refusal tests. Negative controls: prediction on a drifted graph is marked stale and refused for approval use; a preview is never accepted as a preflight. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Prediction interpretation guide (confidence bounds stated, never hidden), simulate-vs-preflight distinction documented until it hurts. Rollout: fan-out display first, prediction second, simulate third. Acceptance: no doc calls a prediction a guarantee.

## Dependencies
05 (dependency scoping), 07 (ceiling enforcement), 08 (views), 30 (preview feeds the proof).

## STATUS
- Phase 1 (domain model): DONE — `domain/prediction.py` adds `ImpactPrediction` (affected set, dependency fan-out with depth, replica-loss delta, expected capacity change, violated rules with observed values, cost estimate) as a pure deterministic function over a frozen graph plus frozen plan, with `is_never_permissive` pinning prediction-vs-gate agreement.
- Phase 2 (engine): DONE — `controller/prediction_service.py` assembles the prediction from live topology plus configuration and returns it beside the real gate's own refusal set, enforcing prediction-vs-gate agreement in production (a calmer preview raises rather than returns); `simulate_plan` runs the mutation backend detached and publishes the observed sink length, so a simulate is provably inert while still reaching a verdict; the four §Controls dimensions are reported as admission dimensions with the Phase 4 wiring named in `PENDING_ADMISSION_WIRING`; an absent price table yields an explicit `unpriced` disclosure with the measured affected-node-seconds, never a dollar figure.
- Phase 3: not started
- Phase 4 (safety and evidence integration): DONE, with one named debt carried forward.
  - **The five §Controls ceilings are enforced by the real gate.** `SafetyContext.blast_ceilings` is a new optional field defaulting to `None`; `controller/safety.py::_check_blast_ceilings` refuses `blast_radius.protected_node`, `…max_dependency_depth`, `…max_customer_facing_services`, `…max_affected_pct` and `…max_affected_nodes` from `check_blast_radius`, in the same order `domain/prediction.py` predicts them, on the same step — so the gate's refusal is inside the preview's flagged set by construction rather than by coincidence. With no ceiling configured the pass is byte-identical to a captured golden (`GOLDEN_NO_CEILINGS`, asserted in `tests/unit/test_prediction_evidence.py`). Measurements are borrowed from `domain.prediction` (`dependency_fan_out`, `customer_facing_node_ids`) rather than re-derived, because a second implementation could disagree with the preview about a depth or a front door.
  - **`PENDING_ADMISSION_WIRING` is now empty, and that emptiness is the assertion.** `is_enforced_by_gate` still derives `CeilingVerdict.enforced_by_gate` from the table, so deleting the five rows flipped every record at once. Phase 2's tripwire (`test_no_pending_ceiling_rule_id_is_one_the_real_gate_can_emit`) was *designed to fire* on this phase and did; it was retired by inversion rather than deleted, since the surviving form of the check — every ceiling reported as enforced is one the gate actually raises — is what keeps the derivation from degenerating into a bare default now the table is empty.
  - **The agreement split is now an explicit, named state.** `AgreementState` (`AGREES` / `UNMODELLED` / `DISAGREES`) replaces Phase 2's emergent consequence. `UNMODELLED` means "the gate found something this preview cannot speak to": `agrees` stays true because nothing modelled was missed, and the report is unusable for approval — now a tested property of the state (`usable_for_approval`) rather than an inference from a non-empty set in a function three call sites away. `DISAGREES` still raises. `GateAgreement.__post_init__` refuses a `state` contradicting the record's own booleans, so the record cannot lie about itself.
  - **Predictions are sealed with the plan, and an uncited one cannot be.** `seal_prediction` commits a prediction into plan 12's existing hash chain and M0023 tables under its own `:prediction` scope (so it cannot overwrite the run-close or `:proof` chain), reusing the same domain functions and unsigned-manifest honesty gate as `controller/proof_sealing.py`. `verify_sealed_prediction` re-verifies chain, then manifest, then the payload's own digest — a chain proves the bytes were not edited, never that they are the right bytes. `evidence_ref` is required and non-blank at both seal time and read-back: a prediction citing no evidence cannot back a decision.
  - **A run whose actual blast exceeded its prediction opens a finding.** `score_prediction_accuracy` reads "exceeded" as a *set* question rather than a count, names the affected ids the forecast did not contain, and records the over-estimated direction without opening a finding against the run.
  - **DEBT CARRIED FORWARD (does not block Phase 4):** `safety_proof.OBLIGATION_FOR_RULE` has no owning line for the five ceiling rule ids, and this lane could not edit `controller/safety_proof.py` (concurrent lanes). Consequence, measured and asserted in `tests/unit/test_prediction_evidence.py`: a run refused on a ceiling compiles to a `VOID` proof naming an unplaceable rule. Fail-closed, not a silent pass, but weaker than the `FAIL` `target_policy` could report. The five rows needed (all to `ObligationName.TARGET_POLICY`), plus adding the five ids to `safety_proof.GATE_RULE_IDS` so a prediction's ceiling findings are attributable, are specified in the comment block above `CEILING_RULES_AWAITING_AN_OBLIGATION` in that suite. Until then `test_proof_compiler.py::test_every_rule_the_gates_can_raise_has_an_owning_proof_line` fails naming all five — left standing deliberately, because the five ids are spelled as inline literals in `_deny_decision` calls precisely so the completeness scanner can see them.
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.
