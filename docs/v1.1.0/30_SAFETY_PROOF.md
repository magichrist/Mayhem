# Plan 30 — Formal Experiment Safety Proof

**Priority:** P0. Gap items 27, 65.

## Objective
Turn the frozen `ExecutionPlan` into a checkable safety case: before anything mutates, produce the artifact that proves why this plan is allowed — and after the run, prove nothing was left behind (residue as proof obligation, gap 65).

## Builds on
- Today the proof's inputs are scattered: `validate_plan` (G1+G2), `pre_exec_assertion` (G3 drift), `DamageLedger` plus `DamageQuota`, `forbidden_fault_pairs`, compensation templates, execution intent, policy decisions (07), impact predictions (14), stop conditions (11). This plan defines no new gate; it compiles the existing gates' outputs into one verifiable object.
- `plan_diff.py` canonical hashing gives the proof its identity: proof-of-plan-X is meaningless for plan-Y, and the type system says so.

## Proof contents
Targets considered, targets excluded (with reasons), faults
considered, faults rejected (with reasons), capabilities required vs.
present, blast-radius calculation, damage calculation, forbidden
combinations checked, approval requirements, rollback plan, stop
conditions, verification probes, residue-scan obligations.

## Output shape
```text
SAFETY PROOF: PASS

pass  max concurrent faults
pass  max duration
pass  damage budget
pass  target policy
pass  capability requirements
pass  compensation
pass  recovery path
pass  stop conditions
pass  required approvals
```

Every line cites the gate output and digest behind it. A PASS with an
uncited line is malformed, not passing.

## Phase 1 — Domain model: proof as a type
Add `domain/safety_proof.py`: `SafetyProof` (plan digest, per-obligation results with cited gate digests, overall verdict), `Obligation` (name, status, evidence ref, evaluated-at timestamp), `ResidueObligation` (per-fault expected-clean predicates for gap 65: no tc rules, no iptables entries, no marker processes, no files, no cgroup overrides, no leases held). Pure types; proof validity as a pure predicate (all obligations pass plus digests match the frozen plan). Acceptance: validity tests including digest-mismatch and missing-obligation cases.

## Phase 2 — Engine: proof compiler over the real gates
Compiler runs the actual admission, blast, quota, capability, compensation, policy, prediction, and approval checks against the frozen plan and assembles their outputs — the preview that IS the gate's shadow (14's read-only twin, generalized). Residue obligations generated per fault from compensation metadata plus the 01 residue-scan definitions. Acceptance: proof-vs-gate agreement tests — the compiler may only ever refuse equally or more, never less, than executing `validate_plan` would.

## Phase 3 — Surface: prove command and proof views
`mayhem plan prove` rendering the PASS/FAIL artifact with per-line citations, plus proof views in UI (08) and PR checks (16). A stale proof (plan changed since) renders as VOID with the diff that voided it, never as an old PASS. Acceptance: golden tests on the rendered artifact; void-on-change tests via canonical-hash mutation.

## Phase 4 — Safety and evidence integration
Proof sealed with the plan pre-execution; post-run, the residue scan discharges the residue obligations line by line (found residue voids the corresponding line and dirties the run — the run cannot close clean with an open obligation); approvals bind to the proof digest, closing the 09 loop. Acceptance: end-to-end run whose sealed proof, residue discharge, and verdict form one verifiable chain.

## Phase 5 — Tests, regression guards, negative controls
Compiler tests per obligation class, agreement tests with each underlying gate, residue-discharge tests (clean and dirty), void-on-change tests, citation-completeness tests (every PASS line traces to a gate output). Negative controls: a hand-written PASS without gate outputs fails validation; a proof for a superseded plan digest is VOID, never PASS. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Proof-reading guide (what each line means and where its citation lives), residue-obligation catalogue per fault family, CI integration for proof-in-PR. Rollout: compiler plus CLI first, PR integration second, residue discharge third, approval binding last. Acceptance: no doc calls the proof a guarantee — it proves the plan satisfied every check Mayhem knows how to perform, and the docs state that boundary explicitly.

## Dependencies
07 (policy evaluation), 09 (approval binding), 11 (stop-condition obligations), 12 (sealing), 14 (prediction inputs), 16 (PR surface).

## STATUS — planning only, 0%
