# Plan 01 — Runtime Certification and Live Fault Verification

**Priority:** P0. Gap items 1, 107, 108, 109.

## Objective
Make every Mayhem fault's runtime status honest, machine-verifiable, and continuously regression-tested.

## Problem
Unit coverage of parameter/refusal/compensation logic is not evidence that a fault works on a live runtime. The current release snapshot distinguishes `verified-unit` from `verified-live`; the latter must become a real certification pipeline.

## Builds on (existing code — extend, do not route around)
- `domain/faults.py` `MaturityLevel` (`experimental → verified-unit → verified-live → stable`) stays the only maturity vocabulary.
- `infra/promotion.py` `evaluate_maturity` stays the only function that decides a reported level.
- `domain/catalog.py` `CATALOG` (141 definitions) and `definition_for()` stay the source of fault truth.
- `controller/janitor.py` sweep and the lease watchdog stay the residue-safety net; certification adds pre/post residue scans, not a parallel mechanism.

## Non-goals
No new maturity enum, no `set_maturity` flag, no `record()` shortcut. A `verified-live` claim without a live execution artifact must remain unrepresentable, exactly as the v1.0.0 harness requires.

## Phase 1 — Domain model: CertificationRecord overlay
Add `domain/certification.py`: `CertificationRecord` (fault id, matrix cell, evidence-bundle refs, injector version, expiry, outcome) plus `CertificationState` (`pending → certified → expiring → stale → failed`, with `incompatible` as a terminal side state). `evaluate_maturity` reads the record store; delete a fault's evidence and its reported level drops with it. Acceptance: pure-domain tests pin every transition, including expiry demotion.

## Phase 2 — Engine: disposable environment runners
Build the certification runner: provision a disposable environment (Docker, then Podman, then Kubernetes per 02), compile the drill, execute through the normal `RunEngine.execute` path (never a side channel), capture the evidence bundle. Matrix dimensions: engine, engine version, OS distribution, kernel version, amd64/arm64, root/rootless, required capabilities. Acceptance: the same spec plus seed reproduces an equivalent verdict class on the same cell.

## Phase 3 — Surface: certify command and matrix queries
Add `mayhem certify` (certify one fault on one cell, show a fault's matrix) reusing the `command_registry.py` single-inventory contract (README table, docs, and Justfile updated together or the release contract fails). Compatibility queries answer without executing: "can `net.latency` run on podman/rootless/kernel 6.11?" Acceptance: every new command resolves against the live Click tree in tests.

## Phase 4 — Safety and evidence integration
Recovery verification is mandatory for reversible faults (undo ran, probe confirms baseline within tolerance); residue scan after every test (no tc rules, iptables entries, marker processes, files, cgroup overrides remain); negative verification proves catalog-only faults still refuse on the live cell. Certification evidence is a normal sealed bundle, referenced — not embedded — by the record. Acceptance: a fault whose recovery regresses is demoted automatically with the demotion event in evidence.

## Phase 5 — Tests, regression guards, negative controls
Nightly and release certification jobs; a previously certified fault going red fails CI (regression blocking); certification expiry policy (time-based plus invalidation on engine/kernel/tool change — gap item 107 drift detection). Negative controls: a test asserting an uncertified fault cannot display a certified badge, and a test asserting fabricated evidence is rejected at record construction. Acceptance: full suite plus the new jobs green; the `nightly` marker gap is closed by attaching real tests to it.

## Phase 6 — Docs, honesty gates, rollout
Update the fault-catalog reliability matrix, the README live-verified count (the honesty test requires a 0-of-141 style count until the first promotion lands), and the public compatibility matrix (gap item 109). Tiered rollout to contain certification explosion: required baseline cells per release, expanded nightly matrix, customer-specific cells on demand. Acceptance: `test_no_document_describes_fault_packs_as_signed`-style overclaim scan extended to certification badges — no document may show a certified state the record store did not produce.

## Dependencies
02 (Kubernetes cells), 03 (agent-based cells), 12 (sealed bundles, retention).

## Risks
Certification explosion across runtime/kernel combinations. Solved with the tiered matrix above, never by promoting a fault to raise a coverage number.

## STATUS
- Phase 1 (domain model): DONE — `domain/certification.py` landed `CertificationState`, `MatrixCell`, `EvidenceBundleRef`, `CertificationRecord` and the pure transition functions/predicates behind them; `infra/promotion.py::evaluate_maturity` now takes an optional `records` mapping and caps the reported level at `verified-unit` when no record still certifies the fault on every required engine; 49 tests.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.

Known limitation: the gate is **opt-in by argument**. `evaluate_maturity(..., records=None)` — the default — preserves 1.0.0 behaviour exactly, so a caller that never supplies a record store is never gated. The gate is deliberately *not* in `CUMULATIVE_CRITERIA`: the ladder is the run-evidence contract, and adding to it would silently redefine the rungs for callers that do not use certification. Any call site that wants the cap has to pass `records` (an empty mapping is enough to arm it).
