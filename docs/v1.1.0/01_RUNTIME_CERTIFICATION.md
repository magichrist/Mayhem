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
- Phase 2 (store + runner): DONE — `infra/certification_repository.py` persists records behind `M0024_CERTIFICATION_RECORDS` as a per-fault **sequence** (append for a new claim, in-place `store_transition` for ageing/demotion/invalidation; the migration has a down path and the chain is contiguous); `infra/certification_runner.py::certify_fault` provisions, compiles, executes, residue-scans, cross-checks the evidence bundle against digests derived from the run's own facts, and mints or refuses. It imports nothing from `mayhem.controller` and shells out to nothing — every seam is a Protocol, so the unit suite drives the whole pipeline with fakes. 45 tests.
- Phase 3 (surface): DONE — `mayhem certify` is a command group with `run` (certify one fault on one cell) and `matrix` (compatibility and certification queries that execute nothing). It is registered in `cli/command_registry.py` (COMMAND_HELP + COMMAND_SPECS + `register_commands`) and the README command table, which is what `test_release_contract.py` checks; the three other hard-coded root-command inventories (`test_command_inventory.py`, `test_cli_active_surface.py`, `test_cli_exhaustive_matrix.py`) were extended with the one name each. No Justfile recipe was added, so nothing new has to resolve there. 32 tests.
- Phase 4: not started (the parts Phase 2 needed — recovery verification, the residue-scan obligation, and negative verification of catalog-only refusals — landed early because the runner cannot certify without them; the *enforcement* in CI, the regression job, and the sealed-bundle integration are Phase 4/5 work)
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.

### Nothing is certified yet, and the README count must stay 0-of-141

**No live cell has been certified.** Every part of this work is the *machinery* for a claim; not one claim has been made. The first `verified-live` promotion still requires a real runtime — a real docker or podman, a real disposable container, a real drill — and nothing in this phase produces one:

- No code path seeds a certification record. `certify matrix` on a fresh database reports `certified_faults: 0` and caps every fault at `verified-unit`; `tests/unit/test_cli_certify.py` asserts exactly that, including the 0-of-141 denominator.
- The live cell path — `cli/certify.py`'s `EngineCell`, `RunEvidenceCapturer`, and the in-container residue probes — is implemented and structurally pinned (it is bound to `RunEngine.execute` and to nothing else) but is **unexercised by CI**, because it needs a container engine. It is written to be read and reviewed, not to be assumed correct.
- **Kubernetes cells are not implemented.** Plan 01 defers them to plan 02, and `mayhem certify run --engine kubernetes` is refused with a pointer rather than falling back to a container lane.
- The README's live-verified count must remain `0 of 141` until a real cell is certified. `tests/unit/test_readme_honesty.py` enforces the zero count and the `0-of-141` form; do not soften it to make a number look better.

### How the certification gate is armed, and where it is still optional

The gate is `evaluate_maturity(..., records=...)`. `records=None` preserves 1.0.0 behaviour exactly, which is correct for callers that do not use certification — but it is a silent way to lose the gate, so the surface that *can* mint a claim does not use it:

- **Non-optional on the certification surface.** `mayhem certify matrix` always calls `evaluate_maturity(..., records=repository.certification_gate(now=...))`. The store returns an **empty mapping** when it has no rows, and an empty mapping is an assertion that nothing is certified, which caps the reported level. There is no flag, mode, or code path in `cli/certify.py` that reports maturity without it. The payload says so (`"certification_gate": "armed: …"`), and `test_a_stored_record_changes_the_answer` proves the arming is real by planting records and watching the answer change.
- **Still optional, precisely, at one call site**: `controller/catalog_report.py::maturity_decision` (and everything downstream of it — `capability_status`, the capability dashboard, `discover capabilities`, `explain catalog fault`) still passes no `records`. It is the *only* maturity-reporting call site outside the certification surface. It stayed optional because it is a **read-time report path with no store handle**: it is called for `mayhem --help`-adjacent catalog reads, from `discover capabilities`, and from tests that construct it directly, several of which have no database at all. Arming it there is a one-line change — add `records: Mapping[str, Sequence[CertificationRecord]] | None = None` to `maturity_decision` and pass it to `evaluate_maturity` — but the *plumbing* is Phase 4/5's: the CLI seam has to open the database and hand the repository in, and today it would arm the gate with `{}` on paths that have no store to consult. That is the correct conservative answer (it can only lower a reported level, never raise one), so arming it early is safe; it is deferred so this phase does not edit files outside its ownership, and so the plumbing decision is made once.
- The gate is deliberately *not* in `CUMULATIVE_CRITERIA`: the ladder is the run-evidence contract, and adding to it would silently redefine the rungs for callers that do not use certification. The gate caps the ladder's result instead.

### Re-certification after expiry is a new record, not a transition

`domain/certification.py` already made a lapsed claim terminal, and the store matches it: the table is keyed `(fault_id, sequence)` with a dense, 1-based sequence per fault, `append` is how a claim is created, and `store_transition` refuses to move a record's identity (a different fault, sequence, or cell) — so ageing, demotion, and invalidation are in-place while re-certification appends. `certify_fault` never promotes by transition: it builds a fresh `pending` record and hands it to `certify`, or hands it back un-certified with the reason. `test_store_is_a_sequence_per_fault_not_a_mutable_row` pins both halves.

### What Phase 4 should build on

The runner already refuses on: a reversible fault with no recovery evidence, recovery that drifted past tolerance, dirty leases, a residue scan that was not performed, residue that was found, a missing bundle, a bundle missing a required digest, and a bundle whose digests do not equal the digests derived from the run. A re-run that regresses demotes the existing claim in place and records the demotion event both in the stored record's reason and as a `demotion` digest inside the sealed bundle the refused attempt references. Phase 4 therefore has the safety properties it needs; what it still owns is the **live** recovery probe (`EngineCell.recovery_evidence` currently reports a normalised lease-state signal, not a numeric baseline — the numeric axis lives in the promotion engine's `Observation` records), the CI/nightly enforcement of the negative controls, and the sealed-bundle retention integration from plan 12.

