# Plan 01 — Runtime Certification and Live Fault Verification

**Priority:** P0. Gap items 1, 107, 108, 109.

## Objective
Make every Mayhem fault's runtime status honest, machine-verifiable, and continuously regression-tested.

## Problem
Unit coverage of parameter/refusal/compensation logic is not evidence that a fault works on a live runtime. The current release snapshot distinguishes `verified-unit` from `verified-live`; the latter must become a real certification pipeline.

## Builds on (existing code — extend, do not route around)
- `domain/faults.py` `MaturityLevel` (`experimental → verified-unit → verified-live → stable`) stays the only maturity vocabulary.
- `infra/promotion.py` `evaluate_maturity` stays the only function that decides a reported level.
- `domain/catalog.py` `CATALOG` (145 definitions) and `definition_for()` stay the source of fault truth.
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
Update the fault-catalog reliability matrix, the README live-verified count (the honesty test requires a 0-of-N style count, where N is the live catalogue size, until the first promotion lands), and the public compatibility matrix (gap item 109). Tiered rollout to contain certification explosion: required baseline cells per release, expanded nightly matrix, customer-specific cells on demand. Acceptance: `test_no_document_describes_fault_packs_as_signed`-style overclaim scan extended to certification badges — no document may show a certified state the record store did not produce.

## Dependencies
02 (Kubernetes cells), 03 (agent-based cells), 12 (sealed bundles, retention).

## Risks
Certification explosion across runtime/kernel combinations. Solved with the tiered matrix above, never by promoting a fault to raise a coverage number.

## STATUS
- Phase 1 (domain model): DONE — `domain/certification.py` landed `CertificationState`, `MatrixCell`, `EvidenceBundleRef`, `CertificationRecord` and the pure transition functions/predicates behind them; `infra/promotion.py::evaluate_maturity` now takes an optional `records` mapping and caps the reported level at `verified-unit` when no record still certifies the fault on every required engine; 49 tests.
- Phase 2 (store + runner): DONE — `infra/certification_repository.py` persists records behind `M0024_CERTIFICATION_RECORDS` as a per-fault **sequence** (append for a new claim, in-place `store_transition` for ageing/demotion/invalidation; the migration has a down path and the chain is contiguous); `infra/certification_runner.py::certify_fault` provisions, compiles, executes, residue-scans, cross-checks the evidence bundle against digests derived from the run's own facts, and mints or refuses. It imports nothing from `mayhem.controller` and shells out to nothing — every seam is a Protocol, so the unit suite drives the whole pipeline with fakes. 45 tests.
- Phase 3 (surface): DONE — `mayhem certify` is a command group with `run` (certify one fault on one cell) and `matrix` (compatibility and certification queries that execute nothing). It is registered in `cli/command_registry.py` (COMMAND_HELP + COMMAND_SPECS + `register_commands`) and the README command table, which is what `test_release_contract.py` checks; the three other hard-coded root-command inventories (`test_command_inventory.py`, `test_cli_active_surface.py`, `test_cli_exhaustive_matrix.py`) were extended with the one name each. No Justfile recipe was added, so nothing new has to resolve there. 32 tests.
- Phase 4 (safety and evidence integration): DONE — `controller/certification_evidence.py` seals each certification's facts into an `AttestedEvent` chain and manifest using plan 12's own machinery (`seal_events`, `build_manifest`, `verify_chain`, `verify_manifest`, `AttestationRepository.save_chain`/`save_manifest`); there is no second sealer and a test asserts the rows land in plan 12's tables. The chain carries the post-run **residue scan** (`performed` and `findings`, not an inferred "clean"), the **recovery probe's numbers**, the content digests, and one `certification.demoted` event per regression — so "the demotion event in evidence" is now a hash-linked member rather than a `demotion` digest sitting beside a hash. `infra/certification_runner.py` gained one optional seam, `EvidenceSealer`, and a seal that raises, returns an unverified chain, or names a different bundle becomes `RefusalClass.EVIDENCE_UNSEALABLE` — a refusal, not a certification. `sealed_certification_gate` re-verifies every live claim and hands `evaluate_maturity` an unverifiable one in the `failed` state, so a record whose bundle does not verify grants no level while `evaluate_maturity` stays the only function that decides one. `CertificationEvidenceHeldError` refuses a retention deletion while a live claim cites the evidence, with `demote_dependents=True` as the deliberate second path, and `reconcile_certification_evidence` demotes claims whose evidence vanished outside retention. 26 tests in `tests/unit/test_certification_evidence.py`.
- Phase 5: not started
- Phase 6: not started

Overall: 4 of 6 phases complete.

### Nothing is certified yet, and the README count must stay 0-of-N

**No live cell has been certified.** Every part of this work is the *machinery* for a claim; not one claim has been made. The first `verified-live` promotion still requires a real runtime — a real docker or podman, a real disposable container, a real drill — and nothing in this phase produces one:

- No code path seeds a certification record. `certify matrix` on a fresh database reports `certified_faults: 0` and caps every fault at `verified-unit`; `tests/unit/test_cli_certify.py` asserts exactly that, deriving the denominator from `len(CATALOG)` rather than pinning it.
- The live cell path — `cli/certify.py`'s `EngineCell`, `RunEvidenceCapturer`, and the in-container residue probes — is implemented and structurally pinned (it is bound to `RunEngine.execute` and to nothing else) but is **unexercised by CI**, because it needs a container engine. It is written to be read and reviewed, not to be assumed correct.
- **Phase 4 did not change that count either.** Sealing a certification's evidence is necessary for a claim to *count*, not sufficient: a sealed chain still needs a cell that actually ran, a bundle that matched the run, and both required engines. No cell has run, so nothing is sealed either, and the gate grants nothing.
- **Kubernetes cells are not implemented.** Plan 01 defers them to plan 02, and `mayhem certify run --engine kubernetes` is refused with a pointer rather than falling back to a container lane.
- The README's live-verified count must remain `0 of N` — N being the live catalogue size — until a real cell is certified. `tests/unit/test_readme_honesty.py` enforces the zero count and the `0-of-N` form, reading N from `len(CATALOG)`; do not soften it to make a number look better.

### How the certification gate is armed, and where it is still optional

The gate is `evaluate_maturity(..., records=...)`. `records=None` preserves 1.0.0 behaviour exactly, which is correct for callers that do not use certification — but it is a silent way to lose the gate, so the surface that *can* mint a claim does not use it:

- **Non-optional on the certification surface.** `mayhem certify matrix` always calls `evaluate_maturity(..., records=repository.certification_gate(now=...))`. The store returns an **empty mapping** when it has no rows, and an empty mapping is an assertion that nothing is certified, which caps the reported level. There is no flag, mode, or code path in `cli/certify.py` that reports maturity without it. The payload says so (`"certification_gate": "armed: …"`), and `test_a_stored_record_changes_the_answer` proves the arming is real by planting records and watching the answer change.
- **Still optional, precisely, at one call site**: `controller/catalog_report.py::maturity_decision` (and everything downstream of it — `capability_status`, the capability dashboard, `discover capabilities`, `explain catalog fault`) still passes no `records`. It is the *only* maturity-reporting call site outside the certification surface. It stayed optional because it is a **read-time report path with no store handle**: it is called for `mayhem --help`-adjacent catalog reads, from `discover capabilities`, and from tests that construct it directly, several of which have no database at all. Arming it there is a one-line change — add `records: Mapping[str, Sequence[CertificationRecord]] | None = None` to `maturity_decision` and pass it to `evaluate_maturity` — but the *plumbing* is Phase 4/5's: the CLI seam has to open the database and hand the repository in, and today it would arm the gate with `{}` on paths that have no store to consult. That is the correct conservative answer (it can only lower a reported level, never raise one), so arming it early is safe; it is deferred so this phase does not edit files outside its ownership, and so the plumbing decision is made once.
- The gate is deliberately *not* in `CUMULATIVE_CRITERIA`: the ladder is the run-evidence contract, and adding to it would silently redefine the rungs for callers that do not use certification. The gate caps the ladder's result instead.
- **Phase 4 added the stricter gate beside it.** `sealed_certification_gate` has the same shape and the same arming point, and additionally re-verifies every live claim's sealed chain, handing on an unverifiable one in the `failed` state. It is a drop-in for `certification_gate`, so switching the certification surface over is one argument. It is *not* switched over, because `cli/certify.py` is outside Phase 4's ownership — and since no chain is written today, arming it now would change nothing except make the report honest about a gate that has nothing to verify yet. Same deferral, same reason.

### Re-certification after expiry is a new record, not a transition

`domain/certification.py` already made a lapsed claim terminal, and the store matches it: the table is keyed `(fault_id, sequence)` with a dense, 1-based sequence per fault, `append` is how a claim is created, and `store_transition` refuses to move a record's identity (a different fault, sequence, or cell) — so ageing, demotion, and invalidation are in-place while re-certification appends. `certify_fault` never promotes by transition: it builds a fresh `pending` record and hands it to `certify`, or hands it back un-certified with the reason. `test_store_is_a_sequence_per_fault_not_a_mutable_row` pins both halves.

### Phase 4 built the sealed-evidence chain; the CLI does not call it yet

Stated plainly because it is the one thing a reader of "Phase 4: DONE" could otherwise get wrong. `controller/certification_evidence.py::CertificationEvidenceStore` implements the runner's `EvidenceSealer`, and `certify_fault` seals whenever it is handed a sealer — but **no call site passes one**. `cli/certify.py` is outside Phase 4's ownership, so in a default deployment no certification chain is written at all. The consequence is the conservative one and is pinned by a test: `sealed_certification_gate` then grants nothing, `certification matrix` stays capped at `verified-unit`, and the README's live-verified count stays `0 of N`, N being the live catalogue size. Wiring the sealer into `cli/certify.py` is one line at the `certify_fault` call site and belongs with the Phase 5 plumbing; it is listed as still-open work rather than quietly counted as done.

Two smaller things Phase 4 deliberately did **not** do, for the same reason:

- `evidence_sealer` is **optional**, and omitting it still certifies. That preserves the pre-Phase-4 surface unchanged, which means a caller can still produce a `certified` row with nothing attested. What closes that is the gate, not the refusal: no chain means no verification, so the claim does not reach a reported level. `test_omitting_the_sealer_certifies_but_leaves_no_chain_behind` exists so a future lane cannot turn the weaker pipeline into a stronger claim silently.
- The **live** recovery probe is unchanged. `cli/certify.py`'s `EngineCell.recovery_evidence` still reports a normalised lease-state signal rather than a numeric baseline; the numeric axis lives in the promotion engine's `Observation` records. The chain faithfully attests whatever the cell reported, and the irreversible-fault branch requires the compensation claim instead of a probe, so neither is over-read.

### Retention versus certification: the hazard, and how it is resolved

A certification record survives its run by design, and so does the evidence the run produced. That creates a real hazard: **retention could delete bytes a live certification still cites, and the claim would go on reporting a level with nothing behind it** — the exact failure the whole plan exists to prevent. It is resolved with both remedies, and the default is the conservative one:

- **Refuse by default.** `expire_certification_evidence` checks `certification_evidence_dependents` first and raises `CertificationEvidenceHeldError` (a `RetentionRefusedError` subclass, so an existing retention caller catches it for free) naming every dependent claim and offering the two remedies. Nothing is written. Unconditional refusal was rejected because a fault that had *ever* been certified would then never have its evidence deleted, and the retention ladder would quietly stop working for the faults most worth keeping records of.
- **Demote-first on request.** `demote_dependents=True` withdraws each dependent claim through `mark_failed` and `store_transition` **before** delegating to `RetentionEngine.expire`, so there is no window in which a claim is demoted and its evidence is still intact, or the reverse. Automatic demotion was rejected as the default because it would let whoever runs a retention sweep withdraw a maturity claim by touching only the evidence — the certification surface would report less than it actually knows, with no transition anyone asked for.
- **Sweep the unsanctioned path.** The guard stops the deletion it can see. `reconcile_certification_evidence` covers evidence removed without going through retention at all (a hand-edited attestation row, a restored snapshot, a cleaned bundle directory), so a claim can never outlive what it is checked against.
- **A lapsed claim holds nothing hostage.** `certification_evidence_dependents` ages with the domain's own `expire_by_time`, so an already-stale claim does not block the ladder. `test_a_lapsed_claim_does_not_hold_its_evidence_hostage` pins this; without it the guard would be unusable.

Every other retention rule is untouched — dual control, the legal hold, the external copy, the tombstone. Phase 4 adds one gate in front of `RetentionEngine.expire` and weakens none of them.

### What Phase 5 still owns

The runner and the chain now refuse on: a reversible fault with no recovery evidence, recovery that drifted past tolerance, dirty leases, a residue scan that was not performed, residue that was found, a missing bundle, a bundle missing a required digest, a bundle whose digests do not match the run's, an evidence bundle that cannot be sealed, and a sealed chain that no longer verifies. What is left is enforcement rather than machinery: the nightly and release certification jobs, CI blocking on a previously-certified fault going red, the expiry/invalidation sweep being scheduled (`CertificationRepository.expire_all` exists; `reconcile_certification_evidence` exists; nothing calls them on a clock yet), and wiring the sealer plus `sealed_certification_gate` into `cli/certify.py`.

