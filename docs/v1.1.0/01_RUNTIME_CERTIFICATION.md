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
- Phase 4 (safety and evidence integration): DONE — `controller/certification_evidence.py` seals each certification's facts into an `AttestedEvent` chain and manifest using plan 12's own machinery (`seal_events`, `build_manifest`, `verify_chain`, `verify_manifest`, `AttestationRepository.save_chain`/`save_manifest`); there is no second sealer and a test asserts the rows land in plan 12's tables. The chain carries the post-run **residue scan** (`performed` and `findings`, not an inferred "clean"), the **recovery probe's numbers**, the content digests, and one `certification.demoted` event per regression — so "the demotion event in evidence" is now a hash-linked member rather than a `demotion` digest sitting beside a hash. `infra/certification_runner.py` gained one optional seam, `EvidenceSealer`, and a seal that raises, returns an unverified chain, or names a different bundle becomes `RefusalClass.EVIDENCE_UNSEALABLE` — a refusal, not a certification. `sealed_certification_gate` re-verifies every live claim and hands `evaluate_maturity` an unverifiable one in the `failed` state, so a record whose bundle does not verify grants no level while `evaluate_maturity` stays the only function that decides one. `CertificationEvidenceHeldError` refuses a retention deletion while a live claim cites the evidence, with `demote_dependents=True` as the deliberate second path, and `reconcile_certification_evidence` demotes claims whose evidence vanished outside retention. 26 tests in `tests/unit/test_certification_evidence.py`. Phase 4 left the sealer unwired on purpose, as Phase 5 plumbing; that is now done (see below).
- Phase 5 (tests, regression guards, negative controls): DONE — the three things the phase puts on a clock rather than in a unit suite are now on a clock. **The marker gap was the first one.** The `nightly` marker was registered in `pyproject.toml` and `.github/workflows/conformance.yml` ran `pytest tests/unit -m nightly -q`, but **no test in the repository carried the marker**, so that job selected nothing and exited green — a CI line standing for a certification sweep that had never executed. `infra/certification_sweep.py` had **zero** references from any test. Both are closed by `tests/unit/test_certification_nightly.py` (10): eight nightly-marked tests over a real migrated SQLite store, because the sweep's whole value is that every write goes through `store_transition` and a fake would not notice if it stopped — the clock half, the drift half (gap item 107), the honest-absence half (`checked_against_a_cell is False` when no cell was supplied, because "nothing moved" and "nothing was looked at" are different findings), the regression-blocking half, and the distinction that makes a matrix mean something (a verdict from **another** cell neither passes nor fails the stored claim and lands in `unreached`). Two meta-tests close the vacuity permanently: the marker must be **registered** (an unregistered marker never errors under `--strict-markers`, it is simply never selected) and all eight job tests must still carry it. Verified: `pytest tests/unit -m nightly` selects **8 tests** where it previously selected 0. **The schedule landed.** `conformance.yml` now has `schedule: - cron: "17 3 * * *"` alongside `workflow_dispatch`, and the `if: github.event_name == 'workflow_dispatch'` guard that would have kept the cron from running anything was removed — adding a schedule without removing it would have produced a green trigger that executes nothing, which is the failure this whole phase exists to end. 03:17 rather than 03:00 because the top of the hour is where every other scheduled workflow queues and this one provisions containers. **CI blocking is wired to a pipeline.** `mayhem certify regress` (`cli/certify.py`) exits non-zero when `RegressionReport.blocked` is true, so a regression fails a build instead of waiting to be noticed; `tests/unit/test_certify_regress_gate.py` (22) drives that exit code through the real CLI and asserts the schedule, the removed guard, and the release job's step. **The execution path was extracted, not copied**: `_execute_certification` is the single body `certify run` and the gate's `--rerun` both call, because a re-run through a second pipeline would say nothing about the claim that pipeline minted. **Four refusals are load-bearing and each is asserted from both sides** — live claims with neither `--rerun` nor `--verdicts` is a usage error (comparing stored claims against nothing passes everything); a `--fault-id` filter matching no live claim is a usage error (a typo must not silence the gate); a verdict naming another cell is `unreached` with `nothing_tested` set, never a pass; an unrecognised verdicts file is refused rather than parsed. **Withdrawal is opt-in** (`--withdraw`) and happens *before* the report is emitted, through `mark_failed`, so a report that changes what it reports on has to be asked to and a claim cannot outlive a gate that named it. **The expiry sweep is on the clock too**: the nightly job runs `certify matrix --all --sweep` before the gate, which is the only place that should opt into a mutation a read is not allowed to make, and doing it after the gate would compare against claims the clock had already lapsed.

- **Surface plumbing, landed in the earlier pass and unchanged:** `cli/certify.py` passes the `EvidenceSealer` and reads through `sealed_certification_gate`; `catalog_report`'s reporting path is armable end to end and every maturity payload states its gate state.
- Phase 6 (docs and rollout): DONE — four sections appended below. **Fault-catalog reliability matrix**: its numbers were already correct and are unchanged; what this phase added is the rule that keeps them correct. **Public compatibility matrix** (gap 109): the nine frozen fields of a `MatrixCell`, why a record stores its cell in its identity rather than pointing at one, and the three answers the matrix can give — compatible, certified, and **unreached**, which is the one a naive matrix would render as a green row. **Tiered rollout**: baseline per release, expanded nightly, customer cells on demand, with the honest status that **the first two tiers have no schedule** — the sweep runs on demand and regression blocking is asserted in a test rather than wired into a pipeline. **Rollout order**: records before maturity before a matrix before a badge, and why a badge is last. The phase's acceptance criterion is the load-bearing part: `tests/unit/test_certification_badge_honesty.py` (72 cases) extends the `test_no_document_describes_fault_packs_as_signed` idea to certification badges across every published document, and it is **derived from the record store** rather than hardcoded — a real migrated SQLite database read through `sealed_certification_gate`, so the day a promotion lands the gate opens for that fault instead of blocking it. Two things the gate had to learn the hard way, both recorded because both were wrong first: requiring a **catalog fault id** in the line, because matching the rung alone flagged eleven innocent documents that merely explain the maturity model; and accepting a **retraction on the same line** ("unit-verified rather than live-verified"), because the reliability matrix's longest paragraphs state the truth and then name the rung they are not at. The README's `0 of N` count is **not** re-asserted here: `test_readme_honesty.py` already derives N from `len(CATALOG)` so the denominator cannot quietly become a smaller lie, and duplicating it would only inflate the count.

Overall: 6 of 6 phases complete. Phase 5 closed on the schedule, the wired gate and the clock-driven sweep, all three of which were previously open. **Nothing here changed a count:** `certified_faults` is still 0 on a fresh database, every fault is still capped at `verified-unit`, and the README is still `0 of N`. The nightly gate currently exits clean on a fresh runner because there is no live claim to regress — that is the honest zero, and the two limits below are what Phase 5 leaves behind rather than what it finished.

### Nothing is certified yet, and the README count must stay 0-of-N

**No live cell has been certified.** Every part of this work is the *machinery* for a claim; not one claim has been made. The first `verified-live` promotion still requires a real runtime — a real docker or podman, a real disposable container, a real drill — and nothing in this phase produces one:

- No code path seeds a certification record. `certify matrix` on a fresh database reports `certified_faults: 0` and caps every fault at `verified-unit`; `tests/unit/test_cli_certify.py` asserts exactly that, deriving the denominator from `len(CATALOG)` rather than pinning it, and `tests/unit/test_certification_gate_arming.py::test_the_cli_matrix_reports_zero_on_a_fresh_database` re-asserts it where the gate-arming claim lives.
- **Arming the gate and wiring the sealer did not move the count, and must not.** Both make an existing claim *more* falsifiable; neither creates one. A `{}` mapping or a missing chain can only lower a reported level, never raise one — `test_arming_the_gate_can_only_lower_a_reported_level` walks the whole catalog to pin that, and `test_a_planted_record_raises_the_level_so_the_cap_is_a_gate_not_a_constant` pins the converse so the cap cannot decay into a constant that quietly refuses everything.
- The live cell path — `cli/certify.py`'s `EngineCell`, `RunEvidenceCapturer`, and the in-container residue probes — is implemented and structurally pinned (it is bound to `RunEngine.execute` and to nothing else) but is **unexercised by CI**, because it needs a container engine. It is written to be read and reviewed, not to be assumed correct.
- **Wiring the sealer did not change that count either.** Sealing a certification's evidence is necessary for a claim to *count*, not sufficient: a sealed chain still needs a cell that actually ran, a bundle that matched the run, and both required engines. No cell has run, so nothing is sealed either, and the gate grants nothing. The fixture in `tests/unit/test_cli_certify.py` now seals a real chain behind each planted record — which is what makes `test_a_stored_record_changes_the_answer` a claim about the *surface* rather than about a row that the gate should have withdrawn anyway.
- **Kubernetes cells are not implemented.** Plan 01 defers them to plan 02, and `mayhem certify run --engine kubernetes` is refused with a pointer rather than falling back to a container lane.
- The README's live-verified count must remain `0 of N` — N being the live catalogue size — until a real cell is certified. `tests/unit/test_readme_honesty.py` enforces the zero count and the `0-of-N` form, reading N from `len(CATALOG)`; do not soften it to make a number look better.

### How the certification gate is armed, and where it is still optional

The gate is `evaluate_maturity(..., records=...)`. `records=None` preserves 1.0.0 behaviour exactly, which is correct for callers that do not use certification — but it is a silent way to lose the gate, so the surface that *can* mint a claim never uses it, and every report that shows a maturity says whether the gate ran:

- **Non-optional on the certification surface.** `mayhem certify matrix` always calls `evaluate_maturity(..., records=<the sealed gate>)`. An empty store yields an **empty mapping**, and an empty mapping is an assertion that nothing is certified, which caps the reported level. There is no flag, mode, or code path in `cli/certify.py` that reports maturity without it. The payload says so (`"certification_gate": "armed: …"`), and `test_a_stored_record_changes_the_answer` proves the arming is real by planting *sealed* records and watching the answer change.
- **Armed everywhere in the reporting path, and loud about it where it cannot be.** `controller/catalog_report.py::maturity_decision` takes `records` and threads it to `evaluate_maturity`, and every reporting function downstream of it does the same: `promotion_refusals`, `capability_status`, `build_capability_statuses`, `build_capability_dashboard`, `build_capability_report`, `build_coverage`, and `explain_catalog_fault`. So the *seam* is complete — there is no longer a maturity-reporting call site that cannot be armed, and `tests/unit/test_certification_gate_arming.py::test_every_reporting_entry_point_threads_the_gate` asserts that structurally (a function that accepted `records` and dropped them would pass every behavioural test, because each of those hands the mapping straight to `maturity_decision`).
- **What is left is the CLI plumbing, and the answer for a store-less path is deliberate.** `discover capabilities`, `toolkit faults --coverage`, and `explain catalog fault` are read-time reports with **no store handle** — `mayhem --help`-adjacent catalog reads, and tests that construct them directly, several of which have no database at all. They pass `records=None`, and `None` means *this report does not use certification*: it preserves 1.0.0 behaviour exactly, and the payload says `"certification_gate": "not-consulted"` so the omission is visible rather than silent. They must **not** pass a fabricated `{}`: `{}` is the assertion "I consulted a certification store and it holds nothing", which caps correctly but is a provenance claim a path that never opened a store cannot make — and it would make a store-less report disagree with `mayhem certify` in the one direction a reader mistakes for verification. Giving those commands a real handle means opening the database at the CLI seam and passing `CertificationEvidenceStore(store).gate(...)` (or `repository.certification_gate(...)`) into the existing parameter; that is the remaining Phase 5 work and it is one argument at each call site.
- The three states are distinguished deliberately: `armed` (a store was consulted and holds a live claim), `asserted-empty` (consulted, holds nothing), `not-consulted` (this report does not use certification). `{fault_id: ()}` is `armed` — a store was consulted and holds nothing *for this fault* — and caps identically to `{}`; only the reader's information differs.
- The gate is deliberately *not* in `CUMULATIVE_CRITERIA`: the ladder is the run-evidence contract, and adding to it would silently redefine the rungs for callers that do not use certification. The gate caps the ladder's result instead.
- **The stricter gate is now the one the surface uses.** `certify matrix` reads through `sealed_certification_gate`, not `certification_gate`. Same shape, same arming point, plus it re-verifies every live claim's sealed chain and hands on an unverifiable one in the `failed` state — so a claim whose bundle was deleted, or whose residue scan was never performed, or whose recovery never came home, stops being reported rather than being reported as standing. This is now observable rather than theoretical, because a chain exists to be lost: `test_a_chain_that_disappears_stops_being_reported_as_a_standing_claim` plants a sealed claim, confirms `certified_faults: 1`, deletes the attestation rows, and confirms `0` with every cell reported `failed`. The converse is pinned too — a record nothing sealed is reported withdrawn even though the stored row still reads `certified` (`test_a_claim_with_no_sealed_chain_is_reported_withdrawn`), because the row is history and the report is a claim.

### Re-certification after expiry is a new record, not a transition

`domain/certification.py` already made a lapsed claim terminal, and the store matches it: the table is keyed `(fault_id, sequence)` with a dense, 1-based sequence per fault, `append` is how a claim is created, and `store_transition` refuses to move a record's identity (a different fault, sequence, or cell) — so ageing, demotion, and invalidation are in-place while re-certification appends. `certify_fault` never promotes by transition: it builds a fresh `pending` record and hands it to `certify`, or hands it back un-certified with the reason. `test_store_is_a_sequence_per_fault_not_a_mutable_row` pins both halves.

### The CLI now seals what it certifies, and reads back through the sealed gate

`controller/certification_evidence.py::CertificationEvidenceStore` implements the runner's `EvidenceSealer`, and `certify_fault` seals whenever it is handed one. `cli/certify.py` now hands it one at the single `certify_fault` call site — `evidence_sealer=CertificationEvidenceStore(store, repository=repository)` — and `certify matrix` reads through `CertificationEvidenceStore.gate()`, which is `sealed_certification_gate`. Two consequences, both on the surface that can mint claims and nowhere else:

- **A claim this CLI mints is re-verifiable.** It reaches a stored `certified` row only if its chain sealed and verified; a bundle that cannot be sealed is `RefusalClass.EVIDENCE_UNSEALABLE`, a refusal. There is no path through `certify run` that produces a live claim with nothing attesting it.
- **A claim that outlives its evidence is withdrawn on read.** Deleting a chain drops the reported level without anybody editing a row, and the report says why (`state: failed`, with the verification failure in `reason`) rather than going quiet.

**This changed no count, and that is the honest headline.** Sealing is necessary for a claim to *count*, not sufficient: a sealed chain still needs a cell that actually ran, a bundle that matched the run, and both required engines. No cell has run, so nothing is sealed, `certified_faults` is still 0 on a fresh database, every fault is still capped at `verified-unit`, and the README's live-verified count is still `0 of N`. Nothing in this change seeds a record or makes a fault look `verified-live`.

Two things deliberately left alone:

- `evidence_sealer` is still **optional** on `certify_fault`, and omitting it still certifies. That is the runner's contract, preserved for the unit suite and any weaker caller — and it is not a hole in this surface, because this surface never omits it. What closes the weaker pipeline is the gate, not the refusal: no chain means no verification, so the claim does not reach a reported level. `test_omitting_the_sealer_certifies_but_leaves_no_chain_behind` exists so a future lane cannot turn the weaker pipeline into a stronger claim silently, and `tests/unit/test_certification_gate_arming.py::test_the_certify_fault_call_site_hands_the_runner_a_sealer` pins that the CLI is not that lane. The sealer argument is asserted structurally (one `certify_fault` call site, passing a `CertificationEvidenceStore`) because that is a fact about wiring that no live cell can be asked about in CI.
- The **live** recovery probe is unchanged. `cli/certify.py`'s `EngineCell.recovery_evidence` still reports a normalised lease-state signal rather than a numeric baseline; the numeric axis lives in the promotion engine's `Observation` records. The chain faithfully attests whatever the cell reported, and the irreversible-fault branch requires the compensation claim instead of a probe, so neither is over-read.

### Retention versus certification: the hazard, and how it is resolved

A certification record survives its run by design, and so does the evidence the run produced. That creates a real hazard: **retention could delete bytes a live certification still cites, and the claim would go on reporting a level with nothing behind it** — the exact failure the whole plan exists to prevent. It is resolved with both remedies, and the default is the conservative one:

- **Refuse by default.** `expire_certification_evidence` checks `certification_evidence_dependents` first and raises `CertificationEvidenceHeldError` (a `RetentionRefusedError` subclass, so an existing retention caller catches it for free) naming every dependent claim and offering the two remedies. Nothing is written. Unconditional refusal was rejected because a fault that had *ever* been certified would then never have its evidence deleted, and the retention ladder would quietly stop working for the faults most worth keeping records of.
- **Demote-first on request.** `demote_dependents=True` withdraws each dependent claim through `mark_failed` and `store_transition` **before** delegating to `RetentionEngine.expire`, so there is no window in which a claim is demoted and its evidence is still intact, or the reverse. Automatic demotion was rejected as the default because it would let whoever runs a retention sweep withdraw a maturity claim by touching only the evidence — the certification surface would report less than it actually knows, with no transition anyone asked for.
- **Sweep the unsanctioned path.** The guard stops the deletion it can see. `reconcile_certification_evidence` covers evidence removed without going through retention at all (a hand-edited attestation row, a restored snapshot, a cleaned bundle directory), so a claim can never outlive what it is checked against.
- **A lapsed claim holds nothing hostage.** `certification_evidence_dependents` ages with the domain's own `expire_by_time`, so an already-stale claim does not block the ladder. `test_a_lapsed_claim_does_not_hold_its_evidence_hostage` pins this; without it the guard would be unusable.

Every other retention rule is untouched — dual control, the legal hold, the external copy, the tombstone. Phase 4 adds one gate in front of `RetentionEngine.expire` and weakens none of them.

### What Phase 5 still owns

The runner and the chain now refuse on: a reversible fault with no recovery evidence, recovery that drifted past tolerance, dirty leases, a residue scan that was not performed, residue that was found, a missing bundle, a bundle missing a required digest, a bundle whose digests do not match the run's, an evidence bundle that cannot be sealed, and a sealed chain that no longer verifies.

The **surface** plumbing is done. `cli/certify.py` passes the sealer and reads through `sealed_certification_gate`, and `catalog_report`'s reporting path is armable end to end. What remains is *enforcement* — the part that turns these refusals into a schedule and a gate that can fail a build. Precisely:

All three are landed. What follows is what remains, and none of it is Phase 5's acceptance criterion — it is named so a reviewer can decide whether to reopen the phase.

- **No job has ever certified a fault, and the schedule does not change that yet.** `.github/workflows/conformance.yml` runs on `17 3 * * *` and the gate exits clean with `claims_considered: 0`, because no live claim exists anywhere: `certified_faults` is 0 on a fresh database and nothing seeds a row. The gate's `--rerun` path provisions a container per live claim through `certify run`'s own execution path, so until a claim exists the nightly re-run is a code path no CI run has taken, and this document will not pretend a cron entry is coverage.
- **A re-run reproduces the claim with catalog-default parameters.** `CertificationRecord` stores the fault, the cell, the injector version and the evidence digests; it does not store the parameters or target it was minted with, so `_rerun_claims` rebuilds the request from the record and the catalog defaults. A fault certified with a non-default parameter will be re-run with defaults, and if the defaults do not reproduce it the gate will report a regression. The fix belongs in the record — `params` and `target` are already captured by `_stored_params` for the evidence bundle — and it is not this phase's to change.
- **The store-less reporting commands still hold no store.** `discover capabilities`, `toolkit faults --coverage`, and `explain catalog fault` pass `records=None` and say `"certification_gate": "not-consulted"`. Giving them a handle is one argument each at the CLI seam, once a decision is made about whether a `--help`-adjacent read may open a database; they must not be armed with a fabricated `{}`, which is the assertion that a store was consulted and held nothing.


## Fault-catalog reliability matrix

The matrix lives at `docs/fault-catalog/reliability-matrix.md`, and this phase
changed **nothing in its numbers**. Every count in it was already correct and
remains correct: the executable faults are `verified-unit`, the live rungs are
unreachable, and the honest zero is a zero.

What this phase added is the rule that keeps it that way. The matrix is a
*published* document, so it is in scope for a new gate:
`tests/unit/test_certification_badge_honesty.py` walks every published Markdown
file, and for each line that names a **catalog fault id** *and* asserts a live
rung — `certified`, `✅`, `verified-live`, `live-verified`, or a rung name sitting
alone in a table cell — it asks the record store whether that claim exists. The
store is a real migrated SQLite database read through
`sealed_certification_gate`, not a literal `set()`.

That comparison is the point. A prohibition on the word "certified" would have
failed every document that *explains* the maturity model, and the first version
of this detector did exactly that: eleven documents, every one of them innocent,
because prose about `verified-live` is most of what the catalog documentation is.
Requiring a named subject fixes it — a badge always names the fault it is about.
When the first real cell is certified the store's set becomes non-empty and the
same gate admits exactly that fault's badge, which is why the allowlist is derived
rather than hardcoded.

## Public compatibility matrix (gap 109)

The compatibility question is "can this fault run here, and who says so?", and
`mayhem certify matrix` answers it without executing anything. A **matrix cell**
is nine frozen fields — `engine`, `engine_version`, `os_distro`,
`kernel_version`, `arch`, `privilege`, `capabilities`, `provider_id`,
`provider_version` — and a certification record stores the cell inside its
identity rather than pointing at one. That is what makes drift detectable: compare
the recorded cell against the cell that exists now and the difference is *named*
rather than averaged away. A record without its cell would be a claim about "a
machine somewhere", which is the claim the harness was built to refuse.

Three answers the matrix can give, and they are not the same thing:

* **compatible** — the fault can run on this cell, with no live claim attached;
* **certified** — it ran, and a sealed record says so;
* **unreached** — the verdict came from *another* cell, so it neither passes nor
  fails this one. A matrix that reported an unreached verdict as a pass would be
  a green row that means nothing.

Every reported maturity comes from `evaluate_maturity(..., records=...)` with the
sealed gate armed, so a fault's level is capped at `verified-unit` on a cell that
has never run it, regardless of what any other cell recorded. `certified_faults` on
a fresh database is **0**, and the payload says the gate was armed
(`"certification_gate": "armed: every reported maturity consulted the record
store"`).

## Tiered rollout

The plan's answer to certification explosion, unchanged: **required baseline cells
per release, expanded nightly matrix, customer-specific cells on demand.** The
reason the tiers are ordered this way is that a cell is the expensive thing — a
real engine, a real disposable container, a real drill — and a promotion is the
thing that outlives it.

* **Baseline per release.** A small fixed set of cells every release must certify.
  This is what makes a regression block a build: the same cells, every release, so
  "it worked last release" is a statement about a comparable thing.
* **Expanded nightly matrix.** Everything else, on a clock. It can be wide because
  nothing downstream depends on one run of it.
* **Customer cells on demand.** A customer's own engine versions and kernel,
  because that is the cell only they have and only they need.

**Honest status: the tiering is designed and documented; it is not yet driving
anything.** The nightly job runs on `17 3 * * *` and now executes the expiry
sweep (`mayhem certify matrix --all --sweep`) and the regression gate
(`mayhem certify regress`), which exits non-zero on a regression. Two things are
still true and both are why this section is not a coverage claim:

* **Nothing in `.github/workflows/` calls `certify run` on a clock.** The gate
  reads a verdicts file and only executes when `--rerun` is passed, and no CI
  run has passed it — so nothing has ever certified a fault on a schedule. The
  nightly job currently compares zero live claims against nothing, because
  `certified_faults` is 0 and no cell anywhere is certified. That is the honest
  zero, and a cron entry is not coverage.
* **Tier one has no schedule at all.** Baseline cells per release — the tier
  that makes "it worked last release" a statement about a comparable thing, and
  therefore the tier a regression gate is meaningful against — is designed here
  and driven by nothing. Tier two has a job but nothing to compare.

## Rollout order

Records before maturity, maturity before a matrix, a matrix before a badge.
A stored record is falsifiable — it can be aged, invalidated, withdrawn, and
checked against its sealed chain. A reported maturity is a *claim* derived from
records and is worthless without them. A matrix is many claims side by side. A
badge is a matrix reduced to a single mark, which is exactly why it is last: it is
the one shape an overclaim takes when the machinery already exists and somebody
fills in the cell, because the cell was there.

So the gate that closes this phase is not a style check. It is a comparison
against the record store, and it is written so that the day a promotion genuinely
lands, it opens rather than blocks.
