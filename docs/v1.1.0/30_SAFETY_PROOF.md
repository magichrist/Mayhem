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

## STATUS
- Phase 1 (domain model): DONE — `domain/safety_proof.py` landed `Obligation`, `ResidueObligation` with its `discharge()` path, and `SafetyProof` whose verdict is stored but re-derived on every read, with the `evaluate`/`is_valid`/`voided` predicates; 45 tests.
- Phase 2 (engine): DONE — `controller/safety_proof.py` landed `compile_safety_proof`, which runs the real `validate_plan`, `check_fault_admission`, `check_blast_radius`, `pre_exec_assertion`, the plan-07 policy gate, the capability derivation plus the adapter, `require_execution_intent`, and the plan-14 prediction against the frozen plan, and cites each gate output's digest on its line; the never-more-permissive rule is structural (every refusable rule id is mapped to an owning line by `OBLIGATION_FOR_RULE`, and an unmapped one voids the proof); 58 tests.
- Phase 3: not started
- Phase 4 (safety and evidence integration): DONE — `controller/safety_proof.py` maps the approval gate's three refusal rule ids onto `REQUIRED_APPROVALS` and reads the gate's verdict onto that line, and a source-parsing completeness test makes an unmapped rule in either gate module a test failure by name; `controller/proof_sealing.py` seals the proof pre-execution through plan 12's existing `seal_events`/`build_manifest`/`AttestationRepository` (no second sealer), discharges the residue obligations line by line from the plan-01 scan vocabulary (found residue voids its line; an unscanned line fails; a run with an open obligation cannot close clean), and refuses an approval whose `proof_digest` is not the sealed proof's.
- Phase 5 (tests and negative controls): DONE — 173 tests across four suites: `tests/unit/test_safety_proof.py` (45) covers the model, `test_proof_compiler.py` (87) the engine, `test_proof_sealing.py` (35) the seal and discharge, and `test_proof_negative_controls.py` (6) the controls below. The negative controls are two-sided: breaking a *collaborator* rather than `src/mayhem` shows the property survives, so each is a statement about the property and not about the assertion. Three properties are pinned deliberately. **The plan digest alone decides `VOID` versus `PASS`** — a proof whose lines all recompute to `PASS` still reports `VOID` when the digest moves, and the control reads the *same* proof under two digests to show the lines are untouched. **A `PASS` line must cite a real gate output** — a citation is refused at construction, so a line cannot be authored without a digest and an evidence reference someone can re-derive. **Found residue `VOID`s rather than merely failing** — a dirty scan leaves `discharged=False` and names each predicate found, while a clean scan of the same fault leaves the line passing, so the verdict is a consequence of the scan and not of the author.
- Phase 6 (guides and rollout): DONE — four sections appended below: **Proof-reading guide** (the four parts of a line; why `VOID` is the verdict readers misread; why a missing line is reported instead of tolerated), **Residue-obligation catalogue** (the six predicates, and the difference between a residue line that `VOID`s and a check that `FAIL`s), **Rollout order** (compiler and CLI, then PR integration, then residue discharge, then approval binding, least-value first), and **What a proof does not claim** (a proof is a record that checks ran, not a certificate; `SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, so a seal demonstrates integrity and never authorship; no proof in this plan has been accepted by a human approver in a live release). Honesty is enforced, not just asserted: `tests/unit/test_proof_plan_docs.py` parses this file, cross-checks the `Overall:` count against the `DONE` ledger lines, requires these four headings by name, refuses guarantee-shaped prose, and proves each of its own checkers bites by running them against mutated copies of this document.

Overall: 5 of 6 phases complete (Phases 1, 2, 4, 5, and 6). **Phase 3 — the `mayhem plan prove` CLI surface — is not started**, so the compiler is reachable from Python but not from the command line.

Known limitations — two deviations the implementer flagged, both deliberate and both binding on Phase 2:
- **Gate digests are bound to 64-char lowercase sha256 hex.** `_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")` and every citation goes through `_require_digest`. The rationale is that `hashing.sha256_hex` is the project's single definition of "same input", so a gate output that cannot be named by one of these digests did not actually run. A Phase 2 compiler that emits a citation in any other form (uppercase, a prefix, a different algorithm) is refused, not normalised.
- **The nine required obligation names are fixed.** `REQUIRED_OBLIGATIONS` is the frozenset of all nine `ObligationName` values — `max_concurrent_faults`, `max_duration`, `damage_budget`, `target_policy`, `capability_requirements`, `compensation`, `recovery_path`, `stop_conditions`, `required_approvals` — and a `PASS`-shaped proof missing any of them is `VOID`, not `PASS`. Phase 2's compiler must emit exactly these spellings; a near-miss is the fail-closed state, so every proof would come out `VOID`. A residue obligation is *additional* to this set, never a substitute.

Phase 4 limitations, binding on Phase 5:
- **Nothing here wires the executor.** `seal_proof` and `seal_and_discharge` are seams a run-close path calls, exactly as plan 12 Phase 2 left `seal_run_evidence` unwired. They are written to be read and reviewed, not assumed correct in a live run. The residue scanner is a `Protocol`: `cli/certify.py`'s `EngineCell.residue_scan` is the shape it is written against and is adapted through `scan_outcome_from_certification_scan`, but no CLI path constructs one yet.
- **The proof seal is its own attestation chain, scoped `<run_id>:proof`.** `attestation_chains.run_id` is a primary key and `save_chain` does `INSERT OR REPLACE`, so keying the proof seal on the run itself would let the later run-close seal silently overwrite the admission case. Runs therefore link at the *manifest* layer via `previous_manifest_digest`, which is the store's own stated design — `domain.attestation`'s verifier defines a chain as starting at genesis, so an event chain cannot be hung off another chain's root.
- **The rule-mapping completeness guard reads two modules' sources, not all of them.** `tests/unit/test_proof_compiler.py` parses `controller/safety.py` and `controller/approval_gate.py` and asserts every rule id either can raise is owned by a line. Rule ids that are *not* spelled as literals at their raise site are deliberately not resolved — the k8s-admission and policy-bundle families reach the compiler as dynamic strings and are placed by kind (`POLICY_REFUSAL_OWNER`), which a source parse cannot enumerate. A new gate that raises a dynamic rule id is covered only by the fail-closed VOID, not by this test.
- **A residue kind outside the plan-01 vocabulary is reported, not mapped.** `scan_outcome_from_certification_scan` keeps an unrecognised finding under its own name in the scan's note rather than dropping it, but it cannot express it as a `ResiduePredicate`, so it cannot by itself dirty the line. The honest reading is "reported and not silently dropped"; a catalogue that adds a class without a predicate mapping is a gap Phase 5's residue-obligation catalogue should close.

## Proof-reading guide

A safety proof is a **record that checks ran**, not a certificate that the system
is safe. Every line of this document exists to keep that distinction legible,
because the failure mode of a proof is a reader who takes `PASS` as a warranty.

**Each line has four parts, and all four matter.** An `Obligation` carries a
`name` (canonical, and a non-canonical one is refused), a `status`, a
`gate_digest` — a sha256 over some gate's own output — and an `evidence_ref`
naming where that output lives. A `PASS` line with a fabricated citation is
refused at construction: the proof's value is that a line can be traced back to
the gate that produced it, so a citation nobody can re-derive is not a citation.

**Three verdicts, and `VOID` is the one readers misread.** `PASS` means every
line passed *for this plan digest*. `FAIL` means a check failed — a claim about
the current plan. `VOID` means **this evidence describes a plan that no longer
exists**: the digest moved. Assert the difference yourself: a proof built against
digest A evaluates `PASS` against A and `VOID` against B, while its own lines
still recompute to `PASS`. Reading `VOID` as `FAIL` reports a safety verdict about
a plan nobody ran; reading it as `PASS` reports a verdict nobody checked.

**A missing line is reported, never tolerated.** A proof that skipped an
obligation names it in `missing_obligations()`, and a proof over an incomplete set
cannot be authored as `PASS` at all — the model compares the declared verdict
against the lines rather than taking the caller's word. That refusal is what
makes a `PASS` mean something: you cannot assemble one by omitting the line you
did not like.

**`FAIL` and `VOID` are not interchangeable, and a `VOID` outranks a `PASS`.** An
approval refused by the gate fails the approvals line rather than voiding it,
because the check *ran* and said no; a ceiling refusal likewise fails its line.
Voiding is for evidence that cannot be applied, not for evidence that is bad.

## Residue-obligation catalogue

Every fault family carries a **residue obligation**: the assertion that the run
left nothing behind. It is a separate line from the safety checks because it is
discharged *after* the run, by the residue scan, and it is discharged line by
line rather than in aggregate.

- **Six predicates, all required.** A residue obligation must assert the complete
  predicate set — `no_tc_rules`, `no_iptables_entries`, `no_marker_processes`,
  `no_files`, `no_cgroup_overrides`, `no_leases_held` — because "we checked some
  of it" is not a claim any reader can act on. The six are the same fixed set
  everywhere; the fault family chooses which are *meaningful*, not which may be
  skipped, so a shorter set is refused at construction.
- **Found residue `VOID`s the line, it does not merely fail it.** A residue line
  with a dirty predicate comes back `VOID` and `discharged=False`, naming each
  predicate found. The run cannot close clean.
- **A scan that did not run `FAIL`s rather than assuming clean.** An unscanned
  fault with no digest and no evidence reference is a failure to observe, not an
  observation of cleanliness — the same fail-closed direction as everywhere else.
- **A scan for another fault cannot discharge this one.** The fault ids must
  match, so a clean scan of `cpu.starve` cannot close `net.latency`'s line.
- **A residue finding cannot be uncited**, for the same reason a `PASS` line
  cannot: it inherits the base citation check.
- **A digest change voids a residue-carrying proof too**, because the obligation
  was about *that* plan's cleanup.

## Rollout order

Compiler plus CLI first, PR integration second, residue discharge third, approval
binding last. The order runs from "mayhem can tell you what it checked" to
"mayhem's own approval layer reads its own proof", and each step is worth less
than the one after it — which is why the last one is last.

## What a proof does not claim

Stated explicitly because it is the boundary a reader is most likely to cross:

**A proof proves the plan satisfied every check Mayhem knows how to perform.**
It proves nothing about checks mayhem does not know about, nothing about
behaviour outside the fault's declared blast radius, and nothing about a *later*
release — the plan digest is what pins it, and a new release is a new digest and
therefore a void proof, not a stale pass. It is also not a performance claim, not
a security assessment, and not a substitute for reviewing the plan itself.

The related honest limits: `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`
is `False` in this build and this phase leaves it `False`, so a sealed proof
demonstrates **integrity** of what was recorded, never **authorship** of it.
Signature verification is *not implemented* in this build. And
no proof in this plan has been reviewed or accepted by a human approver in a live
release — the compiler runs the real checks, and the acceptance path that would
gate it is plan 09's Phase 4.
