# Plan 10 — Emergency Stop and Pre/Post Flight Safety

**Priority:** P0. Gap items 9, 63, 64.

## Objective
Guarantee that running experiments can be stopped safely and that preconditions/postconditions are evaluated automatically.

## Builds on
- `domain/cancellation.py` ladder (`NONE → GRACE → TERM → KILL`, monotonic) and the `_AbortMatrix` signal handling become the stop-escalation spine, extended from process signals to distributed runs.
- `controller/recovery.py` state machine plus `controller/janitor.py` orphan sweep become the stop-execution path; the agent watchdog stays the last resort when the controller is gone.
- The v1.0.0 preflight (`controller/preflight.py`, real-gate evaluation) becomes the preflight phase; postflight is its mirror over recovery output.

## Preflight checks
Cluster health, target health, active incident state, recent deployment,
backup state, replication health, agent availability, policy/budget
availability, dependency health. A failed preflight refuses the run
before anything is injected — a preflight that warns-and-continues is a
bug, not a feature.

## Runtime stop conditions
SLO breach, metric threshold, error-rate threshold, probe failure,
custom webhook, policy trigger, human stop. Condition definitions live
in 11; this plan owns their enforcement teeth.

## Emergency stop flow
```text
freeze new actions
 -> cancel pending actions
 -> compensate active actions
 -> reconcile
 -> residue scan
 -> verify
 -> seal evidence
```

## Requirements
Emergency stop must work when the original controller process is gone.

## Phase 1 — Domain model: stop vocabulary
Add `domain/stop.py`: `StopReason` (human, condition-fired with condition id and observed values, preflight-failed, controller-lost, override), `StopCommand` (run scope: one run vs. environment-wide), `PostflightReport` (per-check pass/fail with evidence refs). Pure types; stop-escalation as a pure ladder over run state. Acceptance: every stop path maps to exactly one reason; unknown reasons unrepresentable.

## Phase 2 — Engine: distributed stop execution
Extend the cancellation ladder across the 03 fabric: freeze dispatch, cancel pending, compensate active via existing undo contracts, reconcile leases, residue-scan, verify, seal. Controller-loss path: standby promotion (08 replication) or agent-watchdog compensation takes over — the run's lease sink is the rendezvous, never controller memory. Acceptance: controller-kill mid-fault stops the run and seals evidence naming `controller-lost` as the reason.

## Phase 3 — Surface: one command, one button
Single stop invocation in CLI and UI (08) for one run; environment-wide emergency stop requires the emergency role (09) and seals accordingly. Preflight and postflight render as checklists with per-check evidence links. Acceptance: stop latency bounded and tested (freeze within seconds, full recovery verified after).

## Phase 4 — Safety and evidence integration
Stop reasons, per-action compensation outcomes, residue scan results, and postflight verdicts all enter the sealed chain (12); a stopped run's verdict reflects the stop (degraded-beyond-tolerance vs. aborted is decided by observations, never defaulted). Acceptance: post-stop evidence proves whether recovery completed — "probably recovered" is not a state.

## Phase 5 — Tests, regression guards, negative controls
Stop-matrix tests (every fault family × every stop trigger), controller-kill drills, preflight-refusal tests (incident active, budget exhausted, agent missing), postflight-failure tests (residue found → run stays dirty, never closed clean). Negative controls: a stop command for a finished run is rejected, not silently accepted; a preflight bypass flag does not exist and a test asserts its absence. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Stop runbook, preflight-check catalogue with per-check meaning, postflight interpretation guide. Rollout: preflight hardening first (it only ever refuses more), stop plumbing second, environment-wide stop last with game-day rehearsal (13). Acceptance: no doc promises stop of irreversible effects — reconciliation of the irreversible is documented as best-effort with explicit limits.

## Stop runbook

The operator's sequence, in the order the code performs it. Every step names the
thing that can refuse it, because a step that cannot fail is not a step.

**1. Decide the scope.** One run or an environment.

```text
mayhem stop r-drill-a1b2c3d4 --reason "operator pressed the button"
mayhem stop --environment staging --reason "incident INC-42 open" --principal u-ana
```

`--reason` is required, and its absence is a refusal rather than a default:
a stop whose cause is unnamed produces sealed evidence that cannot say why it
sealed. Run-scoped stops need no role; the environment-wide scope resolves plan
09's `Role.EMERGENCY_STOP` through the identity store and refuses **before any
write**. There is deliberately no `--force`, `--no-preflight`, or `--skip-role`:
each would be a bypass of a gate whose only job is to refuse, and `mayhem stop`
asserts their absence in
`tests/unit/test_stop_surface.py::test_stop_has_no_bypass_flag`.

**2. Optionally ask the gate first.** `--preflight` evaluates the refusing
preflight gate and renders its checklist. From the CLI this **refuses by
construction**, because the CLI has no witness for the five external systems the
port checks read — that refusal is the plan's rule, not a broken flag. A caller
with witnesses binds them and calls `run_stop(preflight=..., preflight_inputs=...)`.
A refusing checklist is recorded nowhere, because that path mutates nothing; a
*granting* one is written to `observations` so a week-later reader can see which
checks cleared the stop and what they looked at.

**3. The walk.** `freeze → cancel_pending → compensate_active → reconcile →
residue_scan → verify → seal`, from `domain.stop.STOP_FLOW`. Each stage leaves at
least one receipt, so "recorded as done" means "left a trace". A stage that
cannot complete is **recorded, not sealed**: `stalled_at` names it, the partial
receipts it already emitted are kept, and the attempt goes to the ledger unsealed.

**4. Read the verdict, not the exit code alone.**

| verdict | meaning | exit |
| --- | --- | --- |
| `CLEAN` | every mandatory stage ran, the residue scan was empty, the run-completion gate passed | 0 |
| `DIRTY` | a residue finding or an unsettled claim is standing; this run must not be read as recovered | 7 |
| `UNKNOWN` | the stop did not seal, or the evidence has aged past its TTL — nothing was established | 2 |

`DIRTY` beats `UNKNOWN` beats `CLEAN` across a fan-out, worst-first. "Probably
recovered" is not a state mayhem can report.

**5. Confirm the record.** Two records exist and they are different things.
`observations` (`stop_attempt`, `stop_seal`, `stop_command`, `stop_preflight`) is
the operator surface's own durable record and verifies nothing — anyone with the
database can edit it. The **attested chain** under
`attestation_chains`/`attestation_events`/`attestation_manifests`, keyed
`<run_id>:stop`, is the evidence: every link is a SHA-256 over canonical bytes
and the manifest commits to the digests. Read it back with
`AttestationRepository.load_chain("r-...:stop")` and
`verify_chain`/`verify_manifest`.

**6. Sealed is not signed.** Every stop chain carries an explicit
`signature_state` / `signature_reason` of *unsigned, because this build signs
nothing*. `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`
and nothing here implies otherwise. What the chain proves is **integrity** —
that these bytes have not been altered since they were written — and never
**authorship**.

### Limits, stated rather than discovered

* **The freeze is a fence, not a wall.** `FenceDispatchFreezer` mints a strictly
  newer epoch in `repl_fences`; a writer that *asks the ledger* whether its epoch
  is current will be refused afterwards. A controller that never consults
  `repl_fences` is not fenced by this. The reference `fence/<run_id>/<epoch>`
  exists so the epoch can be looked up rather than taken on trust.
* **The stop-latency bound measures mayhem, not the environment.**
  `FREEZE_LATENCY_BOUND_S` (5.0 s) is the time from taking the command to the
  freeze receipt — the button, not the reaction to it. How long a paused queue
  takes to drain is not measured here and cannot be, from inside the process that
  asked. A stop that never reached the freeze reports *no measurement*, which is
  not `0.0 s`.
* **Reconciliation of an irreversible effect is best-effort, and this document
  does not pretend otherwise.** `mayhem stop` cannot undo everything. It cannot
  undo a fault whose undo contract does not exist — an external side effect, a
  message already delivered, a third party's database, a deletion with no
  recorded inverse. The preflight's `agent:capability` check refuses a plan
  whose faults have no *recorded* undoer, which is the strongest statement
  available and is still only about what mayhem knows. Concretely: mayhem
  **does not undo** an effect whose undo contract was never recorded, and it
  does not undo an effect outside the environment mayhem was pointed at. When a
  residue is found
  the run stays `DIRTY` and says which finding and against what evidence; the
  residue scan is `best-effort` with explicit limits, because "we looked and
  found nothing" is scoped to the witnesses that looked.
* **A run with no witness reads `UNAVAILABLE`, not "fine".** An unreachable
  incident manager, an unbound port, a port that raises, a port that answers
  `None`, and a port that answers in the wrong shape are all the same finding.
  Mayhem cannot undo an effect it never knew happened.

## Preflight check catalogue

Twelve checks, three statuses, one rule: `refuses_gate(status)` is `status is not
PASS`, so anything that is not a pass blocks the run. There is no "warn", no
"unknown", and no third state that neither passes nor blocks.

**A gate that evaluated zero checks refuses** (`PreflightReport.vacuous`), and a
narrowed gate shows an omitted check as an *absence* in the report rather than as
a pass — so narrowing can only ever refuse more or say less.

### Real checks — computed from data mayhem already holds

| check | what it means | `FAIL` when |
| --- | --- | --- |
| `plan:admitted` | the v1.0.0 preflight already admitted this plan | no preview was built, the preview blocked items, the preview carries no blast-radius verdict, or the blast radius is not `within_budget` |
| `target:health` | every node this plan names exists in the topology mayhem was given | no graph, or any target node id does not resolve |
| `dependency:health` | the graph is whole enough for a blast radius to be a measurement | no graph, no service node (a blast radius from an empty graph is 0% of nothing), or an unresolved node in the target closure |
| `agent:availability` | there is an agent to run this plan at all | no agent is registered |
| `agent:capability` | some agent may inject every fault **and undo** every fault | no injector, or — the half that is easy to forget — injectable but no undoer, leaving a live payload nobody can remove |
| `policy:available` | a policy decision exists and permits this run | no decision was supplied, or the decision denies (quoting plan 07's own reasons) |
| `budget:available` | a resource budget exists and would mean something | no guard attached, a guard governing no dimension (so it would admit anything), or a guard with no estimate (so admission would be vacuous) |

### Port checks — a system mayhem does not own

Each needs an injected port answering with one `PortObservation`. **Unbound,
raising, `None`, or wrong-shaped are all `UNAVAILABLE`, and `UNAVAILABLE`
refuses.** `FAIL` ("mayhem looked, and the answer was no") and `UNAVAILABLE`
("mayhem has no witness") are different findings and are never collapsed.

| check | port | what it certifies |
| --- | --- | --- |
| `cluster:ready` | `cluster` | a reachable control plane — the graph says what *should* exist; only the control plane knows whether it will take a write |
| `incident:active` | `incident` | no incident is open. Drilling into an environment that already has one is how a drill becomes the second incident |
| `deployment:recent` | `deployment` | nothing changed since the plan was compiled |
| `backup:state` | `backup` | a restore point exists — the mirror of the incident manager, for a fault whose undo *is* a restore |
| `replication:health` | `replication` | the replica is current, so an environment-wide stop has somewhere to land |

The CLI binds none of the five, so `--preflight` refuses from a terminal. That is
the correct reading of "a preflight that warns-and-continues is a bug".

## Postflight interpretation guide

How to read a `mayhem stop` after the fact. Three checks, three witnesses, and a
verdict recomputed on every read by `domain.stop.PostflightReport.verdict` with
precedence `DIRTY > UNKNOWN > CLEAN`.

| check | witness | reads |
| --- | --- | --- |
| `recovery:leases_recovered` | the compensation pass's own result | one entry per lease the pass settled, plus `unsettled=` and `dirty=` |
| `residue:<kind>:<target>` | the residue scan | one `FAIL` per finding; a passing `residue:scan` is the receipt for a scan that came back empty |
| `verify:run_completion_gate` | `mayhem.domain.leases.assert_all_recovered` | the independent check that does not trust the pass that just ran |

Residue finding kinds:

| kind | means |
| --- | --- |
| `lease_missing` | the plan named a lease the sink no longer holds |
| `lease_unplanned` | the run holds a lease the recovery plan did not name |
| `lease_unsettled` | a lease the compensation pass did not settle |
| `claim_unsettled` | a dispatch claim the fabric took and never settled, owning no lease — intent with no observation anywhere. Only seen when a claim ledger is bound; its absence is not evidence of no claims |

**Reading the three verdicts.**

* **`CLEAN`** — every mandatory stage ran, the residue scan was empty, the
  run-completion gate passed. It is a claim about the witnesses that looked, not
  a proof that nothing happened: the residue scan's reach is bounded by what the
  scanner could see.
* **`DIRTY`** — at least one finding is standing. The renderer names every failing
  check with its evidence reference and prints `OPEN RESIDUE OBLIGATIONS`. A
  `DIRTY` verdict cannot be produced by a missing measurement: the only two
  "nothing established" cases are a stall and stale evidence, and both are
  `UNKNOWN`.
* **`UNKNOWN`** — either the walk did not seal (read `stalled_at` for where) or
  the report's observations have aged past their TTL. `UNKNOWN` is fail-closed:
  it exits non-zero, and it is never a synonym for "probably fine".

**The run-completion question.** `preflight_gate.may_close_clean(execution)` is
the predicate: the stop sealed, a report exists, there is no open residue
obligation, and the report recomputes `CLEAN`. The obligation test is written as
its own early return on purpose — it is redundant against
`PostflightReport.verdict`'s precedence today, and it stays redundant if that
precedence is ever edited, which is exactly when a redundant guard earns its
two lines.

**What an operator should do next, by verdict.** `DIRTY` with a
`lease_unsettled` finding: chase the lease id in `fault_leases` and finish the
compensation by hand. `DIRTY` with a `claim_unsettled` finding: re-run the
dispatch under a fresh fence epoch through the lane that owns dispatch (03) —
the stop path deliberately does **not** settle a claim, because a settlement is an
assertion about what an effect became and only the dispatcher may make it.
`UNKNOWN` with a `stalled_at`: the fabric or the agent could not be reached; this
is where plan 02's controller-loss path and plan 13's game-day rehearsal apply.

### Rollout order

1. **Preflight hardening first.** It only ever refuses more, so deploying it can
   break a run that used to start and cannot un-break one that used to.
2. **Stop plumbing second.** The freeze/cancel/compensate/reconcile/scan/verify
   walk, with the attested chain behind it.
3. **Environment-wide stop last, after a game-day rehearsal** (13). It is the one
   action here that fans out over runs mayhem did not enumerate, and the one whose
   blast radius is the environment.

## Dependencies
03 (fabric dispatch/fencing), 08 (replication/standby), 09 (emergency role), 11 (condition definitions), 12 (sealed stop evidence).

## STATUS
- Phase 1 (domain model): DONE — `domain/stop.py` lands `StopReason`/`StopSignal` (total one-to-one path→reason mapping), `StopTrigger` (reason bound to condition id + observed values), `StopCommand` (run vs. environment scope, principal, issued-at, injectable-`now` staleness), `PostflightReport`/`PostflightCheck` (per-check pass/fail, evidence refs required on a pass), and the pure escalation ladder over run state that reuses `cancellation.CancellationLevel` by reference.
- Phase 2 (engine): DONE — `controller/stop_engine.py` walks `STOP_FLOW` against the lease sink (freeze via the dispatch freezer, cancel pending → `EXPIRED`/`mechanism=stop`, compensate active through the existing `RecoveryService`/janitor undo contracts, reconcile, residue-scan, verify via `assert_all_recovered`, seal); a resume that skips an owed stage is refused, a stage that cannot complete is recorded with `stalled_at` naming it and is never sealed, and the postflight is computed from the recovery output so a residue finding keeps the run dirty; the controller-loss path derives run state from the sink and seals `controller_lost`, with `CompensationPath.AGENT_WATCHDOG` driving the agent's own `AgentWatchdog` when no controller exists; 61 tests.
- Phase 3 (surface and run-path wiring): DONE — the engine half and the CLI surface half landed earlier and are unchanged; **what closed the phase is the run-path wiring that kept it INCOMPLETE.** `RunEngine` now takes an optional `preflight_gate` keyword, carries `with_preflight_gate` / `preflight_gate` / `preflight_report`, and `execute` consults it in one `is not None` block immediately before `_open_run` (and before the budget admission it reads through `budget:available`) — so a refusal leaves no run row, no step row and no lease, for **every** entry point, since `RunEngine.execute` is the single funnel every `mayhem run`-family surface reaches through `cli/services.build_run_engine`. `cli/execution.py` lands `attach_preflight_gate`, mirroring `attach_resource_budget`. The engine supplies only what it holds (plan, clock, live graph when it has one, the attached budget guard); the preflight preview, the agent registry and the policy decision stay at their `None` defaults and are judged as `FAIL`s naming what they lacked, because a gate fed an opinion the engine manufactured would certify it. **No bypass exists**: no `skip_preflight`/`force`/`no_preflight` keyword on `RunEngine`, `PreflightGate`, or `cli/execution.py`, no `without_preflight_gate`, and the only absent state is `preflight_gate=None`, which means *no gate was configured* and reads nothing at all — `admit(None, …)` still returns `None` having read nothing, pinned byte-identical by `GOLDEN_NO_GATE`. `test_the_run_path_still_has_no_preflight_gate_seam` was **deleted** rather than edited (so whoever added the seam could not quietly add a bypass beside it) and replaced by four tests: the seam's shape and its position *ahead of* `_open_run`, a refusing gate that stops `execute` with zero rows written, a no-gate run that still completes byte-identically, and `test_the_run_path_has_no_preflight_bypass`. **Stop latency (plan 08's open item) also landed**: `StopEngine` takes an injectable `monotonic` clock and stamps `StopExecution.freeze_latency_s` from taking the command to the `FREEZE` receipt; `FREEZE_LATENCY_BOUND_S = 5.0` and `freeze_latency(execution)` are the executable bound, fail-closed (`None` measures nothing, so `within_bound` is `False`), and `StopOutcome.freeze_latency_s` / `freeze_within_bound` are rendered and emitted in JSON. The number measures mayhem's own freeze — a fence-epoch mint against the local store — and the rendered line and the doc both say it is not a measurement of the environment's reaction. **Plan 13's claim-ledger seam is no longer unwired inside this module**: `StopEngine` takes an optional `claims: ClaimLedger`, and `_stage_reconcile` turns every open claim with no settlement into a `claim_unsettled` residue finding (which makes the postflight `DIRTY` and the run unclosable-clean), with `stop_cmd.FabricJournalClaims` reading plan 03's existing `FabricJournalTable` and `run_stop` binding it after the dry-run return so a refused or previewed stop still reads no journal. Plan 13's *settlement* half is deliberately **not** taken: a settlement asserts what an effect became, and only the dispatcher may make that assertion — plan 10 reports the open claim instead, which is the fail-closed direction. Tests: `tests/unit/test_stop_surface.py` 54, `tests/unit/test_preflight_gate.py` 102, `tests/unit/test_stop_engine.py` 61, `tests/unit/test_stop.py` 88, `tests/unit/test_stop_safety.py` 37 — 342 across the five files, 341 green and 1 failing for a reason that is not this lane's (`schedule` is now a registered command, so `stop` shares a prefix; asserted by this lane's own test and reported to the integration pass).
- Phase 4 (safety and evidence integration): DONE — `controller/stop_engine.py` gains the Phase-4 evidence half: `stop_evidence_payload` (a pure, canonical projection of a `StopExecution` — stop reason and trigger detail, scope, principal, level, run state, compensation path, every stage receipt with its evidence reference, the per-lease compensation outcomes, every residue check, the verdict **read** off the report, the report digest, and the measured freeze latency), `stop_postflight_payload`, `stop_chain_events` (two events, `stop.executed` and `stop.postflight`, built **unsealed** and numbered from 0), `stop_chain_key`/`stop_manifest_id` (namespaced `<run_id>:stop` so no two lanes share a chain row), and `claim_ref`. `cli/stop_cmd.py` gains `StopEvidenceSeal` and `seal_stop_evidence`, which builds *events* and writes them through plan 12's own `seal_events` / `build_manifest` / `verify_chain` / `verify_manifest` / `AttestationRepository` — no second sealer and no second verifier — refusing to persist an invalid chain or manifest, writing nothing for an execution with no record, and carrying the explicit unsigned-with-a-reason state. `run_stop` seals after the walk (not inside it, so a chain failure cannot unwind a stop that already happened) and `stop_payload` emits `seals[]` with each chain root, event kinds, manifest id and `signed: false`. Four properties are asserted rather than claimed: a **stalled** stop still seals, with `sealed=false`, `verdict=UNKNOWN` and the `stalled_at` stage named, because "the stop could not finish" is the fact most worth having on the chain and its absence is indistinguishable from never having tried; an invocation that stopped nothing seals **nothing**; the verdict cannot be authored by a caller (the payload builder takes an execution and nothing else, and the verdict is `StopExecution.verdict` → `PostflightReport.verdict` recomputed on read); and `signed` is `False` with a reason, asserted against `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED is False`. The chain proves **integrity**, never **authorship**. No new boundary gate is called from this lane's code, so no `BOUNDARY_CALL_SITES` row is owed by *this* lane — see the dependency note below. Tests: `tests/unit/test_stop_safety.py` (37, shared with Phase 5).
- Phase 5 (tests, regression guards, negative controls): DONE — `tests/unit/test_stop_safety.py` (37 tests) is the new suite: the four facts reaching a verifying chain read back through `AttestationRepository.load_chain`; a stalled stop sealing `UNKNOWN`; an empty chain never written; built-unsealed plus a blank-command-id producing no events; unsigned-with-a-reason; the verdict unauthorable; the measured freeze latency against the named bound, an injected-clock overrun reported `OVER`, and an unmeasured freeze reported as unmeasured rather than `0.0 s` (both in the projection and in the rendered output); an open dispatch claim forcing `DIRTY` and the same stop with no claim ledger still sealing `CLEAN` (the additive half); the journal reader being inert where there is no journal; both bypass surfaces asserted from the *absence* of a mechanism; the plan's negative controls (a stop for a finished run refused and nothing sealed, a stop with no reason refused and nothing written, a residue finding never closing clean); the stop matrix over three fault families × three triggers (identical ladder, differing only in the sealed reason) and its negative half over the same families with a wedged lease; and the four named run-path refusals — incident active (`UNAVAILABLE`), agent missing, budget missing, policy missing (`FAIL` each) — each asserted on the refusal text, the status, and the absence of a `runs` row. Negative-control discipline: **13 deliberate breaks applied to the new code, 13 killed, 0 survivors, 0 equivalent mutants** — removing the executor's gate block, moving it after `_open_run`, treating a missing preflight report as a grant, making an unmeasured freeze pass the bound, making the bound advisory, making an empty invocation report `within_bound`, never reading the claim ledger, receipting a claim without a finding, emitting only one chain event, sealing inside the builder, writing nothing to the chain, authoring the verdict as `clean`, and skipping the seal after the walk. The harness is `/tmp/p10/mutate.py`; each break restores the file byte-identically and asserts it. The nine breaks the earlier half of this phase recorded stand unchanged (8 killed, 1 documented equivalent mutant on `obligation_verdict`'s redundant conjunct, which is untouched here).
- Phase 6 (docs, honesty gates, rollout): DONE — three deliverables written into this document, asserted by name and by content rather than left to review: **Stop runbook** (the six operator steps with the thing that can refuse each, the verdict/exit table, how to read both records — the mutable `observations` table and the verifying attested chain — and an explicit **Limits** subsection: the freeze is a fence consulted by writers, not a wall; the latency bound measures mayhem and not the environment; **reconciliation of an irreversible effect is best-effort with explicit limits** — mayhem does not undo an effect whose undo contract was never recorded, nor one outside the environment it was pointed at, and the residue scan is scoped to the witnesses that looked; a missing witness reads `UNAVAILABLE`, not "fine"), **Preflight check catalogue** (all twelve checks with per-check meaning and per-check `FAIL` condition, the seven real checks split from the five port checks, and the four ways of having no answer all refusing), **Postflight interpretation guide** (the three checks and their three witnesses, the four residue kinds including `claim_unsettled`, how to read `CLEAN`/`DIRTY`/`UNKNOWN`, the run-completion predicate, and what an operator should do next for each finding), plus the rollout order — preflight hardening first, stop plumbing second, environment-wide stop last after plan 13's game-day rehearsal. Honesty: nothing here claims a real cluster was stopped, that any signature was verified, or that `verified-live` is above 0. Tests: `test_the_plan_document_promises_no_stop_of_an_irreversible_effect` (the four required statements present, five forbidden promises absent), `test_the_stop_runbook_and_the_two_guides_are_in_the_document`, `test_the_catalogue_lists_every_check_the_gate_can_run` (every `ALL_CHECKS` name appears — so a new check that is not documented fails by name).

Overall: 6 of 6 phases complete.

### Integration dependencies this lane could not satisfy

These are exact identifiers, in other lanes' files. None of them fails a test today — stated precisely so that it is a known, named gap rather than an assumption.

1. **`OBLIGATION_FOR_RULE` / `RULE_CHECK` mapping (not owed yet, owed on integration).** `test_proof_compiler.py::BLAMEABLE_SOURCES` is fixed at `("src/mayhem/controller/safety.py", "src/mayhem/controller/approval_gate.py")`, so no rule raised in `preflight_gate.py` or `stop_engine.py` is blameable today and
   `test_every_rule_the_gates_can_raise_has_an_owning_proof_line` is green. If the integration pass adds either module to `BLAMEABLE_SOURCES`, these mappings are required, and they must be added to **both** tables (`test_check_gate.py::test_every_rule_the_proof_compiler_can_blame_has_an_exactly_one_check` asserts every `OBLIGATION_FOR_RULE` key is also a `RULE_CHECK` key):

   | rule id | raised by | obligation | check scope |
   | --- | --- | --- | --- |
   | `preflight.refused` | `preflight_gate.PreflightRefusedError` | `required_approvals` | `SAFETY_POLICY` |
   | `stop_for_terminal_run` | `stop_engine.StopEngine.execute` | `required_approvals` | `SAFETY_POLICY` |
   | `stop_engine_requires_run_scope` | `stop_engine.StopEngine.execute` | `required_approvals` | `SAFETY_POLICY` |
   | `stop_command_stale` | `stop_engine.StopEngine.execute` | `required_approvals` | `SAFETY_POLICY` |
   | `stop_resume_skips_owed_stage` | `stop_engine.StopEngine._resume` | `compensation` | `SAFETY_POLICY` |
   | `stop_seal_requires_complete_walk` / `stop_seal_requires_evidence` / `stop_seal_digest_mismatch` | `stop_engine.SealedStop` | `recovery_path` | `SAFETY_POLICY` |

   `required_approvals` is the plan-09 precedent read the same way: each of these is a statement about whether this run was *allowed to start or continue*, which is the line that already reports `SAFETY_POLICY`. The three `stop_seal_*` rules are about evidence integrity rather than authorisation and would sit better on `recovery_path`; either choice is defensible, and the choice belongs to the lane that owns `safety_proof.py`.

2. **`BOUNDARY_CALL_SITES` row — none owed by this lane.** The stop evidence crosses the evidence boundary through `AttestationRepository.save_chain` / `save_manifest`, which already hold their own `BOUNDARY_CALL_SITES` rows in `tests/unit/test_evidence_boundary.py`. No function in `preflight_gate.py`, `stop_engine.py`, `stop_cmd.py`, `executor.py` or `execution.py` calls a boundary gate directly, so `test_every_module_calling_a_gate_is_registered` stays green with no new row. **If** the stop path is later given a writer of its own rather than going through plan 12's repository, that writer owes the row `("mayhem.<new module>", "<writer>") -> {"require_persistable_document"}`. The existing `StoreStopLedger` writers call `Store.save_observation` and are deliberately *not* evidence, which is exactly why Phase 4 added the chain.

3. **`build_run_engine` is the bind point, and it is not yet configured.** `cli/services.build_run_engine` is the factory every CLI run surface builds through, and `cli/execution.py::attach_preflight_gate` is written for it. **No production call site attaches a gate**, exactly as `attach_resource_budget` has none today: the five port witnesses must be bound by whichever deployment owns the control plane, incident manager, deployment feed, backup system and replication peer, and until then every production run is correctly *ungated*. The lane that owns the run path (`cli/lifecycle.py`, not this plan's) decides when to attach one; the attach point is ready and tested.

4. **The `schedule` prefix collision in this lane's own test.** `tests/unit/test_stop_surface.py::test_stop_is_registered_under_its_own_name_and_no_prefix_shorthand` asserts that no other registered command starts with `s`. Plan 13 registered `schedule`, so the assertion is now false for a reason unrelated to the stop surface. It is **left failing and visible** rather than weakened: relaxing it would delete the guarantee that `mayhem stop` resolves exactly. The integration pass owns `cli/command_registry.py` and can either keep the assertion and rename, or extend it to test prefix *disambiguation* rather than prefix *absence*.

5. **Plan 13's claim settlement.** The read half is wired (`StopEngine(claims=…)`, `stop_cmd.FabricJournalClaims`). The **write** half is not, and should not be: `FabricEngine.settle_claim` is the only correct settler, it needs a live `FabricSession` and a controller id that a stop does not have, and asserting what an unobserved effect became is precisely the claim a stop must not make. `tests/unit/test_stop_safety.py::test_an_open_dispatch_claim_keeps_the_run_dirty` pins the fail-closed direction instead, and the postflight guide names `claim_unsettled` as the operator's cue to re-dispatch through the lane that owns dispatch.
