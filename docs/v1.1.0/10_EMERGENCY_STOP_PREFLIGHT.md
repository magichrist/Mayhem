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

## Dependencies
03 (fabric dispatch/fencing), 08 (replication/standby), 09 (emergency role), 11 (condition definitions), 12 (sealed stop evidence).

## STATUS
- Phase 1 (domain model): DONE — `domain/stop.py` lands `StopReason`/`StopSignal` (total one-to-one path→reason mapping), `StopTrigger` (reason bound to condition id + observed values), `StopCommand` (run vs. environment scope, principal, issued-at, injectable-`now` staleness), `PostflightReport`/`PostflightCheck` (per-check pass/fail, evidence refs required on a pass), and the pure escalation ladder over run state that reuses `cancellation.CancellationLevel` by reference.
- Phase 2 (engine): DONE — `controller/stop_engine.py` walks `STOP_FLOW` against the lease sink (freeze via the dispatch freezer, cancel pending → `EXPIRED`/`mechanism=stop`, compensate active through the existing `RecoveryService`/janitor undo contracts, reconcile, residue-scan, verify via `assert_all_recovered`, seal); a resume that skips an owed stage is refused, a stage that cannot complete is recorded with `stalled_at` naming it and is never sealed, and the postflight is computed from the recovery output so a residue finding keeps the run dirty; the controller-loss path derives run state from the sink and seals `controller_lost`, with `CompensationPath.AGENT_WATCHDOG` driving the agent's own `AgentWatchdog` when no controller exists; 61 tests.
- Phase 3: INCOMPLETE — the engine half is DONE, the surface half has not landed. `controller/preflight_gate.py` lands the refusing half: `CheckStatus` (`PASS`/`FAIL`/`UNAVAILABLE`) with `refuses_gate` total over it, seven *real* checks computed from data mayhem already holds (the existing `preflight` preview read rather than a second blast-radius opinion, topology target/dependency resolution, agent availability, agent inject-**and-undo** capability, policy availability, budget availability) and five *port* checks behind injected protocols (`cluster`, `incident`, `deployment`, `backup`, `replication`); `PreflightGate`/`evaluate`/`admit` raise `PreflightRefusedError` carrying a `PREFLIGHT_REFUSAL` `StopTrigger`; and the postflight mirror reaches `stop_engine.postflight_report` through `StopExecution` via `postflight_report_for`/`obligation_verdict`/`may_close_clean`, with the verdict always recomputed by `domain.stop`. Load-bearing rule: an unbound port, a port that raises, a port that answers `None`, and a port that answers in the wrong shape are all `UNAVAILABLE`, and `UNAVAILABLE` refuses — the absence of the ability to ask is not an answer. A gate that evaluated zero checks is refused (`PreflightReport.vacuous`). `admit(gate=None, ...)` returns `None` having read nothing at all, pinned byte-identical by `GOLDEN_NO_GATE` in `tests/unit/test_preflight_gate.py` (102 tests), which also pins the per-check refusal matrix with a specific evidence reference per check, the postflight clean/dirty/unknown agreement with `domain/stop.py`, and the negative controls. **NOT LANDED: the CLI/UI surface** — there is no `mayhem stop` command, no environment-wide emergency-stop invocation, and no checklist rendering; `executor.py` does not yet hold a `preflight_gate` field, so the refusal is currently reachable only by a caller who asks for it, which is not yet a refusal in the run path. Until the surface exists this phase is INCOMPLETE and the count below stays at 2. Mutation evidence for the engine half (`tests/unit/test_preflight_gate.py`, 9 deliberate breaks): 8 killed — `refuses_gate` no longer refusing `UNAVAILABLE`, a vacuous report granting, a port check rubber-stamping, an unmeasured blast radius passing, a capability refusal citing the wrong fault, the vacuous stop-trigger losing its evidence, `admit(None)` not short-circuiting, and a malformed port answer being read optimistically; 1 survived and is reported as an **equivalent mutant**, not a hidden gap: dropping `obligation_verdict`'s `not open_obligations(...)` conjunct cannot change behaviour today because every open obligation is a non-passing check and `PostflightReport.verdict` returns `DIRTY` on any non-passing check ahead of the stale-evidence branch — a redundancy `preflight_gate.py` documents deliberately, and `test_the_redundant_obligation_guard_rests_on_a_real_domain_property` pins the domain property it rests on.
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.
