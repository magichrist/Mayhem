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

## STATUS — planning only, 0%
