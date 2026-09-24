# Plan 03 — Plan-First Execution and Unified Evidence

## Builder brief

Make every mutating workflow follow one safe sequence: resolve target, build plan, evaluate safety, show diff/preflight, obtain explicit execution intent, execute with leases, and publish evidence. This should apply to `run`, `maniac`, `campaign run`, dependency installation, recovery, and future provider operations.

## Canonical lifecycle

```text
resolve -> compile -> safety -> diff -> approve -> execute -> verify -> evidence
```

`plan` is the default result for any mutating command unless the user explicitly supplies an execution action. The CLI must never interpret `--skip-gate` as approval; it only changes a safety gate and must be shown in the diff.

## Phase 1 — Extract a shared preflight contract

### Work

- Define a `Preflight` domain object containing resolved target, config snapshot, topology snapshot, environment fingerprint, plan, safety decisions, blocked items, and warnings.
- Define `ExecutionIntent` with explicit action, target profile, plan id/hash, policy decision, and approval source.
- Refactor lifecycle commands to build the same preflight object before rendering.
- Make `plan` serialization the stable machine-readable contract for all mutating commands.

### Files

- `src/mayhem/domain/preflight.py`
- `src/mayhem/controller/preflight.py`
- `src/mayhem/cli/render.py`
- `tests/unit/test_preflight.py`

### Verification

- Unit tests prove equivalent plans produce equivalent preflight records.
- No executor or agent code is called while producing a preflight.

## Phase 2 — Add explicit execution actions and plan diffs

### Work

- Add `--execute` to mutating commands as the explicit execution action.
- Add `--from-plan PATH` and `--plan-id ID` for reviewed-plan execution.
- Display target, fault list, durations, safety refusals, blast radius, compensation status, and expected evidence.
- Add `--diff` to compare an authored plan with the last accepted plan.
- Reject stale plans when environment fingerprint or target identity changed.
- Preserve existing `run` behavior only through a compatibility adapter that emits a migration warning and explicit execution intent.

### Files

- `src/mayhem/cli/execution.py`
- `src/mayhem/controller/plan_diff.py`
- `tests/unit/test_plan_diff.py`
- `tests/unit/test_cli_execution.py`

### Verification

- Tests cover plan reuse, stale fingerprint refusal, target change refusal, critical opt-in display, and explicit approval.
- JSON preflight and plan-diff schemas are asserted with exact keys and stable ordering.

## Phase 3 — Publish unified run evidence

### Work

- Define an evidence envelope with run id, plan hash, target profile, engine, safety decisions, step reports, lease timeline, observations, verdict, recovery state, and remediation.
- Write the envelope to the store and expose it through `inspect run`, `inspect history`, and report exporters.
- Add `--evidence-dir` and artifact naming rules.
- Make report rendering independent from execution.
- Add a `verify` operation that checks evidence completeness without mutating a target.

### Acceptance criteria

- An operator can answer what was planned, why it ran, what changed, what was observed, and how it was recovered from one record.
- JSON and human output are projections of the same evidence object.

### Verification

- Full unit suite, schema tests, documentation tests, and Ruff.
- No external runtime is required for evidence rendering tests.
