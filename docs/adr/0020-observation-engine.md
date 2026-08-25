# 0020. Observation Engine

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0004](0004-fault-taxonomy.md) (fault taxonomy), [ADR-0005](0005-recovery-model-lease-journal-janitor.md) (recovery model)

## Context

Experiments in v0.1.0 produce a `RunResult` with `leases`, `evaluation`, and `dirty_leases` — but there is no structured event log of what happened during the run. When something goes wrong, operators have no way to trace the sequence of events: which fault was injected first, when probes fired, which recovery attempt succeeded.

## Decision

An `ObservationLog` is an append-only, in-memory store of `Observation` events. Each observation has:

- **kind** — typed event category (`fault.injected`, `probe.measured`, `threshold.breached`, `recovery.attempted`, `anomaly.detected`, etc.)
- **run_id** — which experiment this belongs to
- **timestamp** — ISO 8601
- **source** — which subsystem generated it (`executor`, `janitor`, `probe_runner`)
- **data** — free-form dict with event-specific payload

**11 observation kinds** cover the full experiment lifecycle:
`fault.injected`, `fault.undone`, `probe.measured`, `threshold.breached`,
`recovery.attempted`, `recovery.succeeded`, `recovery.failed`,
`step.started`, `step.completed`, `step.failed`, `anomaly.detected`

**Query helpers:** `for_run()`, `for_kind()`, `anomalies_for_run()`, `snapshot()`.

**Emit shorthand:** `log.emit(kind, run_id, source=..., **data)` for one-liner recording.

## Consequences

- Every significant event during an experiment is captured with full context.
- Observations are immutable (frozen Pydantic model) — no tampering after creation.
- The evaluation system can consume observations to compute metrics (e.g., time-to-recovery, anomaly count).
- `snapshot()` serializes to JSON-compatible dicts for persistence or streaming.
- Backward compatible: existing runs without an ObservationLog are unaffected.
