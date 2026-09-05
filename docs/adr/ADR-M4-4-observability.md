# ADR-M4-4: Declarative observability/metrics sources
**Status:** Approved
**Date:** 2026-09-05
**Deciders:** Ali
**Relates to:** ADR-M4-1 (additive DSL), ADR-M4-2 (execution-locus checks), ADR-M4-3 (success criteria), ADR-M4-5 (schema freeze)

## Context

Success criteria judge a drill from the observations it recorded, but *what* the
engine records today is mostly check step outcomes. An evaluator needing richer
evidence — container logs at the moment of injection, runtime inspect state, a
polled external probe, a Prometheus metric — had nowhere to declare it, so runs
were recorded without the very evidence a later verdict depends on.

## Decision

- **`observability` is an optional, additive top-level DSL section** (per
  ADR-M4-1) collecting *evidence* into the outcome record, independent of the
  run's own verdict.
- **Four closed source kinds**, discriminated by `kind`:
  - `logs` — container log tail (bounded `tail` 1–10 000, optional `since` filter),
  - `inspection` — container runtime inspect JSON as key/value evidence,
  - `probe` — a `probe` (the same closed probe union as checks) polled on a
    `cadence` (0 = collect once),
  - `metrics` — a Prometheus text-format scrape resolved to a single sample value,
    polled on a `cadence`.
- **Every source is named** (`source_id`, unique within the section) so
  observations can be cross-referenced by later evaluators.
- **Every source is bounded.** Per-source `timeout` (default `10s`) and an
  overall `total_timeout` (default `30s`) bound the whole pass; a source whose
  timeout would exceed the section total is a schema error.
- **Sources are best-effort.** A failing source is recorded as a skip note in
  the run's evidence; it is never fatal to the run.
- The executor collects the sources at the end of the run, persists them on the
  run row, and reports `observations: n/m sources collected` in the summary.
  `metrics`/`logs`/`inspection` use the resolved compose container identity
  (ADR-0020); `probe` uses the probe's own declared locus via the check model
  (ADR-M4-2).

## Consequences

Runs record the evidence future evaluators need, uniformly named and bounded.
Because collection is best-effort and bounded, a broken Prometheus endpoint or a
log rotation race degrades evidence quality without poisoning the run's
verdict. The decision is registered as a governing decision on the run row per
ADR-M4-1.