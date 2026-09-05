# ADR-M4-3: Machine-evaluable success criteria + run verdict
**Status:** Approved
**Date:** 2026-09-05
**Deciders:** Ali
**Relates to:** ADR-M4-1 (additive DSL), ADR-M4-2 (execution-locus checks), ADR-M4-5 (schema freeze), ADR-0019

## Context

A drill ends with a wall clock and a pile of steps, but nothing *decides* whether
the system survived the experiment. "It looked fine" is not an assertion the
engine or an autonomous operator can act on. Mayhem needs a machine-evaluable
outcome: a verdict derived from typed assertions over the observations a drill
recorded — never a human eyeball, and never a number the run did not actually
measure.

## Decision

- **`success` is an optional, additive top-level DSL section** (per ADR-M4-1)
  carrying a list of *typed criteria* and a `require_all` flag (default `true`).
- **Five closed criterion types**, discriminated by `type`:
  `status` (measured status == `expected`), `latency` (measured ms < `lt_ms`),
  `metric` (numeric sample within `gt`/`lt` bounds, min one bound), `count`
  (recorded count ≥ `gte`), `boolean` (recorded outcome == `value`).
- **Source ids are observation rows.** A check step `id` records its boolean
  outcome under the bare `id` and each measured scalar under `id.<name>` —
  e.g. `api-up.status`, `api-up.latency_ms`. Criteria address rows by those
  full source ids.
- **Absence of evidence is not success.** A criterion evaluated against a
  missing observation is **false**, and evaluation never raises.
- **The verdict is derived for completed runs only.** An aborted/failed run
  leaves the verdict undecided even when partial observations would satisfy the
  criteria; absent or empty criteria also yield no verdict (an existing run
  without a `success` block keeps behaving exactly as before).
- The executor persists verdict and per-criterion results on the run row, emits
  a `CRITERIA_EVALUATED` event, and the run summary renders them.

## Consequences

Drills can now be graded deterministically (`PASS`/`FAIL`) by the engine, which
is the prerequisite for M5's autonomous loop. Every verdict is attributable to
the recorded observations that produced it; the decision itself is registered
as a governing decision on the run row per ADR-M4-1.