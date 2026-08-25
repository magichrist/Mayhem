# 0021. Load Generation Strategy Model

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0004](0004-fault-taxonomy.md) (fault taxonomy)

## Context

Load faults (`load.spike`) exist in the catalog, but there's no structured model for *how* load is generated — patterns, phases, concurrency targets, or fuzzing strategies. The existing `LoadProfile` (VUs + duration) is too minimal to express multi-phase load tests.

## Decision

Two new value objects in `domain.load_strategy`:

**`LoadPhase`** — one phase of load:
- `pattern` — `constant`, `ramp_up`, `ramp_down`, `burst`, `spike`, `step`
- `vus` / `rps` — concurrency or throughput target
- `duration` — phase length in seconds
- `ramp_seconds` — ramp time for ramp patterns
- `target_vus` / `target_rps` — endpoint for ramp patterns

**`LoadStrategy`** — complete multi-phase profile:
- `phases` — sequential tuple of `LoadPhase`
- `endpoint`, `method`, `headers`, `timeout` — target configuration
- `total_duration()` — sum of all phase durations
- `max_concurrency()` — peak VUs across phases
- Factory methods: `constant_profile()`, `ramp_profile()`

**`FuzzStrategy`** — configuration for protocol fuzzing:
- `target_field`, `mutations_per_request`, `max_requests`
- `seed` for deterministic fuzzing
- `dictionary` for custom mutation payloads

All models are frozen Pydantic, JSON-serializable.

## Consequences

- The controller can orchestrate multi-phase load during chaos experiments.
- The planner can reason about load intensity without knowing tool specifics.
- Fuzzing strategies are now first-class and composable with load profiles.
- Backward compatible: existing `LoadProfile` in experiments is unaffected.
