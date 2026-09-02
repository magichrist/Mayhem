# ADR-M3-3: Three-locus ExecutionContext
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-0019, ADR-0020, ADR-M1-1, ADR-M3-2, ADR-M3-5
## Context
The pre-refactor `ExecutionContext` was a single enum (`host | container |
process | network | remote`) describing *where the fault lands*. That conflates two
independent questions: where the mutation lands (target) and where the agent/tool
that performs it actually runs. "Inject into a remote pod" and "run a local tool
that mutates a remote target" are different things. With remote execution and
Kubernetes on the horizon (ADR-M3-5 / ADR-M3-6), the single locus cannot express who
runs *what* from *where*.
## Decision
Replace the single-locus context with a **three-locus** model:
- `target_locus` — where the mutation lands (host / container / network-namespace /
  remote pod).
- `agent_locus` — where the controlling agent runs.
- `tool_locus` — where the mutation tool executes.

Each locus is a `LocusSpec(kind, identifier)` so the planner can attach a resolved
id (container id, ns path) once known. `ThreeLocusContext` retains the legacy
`plan_context: ExecutionContext` for M2 drift-detection and planner
back-compatibility.
- **Backward compatible:** `from_single(context)` derives all three loci from the
  legacy single-locus value, so pre-0.3.0 specs and `ExecutionContext` scale
  unchanged.
- Drift detection compares the **target locus identity**, not the authored name
  (ADR-M1-1).
## Consequences
- The engine can reason "tool runs locally → mutates container X" vs "tool runs in
  container → mutates remote Y" unambiguously.
- A lazy `ExecutionContext.to_three_locus()` bridge lets legacy callers upgrade
  without a migration.
- The target-locus identity becomes the drift-compare key, matching ADR-M1-1.
