# ADR-M3-2: CapabilityRequirements + verdict matrix
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-1, ADR-M3-4, ADR-M3-5, ADR-M3-6, ADR-0019
## Context
A plan needs to know *before mutating anything* whether the chosen runtime can
actually honour it. A boolean "docker supports network faults" is too coarse:
rootless podman supports `netns` only via `unshare nsenter` (degraded), and
resource limits may be unenforceable. Refusing on a single missing capability
would be too strict; always proceeding would let plans fail midway with silent
no-ops. Both are unacceptable against the identity/attribution guarantees
(ADR-M1, ADR-0019).
## Decision
Model feasibility as a **requirements × verdicts matrix**, not a boolean:
- `CapabilityRequirements(platforms, runtimes, target_kinds, privileges,
  namespaces, tools, kernel_features, permissions)`: what the plan needs from the
  adapter.
- Per-capability verdict: `SUPPORTED | ALTERNATIVE (degraded but safe) |
  UNSUPPORTED | UNKNOWN`. `AdapterCapabilities.verdict(cap)` is a **pure lookup**
  snapshot (no subprocess calls at evaluate time).
- `evaluate(reqs) → VerdictResult` maps requirements to capabilities and sets
  `blocking=True` iff at least one maps to `UNSUPPORTED`. ALTERNATIVE does not
  block — it warns.
- Feasibility is evaluated **at plan time** (`validate_plan(..., adapter=...)`) and
  is re-validated at run time, preserving the M2 pattern.
## Consequences
- UNSUPPORTED blocks the plan with a typed, machine-readable refusal.
- ALTERNATIVE degrades safely with a warning instead of blocking (rootless podman).
- The matrix is a single source of truth shared by the planner and any future
  port/planning UI.
