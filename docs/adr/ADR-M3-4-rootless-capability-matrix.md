# ADR-M3-4: Rootless capability matrix — verdicts, not workarounds
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-1, ADR-M3-2, ADR-0013, ADR-0019, ADR-0020
## Context
Podman runs two distinct privilege modes: **rootful** and **rootless**. The rootless
mode runs the user-namespace, so capabilities that assume a single shared namespace
behave differently or not at all:
- `netns` requires `podman unshare nsenter` and may be unavailable or require
  elevation.
- resource limits (cgroup `--memory`/`--cpus` on the target) are often rounded,
  unenforced, or blocked outright.
- `exec`, `pid`, `inspect`, and `signal` generally keep working.

Baking a single capability answer for "podman" hides this split and lets plans demand
netns/resource-limit guarantees that cannot be honoured, producing silent faults or
half-applied mutations.
## Decision
The `PodmanAdapter` detects rootless mode at construction (`podman info` →
`security.rootless`) and emits a **capability matrix that is mode-aware** (ADR-M3-2):
- rootful: `EXEC=SUPPORTED`, `PID=SUPPORTED`, `SIGNAL=SUPPORTED`,
  `NETNS=SUPPORTED`, `RESOURCE_LIMITS=SUPPORTED`, `INSPECT=SUPPORTED`,
  `COMPOSE_FILTER=SUPPORTED`.
- rootless: same, except `NETNS=ALTERNATIVE` (requires `unshare nsenter`,
  caller must degrade gracefully) and `RESOURCE_LIMITS=UNSUPPORTED`.

We deliberately **do not** build unsupported workarounds for rootless gaps. The
matrix records the honest verdict and lets the planner refuse (`UNSUPPORTED` blocks)
or degrade (`ALTERNATIVE` warns) per policy. This keeps the tool bounded: no half
features, no fake guarantees.
## Consequences
- Rootless pods that need netns see an `ALTERNATIVE` verdict; callers must treat it
  as best-effort.
- Rootless resource-limit faults are refused at plan time with a clear message
  instead of silently no-op'ing at runtime.
- The matrix is a single source of truth consumed by `validate_plan`'s capability
  gate (ADR-M3-2) and by any future port/planning UI.
