# ADR-M3-8: Fault registry — per-adapter targeting and precedence
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-1, ADR-M3-2, ADR-M3-7, ADR-0013, ADR-0019
## Context
A fault type (e.g. `network_fault`, `processor_fault`) must know *which runtimes*
can carry it, *on which target kinds* it is meaningful, and — when a target is
reachable by more than one adapter — *which adapter wins*. Without an explicit
registry this resolution logic would be scattered across the planner with
unstated precedence, producing surprises when a target is simultaneously a docker
container and a host process, or when podman exists alongside docker.
## Decision
Introduce a **fault registry** that answers, for a fault type, how it targets and
to which adapter it is delegated:
- **Per-fault-type capability map**: each fault type declares the adapter capability
  it depends on (e.g. `network_fault` → `NETNS`; `processor_fault` →
  `RESOURCE_LIMITS`; `tool_fault` → `EXEC`), so `validate_plan` can consult it when
  building `CapabilityRequirements` (ADR-M3-2).
- **Per-adapter targeting**: a fault that names a target declares *where* the
  mutation lands (target locus, ADR-M3-3). The registry selects the adapter by the
  target's owner runtime (`cont` + `engine`, ADR-0020), falling back to the host
  adapter for host-level targets.
- **Precedence** is explicit and deterministic:
  1. target owner runtime adapter (container/service targets);
  2. host adapter (host/process/network-namespace targets owned by this host);
  3. an explicit adapter override in the fault, if any, wins over the above.
  When the winning adapter cannot support the fault's capability, the registry
  returns the `UNSUPPORTED`/`ALTERNATIVE` verdict (ADR-M3-2) rather than silently
  choosing a less-preferred adapter.
## Consequences
- Fault-to-adapter resolution is a single, testable registry instead of scattered
  planner logic.
- Precedence is deterministic, so the same plan resolves the same way every run.
- The registry composes cleanly with the capability matrix: adapter selection and
  capability verdicts are independent, then combined by `validate_plan`.
