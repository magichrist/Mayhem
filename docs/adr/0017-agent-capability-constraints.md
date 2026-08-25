# 0017. Agent Capability Constraints

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0003](0003-agent-architecture.md) (agent architecture), [ADR-0012](0012-safety-gates-inventory.md) (safety gates)

## Context

In v0.1.0, any registered agent could handle any fault. There was no way to restrict which faults an agent can inject, which resources it can touch, or whether it can execute shell commands or make network calls. This is acceptable for development but insufficient for production environments where different agents serve different trust boundaries.

## Decision

Every agent declares `AgentCapabilities` at registration time:

**Capability kinds:**
- `fault_inject` — can inject specific fault types
- `fault_undo` — can clean up specific fault types
- `probe_run` — can execute observation probes
- `resource_access` — can touch tracked resources
- `network_access` — can make outbound network calls
- `shell_exec` — can execute shell commands on hosts

**Fault matching:**
- Specific match: `"net.latency"` matches only `net.latency`
- Prefix match: `"net."` matches `net.latency`, `net.partition`, etc.
- Empty allowlist: all faults allowed (backward compatible default)

**Validation:** `AgentIdentity.validate_fault_dispatch(fault_id)` is called by the controller before dispatching any task. Rejected dispatches raise `InvariantViolationError("agent.capability.denied", ...)`.

## Consequences

- Agents with limited capabilities cannot exceed their authorization.
- Empty capabilities = deny all (fail-closed default).
- Empty allowlists = allow all (backward compatible for unrestricted agents).
- The existing `CapabilityRegistry` is unaffected — it registers agent *types*, while `AgentCapabilities` constrains agent *instances*.
