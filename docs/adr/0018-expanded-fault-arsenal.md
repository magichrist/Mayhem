# 0018. Expanded Fault Arsenal

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0004](0004-fault-taxonomy.md) (fault taxonomy), [ADR-0014](0014-execution-context-model.md) (execution context)

## Context

The v0.1.0 fault catalog covers 12 faults across 9 categories (process, cpu, memory, storage, network, container, node, http_api, database, load, fuzz). Missing categories: DNS, TLS, clock skew, and file descriptor exhaustion — all common failure modes in production systems.

## Decision

Add 5 new fault definitions across 4 new categories:

| Fault ID | Category | Risk | Targets | Description |
|---|---|---|---|---|
| `dns.resolve_delay` | dns | MEDIUM | service, host | Add latency to DNS resolution |
| `dns.nxdomain` | dns | HIGH | service, host | Return NXDOMAIN for a domain |
| `tls.certificate_expired` | tls | HIGH | service, ext_dep | Present expired TLS certificate |
| `clock.skew` | clock | HIGH | host, container | Shift system clock by N milliseconds |
| `fd.exhaust` | fd | HIGH | service, container, host | Consume available file descriptors |

**New FaultCategory values:** `DNS`, `TLS`, `CLOCK`, `FD`

**New prefix mappings:** `dns → DNS`, `tls → TLS`, `clock → CLOCK`, `fd → FD`

**Backward compatibility:** All new faults use existing `ParamSpec` and `ParamType` primitives. No schema changes. Old specs that don't reference these faults are unaffected.

## Consequences

- Catalog grows from 12 → 17 fault definitions (42% increase).
- 4 new failure categories covered that are common in Kubernetes/cloud-native environments.
- All new faults declare appropriate `required_caps` (NET_ADMIN for DNS/clock) to prevent unauthorized use.
- The `fd.exhaust` fault requires careful `max_duration_s` (120s) to prevent permanent damage.
