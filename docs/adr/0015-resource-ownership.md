# 0015. Resource Ownership and Conflict Management

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0005](0005-recovery-model-lease-journal-janitor.md) (lease lifecycle), [ADR-0014](0014-execution-context-model.md) (execution context)

## Context

Fault injection creates or modifies system resources: tc qdisc rules, iptables chains, cgroup limits, toxiproxy toxics, container states, etc. Before this ADR, resource lifecycle was tracked only per-lease — there was no cross-experiment resource ownership model, no conflict detection between concurrent experiments, and no ownership-aware recovery.

## Decision

Every fault that mutates system state declares **tracked resources** — typed, persistent records of what was created, who owns it, and how to clean it up.

### Resource model

`TrackedResource` captures:
- `resource_type` — tc_rule, iptables_rule, cgroup_limit, toxiproxy_toxic, container_state, etc.
- `owner_run_id`, `owner_step_id`, `owner_fault_id` — ownership tuple
- `state` — pending → active → recovering → recovered | dirty | orphaned
- `cleanup_op` — idempotent undo command
- `verify_probe` — post-cleanup verification

### Conflict detection

The `ResourceOwnershipGraph` detects conflicts between experiments:
- **COEXIST** — different resource types on same target → OK
- **SERIALIZE** — same resource type on same target by different runs → must not overlap
- **REJECT** — irreconcilable conflict → experiment cannot run

### Ownership-aware recovery

`ResourceManager.recover_owned(run_id)` cleans up only resources owned by the specified run. `ResourceManager.recover_orphans()` handles stale resources after controller crashes. Recovery is ordered: network rules before process signals.

### Persistence

Resources are persisted in SQLite `tracked_resources` table before injection (write-ahead). The in-memory graph reloads from SQLite on controller startup.

## Consequences

- Cross-run resource conflicts are detected before injection, not after.
- Recovery is deterministic: only the owning run can clean up its resources.
- Orphan detection catches leaked resources from crashed controllers.
- Every resource must have a verify probe — recovery is not complete until verified.
