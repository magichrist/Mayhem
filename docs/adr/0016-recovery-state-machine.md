# 0016. Recovery State Machine and Audit Trail

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0005](0005-recovery-model-lease-journal-janitor.md) (lease lifecycle), [ADR-0015](0015-resource-ownership.md) (resource ownership)

## Context

Recovery in v0.1.0 was implicit — the executor called `undo()` on a lease and checked the result. There was no formal state machine, no audit trail of recovery attempts, no retry limit, and no way to distinguish "recovery succeeded but verify failed" from "recovery never ran."

## Decision

Resource recovery follows a validated state machine:

```
IDLE → RECOVERING → VERIFIED (terminal)
                  ↘ DIRTY → RECOVERING → ...
```

**Transitions:**
- `IDLE → RECOVERING` — cleanup initiated
- `RECOVERING → VERIFIED` — cleanup succeeded, probe satisfied
- `RECOVERING → DIRTY` — cleanup failed or verify failed
- `DIRTY → RECOVERING` — retry (max 3 attempts)
- `VERIFIED` — terminal, no outgoing transitions

**Every transition** is recorded in the `recovery_audit_log` table with:
- resource_id, from_status, to_status, reason, attempt number, timestamp

**Retry exhaustion:** After `MAX_RETRIES` (3) dirty→recovering cycles, the resource is flagged as unrecoverable and requires manual operator intervention.

## Consequences

- Recovery is idempotent — safe to retry from any crash point.
- Every state change has a machine-readable audit trail.
- The Janitor can query `RecoveryAuditLog.current_status()` to decide whether to retry or escalate.
- DIRTY resources with exhausted retries are surfaced in `RunResult.dirty_leases`.
