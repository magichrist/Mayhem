# 0005. Recovery Model: Leases + Write-Ahead Undo Journal + Janitor Reconciliation

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0003](0003-controller-agent-communication-jsonrpc-over-stdio-and-ssh.md) (crash
  independence), [architecture/recovery.md](../architecture/recovery.md) (full design)

## Context

Mayhem intentionally breaks systems. The single most important architectural requirement is that
**a fault is never silently left behind** — including when:

- the controller is SIGKILLed mid-injection,
- the agent dies mid-cleanup,
- an SSH channel drops silently between hosts,
- the operator Ctrl-C's during a partition experiment.

`inject()` without a guaranteed `recover()` is a defect, not a shortcut.

## Options considered

1. **try/finally around injection.** Cannot survive process death; finally-blocks die with the
   interpreter. Insufficient alone.
2. **Saga/compensation pattern only.** Correct sequencing logic, but sagas assume someone executes
   compensations — they have no answer to "nobody came back".
3. **Immutable-infrastructure rollback.** Wrong granularity and latency for process/network faults;
   only fits container recreation.
4. **Leases + write-ahead undo journal + janitor + agent-side TTL watchdog.** Chosen.

## Decision

Every fault invocation is governed by a **FaultLease**, persisted in SQLite before any mutation:

1. **Write-ahead undo:** the lease row stores `undo_json` — idempotent compensation commands
   (`tc.del_qdisc`, `iptables.delete_chain`, `container.unpause`, `process.resume`,
   `cgroup.set_limit`, …) — **before** the fault is injected.
2. **Lease states:** `pending → active → releasing → released | expired | orphaned | dirty`.
3. **Agent-side watchdog:** each agent runs a thread that expires its own leases past TTL and
   compensates locally — this works even if the controller never comes back.
4. **Janitor:** on controller start (and periodically), open leases are reconciled against live
   system state via the owning agent, or re-derived from `undo_json` if the agent is gone.
5. **Verification:** recovery is not complete until a per-fault verification probe passes
   (e.g., tc rule absent, container running, health endpoint 200). Unrecoverable residue is marked
   `dirty` and escalated loudly in run summaries with runbook hints — never silent.

## Consequences

- **Positive:** crash-safe under every failure combination we can construct; manual escape hatch
  (`mayhem recover`) always has authoritative data to work from; auditable ownership of every
  active mutation.
- **Negative / accepted trade-offs:** every fault implementation must author idempotent undo steps
  up front (more upfront work than try/finally — this is the point); leases add DB round-trips to
  hot paths (negligible at our scale); `dirty` states are possible in principle but must be loud,
  never silent.
