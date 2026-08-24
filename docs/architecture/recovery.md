# Recovery Architecture

The guarantee: **a fault is never silently left behind** — under controller kill, agent kill,
channel loss, or operator interrupt. Design record: [ADR-0005](../adr/0005-recovery-model-lease-journal-janitor.md).

---

## 1. The FaultLease

A lease is created **before** any mutation and persisted with write-ahead undo data:

```jsonc
// undo_json (NOT NULL before state can become active)
{
  "steps": [
    {"op": "iptables.delete_chain", "args": {"chain": "TGP-l-a1f3"}, "idempotent": true},
    {"op": "tc.del_qdisc", "args": {"dev": "eth0", "handle": "1:"}, "idempotent": true}
  ],
  "verify": [{"probe": "exec", "cmd": ["iptables", "-L", "TGP-l-a1f3"], "expect_absent": true}],
  "owner_agent": "ag-bm-1-process",
  "created_at": "...", "ttl_seconds": 120
}
```

State machine ([domain-model](domain-model.md) §3):

```
pending ──inject──► active ──duration/abort──► releasing ──verified──► released
   │                   │                          │
   └ never activated   ├ TTL watchdog fires ────► expired   (agent self-compensated)
                       └ owner unreachable ─────► orphaned  (janitor reclaims)
                                                  dirty     (compensation failed → LOUD escalation)
```

## 2. Compensation layers (defense in depth)

| Layer | Actor | Trigger | Scope |
|---|---|---|---|
| 1. Normal release | Recovery manager | duration end / abort / violation | reverse-order release, verification per fault |
| 2. Task cancellation | Agent runtime | step timeout / `task.cancel` / SIGINT graceful path | inline compensate before returning |
| 3. Watchdog self-heal | Agent lease-watchdog thread | TTL expiry | local compensation even if controller dead |
| 4. Janitor reconciliation | Controller startup + periodic | leases not `released`/`expired` | queries owning agent or re-derives from undo_json |
| 5. Manual escape | `mayhem recover` | operator command | full DB-driven sweep; dry-run mode lists residue first |

## 3. Janitor algorithm

On controller start (and every N seconds while idle):

```
for each lease in {pending, active, orphaned}:
    agent = resolve(lease.owner_agent)
    if agent alive:
        ask agent to compensate(undo_json); verify probes
    else:
        re-derive executor from undo_json (controller-side best effort
        for host-level ops; spawn one-shot SSH task if transport exists)
    if verify passes: mark released (note mechanism used)
    else after retries: mark DIRTY + emit loud event + runbook hint in summary
```

Idempotency rule for undo steps: deleting a qdisc/chain that no longer exists must succeed.
Every bundled backend's undo ops are written idempotent-first.

## 4. Verification

Recovery completes only when the lease's verify probe passes:

| Fault class | Probe example |
|---|---|
| net.* | `tc qdisc show` lacks handle; iptables chain absent |
| proc.pause | target PID state is not 'T' |
| container.pause | engine reports running |
| fs.fill | filler files absent |
| db.conn_exhaust | connection count back under threshold |

Failed verify ⇒ `dirty`: run summary shows a prominent recovery-failure block with the exact
residue and suggested manual commands. Dirty states are escalated, never silent.

## 5. Ordering & concurrency

- Release order = reverse of acquisition order within a run.
- Multi-agent releases proceed concurrently across hosts but serialize per host (agents execute
  tasks sequentially per role by default).
- A run may not enter `completed` until every lease it created is in a terminal safe state
  (`released`, or `dirty` with explicit acknowledgment recorded).

## 6. Failure matrix (exhaustive)

| Scenario | Path to safety |
|---|---|
| Controller killed mid-injection | watchdog TTL on agent compensates locally; janitor reconciles row on restart |
| Agent killed mid-injection | channel EOF → lease `orphaned` → janitor re-derives via undo_json |
| Silent SSH loss | same as agent death from controller view; watchdog still fires |
| Inject succeeded, first recover attempt failed | retry ×N → `dirty` → loud summary block |
| Crash between undo-write and inject | lease still `pending`; janitor deletes it (nothing to undo) |
| Operator Ctrl-C during partition | SIGINT graceful: finish step → recover all → summarize |
| Disk full preventing journal write | SQLite WAL failure fails *closed*: injection refused |

## 7. Testing the guarantees

Chaos-of-the-chaos tests ([testing-strategy](testing-strategy.md) §6) kill controllers and agents
at randomized points mid-injection/mid-recovery and assert the invariant: after convergence,
zero non-terminal leases remain and all verify probes pass.
