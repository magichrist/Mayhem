# Experiment Engine

The engine drives one canonical lifecycle for **every** experiment — deterministic YAML, multi-fault,
parallel, scheduled, or Maniac-generated ([ADR-0009](../adr/0009-maniac-deterministic-weighted-stochastic-planner.md)).
Random plans are compiled to the same `ExecutionPlan` type as hand-written ones.

---

## 1. Lifecycle

```text
DISCOVER → PLAN → VALIDATE → PREPARE → INJECT → OBSERVE → EVALUATE → RECOVER → VERIFY → RECORD → SUMMARIZE
```

| Phase | Owner | What happens |
|---|---|---|
| DISCOVER | Topology service | Build/refresh `TopologyGraph`; drift report; resolve `TargetRef`s against live state |
| PLAN | DSL compiler / Maniac | YAML or constraints → `ExecutionPlan` (steps DAG, seed context, safety envelope) |
| VALIDATE | Safety engine | Schema checks; allowlist gate 2; blast-radius fit; capability availability per host; dry-run gate |
| PREPARE | Steps | Load generators warmed; probes baseline (`pre` steady-state window); leases created with write-ahead undo |
| INJECT | Agents | Fault backends applied via tasks; leases → `active` |
| OBSERVE | Observer hub | Events/journal stream; `during` windows evaluated; load runs concurrently |
| EVALUATE | Evaluation runner | Steady-state checks per phase; violations trigger policy (`on_violation`) |
| RECOVER | Recovery manager | Duration end / abort / violation ⇒ release all active leases in reverse order |
| VERIFY | Validation role | Per-fault verification probes must pass before `released` |
| RECORD | Storage | Run row finalized: status, timeline, evaluations, artifacts refs |
| SUMMARIZE | Reporting | Human-readable narrative block written to journal + stdout |

## 2. Step scheduling

- Steps execute in declaration order; a `parallel` step fans out concurrent child steps joined by
  barrier semantics.
- Concurrency bounded by the run's `BlastRadiusBudget.max_concurrent_faults` — the scheduler is the
  enforcement point, not convention.
- Each step carries `timeout`, optional `retries`, and an explicit `on_failure` policy:

| Policy | Behavior on step failure |
|---|---|
| `abort_and_recover` *(default)* | stop scheduling; recover all active leases; run = `failed`/`aborted` |
| `continue` | record failure; keep executing remaining steps |
| `skip_recovery_no` | invalid for fault-injecting steps; rejected at validation |

## 3. Determinism & replay

- `seed: null` derives a seed at plan time and records it (run row + Maniac decision rows).
- Replay = same seed + same config snapshot + same topology snapshot ⇒ identical plan and
  selections; topology/config snapshots are pinned to the run precisely so replays are honest.

## 4. Abort paths ([ADR-0012](../adr/0012-safety-model-environment-identity-and-risk-gates.md))

| Trigger | Semantics |
|---|---|
| SIGINT | graceful: finish current non-fault step → recover all active leases → summarize |
| SIGUSR1 / ABORT file | immediate: cancel running tasks → recover all leases → summarize |
| Pre-window steady-state breach | per-check policy (`skip` run vs abort) |
| During-window breach | `on_violation: abort_and_recover` default |

## 5. Experiment shapes supported

single-fault · sequential multi-fault · parallel/concurrent faults · fault+load composition ·
scheduled runs (external scheduler invokes CLI) · random (Maniac) · manual single faults
(`tgondi run --fault net.latency …`) for development.

## 6. Failure semantics summary

| Event | Guarantee |
|---|---|
| Controller crash mid-run | watchdog TTLs self-compensate; janitor finishes reconciliation next start |
| Agent crash mid-task | channel EOF ⇒ orphaned lease ⇒ janitor reclaims using write-ahead undo |
| Step timeout | cancel + compensate inline; policy decides continue/abort |
| Verification probe fails post-recovery | lease `dirty`; loud warning in summary; runbook pointer |

See [architecture/recovery.md](recovery.md) for the lease machinery and
[reference/experiment-dsl.md](../reference/experiment-dsl.md) for authoring syntax.
