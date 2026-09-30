# v1.0.0 — positioning and thesis

## What mayhem is today

Measured, not aspirational:

| | |
| --- | --- |
| Catalog | **141** fault definitions — 128 executable, 13 refusals |
| Container-lane executable | **67**, each with an executor, a compensation template, and a tool-requirement entry |
| Source | 171 files, **51,062** lines |
| Tests | 165 files, **43,514** lines — suite runs in ~2 min, `15487 passed` |
| CLI | 16 root commands |
| Runtime | local container engines (Docker/Podman) + Kubernetes, no server, no cluster required |

**The three strongest things mayhem has that nobody else does:**

1. **Compensation is structural, not aspirational.** Every planned non-k8s fault
   must carry at least one `UndoOp` and one `VerifyProbe`; `compensated()` raises
   `plan_uncompensated_fault` and the planner refuses the drill otherwise. A
   fault that cannot be undone cannot be planned. This is enforced by a matrix
   over *every* catalog fault × 6 compose containers, not by convention.
2. **Evidence bundles.** `mayhem bundle verify` checks schema, hashes, chain
   order and signature; replay capsules are exportable and re-validatable. A
   chaos run produces an auditable artifact, not a log line.
3. **No cluster required.** Chaos Mesh and Litmus both need Kubernetes as the
   control plane. Mayhem runs against a `docker-compose.yml` on a laptop.

**The three most consequential weaknesses:**

1. **Zero faults have ever been promoted past `verified-unit`.** 128 executable
   faults, 0 `verified-live`, 0 `stable`. The maturity model in
   `catalog_report.MATURITY_PROMOTION_CRITERIA` defines the top rungs; nobody
   has climbed them. For a 1.0 this is the single most embarrassing gap — a
   chaos tool whose fault catalogue has never been verified against a live
   runtime is making a claim it has not earned.
2. **`hypothesis` is prose, not a program.** `DrillSpec.hypothesis` is a free
   string. `success.criteria` is declarative but boolean. There is a
   `steady_state_evaluations` table in the schema and nothing writes a tolerance.
   This is precisely the position the market research says is unclaimed.
3. **No dry run.** `mayhem run` requires `-e/--execute`; the preflight prints a
   blast-radius line that is a *looser re-derivation* than the real gate
   (`preflight._blast_radius_for` omits `dependents_closure`). The number shown
   is not the number enforced.

## The thesis for 1.0.0

> **Mayhem is the chaos tool that tells you whether the system was supposed to
> survive, and proves what it actually did.**

Every competitor's verdict is a boolean: probe passed, probe failed, alarm
state. Mayhem is one layer up and has the unique raw material for it — a
write-ahead undo contract, a verification probe on every fault, replay capsules,
and a hash-chained evidence bundle. None of the CNCF projects can even express
"latency rose 18% and that was inside the band"; they have no tolerance field
in any CRD. Mayhem has a probe on every single fault and simply isn't comparing
against a baseline yet.

That is the 1.0 bet: **stop adding fault ids and start making the verdict
mean something.**

## Where mayhem wins

| Dimension | Mayhem | Chaos Mesh | Litmus | AWS FIS |
| --- | --- | --- | --- | --- |
| Needs Kubernetes | **no** | yes | yes | no (cloud API) |
| Undo/compensation contract | **structural, per fault** | runtime reconcile state | rollback in `ChaosResult` | recovery actions |
| Auditable evidence artifact | **yes, hash-chained** | k8s events | Prometheus metrics | experiment log |
| Fault count (container lane) | 67 | ~90 (mostly k8s+BM) | 53 | ~60 (cloud-scoped) |
| Kernel/BPF depth | none | **KernelChaos, IOChaos, JVMChaos** | none | none |
| Service-aware (RDS/DynamoDB) | none | AWS/GCP/Azure 3/3/3 | 8/4/2 | **deep, first-class** |
| Steady state with tolerance | **planned (1.0)** | HTTP-only threshold counts | probes, no tolerance | alarm-state assertion |
| Dry run | **planned (1.0)** | none | none | none |
| Damage quota over time | **planned (1.0)** | none | none | 5,040 min/7d per table |
| Cost | free, local | free | free | per API call |

## Where mayhem loses, honestly

These are not gaps to paper over in a roadmap. They are capabilities the market
has and mayhem does not, and a user comparing side-by-side will find them.

| Gap | Severity | Note |
| --- | --- | --- |
| **No kernel-layer fault injection** | **high** | Chaos Mesh's `KernelChaos` (BPF) and `IOChaos` (per-path syscalls) reach failure modes `tc`/`iptables`/`python -c` cannot. This is mayhem's largest functional deficit. |
| **No service-aware faults** | **high** | FIS and Chaos Mesh both inject into RDS/DynamoDB/ElastiCache APIs. Mayhem's `db.*` family is a netfilter rule on a port. |
| **No JVM/runtime chaos** | medium | `JVMChaos` targets class and method directly. |
| **No BPF / unprivileged story** | medium | mayhem needs `NET_ADMIN`/`SYS_TIME`/`PROCESS_CONTROL`; there is no unprivileged path. |
| **No recurrence scheduling** | medium | Chaos Mesh `Schedule` (cron), Litmus `ChaosSchedule` (work hours/days). Mayhem has `campaign` but no cron. |
| **No web UI** | medium | Both CNCF projects ship dashboards. mayhem is CLI-only — defensible for its audience, but it will lose procurement conversations. |
| **Never verified live** | **high** | 0 of 128. See above. |
| **62 pre-existing lint errors** | medium | `ruff check src/` is red and has been treated as advisory. |
| **`config.max_faults` is not enforced** | medium | Documented as if it were; the executable control is `blast_radius.max_concurrent_faults`. Corrected in docs at 0.9.1, code not changed. |
| **`fs.read_only` interpolates `path` unquoted** | medium | A latent shell-injection surface in an existing fault. Found during the 0.9.1 work; deliberately not fixed inside a fault-addition commit. |
| **`import-linter` not runnable locally** | low | The three architecture contracts cannot be verified on a dev machine. |

## What 1.0.0 should be

Three things, in priority order. Everything else is optional.

### 1. Earn the maturity claim

`verified-live` and `stable` are currently unreachable in practice: the
promotion criteria in `catalog_report.MATURITY_PROMOTION_CRITERIA` require
recorded verification evidence, and there is no mechanism that produces it. A
1.0 that ships 128 `verified-unit` faults and a maturity model that nothing
climbs is a roadmap, not a release.

Concretely: a repeatable live-verification harness that runs a representative
fault set against a real compose stack and Kubernetes fixture, records the
result against each fault id, and promotes what passes. → [01](02-earn-maturity.md)

### 2. Make the verdict mean something

Executable steady-state hypothesis: baseline capture, per-metric tolerance
bands, explicit before/during/after phases, and a verdict that says *how far it
moved* rather than pass/fail. This is the unclaimed market position, and mayhem
is the only tool that already has a verification probe on every fault to build
it from. → [02](03-steady-state-hypothesis.md)

### 3. Make it safe to press the button

A real dry run — the exact rules, syscalls and PIDs that *would* be applied, the
exact blast radius the gate *would* compute, and the exact undo that *would*
fire — plus a damage quota over time so a repeated campaign cannot quietly
destroy an environment. Neither CNCF project has a simulate field. → [03](04-dry-run-and-quota.md)

## Explicitly out of scope for 1.0.0

Named so the boundary is arguable rather than accidental:

- **Kernel/BPF fault injection.** This is a real deficit, but it is a
  multi-month substrate (bundled BPF object, privileged agent, a new capability
  class) and it would land an untested injection primitive in a *stable* release.
  Better as 1.1. If 1.0 ships without it, say so in the README.
- **A web UI.** Enormous surface, and it competes on a dimension where mayhem's
  CLI is genuinely better for its audience.
- **A hosted/SaaS mode.** The market gap is real (Chaos Mesh's open "Chaos
  Engineering as a Service" issue) but multi-tenancy is a different company.
- **`mq.*` faults.** No broker client, and inventing one in a stable release is
  how you get a 1.0 that corrupts someone's Kafka. Tracked in
  `docs/new-faults/wave-4-new-domains.md`.
- **Promoting the 13 `catalog_only` entries to executable.** Their refusal text
  is the feature. Deleting them to raise a coverage number would be theatre.
