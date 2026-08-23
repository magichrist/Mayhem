# System Overview

Tgondi is a **chaos experiment orchestration engine**: it discovers a system's topology, plans and
executes controlled failure experiments through specialized agents, observes the effects, evaluates
hypotheses, guarantees recovery, and records everything for learning and audit.

> Design decisions referenced below are recorded in [../adr/](../adr/). This document describes
> *what each subsystem is*; linked documents describe *how each works*.

---

## 1. Architecture diagram

```
                        ┌───────────────────────────────────────────────────┐
                        │                   CONTROLLER                       │
                        │                                                   │
 tgondi.yaml ──► Config Loader ──► Policy Engine (allowlists, budgets, gates)
                        │                                                   │
 experiments/*.yaml ──► DSL Compiler ──► ExecutionPlan                      │
                                          │                                  │
                        ┌─────────────────▼──────────────┐   ┌──────────────┐│
                        │        EXPERIMENT ENGINE       │   │    MANIAC    ││
                        │  step scheduler · phase machine│◄──┤    ENGINE    ││
                        │  leases · janitor · abort paths│   │ (plan gen.)  ││
                        └───────┬───────────────┬────────┘   └──────▲───────┘│
                                │               │                   │ history │
                     ┌──────────▼─────┐  ┌──────▼───────┐  ┌────────┴───────┐│
                     │ AGENT COORDIN. │  │   RECOVERY   │  │  OBSERVER HUB  ││
                     │ pools, routing │  │   MANAGER    │  │ event bus →    ││
                     └──┬──────────┬──┘  └──────────────┘  │ journal, sinks ││
          ndjson/stdio  │          │  ndjson over SSH exec │ └───────────────┘│
                 ┌──────▼─────┐ ┌──▼──────────┐                                 │
                 │ HOST A     │ │ HOST B      │   … N hosts (local or remote)   │
                 │ (local)    │ │ (SSH)       │                                 │
                 │ tgondi-    │ │ tgondi-     │                                 │
                 │ agent      │ │ agent       │                                 │
                 │  ├ roles   │ │  ├ roles    │                                 │
                 │  └ toolkit │ │  └ toolkit  │                                 │
                 │ docker /   │ │ bare-metal  │                                 │
                 │ podman /   │ │ processes   │                                 │
                 │ compose    │ │ systemd svc │                                 │
                 └────────────┘ └─────────────┘                                 │
                        SQLite (WAL) · text journal · artifact store            │
                        └───────────────────────────────────────────────────┘
```

Key structural facts ([ADR-0002](../adr/0002-python-single-package-layered-monorepo.md),
[ADR-0003](../adr/0003-controller-agent-communication-jsonrpc-over-stdio-and-ssh.md)):

- Agents are ordinary processes speaking newline-delimited JSON-RPC over stdio. Locally they are
  spawned children; remotely they run as the payload of persistent SSH exec channels.
- **Agents never listen on ports.** Every connection is controller-initiated.
- Only the controller writes storage ([ADR-0007](../adr/0007-sqlite-wal-single-writer-persistence.md)).

## 2. Subsystems

| Subsystem | Responsibility | Explicitly NOT responsible for |
|---|---|---|
| **Config Loader** | Parse, overlay, validate `tgondi/v1`; snapshot effective config per run | Runtime decisions |
| **Topology Service** | Build `TopologyGraph` from providers (compose/docker/podman/host); drift reports | Executing faults |
| **Planner / DSL Compiler** | Compile experiment YAML → validated `ExecutionPlan` | Choosing tools (delegates to toolkit resolution) |
| **Experiment Engine** | Drive lifecycle state machine, schedule steps, enforce timeouts/abort | Talking to the OS directly |
| **Agent Coordinator** | Agent pool per host/role; route tasks; heartbeats; reconnects | Understanding fault semantics |
| **Toolkit Registry** | Per-host tool manifests, capability probing, adapter invocation, fallback chains | Deciding *which* fault runs |
| **Recovery Manager** | Lease bookkeeping, compensation execution, verification, janitor | Injecting anything |
| **Observer Hub** | Typed domain-event bus; journal writer; sink fan-out | Mutating anything |
| **Safety/Policy Engine** | Environment identity, allowlists, risk gates, blast-radius budget, audit log | Being bypassable — sits between planner and executor |
| **Maniac Engine** | Candidate generation → scoring → seeded sampling → plan synthesis | Executing anything itself |

Detailed pages: [experiment-engine.md](experiment-engine.md),
[maniac-engine.md](maniac-engine.md), [recovery.md](recovery.md),
[safety.md](safety.md), [observation.md](observation.md).

## 3. The four-way separation (non-negotiable)

| Layer | Knows about | Never touches |
|---|---|---|
| **Controller** | Experiments, plans, topology, policy, leases, agents, history | Binaries, netlink, containers |
| **Agent** | Executing a *capability* on its host given its privileges; lease TTL watchdog | Other hosts, global policy |
| **Toolkit** | Tool manifests, argv construction, probing, capture, fallback | Why a tool is being run |
| **Observer** | Recording events/observations | Mutating anything |

This separation is enforced structurally: import-linter rules
([ADR-0002](../adr/0002-python-single-package-layered-monorepo.md)), protocol boundaries
([ADR-0003](../adr/0003-controller-agent-communication-jsonrpc-over-stdio-and-ssh.md)), and the
lease protocol ([ADR-0005](../adr/0005-recovery-model-lease-journal-janitor.md)).

## 4. Deployment topologies

### Single host (dev/laptop-in-VM)
Controller + local agent on the same Linux machine managing its own processes and a Docker/Podman
Compose stack. No SSH configuration required.

### Multi-host (MVP-supported)
Controller on one machine; remote bare-metal hosts configured under `hosts:` with SSH details.
Bootstrap via `tgondi agents install --host user@host`
([agent-architecture.md §bootstrap](agent-architecture.md)). Blast-radius budgets span hosts;
the janitor reconciles remote leases over SSH after crashes.

### Future
Kubernetes (providers only — [ADR-0013](../adr/0013-kubernetes-readiness-via-provider-seams.md)),
REST API/UI mounting existing `controller.api` services.

## 5. Walkthrough: one experiment end-to-end

```text
tgondi run experiments/pg-degradation.yaml
 1. Config Loader merges/snapshots effective config.
 2. Safety Engine computes environment fingerprint; refuses mismatch.
 3. Topology Service discovers devstack graph (compose blueprint ∩ docker runtime) + drift report.
 4. DSL Compiler validates YAML → ExecutionPlan (steps, targets resolved against live topology).
 5. Policy gates pass (allowlist triple-gate, risk ceiling, blast radius).
 6. Engine executes steps:
      - INJECT net.latency on postgres → coordinator routes task to network-role agent
        → toolkit resolves backend (tc via nsenter; falls back toxiproxy) → undo_json persisted
        BEFORE injection → lease activated → tc qdisc added.
      - StartLoad k6 baseline (load-role agent).
      - ObservationWindows evaluate hypothesis probes (pre/during/post).
 7. Duration elapses → RECOVER: compensation removes qdisc → verify probe passes → lease released.
 8. EVALUATE checks results; Observer writes journal block + SQLite rows + artifacts.
 9. Summary renders narrative (what ran, symptoms, root symptom, recovery time).
```

Crash anywhere between 6 and 7? Watchdog TTL expires the lease and the agent self-compensates;
next controller start, the janitor closes the loop
([ADR-0005](../adr/0005-recovery-model-lease-journal-janitor.md)).

## 6. Non-goals

- Not a penetration-testing tool (no scanning/exploitation primitives) — see
  [safety.md §charter](safety.md).
- Not a load-testing product; k6/Locust are orchestrated as first-class citizens, not replaced.
- No web UI before the execution engine is proven.
- No Kubernetes coupling before v1.0.
