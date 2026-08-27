# MAYHEM — ARCHITECTURE WAKE-UP REVIEW (CONSOLIDATED)

**Reviewers:** Principal Architect & Reliability Engineer (challenge pass) + Senior Architecture Reviewer (hardening pass)
**Scope:** Audit the redesigned architecture (kind: drill, unified spec, container-name-first targeting, execution-time PID/IP resolution, Docker/Podman execution, redesigned planner/executor) **before** further implementation.
**Method:** Read the actual source (`domain/`, `controller/`, `topology/`, `agents/`, `docs/adr/`) and challenge the execution model against real failures, races, restarts, and concurrency. No code was implemented. This document is the **consolidated** answer — it supersedes `answer.md` by tightening every place the first review was under-specified or too optimistic.

---

# 1. PRIMARY QUESTION

```text
READY WITH CORRECTIONS
```

The direction is sound and can evolve into a production-grade chaos platform; the correct next step is **not** to keep redesigning but to **lock the still-open decisions into ADRs and interfaces before implementing**. The foundation (frozen value objects, closed node union, capability/compensation contracts, write-ahead lease journal) is right.

Four areas are **non-negotiable** before "production-grade" is credible:

> **identity, execution context, resource ownership, recovery evidence.**

Everything below is organized to make those four unambiguous.

---

# PART A — ARCHITECTURE LOCK (P0)

## 1. `RuntimeIdentity` must be separated from `RuntimeMetadata` 🔴 HIGH

The first review's composite `RuntimeIdentity = project + service + container_id + epoch` **mixes identity with metadata and treats `StartedAt` as an epoch**. `StartedAt` is not a monotonic creation token — a restored/restarted container can report a different value, and two views can disagree.

**Correction — two distinct objects:**

```text
RuntimeIdentity                         # must be stable & unique for the runtime object
    runtime                             # "docker" | "podman" | "host" | ...
    host_id                             # which host/runtime daemon owns it
    runtime_id / container_id           # PRIMARY identity (the durable id)

RuntimeMetadata                         # correlation & human context (NOT identity)
    project
    service
    replica / container-number
    container_name
    labels
    created_at                          # durable creation time (an epoch candidate)
    started_at                          # volatile; NOT an epoch/identity
```

- **`container_id` (runtime_id) is the primary runtime identity.** `project/service/container_name` are **correlation metadata**, useful for authoring and the janitor, never the equality key.
- **Where each belongs:** Experiment = logical (service/host/port); **Plan** = logical + `RuntimeIdentity`; **ExecutionRecord** = `RuntimeIdentity` + `RuntimeMetadata`; **RecoveryRecord** = the exact `RuntimeIdentity` + live-locator evidence it must act on (so recovery cannot drift to another container).

**Affected:** `domain/topology.py`, `topology/providers/*`, `topology/service.py`, `spec.py`, `controller/planner.py`, ADR-0020 revision.

---

## 2. Process identity must not be `(host, path/comm)` 🔴 HIGH

The first review answered process identity as `(host, path/comm)` — but that is **not reliable** for multiple identical processes (many replicas, same binary). Path+comm is *evidence*, not *identity*.

**Correction — separate intent from runtime truth:**

```text
ProcessSelector              # what the user means (authored)
    host / machine role
    service / container
    executable / path
    port
    pid (authoring hint only, never authoritative)

ProcessRuntimeIdentity       # what currently exists (resolved, evidenced)
    host_id
    container_id?            # if container-backed
    pid_namespace
    pid                      # valid in that ns
    proc_starttime           # machine-unique; PRIMARY reuse guard
    executable / cmdline / user     # verification evidence, NOT identity

```

- **Never claim `(host, path/comm)` is a stable identity.** PIDs are locators; `proc_starttime` + pid + pid-namespace is the defensible runtime identity; executable/cmdline/user are **verification evidence**.
- A host-process target resolves `ProcessRuntimeIdentity` (fresh pid + starttime + evidence) at act time; a container-backed process resolves via `container_id` and **never** falls back to stale pid (see §4 of `answer.md` — keep that rule).

**Affected:** `domain/topology.py`, `topology/resolve.py`, `controller/executor.py`, `controller/compensation.py`.

---

## 3. `TARGET_DRIFT` must be an explicit state 🔴 HIGH

The failure vocabulary (`FAILED_TO_APPLY`, `UNKNOWN`, `DIRTY`, …) is **incomplete**: it has no term for "the thing changed out from under us". The first review folded this into `UNKNOWN`; it is operationally distinct.

**Correction — add an explicit state:**

```text
TARGET_DRIFT
    reason: container_recreated | process_replaced | wrong_pid/cgroup | network_attachments_changed
    planned RuntimeIdentity != live RuntimeIdentity
```

- A plan that planned `container_id=X` but the live inspector returns `container_id=Y` (recreated, same name) → `TARGET_DRIFT`, **not** "fault failed" and not `DIRTY`. It is a *different* operational outcome: safe-abort + fresh re-plan decision, distinct from "injection failed" or "system is dirty".
- Add `TARGET_DRIFT` to the recovery state machine (§12 of `answer.md`) and to the failure matrix (matrix rows 1, 4, 5).

**Affected:** `domain/leases.py`, `domain/experiments.py`, `controller/executor.py`, `controller/recovery.py`, tests.

---

## 4. Capability prerequisites must be a real model, not a slogan 🔴 HIGH

The first review said "strategy selector + plan-time probe" but did not define what a capability *requires*. Without a model, feasibility checks are ad-hoc `if`s.

**Correction — `CapabilityRequirements`, then two-phase validation:**

```text
CapabilityRequirements
    platforms                  # linux, darwin(macos-local-only), ...
    runtimes                   # host, docker, podman, k8s, remote
    target_kinds               # PROCESS, CONTAINER, HOST, NETWORK_NAMESPACE, SERVICE
    privileges                 # root? CAP_NET_ADMIN? user-ns?
    namespaces                 # pid / net / cgroup / mount
    required_tools             # tc, iptables, stress-ng, nsenter, podman
    required_kernel_features   # cgroup v2, net_cls, iptables-nft, ...
    required_permissions       # can-write-cgroup, can-manipulate-netns, ...
```

Then **both** phases are mandatory and have distinct jobs:

```text
plan-time feasibility       = can this capability POSSIBLY run here? (static: platform, runtime, tools-present-at-plan, privileges-known)
execution-time validation   = is it STILL valid right now? (tools still present, permission still held, container still the same)
```

Plan-time misses live mutation (a tool uninstalled mid-run, an agent dropping privileges, a container recreated). Keep both; a capability is *plan-feasible* and then *execution-validated* immediately before action.

**Affected:** `domain/capabilities.py`, `domain/faults.py`, `toolkit/registry.py`, `controller/planner.py`, `controller/executor.py`.

---

## 5. Tool selection must NOT be plan-time-only 🔴 HIGH

The first review stated unavailable tools should fail at *planning*. **Too strong.** Live state can change after planning: a tool can disappear, an agent can lose permission, a host can be recreated.

**Correction — retain two checkpoints (mirrors §4):**

```text
plan-time capability feasibility   → warn/hard-fail on statically-impossible combos
execution-time capability validation → RE-resolve tool + permission immediately before acting;
                                        on change → TARGET_DRIFT / FAILED_TO_APPLY, never guess
```

The **tool is selected at plan time** from the provider registry (deterministic), but its **availability is revalidated at execution time** before mutation. This removes the "plan passes, runtime silently does nothing-or-wrong-thing" class of failure.

**Affected:** `toolkit/registry.py`, `agents/executors.py`, `controller/executor.py`.

---

# PART B — EXECUTION ENGINE (P1)

## 6. `FaultGroup.mode = "atomic"` is dangerous — redefine the modes 🔴 HIGH

`parallel|sequential|atomic` is the wrong trinity. **True transactional rollback does not exist for external side effects**; claiming `atomic` invites an unmeetable contract.

**Correction:**

```text
FaultGroup.mode
    parallel      # run members concurrently; each has its own lease/compensation
    sequential    # run members in declared order; each has its own lease/compensation
    best_effort   # attempt all; compensate whatever was APPLIED (the default)
```

If you keep `atomic`, **redefine** it as:

> **attempt all-or-compensate-applied-members** — i.e. "all-or-nothing in *commit intent*", never *transactional atomicity* of external mutation.

Every member still carries its own `FaultInvocation` + lease + owned-resources + verdict, so a group reports **partial failure** with per-fault status (§9 of `answer.md`).

**Affected:** `domain/experiments.py`, `controller/planner.py`, `controller/executor.py`, `spec.py`.

---

## 7. Parallel groups need a persistent group identity 🔴 HIGH

First review: "don't rely on list order / equal seq". Add the **durable** side: persist the group structure in the journal/database so recovery and replay are deterministic after a restart.

**Correction — persist fields on every fault/step row:**

```text
execution_group_id
parent_group_id
group_path          # e.g. /root/g1/g1.2  (deterministic ordering)
group_mode          # parallel | sequential | best_effort
```

Every event/probe/lease row records `(plan_order, group_path, step_id)`. Restart recovery walks the persisted group tree, not a re-derived `seq`.

**Affected:** `domain/experiments.py`, `infra/lease_repository.py`, `infra/migrations.py`, `controller/executor.py`, `controller/recovery.py`.

---

## 8. Cancellation must define kill escalation and propagate to tools 🔴 HIGH

`CancellationToken` alone is underspecified: it never answers "what about a subprocess that ignores the token?".

**Correction — bounded escalation ladder with deadlines:**

```text
graceful cancel   → token.atomically_raise / stop request        (N ms)
      ↓ timeout
terminate         → SIGTERM to the owning process / tool         (N ms)
      ↓ timeout
kill              → SIGKILL                                      (hard deadline)
      ↓
recovery          → run compensation for APPLIED members only
```

Cancellation must **propagate to every tool locus**: k6, locust, stress-ng, `tc` operations, long SSH commands, container `exec`. Every tool adapter must expose a cancel path (its process group), so cancellation is not just "signal the python thread".

**Affected:** `toolkit/tool_runner.py`, `agents/executors.py`, `agents/transports.py`, `controller/executor.py`, `toolkit/registry.py`.

---

## 9. `OwnedResource` needs a lifecycle, or the janitor still can't know if a resource exists 🔴 HIGH

`RESERVED/CREATED/APPLIED/RELEASED` was under-specified. Without a lifecycle, the janitor cannot distinguish "resource exists but was never applied" from "resource was applied then released".

**Correction — lifecycle:**

```text
RESERVED    → intent pinned (lease held), nothing mutated yet
CREATED     → mutation boundary passed, resource recorded
APPLIED     → confirmed present by inspection
RELEASED    → removed by this owner; confirms absent
UNKNOWN     → existence uncertain (lost ack)
ORPHANED    → owner gone (lease expired); janitor may act
```

**Janitor rule:** act on `ORPHANED` + `UNKNOWN`; never on a live `RESERVED`; confirm `APPLIED` by inspection before removing. This is the difference between a safe janitor and a cross-experiment deleter.

**Affected:** `domain/resources.py`, `controller/resource_manager.py`, `controller/janitor.py`, `infra/lease_repository.py`.

---

## 10. "Mutation boundary before acting" is incomplete — make the journal order + durability explicit 🔴 HIGH

The first review wrote a journal row before acting. But a process can **die between mutation and persistence**, leaving an intended-but-unrecorded mutation.

**Correction — explicit four-phase persistence with defined durability:**

```text
intent journal        (planned mutation, lease, expected post-state)   → durable BEFORE acting
mutation attempt      (we are now changing reality)                    → durable
mutation evidence     (observed post-state / inspect result)           → durable
resource registration (owned-resource row with fingerprint + owner)   → durable
```

- **Order:** intent → attempt → evidence → registration.
- **Guarantee:** the *intent + expected post-state* is durable **before** the first syscall; if the process dies between attempt and evidence **or between mutation and registration**, the restart janitor knows *exactly* what was about to happen and can inspect/verify/revert — no ambiguity from the lost window.

**Affected:** `infra/store.py`, `infra/lease_repository.py`, `controller/executor.py`, `controller/recovery.py`, `controller/janitor.py`.

---

## 11. Recovery's final truth source = live inspection, not stale journal 🔴 HIGH

First review: "janitor inspects and reconciles". **Tighten it** into an explicit precedence rule:

> **Live system state wins over stale journal assumptions** when determining whether a resource actually exists.
> Journal = intent/history. Runtime inspection = current truth.

Concretely: if the journal says `APPLIED` but live inspection shows no such rule/process/cgroup → it is `RELEASED` (or was owner-released), **do not** run a blind "remove" command that could hit a *different* experiment's resource. If journal says `RELEASED` but inspection shows the resource present → something else owns it; do not touch without owner+fingerprint check.

**Affected:** `controller/recovery.py`, `controller/janitor.py`, `controller/resource_manager.py`.

---

# PART C — RUNTIME MODEL (P2)

## 12. Rootless Podman needs a formal per-capability verdict, not ad-hoc branches 🔴 HIGH

The first review listed differences but left them as prose. **Formalize per capability:**

```text
SUPPORTED                       # native
SUPPORTED_WITH_ALTERNATIVE      # via podman exec / unshare / in-netns tool
UNSUPPORTED                     # cannot be done safely in this mode → plan-time fail
UNKNOWN                         # probe at execution time
```

Example matrix (capability × runtime mode):

| Capability | rootful docker | rootless podman | rootful podman |
|---|---|---|---|
| process.signal (host pid) | SUPPORTED | SUPPORTED_WITH_ALTERNATIVE (`podman exec kill`) | SUPPORTED |
| cpu.resource_pressure (cgroup) | SUPPORTED | SUPPORTED_WITH_ALTERNATIVE (cgroup v2 delegation) / UNSUPPORTED (v1) | SUPPORTED |
| network.latency (tc) | SUPPORTED | SUPPORTED_WITH_ALTERNATIVE (in-netns `unshare -n` / pasta) | SUPPORTED |
| dns / tls / load | per-adapter | per-adapter | per-adapter |

The **capability provider** returns one of the four; the planner consumes the verdict *without* hard-coding `if runtime == "podman"`. This keeps runtime branching inside adapters.

**Affected:** `domain/capabilities.py` (verdict enum), `topology/providers/*`, `toolkit/registry.py`, `agents/executors.py`.

---

## 13. Docker/Podman need one normalized runtime contract 🔴 HIGH

"Differences live in strategy/tool layer" must become a **concrete adapter interface**, or the strategy layer will accumulate provider conditionals anyway.

**Correction — define a common runtime contract that both adapters implement:**

```text
RuntimeAdapter
    inspect(target)            -> LiveContainerState (single pass; see §6 answer.md)
    resolve_identity(target)   -> RuntimeIdentity
    resolve_processes(target)  -> [ProcessRuntimeIdentity]
    resolve_networks(target)   -> [NetworkAttachment]
    resolve_ports(target)      -> [PortBinding]
    exec(target, argv)         -> Result
    signal(target, sig)        -> Result
    resource_info(target)      -> cgroup / mount / ns info
```

`docker_runtime.py` and a new `podman_runtime.py` implement this; consumers depend on the interface only. The domain stays engine-agnostic (ADR-0013 preserved).

**Affected:** new `topology/providers/runtime_adapter.py`, `docker_runtime.py`, new `podman_runtime.py`, `topology/resolve.py`, `agents/executors.py`.

---

## 14. Remote Linux needs an interface contract before being called "ready" 🔴 MED-HIGH

First review's "agent abstraction handles remote" is **conceptually** right but operationally open. Define an ADR/interface before claiming remote support:

```text
remote-agent contract
    SSH session ownership          # who opens/reuses/closes; connection pool
    remote privilege escalation    # sudo? user ns? explicit
    remote tool probing            # same CapabilityRequirements, executed at remote
    disconnect recovery            # in-flight remote mutation + reconnect policy (idempotent compensation)
    remote process identity        # pid valid in REMOTE pid-namespace; evidence gathered at remote
    remote journal behavior        # journal rows persisted at controller or agent? reconcile on reconnect
```

Until these are specified, remote = `REMOTE_HOST` enum value plus hope.

**Affected:** new `docs/adr/ADR-00xx-remote-agent.md`, `agents/transports.py`, `domain/execution_context.py`, `controller/recovery.py`.

---

## 15. Introduce first-class `NetworkPath` 🔴 MED-HIGH

First review gave the correct source/destination model but left it as loose strings. Give it a shape:

```text
NetworkPath
    source           # logical target or *
    destination      # logical target / address / *
    network          # which of the container's networks
    namespace        # which netns the rule lives in
    interface        # vethXYZ / eth0
    protocol         # tcp | udp | icmp | ...
    ports            # [5432] / "*"
    direction        # src→dst | dst→src | both
```

Then the domain is:

```text
NetworkFault → NetworkPath → impairment (latency | loss | delay | ...)
```

This scales to asymmetric, multi-network, multi-interface cases and gives recovery a precise scope.

**Affected:** `domain/faults.py`, `spec.py`, `domain/experiments.py`, `docs/drill-spec.md`, ADR-0021 revision.

---

## 16. Network fault ownership = mandatory operation fingerprints (every backend) 🔴 MED-HIGH

`tc` handles were mentioned; make it **mandatory across every network backend** so overlapping faults can't cross-undo:

```text
resource_id          # stable id for the network mutation
backend              # tc | iptables | nft | netem | ...
rule fingerprint     # deterministic content-hash of the exact rule applied
owner                # FaultInvocation id + lease
recovery operation   # the precise undo bound to the fingerprint
```

Recovery removes by `(backend, fingerprint, owner)`, never "delete all latency rules". Two experiments targeting the same path conflict-check on the fingerprint in `ResourceManager`.

**Affected:** `domain/resources.py`, `controller/resource_manager.py`, `controller/compensation.py`, new network fault toolkit module.

---

# PART D — DSL (P3)

## 17. Make `containers:` a shorthand, not the root abstraction 🔴 MED-HIGH

The first review agreed with `targets/operations/faults/traffic/checks`. **Go further:** define the **core** as:

```yaml
kind: drill
name:
seed:                 # reproducibility
targets:              # logical endpoints (service / host / process / network-path)
operations:           # load / stress / fuzz / protocol / http-error / dns / tls / db
faults:               # destructive mutations (container-scoped OR network-path-scoped)
execution:            # sequential / parallel / wait / check
checks:               # steady-state + assertions
observability:        # otel/prometheus sources
```

and make:

```yaml
containers: { name: { faults: [...] } }
```

an **ergonomic shorthand that compiles** to `targets + operations`. `container` is one kind of target, never the ceiling (long-term: network/DNS/TLS/database faults and traffic generators target *paths and services*).

**Affected:** `spec.py`, `domain/experiments.py`, `controller/planner.py`, `docs/drill-spec.md`.

---

## 18. Separate Hypothesis from assertions from observation sources 🔴 MED

First review put `metrics` beside `hypothesis`. **Keep them semantically separate** — otherwise `hypothesis` becomes a dumping ground:

```text
Hypothesis              # human-readable intent (narrative)
SuccessCriteria / Assertions   # machine-evaluable: latency<X, error_rate<Y, recovery<Z
ObservationSources      # where values come from: otel | prometheus | probe | timer
```

Model as separate fields/objects so evaluation is objective and observational sources are pluggable (§21 of `answer.md`). Integrate Prometheus/OpenTelemetry via a **metrics-source adapter**.

**Affected:** `domain/checks.py`, `controller/observations.py`, new `observability/` adapter, `spec.py`.

---

## 19. Checks need explicit source/locus semantics 🔴 MED

Checks need to know *where* they execute and *which network/agent* — a host-originating request can pass while an in-container request fails.

```text
CheckDefinition
    target        logical name
    runner_locus  HOST | CONTAINER | NETWORK_NAMESPACE | REMOTE_HOST   # where the check executes
    network       which network to resolve in
    resolver      DNS source (runtime DNS vs system resolver)
    agent         which agent/locus runs the probe
    protocol, port, path, expect
```

**Affected:** `domain/checks.py`, `agents/probes.py`, `cli/resolver.py`, `spec.py`.

---

# PART E — INTELLIGENCE (P4)

## 20. Maniac must reason over `ExperimentCandidate`, not directly emit a DrillSpec 🔴 HIGH

This is the **largest remaining omission** in the first review. If Maniac emits a DrillSpec directly, it cannot reason before committing.

**Correction — insert a candidate stage:**

```text
Maniac (policy + history + objectives)
   ↓ generates
ExperimentCandidate            # logical targets + candidate faults + group shape + params
   ↓ gates
Safety feasibility            # CapabilityRequirements feasibility (plan-time view)
Resource conflict check       # fingerprint conflicts
Scoring / objectives
   ↓ produces
DrillSpec                          (fully human-reviewable before execution)
   ↓ plan
ExecutionPlan / Run
```

The **candidate** is where Maniac reasons (risk, coverage, novelty) *before* committing to a drill. It is cheap to generate and gate; a DrillSpec is committed only after gates pass.

**Affected:** new `maniac/` generator module, `controller/planner.py` exposure, `cli/campaign.py`.

---

## 21. Maniac needs coverage as a first-class algorithmic objective 🔴 MED-HIGH

"History-aware" stayed descriptive in the first review. Make objectives explicit so "learning" is algorithmic:

```text
novelty                         # distance from recent experiments
coverage                        # fault × target × context cells not yet exercised
risk                             # expected blast radius / business cost
target criticality               # how important is the target
historical failure probability   # P(clean recovery | this fault)
recovery confidence              # confidence we can revert cleanly
```

A **scoring function** over these drives candidate selection; the result is reviewable and seeded for reproducibility.

**Affected:** new `maniac/scoring.py`, `cli/campaign.py`, domain `risks.py`.

---

## 22. `Run` must be distinguished from `Outcome` 🔴 MED-HIGH

First review conflated "what happened" with "what Mayhem learned".

```text
Run               # what happened (event journal, leases, verdicts, timing)
FaultOutcome      # did THIS fault apply/recover cleanly? + evidence
ExperimentOutcome # did the drill pass/fail its SuccessCriteria?
RecoveryOutcome   # how clean was recovery? RECOVERED / DIRTY / DRIFT
CoverageRecord    # which (fault, target, context, runtime-mode) cells were exercised
```

`Outcome`/`CoverageRecord` feed Maniac's objectives (§21); `Run` is the raw truth. Never let "run succeeded" be confused for "experiment hypothesis validated".

**Affected:** `domain/experiments.py`, `domain/campaigns.py`, new `domain/outcomes.py`, `infra/store.py`.

---

## 23. Campaign execution semantics are still absent 🔴 MED-HIGH

`CampaignService` as CRUD is not a chaos campaign manager. Define:

```text
Campaign
    experiment ordering          # seeded sequence / policy-driven selection
    concurrency                  # how many drills run at once; shared-lease isolation
    stop conditions              # on first fail? on N recoveries? on coverage target?
    abort behavior               # what runs stay, what is compensated, in what order
    recovery boundaries          # group-level vs campaign-level recovery
    campaign-level safety        # blast-radius cap, resource-conflict policy across members
```

Without these, multi-experiment automation is unmanageable and unsafe.

**Affected:** `domain/campaigns.py`, `cli/campaign.py`, `controller/` (new campaign executor), ADR.

---

# PART F — KUBERNETES (final)

## 24. Reframe the Kubernetes claim — "no domain rewrite" ≠ "no domain changes" 🔴 MED

First review said "no domain changes" — **too strong**. The correct requirement:

> Kubernetes must not require rewriting the **core fault lifecycle, capability model, ownership model, or recovery architecture**. Some node-kind and target extensions are reasonable and expected.

Reasonable extensions (extend the *open union*, ADR-0013):

```text
cluster
namespace
pod
workload
container-in-pod
service
endpoint
node
prometheus metric source
```

These add new `NodeKind`s and `RuntimeAdapter`s and `AgentLocus`s; they do **not** change how a fault is owned, compensated, or verified. If the k8s work touches `FaultGroup`, `OwnedResource`, or the recovery state machine, the core was wrong.

**Affected:** `domain/topology.py` (NodeKind union), `domain/execution_context.py`, new `topology/providers/k8s_runtime.py`, `observability/`.

---

# PART G — FAILURE MATRIX (reconciled with new states)

| # | Failure | Expected state | Recovery action | Final state |
|---|---|---|---|---|
| 1 | container disappears before injection | target gone | resolve → fail cleanly, no mutation | FAILED_TO_APPLY |
| 2 | process disappears before injection | pid dead | verify → resolve again; gone → stop | FAILED_TO_APPLY |
| 3 | PID reused | wrong process behind pid | verify `/proc` starttime+cgroup → drift detected → abort | TARGET_DRIFT → RECOVERED |
| 4 | container restarts (same RuntimeIdentity) | locators changed | re-resolve; identity/epoch unchanged → proceed | APPLIED (new locator) |
| 5 | container **recreated** (RuntimeIdentity changed) | planned id != live id | **TARGET_DRIFT**; safe-abort; fresh plan decision | TARGET_DRIFT |
| 6 | IP changes | stale addr | name-addressed re-resolve | APPLIED (new locator) |
| 7 | runtime unavailable | engine down | fail pre-act, no mutation | FAILED_TO_APPLY |
| 8 | tool missing (plan) | static infeasibility | plan-time feasibility fail | FAILED_TO_APPLY (plan gate) |
| 9 | tool disappears / permission lost (after plan) | execution-time revalidation fails | abort before mutation | TARGET_DRIFT / FAILED_TO_APPLY |
| 10 | tool hangs | no response | escalation: grace→term→kill→compensate applied members | RECOVERED (applied) |
| 11 | tool partially succeeds | some rules applied | mutation-evidence + resource registration → revert applied only | RECOVERED / DIRTY |
| 12 | agent dies | control lost | lease expiry → janitor inspects + reverts owned(ORPHANED) | RECOVERED (janitor) |
| 13 | controller dies | orchestration lost | restart → reconcile journal + leases + group tree | RECOVERED / UNKNOWN |
| 14 | network disconnects | cannot signal/heal | idempotent retry; mark pending | RECOVERED (after retry) |
| 15 | SQLite unavailable | no journal | barrier: fail before mutation (journal authoritative) | NOT_STARTED |
| 16 | recovery fails | cannot revert | re-attempt; escalate → DIRTY + manual | DIRTY |
| 17 | verification fails | unknown mutation | inspect → rerun verify → unresolved DIRTY | DIRTY / VERIFIED |
| 18 | parallel sibling fails | group partial | recover sibling's APPLIED resources; group reports partial | PARTIAL / RECOVERED |
| 19 | duplicate recovery | double-revert | compensation idempotent + owner/fingerprint-checked → no-op | RECOVERED |
| 20 | process replaced (same container) | in-container restart | container RuntimeIdentity same → new ProcessRuntimeIdentity resolved | APPLIED (new proc) |

---

# PART H — BUILD ORDER FOR THE BUILDER AGENT

**Do these before implementing anything else.** Lock each into an ADR/interface first, then implement.

### P0 — Architecture lock 🔴
```text
1.  RuntimeIdentity vs RuntimeMetadata                    (§1)
2.  LogicalTarget / RuntimeTarget / LiveTarget           (§3 answer.md)
3.  Explicit ExecutionContext + agent/tool locus          (§7 answer.md, §14)
4.  Process identity + PID-namespace model                (§2)
5.  TARGET_DRIFT state                                   (§3)
6.  CapabilityRequirements + two-phase feasibility        (§4)
7.  OwnedResource lifecycle + fingerprinting              (§9, §16)
8.  Evidence-driven recovery state machine                (§12 answer.md, §10, §11)
```

### P1 — Execution engine
```text
9.  FaultGroup (parallel|sequential|best_effort)          (§6)
10. ParallelGroup / ExecutionGraph + persistent group id  (§7, §10 answer.md)
11. Cancellation/deadline escalation + tool propagation   (§8)
12. Multi-fault lifecycle + partial-failure reporting     (§9 answer.md)
13. Mutation-boundary persistence (intent→evidence→register) (§10)
14. Resource conflict manager                             (§9, §16)
```

### P2 — Runtime / network
```text
15. RuntimeInspector / RuntimeAdapter interface           (§13)
16. Docker adapter (single-pass inspect)                  (§6 answer.md, §13)
17. Podman adapter (rootless-aware)                       (§13, §12)
18. Rootless capability matrix (SUPPORTED / _WITH_ALTERNATIVE / UNSUPPORTED / UNKNOWN) (§12)
19. NetworkPath                                          (§15)
20. Network resource fingerprints (mandatory)             (§16)
21. Remote-agent contract ADR + interface                 (§14)
```

### P3 — DSL
```text
22. targets / operations / faults / execution / checks / observability core (§17)
23. containers: shorthand (compiles to targets+operations) (§17)
24. Machine-evaluable assertions (SuccessCriteria)        (§18)
25. Check execution locus                                 (§19)
```

### P4 — Intelligence
```text
26. ExperimentCandidate                                      (§20)
27. Run vs Outcome separation                               (§22)
28. Coverage model                                          (§21)
29. Maniac scoring / objectives (novelty/coverage/risk/...) (§21)
30. Campaign execution semantics                            (§23)
```

### P5 — Then expand the arsenal
```text
31. network    32. resources    33. storage    34. process
35. container  36. dependency/database    37. load
38. fuzzing    39. DNS/TLS/application faults    40. Kubernetes (§24)
```

---

# PART I — THE FOUR REFUSALS

The four areas that are absolutely non-negotiable before "production-grade" is a defensible claim:

1. **Identity** — `RuntimeIdentity` (runtime + host_id + runtime_id) strictly separated from `RuntimeMetadata` (project/service/name/labels); process identity ≠ `(host, path/comm)`; `container_name` is a resolver key, never identity. (§1, §2)
2. **Execution context** — non-null in the plan; target-locus / agent-locus / tool-locus separated; PID-namespace explicit. (§7 answer.md, §14)
3. **Resource ownership** — `OwnedResource` lifecycle (RESERVED…ORPHANED) + fingerprint + owner; recovery and janitor bind to fingerprint+owner + **live inspection wins** over stale journal. (§9, §11, §16)
4. **Recovery evidence** — evidence-of-mutation state machine; `TARGET_DRIFT` distinguished from failure; mutation-boundary journal order + durability explicit. (§3, §10, §12 answer.md)

If the explicit `README` of the design doesn't state exactly how Mayhem answers **identity, execution context, resource ownership, and recovery evidence**, then Mayhem is still "a sophisticated YAML-to-subprocess runner" — not yet a production chaos framework.

---

# VERDICT

```text
READY WITH CORRECTIONS
```

The original review was directionally right and code-grounded; this consolidated pass **removes every under-specified or over-optimistic claim** so the builder can lock decisions into ADRs and interfaces and implement without more redesign.

The important thing now is **not to keep redesigning**. Lock P0 in this document, then P1–P4, then expand the arsenal. The four refusals above are the gate — if they're unambiguous in the ADRs, Mayhem is genuinely on the path to production-grade.
