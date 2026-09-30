# v1.0.0 — market landscape

Research date **2026-09-28**. This is the evidence base for
[positioning](01-positioning.md) and the feature plans in this directory.

## Provenance — read this first

Two independent evidence sources were used. They are **not** equally strong, and
the difference matters when you weigh a claim in these plans.

| Source | Method | Confidence | Covers |
| --- | --- | --- | --- |
| Chaos Mesh + LitmusChaos | repository-level research against `config/crd/bases`, `chaos-charts/faults/`, GitHub API, and each project's own ROADMAP | **High** — read from CRD schemas and fault trees, cited to file paths | both CNCF projects in depth |
| AWS FIS | `docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html`, fetched directly | **High** — quoted from the live reference | AWS action taxonomy and sequencing |
| Gremlin, Steadybit, Harness | **not retrieved.** Search returned marketing copy with no page content, and the search engine pool was degraded (5 of 7 engines failing) | **Low — not used** | see caveat below |
| Azure Chaos Studio | **not retrieved.** Documentation URLs returned 404 | **Low — not used** | — |

**Caveat carried forward:** any statement about Gremlin, Steadybit, Harness or
Azure Chaos Studio in these plans is either absent or explicitly marked as
unverified. Do not cite this document for those. Re-running the research when
the tooling is healthy is listed as an open item in
[07-release-checklist.md](07-release-gates.md).

## The two CNCF projects

### Scale and freshness

| | Chaos Mesh | LitmusChaos |
| --- | --- | --- |
| Repository | `chaos-mesh/chaos-mesh` — **7,917★**, monorepo | `litmuschaos/litmus` — **5,624★** across **20+ repos** |
| CNCF status | Incubating (2022-02-16) | Incubating (2022-01-01 era) |
| Last release | v2.8.4, **2026-08-18** (quarterly) | chaos-operator 3.31.0, **2026-07-15** (monthly) |
| Taxonomy size | **19 fault CRDs, ~90 actions** | **53 faults, 7 engines** |
| Adopters | 40+; ByteDance, Tencent, DataStax, PingCAP, Microsoft | 20+ documented; Intuit, Mercedes, Orange, adidas |

Litmus's fragmentation is a real signal: `chaos-operator` 158★, `chaos-charts`
91★, `litmus-go` 87★, plus `chaos-workflows` last pushed **2021** and two
archived repos. Chaos Mesh is one repository with every subsystem in-tree.

### The steady-state finding — this is the important part

**Neither project models a steady-state hypothesis properly.** They are stuck at
threshold counts on scalar comparators.

- **Chaos Mesh** has a `StatusCheck` CRD, but `type` is an enum with a **single
  member: `["HTTP"]`**. It carries `failureThreshold` / `successThreshold` as
  *consecutive failure counts*. It is an external health check that can gate a
  workflow (`abortWithStatusCheck: true`), not an experiment-level hypothesis.
- **Litmus** is better and still stops short. Probes are per-experiment
  (`.spec.experiments[].spec.probe[]`) with 4 types — `cmdProbe`, `k8sProbe`,
  `httpProbe`, `promProbe` — and 5 timing modes: `SOT`, `EOT`, `Edge`,
  `Continuous`, `OnChaos`. That phase model (`SOT` before, `EOT` after) is the
  closest anyone gets to before/during/after semantics. But there is **no
  numeric tolerance field** anywhere: no "error rate may rise to 2%", no
  baseline-relative comparison. Litmus's own ROADMAP lists "Enhanced CRD schema"
  as future work.

**The unclaimed position:** a hypothesis primitive with *baseline capture*,
*per-metric tolerance bands*, and *explicit before/during/after phases* — where
the verdict is "latency rose 18%, inside the 20% band" rather than a boolean
probe pass/fail.

### Taxonomy depth

Chaos Mesh is substantially deeper at the kernel and runtime layer:

- `KernelChaos` — BPF-based (`chaos-mesh/bpfki`), arbitrary kernel function
  failure with callchains and predicates
- `IOChaos` — per-path syscall faults, with `errno` and `attrOverride`
- `BlockChaos` — block-device delay
- `JVMChaos` — `latency`, `exception`, `gc`, `stress`, `mysql` targeting
  class/method
- `TimeChaos` — per-clock-id offsets (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, …)
- `PhysicalMachineChaos` — **38 actions** on bare metal via `chaosd`

Litmus explicitly lists `IOChaos`, `HTTPChaos`, `JVMChaos` as **backlog, not
built**. It has **no time/clock fault at all**. Its cloud coverage is
asymmetric (AWS 8 / GCP 4 / Azure 2) where Chaos Mesh is symmetric (3/3/3).

### Abstraction and composition

- **Chaos Mesh** — a fault CR *is* the unit of work. `Schedule` adds cron +
  `concurrencyPolicy: Forbid|Allow`. `Workflow` is a DAG with `entry` +
  `templates[]`; a template may embed a fault, a nested `Schedule`, or a
  `StatusCheck`. `RemoteCluster` dispatches to other clusters.
- **Litmus** — a `ChaosEngine` CR referencing `ChaosExperiment` fault templates.
  `engineState: active|stop` is the pause switch. Durations are **env vars on
  the runner**, not typed CR fields. `ChaosSchedule` supports **work-hours and
  work-days** (`includedHours: 0-12`, `includedDays: "Mon,Tue,Wed"`) — a
  business-hours-aware scheduler Chaos Mesh has no equivalent for. Litmus also
  has **BYOC** (bring-your-own-chaos) plus Go/Python/Ansible SDKs, where Chaos
  Mesh's fault set is closed behind CRDs.

### Guardrails

| | Chaos Mesh | Litmus |
| --- | --- | --- |
| Blast radius | `mode: one\|all\|fixed\|fixed-percent\|random-max-percent` | `PODS_AFFECTED_PERC` env var |
| Pause | annotation `experiment.chaos-mesh.org/pause` | `engineState: active\|stop` |
| Auto-abort | `abortWithStatusCheck` | `stopOnFailure` |
| Validation | full admission-webhook set per CRD | per-experiment minimal RBAC + `definition.scope` |
| Hardened clusters | not documented | ships PSP + **6 Kyverno policies** |
| Audit | `status.experiment.records[].events[]`, conditions, k8s Events | `ChaosResult` + Prometheus exporter |
| Maturity gate | none formal | `CHAOS_EXPERIMENT_MATURITY.md` — GA requires "leaves no chaos residue regardless of success" |
| **Dry run** | **none** | **none** |

Litmus's formal maturity gate is worth stealing as a concept: GA requires that
an experiment "successfully reverses the chaos, leaves the cluster in a healthy
state" and "leaves no chaos residue… **regardless of success**."

### Common structural gaps

1. **Both require Kubernetes** as the control plane. Non-k8s is either
   `chaosd` standalone (Chaos Mesh, giving up 33 of 38 actions) or BYOC (Litmus,
   write your own injector).
2. **Neither has a dry-run / simulate field in any CRD.**
3. **Both need privilege.** Chaos Mesh's DaemonSet is privileged; `KernelChaos`
   loads BPF. This is a hard ceiling on EKS-constrained, Fargate-like and
   multi-tenant environments.
4. **No metric tolerance bands** in either (§steady-state).
5. **No multi-tenant / SaaS story.** Chaos Mesh has an open issue literally
   titled "Chaos Engineering as a Service" (5 reactions) and no OIDC in its
   dashboard (issue #4141); its dashboard has no HTTPS (issue #1348, open since
   2020).

## AWS FIS — a different bet

Fetched from the live actions reference. FIS is worth studying because it is
**not** a CRD framework — it is a cloud-API action catalogue with a first-class
sequencing model.

**Action taxonomy.** Fault injection actions, plus three special classes:

- `aws:fis:inject-api-internal-error`, `inject-api-throttle-error`,
  `inject-api-unavailable-error` — inject failures into the **target's own IAM
  role**, scoped by `service` namespace, `operations` list, and `percentage`
- **Service-aware faults** that nothing else in the CNCF projects has:
  `aws:dynamodb:global-table-pause-replication`,
  `aws:arc:start-zonal-autoshift`, `aws:rds:*`, `aws:elasticache:*`,
  `aws:memorydb:*`, `aws:kinesis:*`, `aws:s3:*`, `aws:ebs:*` (incl.
  `corrupt-volume`, `lose-volume`, `delay-volume-io`, `fill-volume`)
- **Network**: `network-blackhole-port`, `latency`, `packet-loss`,
  `disrupt-connectivity`
- **EC2**: stop, reboot, terminate, pause/resume, hibernate, stress-CPU
- **ECS/EKS**: task and pod actions

**Three ideas worth stealing:**

1. **A `wait` action as a first-class sequence member.** A fault sequence is not
   just a list of injections; you can hold, observe, then continue.
2. **`aws:cloudwatch:assert-alarm-state` is an action, not a side effect.** It
   asserts alarms are in `OK` / `ALARM` / `INSUFFICIENT_DATA` — verification
   living in the same sequence vocabulary as injection, rather than in a
   separate probe system. This is the cleanest resolution of the
   chaos-mesh-vs-litmus probe split that I found.
3. **A runtime-discoverable catalogue.** `list-actions` and `get-action` let a
   client ask "what can you do here, and what does each need?" instead of
   shipping a hardcoded list. FIS documents, for every action, its
   `resource type`, its **parameters**, and its **required IAM permissions**.

**Also notable: fault-as-policy.** Pausing DynamoDB global-table replication
literally appends a time-bounded `Deny` statement to the target's resource
policy and removes it at experiment end. The fault is a policy, not a syscall.
It also enforces a quota: no table may be impaired more than 5,040 minutes in a
rolling 7-day window — **FIS bounds how much damage an operator can do to
themselves.**

**BYOC equivalent:** FIS accepts arbitrary Systems Manager documents as fault
actions, and AWS ships reference documents (`AWSFIS-Run-CPU-Stress`,
`AWSFIS-Run-IO-Stress`, `AWSFIS-Run-Kill-Process`,
`AWSFIS-Run-Network-Blackhole-Port`, `AWSFIS-Run-Network-Latency`,
`AWSFIS-Run-Network-Packet-Loss`).

## What nobody does — the four openings

Ranked by how hard they are to copy:

1. **Tolerance-bearing steady state.** Both CNCF projects stop at boolean
   probes. A hypothesis with baseline capture, per-metric bands, and
   before/during/after phases is unclaimed, and Litmus's probe layer is the
   closest head start to displace.
2. **Dry run.** Neither has a simulate field. "Show me the exact rules and
   syscalls this will apply to these PIDs, then commit" is unoccupied.
3. **Unprivileged execution.** Chaos Mesh's privileged DaemonSet + BPF is its
   ceiling; Litmus answers with Kyverno policies rather than avoidance.
4. **Damage quota.** FIS bounds total impairment per target. Chaos Mesh and
   Litmus bound a single experiment and nothing across time.

## Sources

- Chaos Mesh: `github.com/chaos-mesh/chaos-mesh` — `api/v1alpha1/schedule_types.go`,
  `helm/chaos-mesh/crds/*.yaml`, `api/v1alpha1/common_types.go`, `ADOPTERS.md`
- Litmus: `github.com/litmuschaos/litmus` — `mkdocs/docs/experiments/concepts/chaos-resources/probes/`,
  `ROADMAP.md`, `CHAOS_EXPERIMENT_MATURITY.md`, `COMMERCIAL_SUPPORT.md`;
  `github.com/litmuschaos/chaos-charts` — `faults/`
- AWS FIS: `docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html`
  (fetched 2026-09-28)
