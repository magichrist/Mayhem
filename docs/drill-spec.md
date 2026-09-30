# Drill Spec DSL Reference

The **drill spec** is the single, unified description of a chaos drill. One YAML
file (`kind: drill`) replaces the old arrangement of a separate `mayhem.yml`
config plus a step-based fault spec. It declares:

- **config** — safety and runtime settings (risk ceiling, fault budget, timeout, log level)
- **config.maniac** — optional random-injection dial for `mayhem maniac`
  (random container/fault rounds instead of the authored plan)
- **containers** — per-container faults, keyed by the stable `container_name:`
- **targets** — cross-runtime logical targets (docker / kubernetes workloads /
  pods / nodes); exactly one of `containers:` / `targets:` defines a spec
- **execution** — cross-target ordering (parallel, sequential, wait, check)
- **success** — optional machine-evaluable criteria that turn the run into a
  PASS/FAIL verdict
- **observability** — optional declarative evidence sources collected into the
  outcome record

The spec is consumed by the lifecycle commands:

```bash
mayhem prepare validate examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem prepare plan     examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem run      examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml --execute
mayhem maniac   examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml --execute
```

`run` and `maniac` inject faults, so both need the explicit `--execute`
approval; without it they stop at a preview and no lease is ever created. See
[CLI reference](../README.md#whats-new-in-v090).

The positional spec path may be omitted when the global ``--config`` flag
names the drill spec itself — useful from a directory without a spec file:

```bash
mayhem --config examples/testCase/mayhem.yaml maniac --compose examples/testCase/docker-compose.yml
```

#### Scoping a run to one container (`--ctr`)

`mayhem run` and `mayhem maniac` accept `--ctr CONTAINER`, which restricts the
execution to a single container. `CONTAINER` is any `container_name:`
value from the blueprint or the runtime container name (use
`mayhem discover topology --compose ...` to list them); a value that matches
nothing in the topology is rejected before anything is planned.

For `run`, the frozen plan is calculated normally and then filtered: every
fault step targeting another container is dropped, and wait/check/no-op steps
for other containers disappear with them — the frame fault ids, ordering and
grouping of the surviving container's steps are untouched, so downstream
reports and observability keep working as usual. `maniac` treats `--ctr` as a
draw-pool restriction: when no authored spec exists the synthesized pool is
built from the single container, and with an authored spec the drawn plan is
filtered exactly like `run`, so the run can only ever perturb the requested
container.

```bash
mayhem run      examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml --ctr testcase-api --execute
mayhem maniac   --compose examples/testCase/docker-compose.yml --ctr testcase-api --execute
```

`validate` compiles the spec and runs every safety gate without injecting
anything. `plan` prints the frozen execution plan as JSON. `run` executes it
end-to-end and prints the run summary (status, verdict, observations, per-step
results). `maniac` [compiles the same way](#maniac-mode) but replaces the
authored execution with random (container, fault) rounds. Omit `--compose` to
auto-detect a compose file in the current directory (`docker-compose.yml`,
`compose.yml`, …).

`run` accepts one or more specs through a **campaign** (ADR-0022 / ADR-0023):
group specs under a campaign, add each spec file, then execute them
sequentially with a single policy and window:

```bash
mayhem campaign create weekly-drill --description "Weekly single-fault sweep"
mayhem campaign add-experiment weekly-drill mayhem.yaml
mayhem campaign add-experiment weekly-drill checkout-recovery.yaml
mayhem campaign run weekly-drill --compose examples/testCase/docker-compose.yml --execute
```

Each spec still compiles and gates exactly as `mayhem run` would; the campaign
only layers execution policy on top (failure action, deadlines, cooldowns) and
records per-experiment observations under the campaign id. `campaign run`
mutates the target, so it needs the same explicit `--execute` approval as
`mayhem run` — a global `--dry-run` is honoured structurally (the campaign row
and the target are left untouched), never treated as approval. See
[`campaign`](../README.md#campaigns) in the README for the current
lifecycle commands.

---

## Top-Level Fields

| Field           | Type                               | Required | Default         | Description |
|-----------------|------------------------------------|----------|-----------------|-------------|
| `kind`          | `"drill"` (literal)                | yes      | —               | Discriminator; must be exactly `drill`. |
| `name`          | string                             | yes      | —               | Drill name; run ids carry it as a readable prefix (`r-<name>-<suffix>`). Unlimited runs against one spec are recorded in the persistent DB. |
| `hypothesis`    | string                             | no       | `""`            | What the drill is trying to prove. |
| `config`        | [DrillConfig](#config)             | no       | `DrillConfig()` | Safety / runtime settings. |
| `containers`    | map<string, [DrillContainer](#containers)> | *one of* `containers` / `targets` | — | Docker-family faults per-container, keyed by the stable `container_name:`. |
| `targets`       | map<string, [DrillTarget](#targets-cross-runtime)> | *one of* `containers` / `targets` | — | Cross-runtime logical targets (`docker` / `kubernetes`), keyed by a stable name the `execution:` steps reference. A spec defines **exactly one** of `containers:` / `targets:` (mixing both or defining neither is a compile error). |
| `execution`     | list<[ExecutionStep](#execution)>  | yes      | —               | Ordering of fault rounds. At least one step required. |
| `success`       | [SuccessCriteria](#success-criteria)        | no       | —               | Machine verdict criteria. |
| `observability` | [ObservabilityConfig](#observability) | no    | —               | Evidence sources collected into the record. |
| `slo`          | list<[SloCriterion](#slo-criteria-v090)> | no | —          | Provider-neutral SLO thresholds with explicit units, windows, and failure semantics (v0.9.0). |

`apiVersion: mayhem/v1` is tolerated and ignored — the drill spec is versioned by
its own schema freeze, not by `apiVersion`.

## Config

| Field          | Type                              | Default | Description |
|----------------|-----------------------------------|---------|-------------|
| `risk_ceiling` | `low` / `medium` / `high` / `critical` | `high`  | Refuse any fault whose catalog risk exceeds this. Tightens the policy ceiling in `mayhem.yaml`; it can only make the policy tighter, never looser. |
| `max_faults`   | int (≥ 0)                         | `1`     | **Declared but not enforced.** No gate reads this value, so it does not bound anything. The executable budget is `blast_radius.max_concurrent_faults` in the layered `mayhem.yaml` — see [Fault budgets](#fault-budgets). |
| `timeout`      | duration                          | `30m`   | Whole-run timeout; the executor aborts and recovers past this. |
| `log_level`    | `DEBUG` / `INFO` / `WARNING` / `ERROR` | `INFO` | Log verbosity for the drill run. |
| `recovery`     | bool                              | `true`  | Automatically undo each fault after injection (restore the container). `false` keeps the perturbation in place so downstream checks observe whether the stack self-heals — see [Recovery control](#recovery-control). |
| `on_failure`   | `abort_and_recover` / `continue`  | `abort_and_recover` | Default behavior if a fault round fails. `abort_and_recover` cancels the remaining steps and recovers; `continue` records the failure and keeps testing the remaining faults (the run still ends `failed`). A fault can override this per-fault — see [DrillFault](#drillfault). |
| `maniac`       | [ManiacConfig](#maniac-mode)      | —       | Random-injection tuning for `mayhem maniac` (level, run count, seed). Falls back to the `maniac:` key in the layered `mayhem.yaml` when the drill spec omits it; a spec-level block always wins. |

```yaml
config:
  risk_ceiling: critical
  # Declared, but no gate reads it — see #fault-budgets.
  max_faults: 1
  timeout: 30m
  log_level: INFO
  # true (default): auto-recover the container after each fault.
  # false: keep the fault in place and let downstream checks decide whether
  #        the stack self-heals without the engine reviving anything.
  recovery: true
```

### Fault budgets

Two different settings are called "max faults", and only one of them does
anything.

| Setting | Where | Default | Enforced? |
|---------|-------|---------|-----------|
| `config.max_faults` | the drill spec's own `config:` block | `1` | **No.** It is a declared `DrillConfig` field, and no code path under `src/` reads it. Its value never affects planning or execution. |
| `blast_radius.max_concurrent_faults` | the layered `mayhem.yaml` | `3` | **Yes.** Enforced by the safety gate for every fault step. |

`blast_radius.max_concurrent_faults` is the control that actually refuses a
drill, and it does not measure concurrency. While a plan is walked step by step
it is compared against the running count of fault **steps** seen so far plus
the step being gated (`len(fault_ids_so_far) + 1`), and that count is never
reset between steps or between rounds. It is therefore a **prefix count of the
plan's fault steps**: a plan with 42 fault steps trips the default budget of
`3` on step 4, even when every step is a `sequential` round that injects a
single fault and nothing is ever concurrent. A long drill is refused with:

```
blocked:
  - [safety.refused] blast radius: max_concurrent_faults exceeded
    [blast_radius.max_concurrent_faults]
```

To get such a drill past the gate, raise `blast_radius.max_concurrent_faults`
in the policy or shorten the plan. The remedy is **not** `config.max_faults`.

Note also that the `blast_radius: {...}` line shown by preflight output is a
looser re-derivation than the real gate: it omits the dependents closure and
never surfaces `max_concurrent_faults` or `max_duration_per_fault_s`. The
displayed values are indicative only.

### The two gates that were not gates before 1.0

Two `blast_radius` settings existed in 0.9.x and did not do what their names
said. Both are recorded here because a plan that ran under 0.9.x may now be
refused.

**`blast_radius.forbidden_fault_pairs` was silently inert.** The check
compared a `frozenset` of *every* fault seen so far against two-element
forbidden pairs. On a two-fault plan that coincidentally matched the single
pair; on a plan of **three or more faults** the set was larger than any
two-element pair, so it matched nothing and the rule never fired. It is now
evaluated against each `{earlier, new}` pair, which is complete: a plan
containing a configured pair is refused no matter where the pair sits in the
step ordering. If you configured a pair and believed it was protecting you,
it was not. Plans that relied on a pair co-occurring are now refused.

**`blast_radius.damage_quota` is new, and active by default.** The five
per-step limits above each look at one step. `damage_quota` is the only budget
that sees the sequence: it charges damage-seconds per target across the whole
plan, weighted by the fault's catalog risk and reversibility, and refuses when
the total exceeds `budget_s` or when any single target's total exceeds
`per_fault_ceiling_s` within `window_s`. Defaults are 14400 s, 3600 s, and
7 days. Setting the field to `null` does **not** disable it — `null` means
"use the default quota", because a quota nobody configures is a quota nobody
gets. Lift it by raising the numbers or by shortening the plan.

A refusal names the rule id and both values:

```
blocked:
  - [safety.refused] blast radius: forbidden fault pair
    ['net.bandwidth', 'net.packet_loss'] [blast_radius.forbidden_fault_pairs]
```

See [`config.md`](config.md#blast_radius) for the field reference.

### Maniac mode

`mayhem maniac` compiles a spec exactly like `mayhem run`, but replaces the
authored `execution:` steps with `run_level` random (container, fault) rounds
([ADR-M5-1](#maniac-mode)). The round count can be overridden on the command
line with `mayhem maniac -s N` (or `--steps N`); the CLI override wins over
both the spec's `config.maniac.run_level` and the layered-config `maniac:`
block. `--ctr CONTAINER` confines every draw to one container: the synthesized
zero-config spec is built from that container alone, and an authored spec's
plan is filtered down to it (see
[Scoping a run to one container](#scoping-a-run-to-one-container---ctr)). Every
other contract is unchanged: the risk
ceiling, blast radius budget and conflict checks still gate each drawn fault;
each round runs its own compensation (or opts out via `recovery: false`); the
spec's `check` / `check_spec` steps still replay between rounds; success
criteria still produce the run verdict; and observability sources are still
collected.

| Field       | Type            | Default | Description |
|-------------|-----------------|---------|-------------|
| `level`     | int (1-5)       | `2`     | How far a draw strays from the spec's authored intent — see the table below. |
| `run_level` | int (1–500)     | `10`    | Number of random (container, fault) rounds to inject. |
| `seed`      | int / null      | `null`  | Seeding the PRNG makes the draw reproducible across runs. |

Level semantics:

| Level | Behaviour |
|-------|-----------|
| 1     | Random container, first authored fault on it; no duration jitter. |
| 2     | Random container, random one of its authored faults; no jitter. |
| 3     | Random container, any fault from the whole spec (cross-locus pool); no jitter. |
| 4     | Cross-locus pool + duration jitter of ±10 %. |
| 5     | Cross-locus pool + duration jitter of ±20 % (full chaos). |

Jitter is clamped to the fault's catalog maximum and never drops below
1 second. `validate` and `plan` accept `config.maniac` but `run` ignores it —
only `mayhem maniac` draws rounds.

### Recovery control

After each fault the engine runs its write-ahead undo contract (the
compensation ops resolved at planning time) and verifies the container is
healthy again before releasing its lease. Setting `config.recovery: false`
disables that auto-recovery:

- The fault is injected exactly as planned, but the undo contract is
  **deliberately not executed** — the container stays faulted (paused, memory
  exhausted, partitioned, …) when the step completes.
- The step's lease is still released cleanly and terminally with mechanism
  `kept_faulted`, and a recovery record is written with `verified=false` so a
  later `mayhem inspect run <run-id>` shows the container was intentionally left
  faulted.
- It is **never** marked dirty: withholding recovery is the requested behavior,
  not a compensation failure, so the watchdog/janitor will not re-enqueue it.
- Downstream `check` / `check_spec` steps (and the `success:` criteria) then
  report whether the stack recovered on its own — e.g. a restarting
  orchestrator pulling the container back to healthy, or the probe still
  failing because nothing revived it. If the checks fail, the drill ends
  `failed` and the `summary` shows exactly which check observed the still-faulted
  container.
- Restore the container manually afterwards (resume the process, drop the
  traffic rule, …); the lease is already terminal, so the next drill can
  acquire the same targets.

`recovery` can also be overridden **per fault** on the `DrillFault` itself
(see [below](#drillfault)); the fault-level value wins over the config default.
When you only want a specific fault observed under `recovery: false`, leave
`config.recovery: true` set and opt out per fault.

## Containers

`containers:` is the docker-family authoring shape. It is **exactly one-of**
with the cross-runtime [`targets:`](#targets-cross-runtime) block — a spec
defines faults under one or the other, never both, never neither. The two
shapes target different runtimes:

| Shape | Runtime | Target identity | Points at |
|-------|---------|-----------------|-----------|
| `containers:` | docker / podman | `container_name:` key | compose containers |
| `targets:`     | docker / podman / **kubernetes** | a named `DrillTarget` | compose containers, k8s workloads (`deployment`/`statefulset`/`pod`/…) and **nodes** (`k8s_node`) |

Each key of `containers:` **is** a `container_name:` value from the
`docker-compose.yml` — the stable identity anchor. Mayhem resolves PIDs and
addresses from this name at **execution time**, immediately before injection,
so a fault always targets the live process even if a container restarted in the
meantime. Everything else the drill records stays descriptive — what gates a
fault is the catalog and the impact gate, not runtime hints.

Faults listed under one container run **sequentially**.

### Targets (cross-runtime)

The `targets:` block (k-plan-1) is the cross-runtime counterpart to
`containers:`. Each key is a **logical target name** chosen by the drill; the
`execution:` steps and the planner reference targets by that name. A target
declares its runtime, the locator material for that runtime, an optional
selection, and the faults to run against it:

| Field       | Type                          | Required | Description |
|-------------|-------------------------------|----------|-------------|
| `runtime`   | `docker` / `kubernetes`       | yes      | Which runtime this target addresses. |
| `docker`    | `{container_name: string}`    | if `runtime: docker` | Single-container locator (same `container_name` contract as `containers:`). |
| `kubernetes`| [KubernetesTargetSpec](#kubernetestargetspec) | if `runtime: kubernetes` | Workload / pod / node locator. |
| `selection` | `{mode: one}`                 | no       | Which instances of the target are chosen. `mode: one` is the only implemented mode; `all` / `count` / `percentage` / `random` are schema-valid but refused at plan time with `PlanningError` ("reserved until k-plan-4"). |
| `faults`    | list<[DrillFault](#drillfault)> | yes     | Faults injected against this target (≥ 1). |

Invariants (compile-time): a `kubernetes` runtime requires the `kubernetes:`
block and forbids the `docker:` block (and vice versa) — a target may never
mix both locators; a target with no `faults` is refused.

```yaml
targets:
  checkout:                          # logical name; `execution:` references this
    runtime: kubernetes
    kubernetes:
      kind: deployment              # deployment | statefulset | daemonset | …
      namespace: production
      name: checkout
    selection:
      mode: one
    faults:
      - fault: k8s.pod_kill
        duration: 30s
  lb-egress:                         # docker target under the same spec
    runtime: docker
    docker: { container_name: testcase-lb }
    faults:
      - fault: net.packet_loss
        duration: 10s
  control-plane:                     # node faults target the k8s_node kind
    runtime: kubernetes
    kubernetes:
      kind: k8s_node
      namespace: ""                  # nodes are cluster-scoped
      name: minikube
    faults:
      - fault: k8s.node_pressure      # needs policy.critical_fault_acks for node_drain
        duration: 60s
```

#### KubernetesTargetSpec

| Field       | Type | Required | Description |
|-------------|------|----------|-------------|
| `kind`      | `deployment` / `statefulset` / `daemonset` / `service` / `pod` / `k8s_node` | yes | The runtime resource family. `container` is refused here — it is docker-scoped; pod-level kinds accept pod faults. |
| `namespace` | string | yes | Namespace of the workload (empty for cluster-scoped `k8s_node`). |
| `name`      | string | yes | The **stable** workload name (e.g. `checkout`) — never a generated pod name; mayhem resolves live pods from it at execution time. |
| `container` | string | no | Optional single container inside the workload (container-level faults). |

A `kubernetes` drill compiles and gates against the blueprint entirely
offline (like `containers:` drills); the impact gate proves the pods / nodes
injectable against the live cluster when `run` reaches execution. Faults are
drawn from the catalog's `k8s.*` family (see the [fault catalog](#fault-catalog)).

### `DrillFault`

| Field          | Type                          | Default             | Description |
|----------------|-------------------------------|---------------------|-------------|
| `fault`        | string (catalog id, e.g. `net.latency`) | — | Which fault to inject. See the [fault catalog](#fault-catalog). |
| `duration`     | duration                      | `10s`               | How long to keep the fault injected before running its compensation. Capped per fault by the catalog. |
| `on_failure`   | `abort_and_recover` / `continue`  | *inherit config*  | Overrides `config.on_failure` for this fault only. `abort_and_recover` cancels the remaining steps if this round fails; `continue` records the failure and keeps testing the remaining faults. |
| `targets`      | list<string>                  | `()`                | Network / partition faults only: container names this target is partitioned from. |
| `network_path` | string                        | —                   | Optional named network path to scope a network fault against. |
| `recovery`     | bool                          | *inherit config*    | Per-fault override of `config.recovery`. `false` leaves this container faulted after injection (self-healing observation); overrides the config default for this fault only. |
| *params*       | —                             | —                   | Fault parameters can be inlined as flat keys or grouped under an explicit `params:` map. The reserved keys (`fault`, `duration`, `on_failure`, `targets`, `network_path`, `params`) are never treated as fault parameters. |

```yaml
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
        on_failure: abort_and_recover

  testcase-lb:
    faults:
      - fault: net.latency
        duration: 15s
        params:
          seconds: 5s
          jitter_ms: 10
        targets: [testcase-api]
      - fault: mem.exhaust
        amount: 256M
        duration: 20s
```

Unknown parameters are rejected with a schema error (`mayhem prepare validate` fails);
every fault validates its parameters against the catalog `params_schema`.

## Execution

`execution:` is an ordered list of steps. Each step has **exactly one** key —
the action to take. Steps run left to right, top to bottom.

| Key         | Value                               | Meaning |
|-------------|-------------------------------------|---------|
| `parallel`  | list of names                       | Inject this step's fault on all named targets concurrently (subject to the `blast_radius.max_concurrent_faults` budget, which counts fault steps rather than concurrency — see [Fault budgets](#fault-budgets)). For `containers:` specs these are `container_name:` values; for `targets:` specs they are the logical target names. |
| `sequential`| list of names                       | Run this step's faults against each target one after another (same name contract as `parallel`). |
| `wait`      | `{duration}` (or `{until_check_passes, timeout}`) | Wait before the next step. |
| `check`     | list of inline probes               | Inline health probe(s) evaluated between rounds (legacy shorthand; prefer `check_spec` for new drills). |
| `check_spec`| list of [locus-aware checks](#checks-and-check_spec) | Fully-declared checks with an explicit or inferred execution locus. |

```yaml
execution:
  # Round 1: everything in this step runs together.
  - parallel: [testcase-api, testcase-lb]

  # Round 2: one container at a time.
  - sequential: [testcase-download-1, testcase-api]

  - wait:
      duration: 5s

  # Verify the stack is still serving before finishing.
  - check_spec:
      - id: api-up
        probe:
          type: http
          url: http://testcase-api:8080/
          expected_status: 200
        execution: service
        target: testcase-api
```

Fault steps in a plan are counted, not scheduled, against
`blast_radius.max_concurrent_faults`, and `config.max_faults` gates nothing at
all — see [Fault budgets](#fault-budgets) before assuming a `parallel` step is
bounded by either.

### `check` (inline)

Each entry is a probe:

| Field    | Type                  | Description |
|----------|-----------------------|-------------|
| `http`   | string (URL)          | Probe this endpoint between rounds. |
| `expect` | `{status: <int>}`     | Expected HTTP status (defaults to `200` when omitted). |

```yaml
- check:
    - http: http://testcase-api:8080/
      expect:
        status: 200
```

## Checks and `check_spec`

`check_spec` carries the full check model:

| Field       | Type                            | Description |
|-------------|---------------------------------|-------------|
| `id`        | string                          | Check id; becomes an observation source (`<id>.status`, `<id>.latency_ms`, …) usable in `success` criteria. |
| `probe`     | discriminated probe (see below) | What to probe and with what expectation. |
| `execution` | `host` / `container` / `service` / `process` | Where the check is evaluated. |
| `target`    | container name                  | The fault target used to infer the locus when `execution` is omitted. |

A bare check without `execution` keeps pre-0.3.0 behavior: the executor infers
the locus from the fault target. An explicit locus is honored as-is.

### Probe types

`type` discriminates the probe:

| `type`   | Fields                                              |
|----------|-----------------------------------------------------|
| `http`   | `url`, `method` (default `GET`), `timeout` (default `5s`), `expected_status` (default `200`) |
| `exec`   | `cmd` (list, argv form), `timeout` (default `10s`), `expected_exit_code` (default `0`) |
| `tcp`    | `host`, `port` (1–65535), `timeout` (default `3s`)  |
| `process`| `name` or `pid`, `timeout` (default `5s`)           |
| `metric` | `endpoint`, `query` (metric name / label selector), `threshold` |
| `file`   | `path` (inside the execution locus), optional `contains` substring |

## Success Criteria

An optional `success:` block turns a run into a machine verdict: the executor
evaluates typed criteria against the observations a drill recorded — never a human eyeball.
A criterion evaluated against a **missing** observation is **false** (absence
of evidence is not success) and never raises.

| Field        | Type         | Default | Description |
|--------------|--------------|---------|-------------|
| `criteria`   | list of typed criteria | `()` | Assertions over observation rows. |
| `require_all`| bool         | `true`  | `true` = all must pass; `false` = any pass suffices. |

### Criteria

| `type`    | Fields            | Passes when |
|-----------|-------------------|-------------|
| `status`  | `source_id`, `expected` (int) | measured status equals `expected`. |
| `latency` | `source_id`, `lt_ms` (float > 0) | measured latency (ms) is below `lt_ms`. |
| `metric`  | `source_id`, `gt` and/or `lt` | numeric metric within the declared (exclusive) bounds — at least one bound required. |
| `count`   | `source_id`, `gte` (int, default `1`) | recorded count is at least `gte`. |
| `boolean` | `source_id`, `value` (bool, default `true`) | recorded outcome equals `value`. |

**Source ids.** A check step `api-up` records its boolean outcome under the bare
id `api-up` and each measured scalar under `api-up.<name>` — for example
`api-up.status` and `api-up.latency_ms`. Criteria address rows by those full
source ids:

```yaml
success:
  require_all: true
  criteria:
    - type: status
      source_id: api-up.status
      expected: 200
    - type: latency
      source_id: api-up.latency_ms
      lt_ms: 500
```

## SLO criteria (v0.9.0)

An optional `slo:` block states thresholds a provider-neutral observation is
judged against. Every criterion carries an explicit **unit**, **window**, and
**operator**, so nothing is compared across an implicit default.

| Field      | Type   | Default | Description |
|------------|--------|---------|-------------|
| `metric`   | string | —       | Metric name a provider returns. Required. |
| `kind`     | `latency` / `error_budget` / `recovery_time` / `saturation` / `absence` | `latency` | What the criterion means. |
| `operator` | `lt` / `lte` / `gt` / `gte` / `eq` | `lte` | How the observation is compared to `threshold`. |
| `threshold`| number | `0`     | The value compared against. |
| `unit`     | string | `ms`    | Unit of both the observation and the threshold. |
| `window_s` | number | `60`    | Window the observation must cover. |
| `name`     | string | derived | Stable criterion id recorded in evidence. |
| `target`   | string | `""`    | Optional locator passed to the provider (e.g. an HTTP URL). |

**A missing observation fails the criterion.** If no provider returns the metric,
or a provider errors, the criterion evaluates to `false` with the reason
`observation unavailable (missing|error)` — an unreachable metrics endpoint is
never mistaken for a healthy system.

```yaml
kind: drill
name: checkout-latency-slo
containers:
  checkout:
    faults:
      - fault: cpu.saturate
        duration: 2m
execution:
  - sequential: [checkout]
slo:
  - metric: http.latency
    kind: latency
    operator: lte
    threshold: 250
    unit: ms
    window_s: 30
    target: "http://checkout/healthz"
  - metric: cpu.saturation
    kind: saturation
    operator: lte
    threshold: 0.8
    unit: ratio
    window_s: 60
```

The run records, in the evidence envelope, `observation_provenance` (counts and
source names only — never a raw payload) and `slo_outcomes` (one entry per
criterion, with `passed`, `observed`, and `reason`).

## Scenarios (v0.9.0)

A **scenario is its own document, not a drill-spec field.** It describes a
variable-driven rehearsal and is compiled — never executed in place — by
`mayhem experiment compose SCENARIO.yaml`. (If you want SLO thresholds inside a
drill, use the [`slo:` block](#slo-criteria-v090) above.) Compilation is
deterministic: the same variables and seed always produce the same plan digest.

| Field      | Type | Required | Description |
|------------|------|----------|-------------|
| `name`     | string | yes | Scenario name recorded with the plan. |
| `variables`| list of [ScenarioVariable](#scenario-variables) | no | Typed inputs, with defaults or `required: true`. |
| `steps`    | list of [ConditionalStep](#conditional-steps) | no | Steps that compile only when their conditions hold. |

### Scenario variables

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Referenced by conditions and by `--set NAME=VALUE`. |
| `type` | `string` / `integer` / `number` / `boolean` / `duration` / `enum` | `string` | Coercion is explicit; a bad value is a compile error naming the variable. |
| `default` | any | `None` | Used when the value is not supplied. |
| `required` | bool | `false` | A missing value then fails compilation. |
| `choices` | list | `()` | Required for `enum`. |
| `minimum` / `maximum` | number | `None` | Range check for numeric, integer, and duration variables. |
| `pattern` | regex | `""` | Applies to string variables. |
| `description` | string | `""` | Operator-facing help. |

Durations normalise to seconds (`500ms` → `0.5`, `2m` → `120.0`).

### Conditional steps

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Step id; duplicates are a validation error. |
| `when` | list of conditions | Every condition must hold for the step to compile. |
| `action` | map | The action compiled into the plan when `when` holds. |
| `else_action` | map | Compiled as `<id>:else` when `when` does not hold. |
| `window` | `{start: "HH:MM", end: "HH:MM"}` | Wall-clock window; outside it the step is skipped. A window may wrap midnight (`22:00`–`02:00`). |

Conditions compare one variable with `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`,
or `contains`. A condition on an undeclared variable fails validation.

```yaml
# scenario.yaml — a standalone document
name: checkout-degradation
variables:
  - name: mode
    type: enum
    choices: [smoke, full]
    default: smoke
  - name: concurrency
    type: integer
    default: 5
    minimum: 1
    maximum: 50
steps:
  - id: baseline
    action: { type: check_http, url: "http://checkout/healthz" }
  - id: degrade
    when: [{ variable: mode, operator: eq, value: full }]
    action: { type: start_load, concurrency: 50 }
    else_action: { type: start_load, concurrency: 1 }
```

```console
$ mayhem experiment compose scenario.yaml --set mode=full --seed 7 --json
```

`compose` is plan-only: it prints the resolved variables, the compiled steps, the
skipped steps, and the plan digest, and it never builds a run engine. The
compiled plan keeps its own scenario source, so a replay needs no extra inputs.

## Observability

An optional `observability:` section collects **evidence** into the outcome
record — the values an evaluator later needs.
Every source is named (`source_id`, for cross-referencing), bounded
(per-source `timeout` and an overall `total_timeout`), and best-effort (a
failing source is recorded as a skip note, never fatal).

| Field          | Type                      | Default | Description |
|----------------|---------------------------|---------|-------------|
| `sources`      | list of typed sources     | `()`    | Evidence sources, each with a unique `source_id`. |
| `cadence`      | duration                  | `5s`    | Default polling cadence for sources that repeat. |
| `total_timeout`| duration                  | `30s`   | Hard bound across the whole collection pass. |

### Sources (`kind` discriminates)

| `kind`       | Fields                                                       |
|--------------|--------------------------------------------------------------|
| `logs`       | `source_id`, `container` (compose container name), `tail` (1–10 000, default `100`), `since` (optional filter), `timeout` (default `10s`) |
| `inspection` | `source_id`, `container`, `timeout` (default `10s`) — runtime inspect JSON as key/value evidence |
| `probe`      | `source_id`, `probe` (any [probe type](#probe-types)), `cadence` (`> 0` polls repeatedly, `0` collects once), `timeout` (default `10s`) |
| `metrics`    | `source_id`, `endpoint`, `metric` (Prometheus metric to resolve to a sample value), `cadence`, `timeout` (default `10s`) |

```yaml
observability:
  cadence: 5s
  total_timeout: 30s
  sources:
    - kind: logs
      source_id: api-logs
      container: testcase-api
      tail: 200
    - kind: probe
      source_id: api-probe
      probe:
        type: http
        url: http://testcase-api:8080/
      cadence: 2s
```

## Durations

Durations accept either a bare number (seconds, optionally fractional) or a
unit suffix string: `10s`, `5m`, `2h`, `1.5s`. Whole-run `timeout`, per-fault
`duration`, waits, probe timeouts, cadences and bounds are all durations. A
requested per-fault `duration` that exceeds the fault's catalog maximum is
rejected at validate time.

## Fault Catalog

`fault:` values reference the registry shipped in `mayhem.domain.catalog`.
Each definition carries a risk level (gated by `risk_ceiling`), a maximum
duration, the node kinds it applies to, and the runtime capability it needs
(checked against the compute engine at validate time). Parameters and their
types are catalog-native; table entries below are normative only as of this
writing — the catalog implementation is authoritative and is what
`mayhem prepare validate` enforces.

| Fault | Category | Risk | Max | Node kinds | Capability | Parameters |
|---|---|---|---|---|---|---|
| `clock.skew` | clock | high | 300s | container, host, service | net_admin | `offset_ms` (integer, **required**) |
| `container.kill` | container | medium | 60s | container, service | docker_engine | `signal` (string, default `SIGKILL`) |
| `container.pause` | container | medium | 300s | container, service | docker_engine | — |
| `container.restart` | container | medium | 60s | container, service | docker_engine | — |
| `cpu.saturate` | cpu | medium | 300s | host, service | — | `percent` (percent, min 1, max 100) |
| `cpu.throttle` | cpu | medium | 300s | container, service | docker_engine | `percent` (percent, min 1, max 100) |
| `db.connection_exhaust` | database | high | 120s | container, external_dependency, service | — | `connections` (integer, min 1, max 256, **required**); `host` (string, **required**); `port` (integer, min 1, max 65535, default `3306`) |
| `db.query_error` | database | high | 300s | container, external_dependency, service | net_admin | `probability` (percent, min 1, max 100, default `100.0`); `error` (`deadlock` / `lock_timeout` / `serialization_failure`, default `deadlock`); `timeout_ms` (integer, min 100, max 120000, default `5000`); `port` (integer, min 1, max 65535, default `3306`) |
| `db.slow_query` | database | medium | 300s | external_dependency, service | — | `seconds` (duration); `mode` (`latency` / `timeout`, default `latency`) |
| `dependency.block` | dependency | high | 300s | container, external_dependency, service | net_admin | `port` (integer, min 1, max 65535, **required**); `protocol` (string, default `tcp`) |
| `dependency.circuit_open` | dependency | medium | 300s | external_dependency, container, service | net_admin | `status` (integer, min 100, max 599, default `503`); `retry_after_s` (integer, min 0, max 3600, default `30`); `probability` (percent, min 1, max 100, default `100.0`); `port` (integer, min 1, max 65535, default `80`) |
| `dependency.connection_refuse` | dependency | high | 300s | container, external_dependency, service | net_admin | `port` (integer, min 1, max 65535, **required**); `protocol` (string, default `tcp`) |
| `dependency.flap` | dependency | high | 300s | container, external_dependency, service | net_admin | `port` (integer, min 1, max 65535, **required**); `interval` (duration, default `10.0`); `failure_probability` (percent, default `50.0`); `protocol` (string, default `tcp`) |
| `dependency.rate_limit` | dependency | medium | 300s | container, external_dependency, service | — | `rate` (integer, **required**); `burst` (integer, default `200`); `code` (integer, min 100, max 599, default `429`); `port` (integer, min 1, max 65535, default `80`) |
| `dependency.response_truncate` | dependency | medium | 300s | external_dependency, container, service | net_admin | `status` (integer, min 100, max 599, default `200`); `bytes` (integer, min 0, max 65536, default `64`); `probability` (percent, min 1, max 100, default `100.0`); `port` (integer, min 1, max 65535, default `80`) |
| `dependency.timeout` | dependency | medium | 300s | container, external_dependency, service | net_admin | `port` (integer, min 1, max 65535, **required**); `delay_ms` (integer, min 1, max 30000, **required**); `protocol` (string, default `tcp`) |
| `dns.nxdomain` | dns | high | 300s | host, service | net_admin | `domain` (string) |
| `dns.resolve_delay` | dns | medium | 300s | host, service | net_admin | `seconds` (duration) |
| `dns.servfail` | dns | medium | 120s | host, service | net_admin | — |
| `dns.timeout` | dns | high | 120s | host, service | net_admin | — |
| `fd.exhaust` | fd | high | 120s | container, host, service | — | `limit` (integer, default `64`); `mode` (`exhaust` / `leak`, default `exhaust`) |
| `fs.corrupt` | storage | high | 120s | process, container, service | fs_control | `path` (string, **required**, must be absolute); `bytes` (integer, min 16, max 1048576, default `4096`); `seed` (integer, min 1, max 65535, default `1`) |
| `fs.fill` | storage | medium | 300s | container, host, service | — | `percent` (percent, min 1, max 99); `path` (string, default `/tmp`) |
| `fs.inode_exhaust` | storage | medium | 300s | container, host, service | — | `percent` (percent, min 1, max 99) |
| `fs.io_stress` | storage | medium | 120s | container, host, service | — | `seconds` (duration); `workers` (integer, min 1, max 8, default `1`); `io_bytes` (bytes, default `64M`); `read_mb_s` (integer, min 1, max 512); `write_mb_s` (integer, min 1, max 512); `block_size` (string, default `64k`); `op` (`read` / `write` / `both`, default `both`) |
| `fs.read_only` | storage | high | 120s | container, host, service | fs_control | `path` (string, default `/`) |
| `fuzz.protocol_abuse` | fuzz | high | 180s | external_dependency, service | — | — |
| `http.error_injection` | http_api | medium | 300s | external_dependency, service | — | `status` (integer, default `500`); `probability` (percent, min 0, max 100, default `0.0`); `port` (integer, min 1, max 65535, default `80`) |
| `http.header_inject` | http_api | medium | 300s | external_dependency, container, service | net_admin | `status` (integer, min 100, max 599, default `200`); `headers` (string, default `""`, **validated not escaped** — see the subsection); `probability` (percent, min 1, max 100, default `100.0`); `port` (integer, min 1, max 65535, default `80`) |
| `http.latency` | http_api | medium | 300s | external_dependency, service | — | `delay_ms` (integer, min 1, max 30000); `probability` (percent, min 1, max 100, default `100.0`); `port` (integer, min 1, max 65535, default `80`) |
| `http.response_truncate` | http_api | medium | 300s | external_dependency, container, service | net_admin | `status` (integer, min 100, max 599, default `200`); `bytes` (integer, min 0, max 65536, default `64`); `probability` (percent, min 1, max 100, default `100.0`); `port` (integer, min 1, max 65535, default `80`) |
| `http.stream_stall` | http_api | medium | 300s | external_dependency, container, service | net_admin | `stall_ms` (integer, min 1, max 30000, default `5000`); `probability` (percent, min 1, max 100, default `100.0`); `port` (integer, min 1, max 65535, default `80`) |
| `k8s.network_policy` | k8s | high | 300s | k8s_node, pod | kubernetes_engine | `policy_name` (string); `direction` (string, default `ingress`) |
| `k8s.node_drain` | k8s | critical | 600s | k8s_node | kubernetes_engine | `grace_period` (integer, default `30`) |
| `k8s.node_pressure` | k8s | high | 300s | k8s_node | kubernetes_engine | `resource` (string, default `cpu`); `target_percent` (percent, min 1, max 100) |
| `k8s.pod_evict` | k8s | high | 120s | pod | kubernetes_engine | — |
| `k8s.pod_kill` | k8s | high | 60s | pod | kubernetes_engine | — |
| `k8s.pod_latency` | k8s | medium | 300s | pod | kubernetes_engine | `seconds` (duration); `jitter_ms` (float, min 0, max 5000) |
| `k8s.pod_oom` | k8s | medium | 120s | pod | kubernetes_engine | `memory_limit` (string, default `64Mi`) |
| `k8s.pod_partition` | k8s | high | 300s | pod | kubernetes_engine | `seconds` (duration) |
| `k8s.pod_pressure` | k8s | medium | 300s | pod | kubernetes_engine | `resource` (string, default `cpu`); `target_percent` (percent, min 1, max 100) |
| `load.spike` | load | low | 900s | service | — | `rps` (integer, min 1); `seconds` (duration) |
| `mem.exhaust` | memory | high | 120s | container, service | — | `percent` (percent, min 1, max 99); `amount` (bytes); `mode` (`allocate` / `reclaim` / `freeze`, default `allocate`) |
| `mem.leak` | memory | high | 300s | container, service | — | `rate_mb` (integer, min 1, max 512, default `8`) |
| `net.bandwidth` | network | medium | 300s | container, service | net_admin | `rate` (string, **required**); `burst` (string, default `10k`); `direction` (string, default `egress`) |
| `net.conn_exhaust` | network | high | 300s | process, container, service | — | `count` (integer, min 1, max 8192, default `512`); `mode` (`ephemeral` / `accept`, default `ephemeral`); `port` (integer, min 1, max 65535, default `8080`, used by `accept` only) |
| `net.connection_refuse` | network | high | 300s | container, service | net_admin | `port` (integer, min 1, max 65535, **required**); `protocol` (string, default `tcp`) |
| `net.connection_reset` | network | medium | 300s | container, service | net_admin | `port` (integer, min 1, max 65535, **required**); `protocol` (string, default `tcp`) |
| `net.duplicate` | network | medium | 300s | container, service | net_admin | `percent` (percent, min 1, max 100); `direction` (string, default `egress`) |
| `net.interface_down` | network | high | 300s | process, container, service | net_admin | `device` (string, default `eth0`) |
| `net.latency` | network | medium | 300s | container, service | net_admin | `seconds` (duration); `jitter_ms` (integer, default `0`); `direction` (string, default `egress`) |
| `net.load` | network | medium | 600s | container, service | — | `users` (integer, min 1); `url` (string, default container `ip:port`); `script` (string) |
| `net.mtu_mismatch` | network | medium | 300s | process, container, service | net_admin | `device` (string, default `eth0`); `mtu` (integer, min 576, max 9216, default `1400`) |
| `net.packet_loss` | network | medium | 300s | container, service | net_admin | `percent` (percent, max 100); `direction` (string, default `egress`) |
| `net.partition` | network | high | 120s | container, service | net_admin | — |
| `net.reorder` | network | medium | 300s | container, service | net_admin | `percent` (percent, min 1, max 100); `delay_ms` (integer, default `50`); `direction` (string, default `egress`) |
| `net.tcp_half_open` | network | high | 300s | process, container, service | net_admin | `port` (integer, min 1, max 65535, **required**) |
| `node.service_stop` | node | high | 120s | service | — | — |
| `proc.pause` | process | low | 600s | container, process, service | process_control | — |
| `process.child_exhaust` | process | high | 300s | process, container, service | — | `children` (integer, min 1, max 4096, default `256`) |
| `process.crash_loop` | process | high | 120s | container, service | docker_engine | `restarts` (integer, min 1, max 1000, default `10`); `interval` (string, default `2s`) |
| `process.kill` | process | high | 60s | container, process, service | process_control | — |
| `process.stop` | process | medium | 300s | container, process, service | process_control | — |
| `process.thread_exhaust` | process | high | 300s | process, container, service | — | `threads` (integer, min 1, max 65536, default `512`) |
| `tls.certificate_expired` | tls | high | 120s | external_dependency, service | — | — |
| `tls.handshake_failure` | tls | high | 120s | container, external_dependency, service | net_admin | `port` (integer, min 1, max 65535, default `443`) |

The full, authoritative catalog is available at runtime: `mayhem discover faults`
lists every definition with its risk and compensatability; `mayhem discover capabilities`
probes the host for the tool capabilities (docker, podman, network tooling, …)
the faults require.

Several faults expose a **variant parameter** that selects between mechanisms
behind one fault id, rather than requiring a separate id per mechanism. The
sections below document those axes, and the faults whose parameter contract is
load-bearing in its own right — a required parameter, an absolute-path
constraint, a validated value — so the constraint is stated next to the fault
rather than only in the catalog. Every example uses the explicit `params:`
mapping; a param matching a `ParamSpec` name may equally be given as a flat
sibling key of `fault:` (see [`DrillFault`](#drillfault)).

### `db.query_error`

`error` selects the wire mechanism the client sees, and `timeout_ms` bounds how
long the client waits for the two timeout-shaped mechanisms.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `error` | string | `deadlock` | `deadlock` — connection reset (TCP RST) to the DB port. `lock_timeout` — the connection is blackholed, so the client's own statement timeout fires. `serialization_failure` — latency is injected on the DB flow, so the transaction fails client-side. |
| `timeout_ms` | integer (100–120000) | `5000` | How long the client waits. Applies to `lock_timeout` and `serialization_failure`; `deadlock` resets immediately and ignores it. |

```yaml
# A deadlock: the connection is reset, the client fails at once.
- fault: db.query_error
  duration: 30s
  params:
    error: deadlock

# A lock timeout: the client waits 2s on its own statement timeout.
- fault: db.query_error
  duration: 30s
  params:
    error: lock_timeout
    timeout_ms: 2000

# A serialization failure: injected latency on the DB flow aborts the
# transaction client-side.
- fault: db.query_error
  duration: 30s
  params:
    error: serialization_failure
    timeout_ms: 8000
```

### `db.slow_query`

`mode` decides whether the fault is actually slow or actually times out.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `mode` | string | `latency` | `latency` — real added latency on the DB flow. `timeout` — packets are dropped, so the client blocks until its own timeout. |

> **Breaking change.** The default is `latency`, which is **not** the
> behaviour this fault had before the `mode` parameter existed. The previous
> build always blackholed the DB flow — that is now `mode: timeout`. Any drill
> that relied on the old blackhole must now say so explicitly, or it will
> silently become a latency fault instead of a hang.

```yaml
# The default: the query really does get slower.
- fault: db.slow_query
  duration: 30s
  params:
    seconds: 5s

# The pre-`mode` behaviour, spelled out: the client hangs until its own timeout.
- fault: db.slow_query
  duration: 30s
  params:
    mode: timeout
```

### `dependency.circuit_open`

The upstream is never dialled. The proxy answers from its own accept loop, which
is exactly what a tripped breaker looks like from the caller's side.
`Retry-After` is emitted alongside the status, because without it the caller sees
a bare 503 and cannot tell an open circuit from a failing backend.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `status` | integer (100–599) | `503` | The status the caller receives. Any code in range; `503` is the one that reads as "unavailable". |
| `retry_after_s` | integer (0–3600) | `30` | Seconds written into `Retry-After`. `0` tells the caller to retry immediately, which is how you test a client with no backoff. |
| `probability` | percent (1–100) | `100.0` | Share of requests answered from the breaker. Requests outside it are relayed to the real upstream untouched, so a partly-degraded upstream is expressible. |
| `port` | integer (1–65535) | `80` | Port whose traffic is redirected to the fault. |

```yaml
# The upstream is never contacted; the caller gets 503 with Retry-After: 30.
- fault: dependency.circuit_open
  duration: 60s
  params:
    status: 503
    retry_after_s: 30

# A fast retry hint, on one request in four; the rest reach the real upstream.
- fault: dependency.circuit_open
  duration: 60s
  params:
    retry_after_s: 2
    probability: 25
```

### `dependency.response_truncate`

The same short-body mechanism as [`http.response_truncate`](#httpresponse_truncate)
on the dependency lane: the response declares more bytes than it delivers, then
the connection is closed.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `status` | integer (100–599) | `200` | Status line of the truncated response. The head is well formed, so the shortfall is the client's to notice. |
| `bytes` | integer (0–65536) | `64` | Bytes actually delivered. The declared `Content-Length` is 64× this value, so the default promises 4096 and sends 64. `0` declares and delivers nothing, which is a complete response rather than a truncated one. |
| `probability` | percent (1–100) | `100.0` | Share of responses truncated; the rest are relayed untouched. |
| `port` | integer (1–65535) | `80` | Port whose traffic is redirected to the fault. |

```yaml
# A dependency answers 200 with Content-Length: 4096 and 64 bytes of body.
- fault: dependency.response_truncate
  duration: 60s
  params:
    status: 200
    bytes: 64

# A JSON response cut off after 8 bytes, on half the calls.
- fault: dependency.response_truncate
  duration: 60s
  params:
    bytes: 8
    probability: 50
```

### `fd.exhaust`

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `mode` | string | `exhaust` | `exhaust` — open descriptors up to `limit` and hold them. `leak` — descriptors are acquired gradually and never released, so the process leaks them. |

```yaml
# Fill the table and hold it there for the duration.
- fault: fd.exhaust
  duration: 20s
  params:
    limit: 64
    mode: exhaust

# Leak descriptors gradually; the count never comes back down.
- fault: fd.exhaust
  duration: 60s
  params:
    limit: 256
    mode: leak
```

### `fs.corrupt`

Overwrites a file with deterministic garbage. This is the one fault in the tree
that mutates data the target already owns, so it copies the original to
`<path>.mayhem-orig` first and the undo puts it back: the file is **restored**,
not reconciled by restarting anything. `path` must be absolute because it is
resolved inside the target's own filesystem namespace, where a relative path
would be ambiguous about which working directory was meant.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `path` | string | *none* — **required** | Absolute path of the file to corrupt, resolved inside the fault target. A relative path is refused at plan time (`fs.corrupt path must be absolute`). |
| `bytes` | integer (16–1048576) | `4096` | How many bytes of garbage to write. The file is truncated to exactly this length, so a `bytes` smaller than the file destroys its tail. |
| `seed` | integer (1–65535) | `1` | Seed for the generator. The garbage is deterministic — the same `seed` and `bytes` produce the same corrupted content on every run, so a test can assert on it. |

```yaml
# Corrupt a config file in place; the undo restores the original bytes.
- fault: fs.corrupt
  duration: 30s
  params:
    path: /etc/app/config.yaml
    bytes: 8192
    seed: 7
```

### `fs.fill`

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `path` | string | `/tmp` | The filesystem to fill. Any path reachable from the fault's target. |

`path` replaces two narrower concepts. Filling a scratch filesystem is
`path: /tmp`; filling a log filesystem is `path: /var/log`. Neither needs its
own fault id.

```yaml
- fault: fs.fill
  duration: 30s
  params:
    percent: 90
    path: /var/log     # the default is /tmp
```

### `fs.io_stress`

`op` selects which of the already-declared throughput parameters are driven.
`read_mb_s` and `write_mb_s` keep their own meaning; `op` decides whether each
one is acted on.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `op` | string | `both` | `read` — drive `read_mb_s` only. `write` — drive `write_mb_s` only. `both` — drive whichever of the two is set. |

```yaml
# Sustained reads at 200 MiB/s per worker; write_mb_s is not driven.
- fault: fs.io_stress
  duration: 30s
  params:
    op: read
    read_mb_s: 200

# Sustained writes at 100 MiB/s per worker; read_mb_s is not driven.
- fault: fs.io_stress
  duration: 30s
  params:
    op: write
    write_mb_s: 100
```

### `http.header_inject`

Adds caller-supplied headers to the response. A broken or unexpected header is a
real production failure a status code cannot express: the response is well
formed and the client still misbehaves because of a header it did not expect.

`headers` is **validated, not escaped.** Three rules are enforced at plan time,
before the value ever reaches the target container:

- **No CR.** HTTP heads are CRLF-delimited, so a CR inside a value can end the
  line early and start a new one. Any CR is rejected outright.
- **Every line must parse as a `Name: value` pair.** Multiple headers are
  separated by a single LF, and the lines are rejoined as CRLF when the head is
  built. This rule is what makes multi-header input safe by construction: a line
  crafted to split the response would not be a header, so it is refused rather
  than escaped.
- **ASCII only.** The head is encoded as ASCII, so a non-ASCII value is refused
  rather than mangled.

Refusing is the honest outcome — silently stripping characters would produce a
fault that does not do what the operator wrote.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `headers` | string | `""` | The headers to add, separated by a single LF. Empty injects nothing. Subject to the three rules above. |
| `status` | integer (100–599) | `200` | Status line of the response the headers are spliced into. |
| `probability` | percent (1–100) | `100.0` | Share of responses carrying the headers; the rest are relayed untouched. |
| `port` | integer (1–65535) | `80` | Port whose traffic is redirected to the fault. |

The response is synthesized — your headers, then `Content-Length: 0`, then a
closed connection — rather than relayed from the upstream, which is what makes
the fault deterministic. What is under test is the client's reaction to a header
it did not expect, not its reaction to a short body. Use
[`http.stream_stall`](#httpstream_stall) when you need the real upstream response.

```yaml
# One unexpected header, on every response.
- fault: http.header_inject
  duration: 60s
  params:
    headers: "X-Request-Id: mayhem-drill-42"

# Several headers, separated by a single LF. Every line is a `Name: value` pair.
- fault: http.header_inject
  duration: 60s
  params:
    status: 200
    headers: |
      X-Drill: wave-2
      X-Upstream-Region: eu-west-1
    probability: 50
```

### `http.response_truncate`

The response declares more bytes than it delivers, then closes. This is not a
reset: the client holds a valid status line and a short body, and it is the
client's framing logic that has to notice.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `status` | integer (100–599) | `200` | Status line of the truncated response. The head is well formed, so the shortfall is the client's to notice. |
| `bytes` | integer (0–65536) | `64` | Bytes actually delivered before the connection is closed. The declared `Content-Length` is 64× this value, so the default promises 4096 and sends 64. `0` declares and delivers nothing, which is a complete response rather than a truncated one. |
| `probability` | percent (1–100) | `100.0` | Share of responses truncated; the rest are relayed untouched. |
| `port` | integer (1–65535) | `80` | Port whose traffic is redirected to the fault. |

```yaml
# The default: a 200 promising 4096 bytes and delivering 64.
- fault: http.response_truncate
  duration: 60s
  params:
    status: 200
    bytes: 64

# A JSON body cut off after 8 bytes, on a quarter of the calls.
- fault: http.response_truncate
  duration: 60s
  params:
    bytes: 8
    probability: 25
```

### `http.stream_stall`

The response head arrives and the body is then held mid-flight. The relay
streams in 64 KiB chunks on two threads, so the client-bound direction pauses
after its first chunk — the status line and headers — and the pause is
one-sided for free: the request still reaches the upstream and the upstream
still does its work. Unlike the other proxy-backed faults, the real upstream
response is relayed, so the body under test is the real body.

`stall_ms` is capped at 30000 because that is the timeout on the upstream socket
the relay reads from. A longer pause would be cut short by the relay's own read
timing out, which degrades the fault into a plain close; 30000 is the longest
stall that is still a stall.

The effect is strongest against streaming or large responses. A small body that
arrives in a single segment may not visibly stall, because the client has
nothing left to wait for.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `stall_ms` | integer (1–30000) | `5000` | How long the client waits after the response head, bounded by the upstream socket's 30 s timeout. |
| `probability` | percent (1–100) | `100.0` | Share of responses stalled; the rest are relayed untouched. |
| `port` | integer (1–65535) | `80` | Port whose traffic is redirected to the fault. |

```yaml
# The head arrives, the body waits 5s: a slow upstream that never times out.
- fault: http.stream_stall
  duration: 60s
  params:
    stall_ms: 5000

# The longest stall that is still a stall, on every third response.
- fault: http.stream_stall
  duration: 90s
  params:
    stall_ms: 30000
    probability: 34
```

### `mem.exhaust`

`mode` was previously reserved on the schema and rejected every value other
than `allocate`; the rejection is gone and each value is a real mechanism.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `mode` | string | `allocate` | `allocate` — commit anonymous memory and hold it. `reclaim` — allocate then release, forcing continuous kernel reclaim and thrash. `freeze` — hold resident memory, forcing reclaim pressure without further allocation. |

```yaml
# The default: grow the resident set and keep it.
- fault: mem.exhaust
  duration: 30s
  params:
    amount: 512M
    mode: allocate

# Churn: allocate and release in a loop so the kernel reclaims continuously.
- fault: mem.exhaust
  duration: 60s
  params:
    amount: 256M
    mode: reclaim

# Hold what is already resident and apply pressure without growing.
- fault: mem.exhaust
  duration: 60s
  params:
    mode: freeze
```

### `net.conn_exhaust`

Two different failures behind one id: running out of **outbound** ports is not
the same as running out of **accept** capacity, and they fail in different
places.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `mode` | string | `ephemeral` | `ephemeral` — bind and hold `count` loopback listeners, consuming the container's outbound ephemeral ports so new connections cannot be sourced. `accept` — connect to `port` `count` times and hold each socket without sending anything, filling the listener's accept queue so the server's accept loop stalls. |
| `count` | integer (1–8192) | `512` | How many sockets to take. Injection stops early when the resource runs out first, so the effective ceiling is the ephemeral port range or the listener backlog, not `count`. |
| `port` | integer (1–65535) | `8080` | The listener to fill. **Used by `mode: accept` only** — `ephemeral` never connects anywhere and ignores it, so the default is not a statement about your service. |

```yaml
# The default: eat the outbound ephemeral ports, so nothing new can be sourced.
- fault: net.conn_exhaust
  duration: 60s
  params:
    count: 512
    mode: ephemeral

# Fill the accept queue of a specific listener instead.
- fault: net.conn_exhaust
  duration: 60s
  params:
    mode: accept
    port: 8080
    count: 256
```

### `net.interface_down`

Takes the link down rather than shaping traffic. `net.partition` shapes with a
qdisc and leaves the link up, so a driver that still sees carrier — or that still
holds the interface — behaves differently from one whose link is genuinely gone.
The undo re-links the device and then proves it is usable, so a mistyped
`device` cannot pass silently.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `device` | string | `eth0` | The interface to take down. Set it to the device the fault target actually has; the undo probe fails if the name does not exist. |

```yaml
# The link on the target goes down; the undo brings it back and proves it is up.
- fault: net.interface_down
  duration: 30s
  params:
    device: eth0
```

### `net.load`

`net.load` saturates egress from the target container with a k6 HTTP load
generator running on the drill host. When `script` is set, that file (a path
relative to the drill spec) is materialized on the host and run as
`k6 run -u <users> -d <duration>s`, so you can drive arbitrarily shaped load
functions against any URL or endpoint the container can reach. When `script`
is omitted the target is derived from the first TCP port binding: a binding on
a loopback host address (`127.0.0.1`/`::1`) is reached through the host at
`http://localhost:<host-port>/` (host port may differ from the container
port), while any other binding is reached at the container's own live IP and
container-side port (`http://<container-ip>:<port>/`). Either way `url`
overrides the derived target. Both forms run the same marker/pid-undo contract. The
impact gate treats `k6` as **host-side tooling**: `net.load` is gated on the
`k6` binary being present on the drill host (never inside the container), and
`mayhem prepare dependencies` never lists or installs it as a container package — install
k6 on the host directly.

```yaml
- fault: net.load
  duration: 120s
  params:
    users: 10000
    url: http://10.0.0.5:8080/   # used by the auto-generated script only

- fault: net.load
  duration: 120s
  params:
    users: 10000
    script: k6/script.js         # custom load function (relative to this drill file)
```

### `net.mtu_mismatch`

Drops the interface MTU so packets larger than the new value must fragment or
are dropped. The original MTU is read into a marker file at inject time and
written back at undo, so the restore is exact even on an interface that was
never 1500.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `device` | string | `eth0` | The interface whose MTU is changed. |
| `mtu` | integer (576–9216) | `1400` | The MTU to set. Below 1500, anything that does not path-MTU-discover has to fragment or stall. The 576 floor is what RFC 791 requires an IPv4 host to be able to forward — below it the interface is unusable, which is a different fault from fragmentation. |

```yaml
# Drop to the classic Ethernet-with-VPN MTU: large packets fragment.
- fault: net.mtu_mismatch
  duration: 60s
  params:
    device: eth0
    mtu: 1400
```

### `net.tcp_half_open`

Drops the SYN-ACK on `port`, so the client's socket is created on both sides
and then hangs. `net.partition` is a total egress blackhole and
`net.connection_reset` fails an established flow with an RST; neither produces
the half-open state a client sees when its SYN is answered by nothing at all.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `port` | integer (1–65535) | *none* — **required** | Destination port whose SYN-ACK is dropped. There is no safe default: a wrong guess installs the rule against a port nobody is using, the fault never fires, and the round still passes because the undo probe only checks the rule is gone. |

```yaml
# Connections to 5432 open and then hang; nothing is ever established.
- fault: net.tcp_half_open
  duration: 60s
  params:
    port: 5432
```

### `process.child_exhaust`

Forks until the container's **pid cgroup** refuses, then holds the survivors
open. It is the cgroup, not `RLIMIT_NPROC`: a container is bounded by the cgroup
pid limit, whereas `RLIMIT_NPROC` counts per-uid across the whole host and is
usually not set at all — so a fault that leaned on it would not reproduce the
failure a real container hits.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `children` | integer (1–4096) | `256` | How many children to fork before holding. Forking stops when the cgroup refuses, and the count actually reached is reported rather than assumed. |

```yaml
# Fork until the pid cgroup says no; the survivors sleep and are held.
- fault: process.child_exhaust
  duration: 60s
  params:
    children: 256
```

### `process.thread_exhaust`

Spawns worker threads that park on an event until the pool is spent. Threads are
cheaper than processes and hit a different limit, so this exercises the
thread/worker-pool exhaustion path a fork bomb cannot: a container that can
still fork but whose workers refuse new tasks. The threads are daemonised and
held by a reference so the interpreter stays alive; the undo kills the payload
process and they all go with it.

| Param | Type | Default | Accepted values |
|-------|------|---------|-----------------|
| `threads` | integer (1–65536) | `512` | How many threads to create. Creation stops when the runtime refuses, and the count actually reached is reported rather than assumed. |

```yaml
# The default: 512 parked workers, so the thread pool is spent.
- fault: process.thread_exhaust
  duration: 60s
  params:
    threads: 512
```

### Compensation lifecycle

Every compensatable fault resolves to a `CompensationTemplate` (see
`controller.compensation`). A template pairs an **undo builder** with a
**verify builder**. The undo leg produces one or more `UndoOp`s that reverse
the injection; the verify leg produces `VerifyProbe`s that prove the fault is
gone. Both are generated from the same `PlannedFault` parameters and address
the same marker artifacts the inject leg created, so what was injected is
exactly what gets removed and verified.

Undo strategies are grouped by mechanism (executor routing and the full
per-fault template table live in `docs/compensation.md`):

| Mechanism | Representative faults | Undo | Verify |
|---|---|---|---|
| Payload marker (pid) | `mem.exhaust`, `mem.leak`, `cpu.saturate`, `fs.fill`, `fs.inode_exhaust`, `fs.io_stress`, `fd.exhaust`, `load.spike`, `fuzz.protocol_abuse`, `process.thread_exhaust`, `process.child_exhaust`, `net.conn_exhaust` | `kill -9` on marker pid (plus `rm` of marker siblings for the `fs.*` faults) | pidfile absent |
| tc qdisc | `net.latency`, `net.packet_loss`, `net.bandwidth`, `net.reorder`, `net.duplicate`, `net.load`, `dependency.timeout` | `tc qdisc del` | tc chain absent |
| Link / MTU state | `net.interface_down`, `net.mtu_mismatch` | `ip link set … up`, or the MTU read back from the marker at inject | interface reports `state UP`; saved-MTU marker absent |
| iptables rule | `db.query_error`, `db.slow_query`, `tls.handshake_failure`, `dependency.block`, `net.tcp_half_open` | `iptables -D` rule removal | rule absent |
| iptables reject | `net.connection_reset`, `net.connection_refuse`, `dependency.connection_refuse` | `iptables -D` rule removal (`tcp-reset` / `icmp-port-unreachable`) | rule absent |
| Pulsing rule | `dns.timeout`, `dns.servfail`, `dependency.flap` | Time-gated rule removal (marker-suffixed) | iptables rule absent |
| In-container proxy | `http.latency`, `http.error_injection` (prob = 100), `dependency.rate_limit`, `db.connection_exhaust`, `http.response_truncate`, `http.header_inject`, `http.stream_stall`, `dependency.response_truncate`, `dependency.circuit_open` | Kill proxy pid, delete nat REDIRECT, remove markers | pidfile + rule absent |
| Engine state | `cpu.throttle`, `clock.skew`, `process.crash_loop` | Engine `update --cpus` / clock restore / engine `start` | engine state restored |
| Filesystem remount | `fs.read_only` | `mount -o remount,rw` restore | write-probe succeeds |
| File revert | `dns.nxdomain`, `tls.certificate_expired`, `fs.corrupt` | Restore original file from backup marker | file content restored |
| Container network | `net.partition` | Engine network disconnect / connect restore | connectivity restored |

`http.error_injection` is a dual personality at plan time (ADR note in
`docs/compensation.md`): `probability < 100` uses a synchronous iptables
`REJECT` (undo deletes the rule), while `probability == 100` (the default)
uses the in-container proxy track.

The inject path, the undo path, and the verify probe are generated from the
same plan-level parameters and address the same marker artifacts — this
"same-contract" invariant is what makes verification check the full lifecycle
rather than a partial teardown.

Full details: [docs/compensation.md](compensation.md).

## Design Rules

- **Identity is the target name.** For `containers:` specs, fault targets and
  check loci resolve from `container_name:` against the compose blueprint.
  For `targets:` specs, they resolve from the logical target names against the
  locator blocks (compose containers, k8s workloads / pods / nodes). Compose
  project filtering and drift detection keep the discovered topology aligned
  with the blueprint; k8s workloads are resolved to live pods at execution
  time. `mayhem run --ctr` / `mayhem maniac --ctr` accept the same value (or
  the runtime container name) to scope an entire execution to a single
  container, so a target can be faulted in isolation without editing the spec.
- **The fault applies only if the catalog says it can.** Applicable node kinds
  (container / service / host / k8s_node / pod / process / external_dependency)
  and required capabilities gate injection at validate and plan time.
- **Risk ceilings compose, tightening only.** The drill `config.risk_ceiling`
  intersects the policy ceiling in `mayhem.yaml`; a fault passes only when below
  both. `critical`-risk faults (`k8s.node_drain`) additionally need a triple
  opt-in: `policy.allow_critical: true`, a per-fault ack in
  `policy.critical_fault_acks`, and the `--allow-critical` CLI flag.
- **Every fault is compensated.** Reversible faults run their declared inverse;
  irreversible ones (`container.kill`, `k8s.pod_evict`, …) are followed by a
  container-spec reconciliation that restores the faulted workload
  (the compensation contract). Node drains/pressure run the node-scope
  executors via the `kubernetes_engine` capability.
- **Rounds recover independently.** A failed round aborts-and-recovers its own
  faults first, then propagates; orphaned leases are swept by the janitor.
- **The spec schema is frozen.** Evolution happens through migrations on the
  database side, not by editing the DSL shape.
- **Decisions are recorded on the run.** Each run row snapshots the governing
  decision revisions it executed under, so an old run is reproducible even after
  the catalog moves on.