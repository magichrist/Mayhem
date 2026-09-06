# Drill Spec DSL Reference

The **drill spec** is the single, unified description of a chaos drill. One YAML
file (`kind: drill`) replaces the old arrangement of a separate `mayhem.yml`
config plus a step-based fault spec. It declares:

- **config** — safety and runtime settings (risk ceiling, fault budget, timeout, log level)
- **config.maniac** — optional random-injection dial for `mayhem maniac`
  (random container/fault rounds instead of the authored plan)
- **containers** — per-container faults, keyed by the stable `container_name:`
- **execution** — cross-container ordering (parallel, sequential, wait, check)
- **success** — optional machine-evaluable criteria that turn the run into a
  PASS/FAIL verdict
- **observability** — optional declarative evidence sources collected into the
  outcome record

The spec is consumed by the lifecycle commands:

```bash
mayhem validate examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem plan     examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem run      examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem maniac   examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
```

`validate` compiles the spec and runs every safety gate without injecting
anything. `plan` prints the frozen execution plan as JSON. `run` executes it
end-to-end and prints the run summary (status, verdict, observations, per-step
results). `maniac` [compiles the same way](#maniac-mode) but replaces the
authored execution with random (container, fault) rounds. Omit `--compose` to
auto-detect a compose file in the current directory (`docker-compose.yml`,
`compose.yml`, …).

---

## Top-Level Fields

| Field           | Type                               | Required | Default         | Description |
|-----------------|------------------------------------|----------|-----------------|-------------|
| `kind`          | `"drill"` (literal)                | yes      | —               | Discriminator; must be exactly `drill`. |
| `name`          | string                             | yes      | —               | Drill name; run ids carry it as a readable prefix (`r-<name>-<suffix>`). Unlimited runs against one spec are recorded in the persistent DB. |
| `hypothesis`    | string                             | no       | `""`            | What the drill is trying to prove. |
| `config`        | [DrillConfig](#config)             | no       | `DrillConfig()` | Safety / runtime settings. |
| `containers`    | map<string, [DrillContainer](#containers)> | yes | — | Faults per container. At least one required. |
| `execution`     | list<[ExecutionStep](#execution)>  | yes      | —               | Ordering of fault rounds. At least one step required. |
| `success`       | [SuccessCriteria](#success)        | no       | —               | Machine verdict criteria. |
| `observability` | [ObservabilityConfig](#observability) | no    | —               | Evidence sources collected into the record. |

`apiVersion: mayhem/v1` is tolerated and ignored — the drill spec is versioned by
its own schema freeze, not by `apiVersion`.

## Config

| Field          | Type                              | Default | Description |
|----------------|-----------------------------------|---------|-------------|
| `risk_ceiling` | `low` / `medium` / `high` / `critical` | `high`  | Refuse any fault whose catalog risk exceeds this. Tightens the policy ceiling in `mayhem.yaml`; it can only make the policy tighter, never looser. |
| `max_faults`   | int (≥ 0)                         | `1`     | Maximum number of faults injected concurrently. `0` lets a parallel step run unbounded. |
| `timeout`      | duration                          | `30m`   | Whole-run timeout; the executor aborts and recovers past this. |
| `log_level`    | `DEBUG` / `INFO` / `WARNING` / `ERROR` | `INFO` | Log verbosity for the drill run. |
| `recovery`     | bool                              | `true`  | Automatically undo each fault after injection (restore the container). `false` keeps the perturbation in place so downstream checks observe whether the stack self-heals — see [Recovery control](#recovery-control). |
| `maniac`       | [ManiacConfig](#maniac-mode)      | —       | Random-injection tuning for `mayhem maniac` (level, run count, seed). Falls back to the `maniac:` key in the layered `mayhem.yaml` when the drill spec omits it; a spec-level block always wins. |

```yaml
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 30m
  log_level: INFO
  # true (default): auto-recover the container after each fault.
  # false: keep the fault in place and let downstream checks decide whether
  #        the stack self-heals without the engine reviving anything.
  recovery: true
```

### Maniac mode

`mayhem maniac` compiles a spec exactly like `mayhem run`, but replaces the
authored `execution:` steps with `run_level` random (container, fault) rounds
([ADR-M5-1](#maniac-mode)). Every other contract is unchanged: the risk
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
  later `mayhem audit` shows the container was intentionally left faulted.
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

Each key of `containers:` **is** a `container_name:` value from the
`docker-compose.yml` — the stable identity anchor. Mayhem resolves PIDs and
addresses from this name at **execution time**, immediately before injection,
so a fault always targets the live process even if a container restarted in the
meantime. Everything else the drill records stays descriptive — what gates a
fault is the catalog and the impact gate, not runtime hints.

Faults listed under one container run **sequentially**.

### `DrillFault`

| Field          | Type                          | Default             | Description |
|----------------|-------------------------------|---------------------|-------------|
| `fault`        | string (catalog id, e.g. `net.latency`) | — | Which fault to inject. See the [fault catalog](#fault-catalog). |
| `duration`     | duration                      | `10s`               | How long to keep the fault injected before running its compensation. Capped per fault by the catalog. |
| `on_failure`   | `abort_and_recover`           | `abort_and_recover` | Behavior if the round fails (currently the only supported value). |
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

Unknown parameters are rejected with a schema error (`mayhem validate` fails);
every fault validates its parameters against the catalog `params_schema`.

## Execution

`execution:` is an ordered list of steps. Each step has **exactly one** key —
the action to take. Steps run left to right, top to bottom.

| Key         | Value                               | Meaning |
|-------------|-------------------------------------|---------|
| `parallel`  | list of container names             | Inject this step's fault on all named containers concurrently (subject to `max_faults`). |
| `sequential`| list of container names             | Run this step's faults against each container one after another. |
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

`max_faults` gates **concurrently injected** faults, not the count of steps —
a `parallel` step with more containers than `max_faults` queues containers into
rounds so the concurrency ceiling is never exceeded.

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
`mayhem validate` enforces.

| Fault | Category | Risk | Max | Applicable node kinds | Capability | Parameters |
|---|---|---|---|---|---|---|
| `clock.skew` | clock | high | 300s | container, host, service | net_admin | `offset_ms` (int, required) |
| `container.kill` | container | medium | 60s | container, service | docker_engine | `signal` (string, default `SIGKILL`) |
| `container.pause` | container | medium | 300s | container, service | docker_engine | — |
| `container.restart` | container | medium | 60s | container, service | docker_engine | — |
| `cpu.saturate` | cpu | medium | 300s | host, service | — | `percent` (1–100) |
| `db.slow_query` | database | medium | 300s | external_dependency, service | — | `seconds` (duration) |
| `dependency.block` | dependency | high | 300s | container, external_dependency, service | net_admin | `port` (int 1–65535, required), `protocol` (string, default `tcp`) |
| `dependency.timeout` | dependency | medium | 300s | container, external_dependency, service | net_admin | `port` (int, required), `delay_ms` (int 1–30000, required), `protocol` (string, default `tcp`) |
| `dns.nxdomain` | dns | high | 300s | host, service | net_admin | `domain` (string) |
| `dns.resolve_delay` | dns | medium | 300s | host, service | net_admin | `seconds` (duration) |
| `fd.exhaust` | fd | high | 120s | container, host, service | — | `limit` (int, default 64) |
| `fs.fill` | storage | medium | 300s | container, host, service | — | `percent` (1–99) |
| `fs.inode_exhaust` | storage | medium | 300s | container, host, service | — | `percent` (1–99) |
| `fs.io_stress` | storage | low | 120s | container, host, service | — | `seconds`, `workers` (1–8, default 1), `io_bytes` (1M–1G, default 64M) |
| `fuzz.protocol_abuse` | fuzz | high | 180s | external_dependency, service | — | — |
| `http.error_injection` | http_api | medium | 300s | external_dependency, service | — | `status` (int, default 500) |
| `k8s.network_policy` | k8s | high | 300s | k8s_node, pod | kubernetes_engine | `policy_name` (string), `direction` (string, default `ingress`) |
| `k8s.node_drain` | k8s | critical | 600s | k8s_node | kubernetes_engine | `grace_period` (int, default 30) |
| `k8s.node_pressure` | k8s | high | 300s | k8s_node | kubernetes_engine | `resource` (string, default `cpu`), `target_percent` (1–100) |
| `k8s.pod_evict` | k8s | high | 120s | pod | kubernetes_engine | — |
| `k8s.pod_kill` | k8s | high | 60s | pod | kubernetes_engine | — |
| `k8s.pod_latency` | k8s | medium | 300s | pod | kubernetes_engine | `seconds` (duration), `jitter_ms` (float 0–5000) |
| `k8s.pod_oom` | k8s | medium | 120s | pod | kubernetes_engine | `memory_limit` (string, default `64Mi`) |
| `k8s.pod_partition` | k8s | high | 300s | pod | kubernetes_engine | `seconds` (duration) |
| `k8s.pod_pressure` | k8s | medium | 300s | pod | kubernetes_engine | `resource` (string, default `cpu`), `target_percent` (1–100) |
| `load.spike` | load | low | 900s | service | — | `rps` (int ≥ 1), `seconds` (duration) |
| `mem.exhaust` | memory | high | 120s | container, service | — | `percent` (1–99), `amount` (bytes, e.g. `256M`) |
| `net.latency` | network | medium | 300s | container, service | net_admin | `seconds` (duration), `jitter_ms` (int, default 0) |
| `net.load` | network | medium | 600s | container, service | — | `users` (int ≥ 1), `url` (string, default `http://localhost/`), `script` (optional string — path relative to the drill spec to a k6 `script.js`) |
| `net.partition` | network | high | 120s | container, service | net_admin | — (use `targets:` to name the partition peers) |
| `node.service_stop` | node | high | 120s | service | — | — |
| `proc.pause` | process | low | 600s | container, process, service | process_control | — |
| `process.kill` | process | high | 60s | container, process, service | process_control | — |
| `process.stop` | process | medium | 300s | container, process, service | process_control | — |
| `tls.certificate_expired` | tls | high | 120s | external_dependency, service | — | — |

The full, authoritative catalog is available at runtime: `mayhem toolkit faults`
lists every definition with its risk and compensatability; `mayhem toolkit list`
probes the host for the tool capabilities (docker, podman, network tooling, …)
the faults require.

### `net.load`

`net.load` saturates egress from the target container with a k6 HTTP load
generator. When `script` is set, that file (a path relative to the drill spec)
is copied into the container and run as `k6 run -u <users> -d <duration>s`, so
you can drive arbitrarily shaped load functions against any URL or endpoint the
container can reach. When `script` is omitted the fault needs no input beyond
`users` and `url`: a minimal script that GETs `url` is generated automatically,
exactly as before — both forms run the same marker/pid-undo contract, and both
require the `k6` binary inside the target container (checked by the impact
gate).

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

## Design Rules

- **Identity is the container name.** Fault targets and check loci resolve from
  `container_name:` against the compose blueprint. Compose project filtering and
  drift detection keep the discovered topology aligned with the blueprint.
- **The fault applies only if the catalog says it can.** Applicable node kinds
  (container / service / host / k8s_node / pod / process / external_dependency)
  and required capabilities gate injection at validate and plan time.
- **Risk ceilings compose, tightening only.** The drill `config.risk_ceiling`
  intersects the policy ceiling in `mayhem.yaml`; a fault passes only when below
  both. `--allow-critical` is the operator-side acknowledgment for
  `critical`-risk faults (`k8s.node_drain`).
- **Every fault is compensated.** Reversible faults run their declared inverse;
  irreversible ones (`container.kill`, `k8s.pod_evict`, …) are followed by a
  container-spec reconciliation that restores the faulted workload
  (the compensation contract).
- **Rounds recover independently.** A failed round aborts-and-recovers its own
  faults first, then propagates; orphaned leases are swept by the janitor.
- **The spec schema is frozen.** Evolution happens through migrations on the
  database side, not by editing the DSL shape.
- **Decisions are recorded on the run.** Each run row snapshots the governing
  decision revisions it executed under, so an old run is reproducible even after
  the catalog moves on.