# Drill Spec DSL Reference

The **drill spec** is the single, unified description of a chaos drill (ADR-0019).
One YAML file (``kind: drill``) replaces the old two-file arrangement (``mayhem.yml``
config + step-based fault spec). It declares:

- **config** — safety and runtime settings (risk ceiling, timeout, log level)
- **containers** — per-container faults, keyed by the stable ``container_name:``
- **execution** — cross-container ordering (parallel, sequential, wait, check)

A drill spec is validated and planned with the app lifecycle commands:

```bash
mayhem validate examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem plan     examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
mayhem run      --db .mayhem/e2e.db examples/testCase/mayhem.yaml --compose examples/testCase/docker-compose.yml
```

---

## Top-Level Fields

| Field         | Type                    | Required | Default          | Description |
|---------------|-------------------------|----------|------------------|-------------|
| `kind`        | `"drill"` (literal)     | yes      | —                | Discriminator; must be exactly `drill`. |
| `name`        | string                  | yes      | —                | Drill name; run ids carry it as a readable prefix (`r-<name>-<suffix>`). The unique suffix lets unlimited runs against one spec be recorded in a persistent DB. |
| `hypothesis`  | string                  | no       | `""`             | What the drill is trying to prove. |
| `config`      | [DrillConfig](#config)  | no       | `DrillConfig()`  | Safety / runtime settings. |
| `containers`  | map<string, [DrillContainer](#containers)> | yes | — | Faults per container. At least one required. |
| `execution`   | list<[ExecutionStep](#execution)> | yes | — | Ordering of fault rounds. At least one step required. |

### Container Keys

The keys of `containers:` **are** the `container_name:` values declared in the
`docker-compose.yml`. This is the identity anchor (ADR-0020): Mayhem resolves PIDs
and IPs from this name **at execution time**, immediately before injection, so fault
injection always targets the live process even if a container restarted.

```yaml
# docker-compose.yml
services:
  api:
    name: testcase-api   # <-- used as the drift spec container key below
```

Every service in the compose file must set `name:` — there is no fallback to the
service key.

---

## `config`

Replaces the separate `mayhem.yml` for drill contexts.

| Field          | Type            | Default   | Description |
|----------------|-----------------|-----------|-------------|
| `risk_ceiling` | `low`/`medium`/`high`/`critical` | `high` | Maximum allowed fault risk. A drill that would inject a higher-risk fault is refused at plan time (safe-by-construction). |
| `max_faults`   | int (≥ 0)       | `1`       | Maximum number of faults injected per round. |
| `timeout`      | duration string | `30m`     | Overall drill timeout (e.g. `10s`, `5m`, `30m`). |
| `log_level`    | `DEBUG`/`INFO`/`WARNING`/`ERROR` | `INFO` | Log verbosity for the drill run. |

```yaml
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 30m
  log_level: INFO
```

---

## `containers`

Each container maps a `container_name` to a list of faults. Faults on the same
container run **sequentially**.

### `DrillFault`

| Field         | Type                         | Default               | Description |
|---------------|------------------------------|-----------------------|-------------|
| `fault`       | string (catalog id)          | —                     | Which fault to inject. See the [fault catalog](#fault-catalog). |
| `duration`    | duration string              | `10s`                 | How long to keep the fault injected before undoing. |
| `on_failure`  | `abort_and_recover`          | `abort_and_recover`   | Behavior if the round fails (currently the only supported value). |
| `targets`     | list<string>                 | `()`                  | Network faults only: container names an upstream should be partitioned from. |

```yaml
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
        on_failure: abort_and_recover

  testcase-lb:
    faults:
      - fault: net.partition
        duration: 5s
        targets: [testcase-api, testcase-download-1]
```

---

## `execution`

Controls cross-container ordering. A list of steps run in order; each step is one of:

| Step            | Type                         | Semantics |
|-----------------|------------------------------|-----------|
| `parallel`      | list<string> (container names) | Run those containers' faults concurrently. |
| `sequential`    | list<string> (container names) | Run those containers' faults one after another. |
| `wait`          | duration string              | Pause before moving on (lets effects manifest). |
| `check`         | list<[CheckProbe](#checkprobe)> | Run health probes and fail the drill if expectations aren't met. |

A step must contain exactly one of these keys.

### `CheckProbe`

| Field    | Type               | Description |
|----------|--------------------|-------------|
| `http`   | string (URL)       | HTTP URL to probe. Resolved from container name → IP at check time. |
| `expect` | map                | Expectations; currently `status` (int). |

```yaml
execution:
  - parallel: [testcase-api, testcase-download-1]
  - wait: 5s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
  - sequential: [testcase-lb]
  - wait: 3s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
```

---

## Fault Catalog

Faults are identified by their catalog id in `fault:`. Risk levels feed the
`risk_ceiling` gate. Durations are capped per fault (see column).

| Fault id                | Category | Risk    | Max duration | Parameters |
|--------------------------|----------|---------|--------------|------------|
| `proc.pause`             | process  | low     | 600s         | — |
| `cpu.saturate`           | cpu      | medium  | 300s         | `percent` (1–100) |
| `mem.exhaust`            | memory   | high    | 120s         | `percent` (1–99) **or** `amount` (byte DSL) |
| `fs.fill`                | storage  | medium  | 300s         | `percent` (1–99) |
| `net.latency`            | network  | medium  | —            | `ms`, `jitter_ms` |
| `net.partition`          | network  | high    | —            | `targets` (list in the fault) |
| `container.kill`         | container| medium  | —            | `signal` (default `SIGKILL`) |
| `node.service_stop`      | node     | high    | —            | — |
| `http.error_injection`   | http_api | medium  | —            | `status` (default `500`) |
| `db.slow_query`          | database | medium  | —            | `seconds` |
| `load.spike`             | load     | low     | —            | `rps`, `duration` |
| `fuzz.protocol_abuse`    | fuzz     | medium  | —            | — |
| `dns.resolve_delay`      | dns      | high    | —            | `ms` |
| `dns.nxdomain`           | dns      | low     | —            | `name` |
| `tls.certificate_expired`| tls      | high    | —            | — |
| `clock.skew`             | clock    | high    | 300s         | `offset_ms` (required) |
| `fd.exhaust`             | fd       | high    | 120s         | `limit` (default `64`) |

### Byte-quantity DSL

Faults that take a size (e.g. `mem.exhaust` with `amount`) accept a byte-quantity
string: a number plus an optional unit. Plain `K`/`M`/`G`/`T` and `KiB`/`MiB`/
`GiB`/`TiB` are powers of 1024; `KB`/`MB`/`GB`/`TB` are powers of 1000; a bare
number is plain bytes.

```yaml
- fault: mem.exhaust
  amount: 256M   # 256 * 1024 * 1024 bytes
  duration: 20s
```

When both `amount` and `percent` are given, `amount` wins. `amount` is also
capped at 95% of the container's memory limit so a drill can never OOM-kill the
whole container.

> A fault whose definition lacks an executable compensation/undo template is refused
> at plan time — every injected fault is reversible.

---

## Examples

### 1. Basic

A single-pause drill on one container.

```yaml
kind: drill
name: pause-drill
hypothesis: "A brief pause of the API is survivable"

config:
  risk_ceiling: high
  max_faults: 1
  timeout: 10m

containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s

execution:
  - parallel: [testcase-api]
  - wait: 3s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
```

### 2. Full Stack

Faults across API, download server, and load balancer with checks between rounds.

```yaml
kind: drill
name: full-stack-drill
hypothesis: "The stack recovers from every implemented fault"

config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 30m
  log_level: INFO

containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
        on_failure: abort_and_recover
  testcase-download-1:
    faults:
      - fault: proc.pause
        duration: 10s
  testcase-lb:
    faults:
      - fault: fuzz.protocol_abuse
        duration: 5s

execution:
  - parallel: [testcase-api, testcase-download-1]
  - wait: 5s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
  - sequential: [testcase-lb]
  - wait: 3s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
```

### 3. Network Partition

Isolate the load balancer from its upstreams and verify it recovers.

```yaml
kind: drill
name: network-partition-drill
hypothesis: "The load balancer recovers after a partition from its backends"

config:
  risk_ceiling: high
  max_faults: 1
  timeout: 15m

containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
  testcase-lb:
    faults:
      - fault: net.partition
        duration: 5s
        targets: [testcase-api, testcase-download-1]

execution:
  - sequential: [testcase-api, testcase-lb]
  - wait: 5s
  - check:
      - http: http://testcase-lb:8080/
        expect: { status: 200 }
```

---

## Design Rules

- `containers:` keys ARE the `container_name:` values from `docker-compose.yml` — the
  stable identity anchor. No PID fragility, no process-name selectors.
- `faults:` run sequentially within each container; cross-container ordering is
  controlled by `execution:`.
- `check:` targets are resolved by container name → IP at check time.
- `config:` replaces the separate `mayhem.yml` for drill contexts — single source of truth.
- PIDs and IPs are resolved immediately before the injection syscall (ADR-0020), so a
  restarted container never receives a stale PID.
- Only `kind: drill` is supported; `deterministic` and `random` were removed (ADR-0021).
