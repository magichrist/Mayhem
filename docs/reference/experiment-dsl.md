# Experiment DSL Reference

YAML authoring surface compiled into `ExecutionPlan` ([experiment-engine](../architecture/experiment-engine.md)).
Two kinds: `DeterministicExperiment` and `RandomExperiment`. Validation errors are typed and
point at the offending field.

---

## 1. Deterministic experiment

```yaml
kind: DeterministicExperiment
apiVersion: mayhem.dev/v1
metadata:
  name: db-partition-during-checkout
  labels: {team: payments, env: staging}
  hypothesis: >-
    A 30s api→db partition causes connection-pool exhaustion that outlives the fault.

method:                          # free-form narrative, rendered into journal
  approach: partition, observe, recover, compare steady-state windows

constraints:
  duration_cap: 5m
  abort_on_violation: true       # default true
  blast_radius:                  # optional per-experiment tightening of policy budgets
    max_concurrent_faults: 1

steady_state:                    # reusable checks; evaluated pre/during/post
  - id: api-healthy
    probe: {type: http, url: "http://api:8000/healthz", timeout: 2s}
    expect: {status: 200, p99_ms_lt: 500}
    on_pre_failure: skip_run     # skip_run | abort
  - id: pg-reachable
    probe: {type: exec, cmd: ["pg_isready", "-h", "postgres"]}
    expect: {exit_code: 0}

steps:
  - start_load:
      tool: k6
      script: ./scenarios/checkout.js
      profile: {vus: 50, duration: 4m}

  - inject_fault:
      fault: net.partition
      targets: [{kind: service, expr: api}, {kind: external_dependency, expr: postgres}]
      params: {direction: bidirectional}
      duration: 30s
      backend: auto              # auto | explicit backend name (ADR-0010)

  - wait: {duration: 60s}        # observe past recovery point

  - check: {ref: api-healthy}
```

### Step types

| Step | Fields |
|---|---|
| `inject_fault` | `fault`, `targets[]`, `params` (fault schema), `duration`, `backend?`, `on_failure?` |
| `start_load` / `stop_load` | `tool`, `script/profile`, `name` for later stop reference |
| `wait` | `duration` or `until_check_passes {ref, timeout}` |
| `check` | `ref` (evaluates in current phase context) |
| `parallel` | `branches[]` — child steps run concurrently; barrier join; budget-capped |
| `notify` | `channel: slack\|webhook`, `message` |

Common step fields: `timeout`, `retries {attempts, backoff}`, `on_failure`
(`abort_and_recover` default | `continue`).

## 2. Target selectors (`TargetRef`)

```yaml
{kind: service,              expr: postgres}
{kind: container,            expr: "label=com.docker.compose.service=api"}
{kind: host,                 expr: bm-1}
{kind: process,              expr: "cmdline~=uvicorn"}
{kind: external_dependency,  expr: redis}
```

Resolved at validation and re-asserted at injection ([safety](../architecture/safety.md) G3).

## 3. Random experiment

```yaml
kind: RandomExperiment
apiVersion: mayhem.dev/v1
metadata: {name: maniac-nightly-staging}
seed: null                      # null = derive + record; integer = reproduce
selection:
  count: 1                      # faults per generated plan
  categories: [process, cpu, memory, network, storage]
  exclude_faults: [node.reboot]
  forbidden_pairs: [[storage.fill, db.conn_exhaust]]
  diversity_window: 10          # runs
constraints:
  risk_ceiling: high            # policy may cap lower; never higher
  require_dry_run_first: true   # default from policy
```

Generated plans are re-validated through the identical compiler path; decisions recorded to
`maniac_decisions` ([maniac-engine](../architecture/maniac-engine.md)).

## 4. Compilation rules

1. Unknown fields rejected (strict schemas) — typo-safety over leniency.
2. Durations parsed as `30s | 5m | 1h`; percentages as floats ≤ 100.
3. Every referenced check id must exist; every load started must be stopped or self-expiring.
4. Budget fit checked at compile time against current policy budgets.
5. Output: frozen `ExecutionPlan` JSON pinned with config snapshot + topology snapshot.
