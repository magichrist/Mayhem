# Config (`mayhem.yaml` / mayhem config)

This document is the **complete reference for authoring Mayhem configuration** —
the layered `config:` file, its discovery order, its merged syntax, every field
with its type and default, environment-variable overrides, CLI overrides, and
how every command absorbs config.

Everything below was verified against the live schema in
`src/mayhem/infra/config.py` and the actual command wiring in
`src/mayhem/cli/*.py`. Where a folk claim diverges from the implementation,
the implementation is stated and marked.

---

## 1. What a config file is

A Mayhem config file is a YAML standalone (`mayhem.yaml`, `mayhem.yml`,
`.mayhem.yaml`, `.mayhem.yml`) that may appear in **two syntactically distinct
forms**, both absorbed through the same layered engine:

### 1a. Standalone config (no `kind:`)

```yaml
config:
  policy:
    risk_ceiling: critical
    allow_critical: true
  blast_radius:
    storage: [db]
    network: none
    host: [process]
  log_level: INFO
```

### 1b. Drill spec with an embedded `config:` block

A drill spec (`kind: drill`) may carry a config block at the **top level** of
the drill spec — this is "embedded config". When Mayhem runs the drill, the
embedded `config:` block is **absorbed into the layered config** before the
drill's gates are executed:

```yaml
# drill-spec-a.mayhem (or mayhem.yaml)
apiVersion: mayhem/v1
kind: drill
metadata:
  name: dependency drill
config:                # <-- embedded config block, absorbed on run
  policy:
    risk_ceiling: critical
  runtime:
    recovery: false
drills:
  - name: dependency drill
    env: [MAYHEM_RISK_CEILING=critical]
```

Both forms flow through the same `layered_config` absorption; an embedded
`config:` block is simply a config layer authored inside the spec. The drill
spec reference ([drill-spec.md](./drill-spec.md)) documents the embedded
config absorption in the *drill* context; this document is the *config* file
reference.

---

## 2. Discovery order (where Mayhem looks for config)

`search_for_config_file()` in `src/mayhem/infra/config.py` resolves the config
file in this order; the **first existing file wins**:

| # | Location | Example |
|---|----------|---------|
| 1 | `--config <path>` CLI flag | `mayhem --config ./ops/mayhem.yaml explore ...` |
| 2 | `MAYHEM_CONFIG` env var | `MAYHEM_CONFIG=/srv/mayhem.yaml mayhem explore` |
| 3 | CWD-relative | `./mayhem.yaml`, `./mayhem.yml`, `./.mayhem.yaml`, `./.mayhem.yml` |
| 4 | `.mayhem/` subdir | `./.mayhem/mayhem.yaml`, `./.mayhem/mayhem.yml` |
| 5 | `~/.mayhem/` | `~/.mayhem/mayhem.yaml`, `~/.mayhem/mayhem.yml` |
| 6 | `~/.config/mayhem/` | `~/.config/mayhem/mayhem.yaml`, `~/.config/mayhem/mayhem.yml` |

### Layered config

Mayhem supports **layered / partial config absorption** in addition to a single
file. The engine merges config blocks (in-memory dicts) across layers:

1. **Built-in defaults** (`DEFAULTS` in `config.py`, bounded & minimal).
2. **The resolved config file** (from the discovery order above).
3. **Profile overlays** — `mayhem --profile <name>` loads a profile
   (see §4).
4. **Environment variables** (`MAYHEM_*`, see §3).
5. **CLI flags** (`--profile`, `-c/--config`, per-command flags).
6. **Explicit `config:` argument** (API layer / JSON/YAML string passed as
   `config=`).

Later layers override earlier ones for scalar fields; container fields
(storage, blast radius lists, policy block opt-ins) **merge**, not replace.

---

## 3. Environment variables

Config precedence — env vars override file config. The full set absorbed by
`absorb_layered_config`:

| Variable | Type | Overrides | Notes |
|----------|------|-----------|-------|
| `MAYHEM_CONFIG` | str | config file path | Also used as discovery source; same flag `--config`. |
| `MAYHEM_PROFILE` | str | active profile | Equivalent to `--profile`; sets the profile overlay. |
| `MAYHEM_RISK_CEILING` | enum | `policy.risk_ceiling` | `critical` / `high` / `medium` / `low` / `none`. |
| `MAYHEM_ALLOW_CRITICAL` | bool | `policy.allow_critical` | `1`/`true`/`yes` → `true`. |
| `MAYHEM_BLAST_RADIUS` | JSON | `blast_radius.*` | JSON object, e.g. `{"storage":["db"],"network":"none"}`. |
| `MAYHEM_STORAGE_DB_PATH` | str | `storage.db_path` | SQLite database file path. |
| `MAYHEM_STORAGE_DISABLED` | bool | `storage.disabled` | `1`/`true`/`yes` → `true`. |
| `MAYHEM_TOOLKIT_DOCKER` | bool | `toolkit.docker` | `1`/`true`/`yes` → `true`. |
| `MAYHEM_TOOLKIT_PODMAN` | bool | `toolkit.podman` | `1`/`true`/`yes` → `true`. |
| `MAYHEM_TIMEOUT` | str | `runtime.timeout` | e.g. `30m`, `1h` (click Duration). |
| `MAYHEM_BUDGET` | int | `runtime.budget` | Max fault-injection budget (drill). |
| `MAYHEM_LOG_LEVEL` | enum | `log_level` | `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL`. |
| `MAYHEM_RECOVERY` | bool | `runtime.recovery` | Per-run auto-recover default. |
| `MAYHEM_MAX_FAULTS` | int | `runtime.max_faults` | Ceiling on faults per drill run. |
| `MAYHEM_DEBUG` | bool | `debug` | Equivalent to `--debug`. |

The absorption functions are case-insensitive on env-set keys and treat the
values `"1"`, `"true"`, `"yes"` (case-insensitive) as boolean true; empty env
values are ignored (never crash).

---

## 4. Profiles

A profile is a named config overlay. Define them in the config file:

```yaml
config:
  profiles:
    ci:
      policy:
        risk_ceiling: low
    dev:
      policy:
        risk_ceiling: medium
        allow_critical: false
```

Select with `mayhem --profile ci ...` or `MAYHEM_PROFILE=ci mayhem ...`.
The profile layer is merged ABOVE the base config file layer and BELOW env/CLI
layers. Unknown profile names are ignored (never fatal).

---

## 5. Top-level config schema

The full `MayhemConfig` schema (from `src/mayhem/infra/config.py`), with every
field, type, and default:

### 5.1 `policy`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `risk_ceiling` | enum | `"medium"` | Highest fault risk a run may execute: `none`, `low`, `medium`, `high`, `critical`. |
| `allow_critical` | bool | `false` | Config-side half of the `critical` opt-in. See the triple opt-in below. |
| `critical_fault_acks` | seq[str] | `[]` | Per-fault acknowledgments for `critical`-risk faults (e.g. `k8s.node_drain`). A critical fault is injectable only when **all three** of `policy.allow_critical: true`, a matching entry here, and the `--allow-critical` CLI flag are present (k-plan-5 §5.1). |
| `allow_faults` | seq[str] \| null | `null` | `null` = whole catalog; a list restricts injection to those fault ids. |
| `deny_faults` | seq[str] | `[]` | Fault ids never injectable. |
| `max_faults` | int | (none) | Ceiling on faults executed per run. |
| `timeout` | str | (none) | Maximum wall-clock for a run (click Duration, e.g. `30m`). |
| `recovery` | bool | `true` | Auto-recover the target after each fault. |

### 5.2 `blast_radius`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `storage` | seq[str] | `[]` | Storage surfaces the drill may affect (`db`, `redis`, `files`, …). |
| `network` | str \| seq | `"none"` | Network surfaces (`none` = this topology only; `any` = shared/upstream). |
| `host` | seq[str] | `[]` | Host surfaces (`process`, `container`, `vm`, …). |

### 5.3 `storage`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `db_path` | str | `"mayhem.db"` | SQLite database path used by the report/queue persistence. |
| `disabled` | bool | `false` | If `true`, run without persistence (report/drill history not stored). |

### 5.4 `toolkit`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `docker` | bool | `true` | Allow Docker background/container execution. |
| `podman` | bool | `true` | Allow Podman execution (alias `podman: true`). |

### 5.5 `runtime`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `runtime` | `"docker"` \| `"podman"` \| `"kubernetes"` | `"docker"` | Default runtime for drills that do not pin one per target. `kubernetes` makes discovery target a live cluster (`mayhem topology discover --runtime kubernetes`); compose blueprints stay docker-scoped. |
| `timeout` | str | (none) | Run timeout (click Duration). |
| `budget` | int | (none) | Fault budget for the run. |
| `recovery` | bool | `true` | Auto-recover topology after each fault. |
| `max_faults` | int | (none) | Ceiling on faults per run. |

### 5.5a `kubernetes`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `context` | str \| null | `null` | Kubeconfig context for discovery/execution; `null` uses the current context. |
| `namespace` | str \| null | `null` | Namespace filter for discovery; `null` = all namespaces. |

### 5.6 `log_level`

| Type | Default | Meaning |
|------|---------|---------|
| enum | `"WARNING"` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`. |

### 5.7 `recovery_grace` (k-plan-4)

| Type | Default | Meaning |
|------|---------|---------|
| float | `300.0` | Seconds pod-lifecycle compensation waits for the controller's replacement pod to reach Ready (timeout → `compensation_timeout` + janitor watch). |

---

## 6. The `config:` block inside a drill spec

The canonical "taken syntax" for embedded config. When a drill spec is run
through **expert/expert-run/explore/drill/validate/maniac/plan**, its top-level
`config:` block is absorbed into the layered config so that the drill's gates,
recovery, risk ceiling, and observability inherit from it.

### Minimal authored drill spec with config (expert flow)

```yaml
apiVersion: mayhem/v1
kind: drill
metadata:
  name: auth service drill
config:
  policy:
    risk_ceiling: medium
  runtime:
    recovery: true
faults:
  - name: dependency timeout
    kind: dependency.timeout
    parameter:
      port: 8080
    gate: medium
```

Absorption proof:
- **expert stores** the absorbed config into the drill record; the run's
  gate pipeline consults `config.policy.risk_ceiling` to size the risk gate.
- **expert/plan** read the same layered config block to decide fault
  ordering and budget (`mayhem expert --config ... mayhem.yaml ...`).
- **explore** absorbs the choreographed topology + config when given an
  authored spec; gates consult absorbed config.

### Where config matters per command

| Command | Config absorption |
|---------|-------------------|
| `mayhem run` | absorbs `mayhem.yaml`, `-c/--config`, embedded spec config, applied to gate pipeline (wall clock, risk ceiling). |
| `mayhem expert` | absorbed config drives plan + gates (proven end-to-end in this repo's drill). |
| `mayhem explore` | absorbs config when driving an authored spec; the compose-only catalog-synthesis path is blocked by a pre-existing catalog bug (see §8). |
| `mayhem maniac` | layered config `maniac:` block / `explore`-style config tuning. |
| `mayhem validate` | config file discovery + schema validation against `config.py`. |
| `mayhem status` | reads mayhem.db. |

---

## 7. CLI override matrix

| CLI | Overrides | Precedence |
|-----|-----------|------------|
| `--config <path>` | config file location | highest (file) |
| `--profile <name>` | active profile | above file, below env |
| `--debug` | log_level + debug flag | env-level |
| `--skip-gate` | by-passes gate pipeline check | run-level |
| `--allow-critical` | allow_critical | run-level |
| `--budget N` | runtime.budget | run-level |

---

## 8. Known limitation: `explore` + compose-only catalog synthesis

Reported and independently reproduced: `mayhem explore -c <compose>` crashes
with:

```
error: params[dependency.timeout]: missing required parameter 'port'
```

This is a **pre-existing catalog synthesis bug, independent of config**: the
compose-only explore path synthesizes drill candidates from the catalog, and
the catalog fault `dependency.timeout` requires an implicit `port` parameter
that a bare compose topology cannot provide. The identical crash occurs with
and without a config file — proving it is not a config-absorption defect.

**Workaround:** author the drill spec (positional spec with an authored
`dependency.timeout` cell carrying `parameter: {port: …}`), and explore
absorbs config + the authored topology. Root-cause fix (out of scope of this
docs change, tracked for the code path): the catalogue synthesis should not
require implicit params it cannot derive; it should emit a skip note instead of
failing the run.
