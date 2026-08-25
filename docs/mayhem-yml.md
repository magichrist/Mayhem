# `mayhem.yaml` — Complete Configuration Reference

This document covers every field accepted by the `mayhem.yaml` configuration
file. It is the canonical reference for writing or validating a configuration.

---

## Minimal Example

```yaml
apiVersion: mayhem/v1

environment:
  name: production
  klass: production

policy:
  deny_faults:
    - proc.kill
  risk_ceiling: high

blast_radius:
  max_services_pct: 30
  max_concurrent_faults: 2
  cooldown_seconds: 60

target:
  containers:
    - my-api
    - my-worker

runtime: docker
log_level: INFO
```

---

## Full Schema Reference

Every field, every type, every default. Fields marked **REQUIRED** must be
present. All other fields are optional and will use their defaults if omitted.

> All models use `extra="forbid"` — unknown keys are rejected with a validation
> error. This is intentional: a typo in your config will fail loudly rather than
> being silently ignored.

---

### Top-Level Keys

```yaml
apiVersion: mayhem/v1          # REQUIRED. Must be the string "mayhem/v1".
environment: { ... }           # Environment metadata
policy: { ... }                # Fault policy controls
blast_radius: { ... }          # Blast radius limits
storage: { ... }               # Storage paths
toolkit: { ... }               # Tool overrides
runtime: docker                # Container runtime: "docker" | "podman"
target: { ... }                # Explicit container targets
log_level: INFO                # Log verbosity: "DEBUG" | "INFO" | "WARNING" | "ERROR"
```

---

### `environment`

Metadata about the environment where mayhem runs. Used for snapshotting and
audit trails.

```yaml
environment:
  name: default            # string. Descriptive name for this environment.
                           # Default: "default"

  klass: development       # One of: "development" | "staging" | "production"
                           # Default: "development"
                           # Controls risk tolerance in safety gates.
```

**Environment class behavior:**
- `production` — strictest safety, critical faults blocked unless explicitly opted in
- `staging` — moderate safety
- `development` — permissive, suitable for local testing

---

### `policy`

Controls which faults are allowed and how strict the safety gates are.

```yaml
policy:
  allow_faults:              # Optional allowlist of fault IDs.
    - proc.pause             # When set, ONLY these faults are permitted.
    - net.latency            # When null (default), the full catalog is available.
                             # Type: list[str] | null
                             # Default: null

  deny_faults:               # Denylist of fault IDs that are always blocked.
    - proc.kill              # These faults will be rejected at planning time,
    - container.kill          # before any execution occurs.
                             # Type: list[str]
                             # Default: [] (empty)

  risk_ceiling: null         # Maximum risk level allowed for any fault in an experiment.
    # One of: "low" | "medium" | "high" | "critical"
    # When null (default): no ceiling — all risk levels allowed.
    # When set: faults above this level are blocked at planning time.
                             # Type: "low" | "medium" | "high" | "critical" | null
                             # Default: null

  allow_critical: false      # Opt-in for critical-risk faults.
    # When false: critical-risk faults are blocked even if risk_ceiling allows them.
    # Must also be enabled via --allow-critical CLI flag for runtime execution.
                             # Type: bool
                             # Default: false
```

**Denylist evaluation order:**
1. `deny_faults` is checked first — blocked faults never reach planning
2. `risk_ceiling` is checked next — faults above the ceiling are blocked
3. `allow_critical` is checked last — critical faults require explicit opt-in

---

### `blast_radius`

Limits on how much chaos can be applied simultaneously. Enforced by the planner
and the safety gate before execution.

```yaml
blast_radius:
  max_services_pct: 50.0     # Maximum percentage of services that can be targeted
                              # simultaneously. Range: (0, 100].
                              # Type: float
                              # Default: 50.0

  max_hosts: 2               # Maximum number of distinct hosts that can be affected.
                              # Range: [1, ∞)
                              # Type: int
                              # Default: 2

  max_concurrent_faults: 3   # Maximum number of faults that can be active at once.
                              # Range: [1, ∞)
                              # Type: int
                              # Default: 3

  cooldown_seconds: 30.0     # Minimum seconds between consecutive fault injections
                              # on the same target.
                              # Range: [0, ∞)
                              # Type: float
                              # Default: 30.0
```

---

### `storage`

Paths for persistent state and artifacts.

```yaml
storage:
  path: .mayhem/state.db     # Path to the SQLite database.
                              # Type: string
                              # Default: ".mayhem/state.db"

  artifacts_dir: .mayhem/artifacts  # Directory for run artifacts (journals, reports).
                                    # Type: string
                                    # Default: ".mayhem/artifacts"
```

The database stores: runs, step_runs, config snapshots, topology snapshots,
leases, fault invocations, recovery records, and the event journal.

---

### `toolkit`

Override tool binaries or versions.

```yaml
toolkit:
  binaries: {}                # Map of tool name to binary path.
    # Example:
    #   docker: /usr/local/bin/docker
    #   stress-ng: /opt/tools/stress-ng
    # When empty (default), tools are resolved via PATH.
                               # Type: dict[str, str]
                               # Default: {} (empty)
```

---

### `runtime`

Which container runtime to use for topology discovery and fault injection.

```yaml
runtime: docker               # "docker" | "podman"
                               # Default: "docker"
                               # Also settable via --podman CLI flag.
```

When `podman` is selected:
- `ContainerRuntimeProvider` queries `podman ps` instead of `docker ps`
- Container execution uses `podman exec` / `podman kill` / `podman pause`
- The topology host node is labeled `podman` instead of `docker`

---

### `target`

Explicit container targeting for use **without** a compose file.

```yaml
target:
  containers:                 # List of container names to include in topology.
    - my-api                  # When a compose file IS provided, this is ignored
    - my-worker               # (compose project filtering takes precedence).
    - my-redis                # Containers are matched by name (case-insensitive).
                              # Type: list[str]
                              # Default: [] (empty — discover all running containers)
```

**Behavior matrix:**

| Compose file provided? | `target.containers` set? | Result |
|---|---|---|
| Yes | (ignored) | Runtime filtered to that compose project only |
| No | Yes | Runtime filtered to those named containers |
| No | No | All running containers discovered |

---

### `log_level`

Controls the verbosity of structured log output.

```yaml
log_level: INFO               # "DEBUG" | "INFO" | "WARNING" | "ERROR"
                               # Default: "INFO"
```

- `DEBUG` — full trace of config loading, provider pipeline, plan compilation
- `INFO` — run lifecycle events, step completions
- `WARNING` — non-fatal issues (tool probe failures, deprecated options)
- `ERROR` — only errors

---

## Configuration Loading Order

Mayhem uses layered configuration. Later layers override earlier ones:

```
1. Built-in defaults (hardcoded in MayhemConfigBase)
2. mayhem.yaml (project root or --config path)
3. Profile overlay: mayhem.{profile}.yaml (when --profile is set)
4. Environment variables: MAYHEM_* (limited allowlist)
5. CLI flags (--db, --config, --profile, --allow-critical, --podman, --debug)
```

### Environment Variables

Only these are recognized (case-sensitive):

| Variable | Maps To | Example |
|---|---|---|
| `MAYHEM_STORAGE_PATH` | `storage.path` | `MAYHEM_STORAGE_PATH=/var/lib/mayhem/state.db` |
| `MAYHEM_ARTIFACTS_DIR` | `storage.artifacts_dir` | `MAYHEM_ARTIFACTS_DIR=/var/lib/mayhem/artifacts` |
| `MAYHEM_LOG_LEVEL` | `log_level` | `MAYHEM_LOG_LEVEL=DEBUG` |

### Profile Overlays

When `--profile staging` is set, mayhem loads `mayhem.staging.yaml` on top of
`mayhem.yaml`. Only the fields present in the overlay are applied — the rest
inherit from the base file.

---

## Validation Rules

- `apiVersion` must be exactly `"mayhem/v1"` — any other value is rejected
- Unknown top-level keys are rejected (`extra="forbid"` on all models)
- `blast_radius.max_services_pct` must be `> 0` and `≤ 100`
- `blast_radius.max_hosts` must be `≥ 1`
- `blast_radius.max_concurrent_faults` must be `≥ 1`
- `blast_radius.cooldown_seconds` must be `≥ 0`
- `policy.risk_ceiling` must be one of the valid `RiskLevel` values when set
- `policy.deny_faults` entries must be valid fault IDs (category prefix checked)
- `policy.allow_faults` entries must be valid fault IDs
- `target.containers` entries are case-insensitive strings
- `storage.path` and `storage.artifacts_dir` are strings (created on first use)
- `toolkit.binaries` values are strings (paths)

---

## Snapshotting

Every time a config is loaded, a deterministic snapshot ID is computed:

```
cfg-{sha256(canonical_json)[:12]}
```

The canonical JSON is produced by `json.dumps(config.model_dump(mode="json"), sort_keys=True)`.
This snapshot ID is stored in the database with every run, so you can always
trace which exact configuration produced a given experiment result.

---

## Example: Production Configuration

```yaml
apiVersion: mayhem/v1

environment:
  name: production-us-east
  klass: production

policy:
  deny_faults:
    - proc.kill
    - container.kill
  risk_ceiling: high
  allow_critical: false

blast_radius:
  max_services_pct: 25
  max_hosts: 1
  max_concurrent_faults: 2
  cooldown_seconds: 60

storage:
  path: /var/lib/mayhem/state.db
  artifacts_dir: /var/lib/mayhem/artifacts

toolkit:
  binaries:
    docker: /usr/bin/docker

runtime: docker

target:
  containers: []          # empty — compose file will be used

log_level: INFO
```

---

## Example: Local Development Configuration

```yaml
apiVersion: mayhem/v1

environment:
  name: local-dev
  klass: development

policy:
  risk_ceiling: medium
  allow_critical: false

blast_radius:
  max_services_pct: 100
  max_hosts: 1
  max_concurrent_faults: 5
  cooldown_seconds: 5

storage:
  path: .mayhem/state.db
  artifacts_dir: .mayhem/artifacts

runtime: podman
log_level: DEBUG
```

---

## Example: Target-Only Configuration (No Compose)

```yaml
apiVersion: mayhem/v1

environment:
  name: existing-infra
  klass: staging

policy:
  risk_ceiling: medium

blast_radius:
  max_concurrent_faults: 2

runtime: docker

target:
  containers:
    - postgres-primary
    - redis-cache
    - api-server

log_level: INFO
```

Used with: `mayhem run experiment.yaml` (no `--compose` flag needed — the
target containers are discovered from the named containers above).
