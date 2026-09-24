# Configuration reference

This reference describes the checked-in contract implemented by
[`src/mayhem/config.py`](../src/mayhem/config.py). Unknown keys and unsupported
`apiVersion` values are rejected.

## File selection and layer order

Configuration is loaded in this order, with later layers taking precedence:

1. Pydantic model defaults from `MayhemConfigBase`.
2. The base YAML document.
3. A separate `mayhem.{profile}.yaml` overlay.
4. The three allowlisted `MAYHEM_*` environment variables.
5. Values supplied through the `load_config(cli_overrides=...)` argument.

The base file is selected as follows:

- `--config PATH` selects that exact path.
- Without `--config`, the loader checks only `./mayhem.yaml`.
- A profile overlay is resolved beside the selected base path. With the default
  path, `--profile ci` reads `./mayhem.ci.yaml`.

There is no implicit search of `.mayhem/`, the home directory, or
`~/.config/mayhem/`. There is also no `profiles:` mapping inside the base file.
An explicitly selected file must exist; the default `mayhem.yaml` is optional
when no profile or file path is requested.

Nested mappings are deep-merged. Scalar and list values are replaced by the
later layer. Provenance records the last layer that supplied each top-level
field.

## Standalone configuration

A standalone configuration document has fields at the top level; it does not
wrap them in another `config:` key.

```yaml
apiVersion: mayhem/v1
policy:
  allow_faults: null
  deny_faults: []
  risk_ceiling: high
  allow_critical: false
  critical_fault_acks: []
blast_radius:
  max_services_pct: 50.0
  max_hosts: 2
  max_concurrent_faults: 3
  max_duration_per_fault_s: 300.0
  forbidden_fault_pairs: []
storage:
  path: mayhem.db
  artifacts_dir: .mayhem/artifacts
toolkit:
  binaries: {}
runtime: docker
target:
  containers: []
kubernetes:
  context: null
  namespace: null
recovery_grace: 300.0
log_level: INFO
maniac:
  level: 2
  run_level: 10
  seed: null
```

`apiVersion: mayhem/v1` is required in a YAML document. The Pydantic model has a
default so direct construction does not need one, but `_read_document` rejects a
file that omits or misspells the YAML field.

## Top-level fields

| Field | Type | Default | Contract |
|-------|------|---------|----------|
| `apiVersion` | literal `mayhem/v1` | `mayhem/v1` | Version gate for every YAML configuration document. |
| `policy` | mapping | empty policy | Fault allow/deny lists, risk ceiling, and critical opt-in state. |
| `blast_radius` | mapping | limits shown below | Topology and concurrency budgets enforced by planning/safety. |
| `storage` | mapping | `mayhem.db`, `.mayhem/artifacts` | Store and artifact locations. |
| `toolkit` | mapping | empty map | Binary overrides keyed by toolkit name. |
| `runtime` | `docker`, `podman`, or `kubernetes` | `docker` | Runtime setting in the configuration model. Root CLI runtime flags are tracked separately by the CLI. |
| `target` | mapping | empty list | Explicit container names for discovery when no compose blueprint is used. |
| `kubernetes` | mapping | `null` context and namespace | Discovery overrides for Kubernetes. |
| `recovery_grace` | positive float seconds | `300.0` | Bounded wait used by pod-lifecycle compensation. |
| `log_level` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` | `INFO` | Configured log verbosity. |
| `maniac` | mapping | level 2, 10 rounds, no fixed seed | Fallback random-injection settings for `mayhem maniac`. A drill spec's own `config.maniac` takes precedence. |

### `policy`

| Field | Type | Default | Contract |
|-------|------|---------|----------|
| `allow_faults` | list of strings or `null` | `null` | `null` admits the full catalog; a list restricts it. |
| `deny_faults` | list of strings | `[]` | Fault identifiers that cannot execute. |
| `risk_ceiling` | `low`, `medium`, `high`, `critical`, or `null` | `null` | Highest permitted catalog risk. There is no `none` value. |
| `allow_critical` | boolean | `false` | Config-side half of the critical opt-in. |
| `critical_fault_acks` | list of strings | `[]` | Per-fault acknowledgements required in addition to `allow_critical` and the CLI `--allow-critical` flag. |

A drill-level `risk_ceiling` can tighten the policy ceiling. It does not loosen
it. Critical execution requires all three controls: `policy.allow_critical`,
the matching `policy.critical_fault_acks` entry, and root
`--allow-critical`.

### `blast_radius`

| Field | Type | Default | Constraints |
|-------|------|---------|-------------|
| `max_services_pct` | float | `50.0` | Greater than 0 and at most 100. |
| `max_hosts` | integer | `2` | At least 1. |
| `max_concurrent_faults` | integer | `3` | At least 1. |
| `max_duration_per_fault_s` | float | `300.0` | Duration budget in seconds. |
| `forbidden_fault_pairs` | list of two-item string lists | `[]` | Fault pairs that cannot overlap. |

### `storage`, `toolkit`, `target`, and `kubernetes`

| Path | Type | Default | Contract |
|------|------|---------|----------|
| `storage.path` | string | `mayhem.db` | Store path represented by the configuration model. |
| `storage.artifacts_dir` | string | `.mayhem/artifacts` | Artifact directory represented by the configuration model. |
| `toolkit.binaries` | string-to-string map | `{}` | Binary override per toolkit key. |
| `target.containers` | list of strings | `[]` | Explicit container names for no-compose discovery. |
| `kubernetes.context` | string or `null` | `null` | Kubeconfig context; `null` means the current context. |
| `kubernetes.namespace` | string or `null` | `null` | Namespace scope; `null` means no namespace filter. |

### `maniac`

| Field | Type | Default | Constraints |
|-------|------|---------|-------------|
| `level` | integer | `2` | 1 through 5. |
| `run_level` | integer | `10` | 1 through 500 random fault rounds. |
| `seed` | non-negative integer or `null` | `null` | `null` draws a fresh seed. |

## Profile overlays

A profile is a separate configuration document with the same version and
top-level schema; omitted fields retain earlier-layer values. Relative
references such as a profile's `toolkit.binaries` values are data; the loader
does not discover additional files from them.

```bash
mayhem --config ./ops/base.yaml --profile ci config show
```

With an explicit base path, this loads:

1. `./ops/base.yaml`
2. `./ops.mayhem.ci.yaml`

The overlay must itself contain `apiVersion: mayhem/v1`. Unknown profiles are
not ignored: selecting a profile whose overlay does not exist raises a
configuration error.

## Environment variables

Only these names are read by `load_config`:

| Variable | Configuration path | Accepted value |
|----------|--------------------|-----------------|
| `MAYHEM_STORAGE_PATH` | `storage.path` | string |
| `MAYHEM_ARTIFACTS_DIR` | `storage.artifacts_dir` | string |
| `MAYHEM_LOG_LEVEL` | `log_level` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |

No `MAYHEM_CONFIG`, `MAYHEM_PROFILE`, risk, recovery, runtime, target, or
Kubernetes environment variable is supported by the loader.

`mayhem config show` and `mayhem config validate` call the loader with an empty
environment mapping, so their output is deterministic and does not absorb the
caller's ambient `MAYHEM_*` values. Commands that prepare a run also currently
pin the environment layer's `log_level` to `INFO`; the other allowlisted values
are not supplied by the current CLI path.

## Drill-spec projection

A file with a top-level `kind: drill` is recognized as a drill spec, not a
strict standalone config document. Only two keys from its embedded `config:`
mapping are projected into the configuration layer:

| Embedded drill key | Projected configuration path |
|--------------------|------------------------------|
| `log_level` | `log_level` |
| `risk_ceiling` | `policy.risk_ceiling` |

The rest of the drill `config:` vocabulary is parsed by the drill model and
used by the plan; it is not copied into `MayhemConfig`. Spec-only settings such
as `max_faults`, `timeout`, `recovery`, `on_failure`, and `maniac` are not
standalone configuration fields.

If a drill spec has no embedded `config:` mapping, loading it as configuration
uses defaults and emits `SpecFileUsedAsConfig`. The lifecycle commands still
parse the drill independently. See [`drill-spec.md`](drill-spec.md) for that
separate schema.

## CLI and programmatic overrides

`load_config` accepts a `cli_overrides` mapping as its highest-precedence layer.
Keys use configuration field names (`log_level`, `storage`, `policy`, and so
on), and `None` values are ignored. The current CLI does not expose a generic
flag that forwards arbitrary configuration fields to this argument.

Current root CLI controls relate to layering and execution as follows:

| Root option | Effect |
|-------------|--------|
| `--config PATH` | Selects the base document; it does not itself override a field. |
| `--profile NAME` | Adds the separate profile overlay; it does not itself override a field. |
| `--allow-critical` | Supplies the CLI-side critical acknowledgement in `SafetyContext`; it does not mutate `policy.allow_critical`. |
| `--skip-gate` | Controls the impact gate; it is not a configuration field. |
| `--podman` / `--kubernetes` | Select CLI engine state; they do not rewrite `runtime`. |

Use [`reference/cli.md`](reference/cli.md) for the executable command surface.
