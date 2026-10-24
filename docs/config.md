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
`~/.config/mayhem/`. An explicitly selected file must exist; the default
`mayhem.yaml` is optional when no profile or file path is requested.

Nested mappings are deep-merged, with one exception: `targets` (target
profiles) merge per profile *name*, so a later layer replaces a same-named
profile whole instead of merging into it. Provenance records the last layer
that supplied each top-level field.

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
  damage_quota:
    budget_s: 14400.0
    per_fault_ceiling_s: 3600.0
    window_s: 604800.0
storage:
  path: mayhem.db
  artifacts_dir: .mayhem/artifacts
toolkit:
  binaries: {}
runtime: docker
target:
  containers: []
targets: {}
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

## Target profiles

`targets` holds the named target profiles — the validated description of what a
run may touch. `profiles:` is an accepted alias for the same block; it
normalizes into `targets` and is not a second field.

```yaml
apiVersion: mayhem/v1
targets:
  dev:
    engine: docker
    compose: docker-compose.yml
  prod:
    engine: kubernetes
    context: prod-eu
    namespace: checkout
```

| Profile field | Type | Default | Contract |
|---------------|------|---------|----------|
| `engine` | `docker`, `podman`, or `kubernetes` | `docker` | Runtime the profile targets. |
| `compose` | string or `null` | `null` | Compose blueprint for container engines. |
| `context` | string or `null` | `null` | Kubeconfig context for `kubernetes`. |
| `namespace` | string or `null` | `null` | Kubernetes namespace scope. |
| `policy` | string or `null` | `null` | Declarative policy name. It is **not** enforced: the enforced policy is the one `--policy` or the `policy:` block resolves. `mayhem doctor` reports a name that is not a built-in policy. |
| `workload_selector` | string or `null` | `null` | Kubernetes workload selector. |
| `capability_policy` | string or `null` | `null` | Capability policy for Kubernetes target resolution. |
| `targets` | list of strings | `[]` | Container names the profile addresses. |
| `observability` | mapping or `null` | `null` | Evidence sources for the target. |
| `extends` | string or `null` | `null` | Name of a single parent profile to inherit from. |
| `env_ref` | string or `null` | `null` | Opaque reference to externally held environment data. |

The mapping key is the profile's identity and is validated: names match
`[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}`. A profile's own `name` field is redundant, not
authoritative: the key always wins and a `name` in the body is **overwritten**
with the key, not refused. Every profile is validated by one pure validator
(`parse_profiles_mapping` in
[`src/mayhem/domain/target_profiles.py`](../src/mayhem/domain/target_profiles.py)),
which the loader, the standalone profile-file reader, and the diagnostics all
delegate to. It refuses unknown keys, a non-mapping profile, an unsupported
`engine`, a forbidden credential key, and an `extends` that does not resolve.
Inheritance is one level deep: `extends` may not itself extend, and a child may
only set keys from the allowlist `engine`, `compose`, `namespace`, `context`,
`policy`, `workload_selector`, `capability_policy`, `targets`, `observability`,
`env_ref`.

Forbidden credential keys in a target profile: `password`, `secret`, `token`,
`credentials`, `api_key`, `apikey`. A wider set is redacted when configuration
is rendered — by `config show`, by `config explain`, and by evidence alike — so
free-form blocks such as a profile's `observability:` are filtered by one
policy; see `src/mayhem/controller/safety.py`.

A drill document's own top-level `targets:` block is *not* a target-profile
block. It declares the spec's logical targets
(`runtime:`/`docker:`/`kubernetes:`/`faults:`) and is never read as profiles;
see [`drill-spec.md`](drill-spec.md).

Selection is `--target`, not `--profile`: an explicit `--target` wins, a single
configured profile is selected implicitly, and more than one without `--target`
is ambiguous — nothing is selected and `mayhem doctor` says so.

### Where profiles are resolved from

One function answers "which target profiles are in effect":
`mayhem.config.effective_target_profiles(config_path, profile)`, the base
document merged with the `mayhem.{profile}.yaml` overlay. Every consumer goes
through it — CLI services, topology discovery, preflight, and diagnostics — so
a profile declared only in an overlay is visible to all of them and none of them
re-reads the base file on its own.
`mayhem.config.select_target_profile(...)` is the same resolution plus the
selection rule.

Two shapes are tolerated deliberately, because the readers that predate the
overlay-aware loader had them: a profile-only document with no `apiVersion` is
not a loadable configuration, so the profile-file reader answers for it (and an
overlay cannot be merged onto it); and a *requested but missing* overlay leaves
the base document's profiles in place, with `mayhem doctor` reporting the
missing overlay.

## Top-level fields

| Field | Type | Default | Contract |
|-------|------|---------|----------|
| `apiVersion` | literal `mayhem/v1` | `mayhem/v1` | Version gate for every YAML configuration document. |
| `policy` | mapping | empty policy | Fault allow/deny lists, risk ceiling, and critical opt-in state. |
| `blast_radius` | mapping | limits shown below | Topology and concurrency budgets enforced by planning/safety. |
| `storage` | mapping | `mayhem.db`, `.mayhem/artifacts` | Store and artifact locations. |
| `toolkit` | mapping | empty map | Binary overrides keyed by toolkit name. |
| `runtime` | `docker`, `podman`, or `kubernetes` | `docker` | Runtime setting in the configuration model. Root CLI runtime flags are tracked separately by the CLI. |
| `target` | mapping | empty list | Explicit container names for discovery when no compose blueprint is used. Unrelated to `targets`. |
| `targets` | mapping of name to target profile | `{}` | Named target profiles. `profiles:` is an accepted alias. See [Target profiles](#target-profiles). |
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

The five limits above are **per-step**. `damage_quota` is the only budget that
sees the *sequence*.

| Field | Type | Default | Constraints |
|-------|------|---------|-------------|
| `max_services_pct` | float | `50.0` | Greater than 0 and at most 100. |
| `max_hosts` | integer | `2` | At least 1. |
| `max_concurrent_faults` | integer | `3` | At least 1. |
| `max_duration_per_fault_s` | float | `300.0` | Duration budget in seconds. |
| `forbidden_fault_pairs` | list of two-item string lists | `[]` | Fault pairs that must not both appear in a plan. **Enforced**: a plan containing a configured pair is refused. This rule was silently inert in 0.9.x on any plan of three or more faults; it now fires. |
| `damage_quota` | object or `null` | `null` | Cumulative damage budget across the whole plan. `null` means "use the default quota", which is **active, not absent**. |

`damage_quota` charges damage-seconds per target, weighted by the fault's
catalog risk and reversibility:

| Field | Type | Default | Constraints |
|-------|------|---------|-------------|
| `budget_s` | float | `14400.0` | Greater than 0. Total damage across the plan. |
| `per_fault_ceiling_s` | float | `3600.0` | Greater than 0. Total damage charged to any single target. |
| `window_s` | float | `604800.0` | Greater than 0. The rolling window the totals accumulate over. |

A plan whose every individual step satisfies the five per-step limits can
still be refused, because the cumulative total is a different question. The
refusal names the rule id (`damage_quota.budget`,
`damage_quota.per_fault_ceiling`), the observed value, and the value that
would have been required.

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
does not discover additional files from them. `--profile` selects a
*configuration overlay*, not a target profile — target profiles are chosen with
`--target`.

```bash
mayhem --config ./ops/base.yaml --profile ci prepare config show
```

With an explicit base path, this loads:

1. `./ops/base.yaml`
2. `./ops.mayhem.ci.yaml`

The overlay must itself contain `apiVersion: mayhem/v1`. Unknown profiles are
not ignored: selecting a profile whose overlay does not exist raises a
configuration error.

An overlay may contribute target profiles. Profiles merge per name across
layers, so an overlay that redefines `prod` replaces the base layer's `prod`
whole and leaves every other profile untouched; a profile the overlay does not
mention is inherited unchanged. A name declared under both `targets:` and
`profiles:` in the *same* document is a duplicate and is refused rather than
resolved by precedence. Because the accumulated profile block is re-validated
after each layer, a profile may `extends:` a profile declared in an earlier
layer, and a profile a later layer replaced with an invalid one is still
refused. The section's provenance is reported as `targets` by
`mayhem prepare config explain`, whose rows are redacted with the same policy
`config show` uses. An overlay's profiles are in effect for the whole run, not
just for the loader: discovery, preflight, and the doctor all resolve them from
the same effective configuration.

## Environment variables

Only these names are read by `load_config`:

| Variable | Configuration path | Accepted value |
|----------|--------------------|-----------------|
| `MAYHEM_STORAGE_PATH` | `storage.path` | string |
| `MAYHEM_ARTIFACTS_DIR` | `storage.artifacts_dir` | string |
| `MAYHEM_LOG_LEVEL` | `log_level` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |

No `MAYHEM_CONFIG`, `MAYHEM_PROFILE`, risk, recovery, runtime, target, or
Kubernetes environment variable is supported by the loader.

`mayhem prepare config show` and `mayhem prepare config validate` call the loader
with an empty environment mapping, so their output is deterministic and does not
absorb the caller's ambient `MAYHEM_*` values. Commands that prepare a run also
currently pin the environment layer's `log_level` to `INFO`; the other
allowlisted values are not supplied by the current CLI path.

## Bindings outside `mayhem.yaml`

Two environment variables bind objects a run consults that no YAML file
declares:

| Variable | Binds | Read by |
|----------|-------|---------|
| `MAYHEM_GATE_WITNESSES` | The preflight gate's port witnesses | `mayhem.cli.app.run_gate` |
| `MAYHEM_BUDGET_GUARD` | The run's resource budget guard | `mayhem.cli.app.run_budget_guard` |

Both are read once at the CLI edge by
[`src/mayhem/cli/app.py`](../src/mayhem/cli/app.py) — by nothing else, and in
particular **not** by [`src/mayhem/config.py`](../src/mayhem/config.py). That is
exactly why they appear here rather than in the reference above: this file is
the authoritative checked-in summary of that loader (see [`README.md`](README.md)),
the loader never reads these two names, and listing them among the allowlisted
variables it does read would be wrong. `mayhem doctor` reports each variable's
binding state — unset, or the spec it names and whether that spec resolves.

Each variable holds an import spec of the form `module:attribute`, naming an
attribute of an importable module. Both are unset by default: mayhem owns no
incident manager, deployment feed, backup system, or replication peer, so it
binds none of the five witnesses and no guard, and the run path is unchanged
from before either binding existed.

`MAYHEM_GATE_WITNESSES` accepts four shapes for the attribute:

1. A `PreflightGate`, returned verbatim — a gate a deployment configured
   itself is never rebuilt or widened.
2. A `PreflightPorts` — the five ports `cluster`, `incident`, `deployment`,
   `backup`, and `replication`.
3. A mapping of witness name to witness, checked against those same five names
   so a typo in a witness name is refused by name.
4. A zero-argument callable returning any of the above.

`MAYHEM_BUDGET_GUARD` accepts a `RunBudgetGuard`, or a callable taking this
run's `run_id` and returning one:

```bash
MAYHEM_BUDGET_GUARD=your.module:budget_for_run
```

The factory receives the `run_id` — the run about to execute — rather than
declaring one, because its budgets are scoped to the run it guards.

Three promises govern both bindings; the full argument is the design block in
[`src/mayhem/cli/execution.py`](../src/mayhem/cli/execution.py):

1. **Binding is explicit, and it can only add.** Either variable can produce a
   gate or a guard; neither can remove one a deployment bound in-process, narrow
   one away, or switch off what a binding installed, and there is no second
   spelling that gets past what a binding installed.
2. **An empty binding is no gate, not a refusing one.** An attribute resolving
   to `None`, or to a `PreflightPorts` with nothing bound, is the
   *unconfigured* state: no gate is attached and the run behaves exactly as it
   did before this lane existed. Attaching a gate over it instead would refuse
   every run for five systems nobody can answer for.
3. **A binding that cannot be loaded is refused loudly**, never degraded into
   "no gate". A malformed spec, an unimportable module, a missing attribute, a
   factory that raises, or an attribute of the wrong shape raises
   `InvariantViolationError` before any store is touched — an operator who asked
   for gating and silently got none would be told the safe thing is on when it
   is off.

[`src/mayhem/cli/witnesses.py`](../src/mayhem/cli/witnesses.py) is the shipped
example. The starting point for an operator is the empty binding:

```bash
MAYHEM_GATE_WITNESSES=mayhem.cli.witnesses:empty_ports
```

`empty_ports` binds nothing and resolves to *no gate at all* — the
unconfigured state — and is the right first binding to grow from: bind the
ports you have real witnesses for and leave the rest unbound.
**`unavailable_ports` refuses every run it is attached to**, by design and
without exception; it is the shape to copy, not a configuration to deploy.
Copy the module into your own package and replace each port with a witness for
a system you actually own.

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

A drill spec's top-level `targets:` block declares the spec's logical targets,
not target profiles, so loading a spec as configuration never produces profiles
and the spec's own `targets:` is never read as one.

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
| `--target NAME` | Selects a target profile from `targets`; it does not rewrite the configuration. |
| `--allow-critical` | Supplies the CLI-side critical acknowledgement in `SafetyContext`; it does not mutate `policy.allow_critical`. |
| `--skip-gate` | Controls the impact gate; it is not a configuration field. |
| `--podman` / `--kubernetes` | Select CLI engine state; they do not rewrite `runtime`. |

Use `src/mayhem/cli/command_registry.py` for the executable command surface.
