# CLI reference

> **Migration status:** The workflow-oriented command tree is implemented with compatibility-preserving legacy aliases. Existing commands, exit codes, JSON fields, and database behavior remain supported during the migration window. See [`../product/cli-product-direction.md`](../product/cli-product-direction.md) and [`../new-plan/README.md`](../new-plan/README.md).

The executable `mayhem` command is assembled in
[`src/mayhem/cli/app.py`](../../src/mayhem/cli/app.py) from Click command and
group objects. This page records that current surface; removed historical flags
are not part of it.

Run `mayhem --help` or `mayhem COMMAND --help` for the installed command's
own output. The documentation consistency test checks the exit-code identifiers
below against [`src/mayhem/cli/exit_codes.py`](../../src/mayhem/cli/exit_codes.py).

## Invocation and abbreviations

Root options precede the command:

```bash
mayhem [ROOT OPTION]... COMMAND [COMMAND OPTION]... [ARGUMENT]...
```

Unique prefixes are accepted by the root and by the `PrefixGroup` command groups.
For example, `mayhem t f` resolves to `mayhem toolkit faults`; an ambiguous
prefix exits with `ExitCode.AMBIGUOUS_COMMAND`. The `dependency` group is a
plain Click group in the current source, so its subcommand names are not
abbreviated. Use full names in automation when clarity matters.

## Root options

| Option | Effect |
|--------|--------|
| `--db PATH` | Sets the command context's SQLite path. The default is `mayhem.db`. Some store-reading commands also expose a command-local `--db`. |
| `--config PATH` | Selects the configuration or drill-spec file used by lifecycle commands. See [`../config.md`](../config.md). |
| `--profile NAME` | Loads the separate `mayhem.{profile}.yaml` overlay beside the selected base file. |
| `--allow-critical` | Supplies the CLI-side critical acknowledgement. It does not set `policy.allow_critical`. |
| `--skip-gate` | Disables the impact gate for commands that expose that gate. |
| `-p, --podman` | Selects the Podman engine instead of Docker. |
| `-k, --kubernetes` | Selects the Kubernetes CLI engine. It is mutually exclusive with `--podman`. |
| `-d, --debug` | Streams progress and re-raises unexpected errors at the root boundary. |

Use each command's current `--help` output for its accepted arguments. Compose
targets are identified by the container names present in the selected topology.
`mayhem toolkit list --host` is a separate host-probe option for that command
only.

## Workflow views

The workflow groups are presentation-layer views over the existing handlers:

| Group | Views |
|-------|-------|
| `mayhem discover` | `topology`, `faults`, `capabilities`, `engines` |
| `mayhem prepare` | `config`, `validate`, `dependencies`, `check`, `plan` |
| `mayhem inspect` | `runs`, `run`, `coverage`, `history`, `expert`, `next`, `leases` |
| `mayhem extend` | `faults`, `capabilities`, `dependencies` |

## Command map

`mayhem commands show` lists command ownership and migration mappings. Add
`--json` for a machine-readable map.

## Lifecycle commands

### `mayhem validate [SPEC] [-c COMPOSE]`

Compiles a drill and runs safety validation without injecting a fault. If
`SPEC` is omitted, the command uses a drill spec named through `--config` or
auto-detects `mayhem.yaml` / `mayhem.yml` in the current directory.
`--compose` is the blueprint input; without it, compose candidates are
auto-detected.

### `mayhem plan [SPEC] [-c COMPOSE]`

Compiles a drill and prints the frozen execution plan as JSON. It accepts the
same spec and compose resolution as `validate`.

### `mayhem run [SPEC] [-c COMPOSE] [--ctr CONTAINER] [--next]`

Compiles, gates, and executes a drill. `--ctr` restricts the plan to a compose
container and rejects a name absent from the topology. `--next` adds a ranked
next-cell suggestion after a completed run.

### `mayhem maniac [SPEC] [-c COMPOSE] [-s STEPS] [--ctr CONTAINER] [--next]`

Runs random fault-injection rounds. Without an authored spec, the command can
synthesize a drill from the selected topology. `-s/--steps` overrides
`maniac.run_level`; `--ctr` narrows synthesized or authored container draws and
is not available for Kubernetes target scopes.

### `mayhem status [--db PATH] [--run RUN_ID] [--limit N] [--json]`

Lists recent runs. `--run` prints one run's stored metadata as JSON;
`--json` changes the list output to JSON. `--limit` defaults to 20.

### `mayhem history RUN_ID [--json]`

Prints steps, events, and leases for one run. The command currently prints JSON;
`--json` is accepted for command-contract compatibility.

### `mayhem recover RUN_ID`

Recovers orphaned fault leases for the required run identifier. There is no
runless recovery form.

### `mayhem janitor`

Sweeps expired leases, recovers leases whose owning controller is gone, and
reports dirty leases. It has no `sweep` subcommand.

## Topology and catalog commands

### `mayhem topology discover [--compose PATH] [--runtime RUNTIME] [--context CONTEXT] [--namespace NAMESPACE]`

Discovers a topology graph and drift report.

- `--runtime` accepts `docker`, `podman`, or `kubernetes` and overrides the
  global engine flag for discovery.
- Kubernetes discovery uses a kubeconfig-selected live cluster. In this
  command, `--compose` does not turn live discovery into manifest planning.
- The separate `KubernetesManifestProvider` is used by lifecycle planning when
  root `--kubernetes` and a Kubernetes manifest `--compose` path are supplied.

### `mayhem toolkit faults`

Lists catalog definitions with risk, reversibility, maturity, and engine support. With root
`--kubernetes`, the list is restricted by the Kubernetes executor support
register and includes a delivery-lane label, the compatibility execution anchor,
and the complete target-kind set. Use `--coverage --json` for the runtime-free
reliability matrix.

### `mayhem toolkit fault explain ID [--engine ENGINE]`

Prints the parameters, target, capability, observable effect, verification method,
undo or refusal, evidence, maturity, and deprecation path for one catalog ID.
Supported engines are `docker`, `podman`, and `kubernetes`.

The container expansion IDs are `cpu.burst`, `mem.freeze`, `mem.swap_pressure`,
`fs.quota`, `fs.write_delay`, `net.corrupt`, `net.congestion`,
`process.restart_delay`, `http.upstream_timeout`, and `app.response_5xx`.
The Kubernetes expansion IDs are `k8s.pod_restart_churn`,
`k8s.sidecar_termination`, `k8s.workload_stall`, `k8s.service_5xx`,
`k8s.dns_timeout`, `k8s.node_disk_pressure`, `k8s.node_memory_pressure`,
`k8s.node_pid_pressure`, `k8s.hpa_oscillation`, and `k8s.pdb_over_eviction`.
These entries are unit-verified through fake execution seams; this does not claim
live Podman, Docker, kubectl, Minikube, or cluster verification.

### `mayhem toolkit list [--host HOST] [--json]`

Probes tool capabilities. `--host` defaults to `local` and is local to this
command.

## Experiment and configuration commands

### `mayhem experiment show SPEC`

Parses a drill and prints it as JSON.

### `mayhem experiment validate [SPEC] [-c COMPOSE]`

The same validation handler as root `mayhem validate`.

### `mayhem config show [--json]` / `mayhem cfg show [--json]`

Prints the effective configuration after base-file and profile layers merge.
The implementation supplies an empty environment mapping to the loader, so
ambient `MAYHEM_*` values are not included in this view.

### `mayhem config validate` / `mayhem cfg validate`

Loads and validates the selected configuration layers without injecting or
executing a drill.

## Dependency commands

These commands compile a container plan and inspect or modify dependency
requirements; the compile/install forms can invoke container tooling.

| Command | Behavior |
|---------|----------|
| `mayhem dependency check [SPEC] [-c COMPOSE]` | Reports missing in-container packages, manual binaries, capabilities, and host tools. |
| `mayhem dependency install [SPEC] [-c COMPOSE] [-y] [--dry-run]` | Detects package managers and installs mapped packages, then re-probes. `--dry-run` prints commands without installing. |
| `mayhem dependency compile [SPEC] [-c COMPOSE] [-o OUTPUT]` | Writes a derived compose file with capabilities and dependency bootstrap changes. Default output: `docker-compose.mayhem.yml`. |

## Exploration, coverage, and diagnostics

### `mayhem explore [SPEC] [-c COMPOSE]`

Options include `--budget N`, `--deadline DURATION`, `--seed N`,
`--supervised`, `--dry-run`, `--allow-critical`, `--json`, `--quiet`,
`--no-color`, `--db PATH`, and `--profile NAME`.

`explore` generates candidates from the selected topology, applies safety and
feasibility gates, and can execute up to the budget. A dry run previews the
queue without execution.

### `mayhem next [SPEC] [-c COMPOSE]`

Options: `--limit N`, `--seed N`, `--explain`, `--json`, `--quiet` / `-q`, and
`--no-color`. The command ranks untested cells for the selected engine.

### `mayhem coverage [SPEC] [-c COMPOSE]`

Options: `--service NAME`, `--fault KIND`, `--fault-category CATEGORY`,
`--state STATE`, `--json`, `--quiet` / `-q`, and `--no-color`. Valid state
values are `unknown`, `covered`, `inconclusive`, `failed`, and `blocked`.
`--fault` and `--fault-category` are mutually exclusive.

### `mayhem expert [-c COMPOSE] [--run RUN_ID] [--json] [--quiet] [--no-color]`

Probes compose and configuration, checks local Docker/Podman availability, and
analyzes recorded failures. This command is a diagnostic surface; it does not
prove that a Kubernetes cluster is reachable.

## Campaign commands

Campaign names and identifiers are positional.

| Command | Behavior |
|---------|----------|
| `mayhem campaign create NAME [-d DESCRIPTION] [-h HYPOTHESIS] [--db PATH] [--json]` | Creates a draft campaign. There is no `--name` option. |
| `mayhem campaign list [--db PATH] [--json]` | Lists campaigns. |
| `mayhem campaign show CAMPAIGN_ID [--db PATH] [--json]` | Shows campaign details and recorded runs. |
| `mayhem campaign status CAMPAIGN_ID [--db PATH]` | Shows the campaign state. |
| `mayhem campaign add-experiment CAMPAIGN_ID SPEC [--db PATH] [--json]` | Adds an existing drill-spec path. |
| `mayhem campaign start CAMPAIGN_ID [--db PATH] [--json]` | Changes a draft campaign to running. |
| `mayhem campaign run CAMPAIGN_ID [-c COMPOSE] [--no-gate] [--db PATH] [--json]` | Runs authored experiments sequentially. |
| `mayhem campaign abort CAMPAIGN_ID [--db PATH]` | Aborts the campaign. |
| `mayhem campaign archive CAMPAIGN_ID [--db PATH] [--json]` | Marks the campaign completed/archived. |
| `mayhem campaign delete CAMPAIGN_ID [-y] [--db PATH] [--json]` | Deletes a draft campaign. |

For example:

```bash
mayhem campaign create e2e-campaign --hypothesis "stack survives chaos"
```

## Exit codes

These identifiers and numeric values are the stable contract in
[`src/mayhem/cli/exit_codes.py`](../../src/mayhem/cli/exit_codes.py).

| Identifier | Code | Meaning |
|------------|------|---------|
| `ExitCode.SUCCESS` | 0 | Command completed successfully. |
| `ExitCode.GENERAL_FAILURE` | 1 | Unclassified or domain-level failure. |
| `ExitCode.USAGE_ERROR` | 2 | Invalid command, flag, or argument. |
| `ExitCode.CONFIG_ERROR` | 3 | Configuration layering or validation failed. |
| `ExitCode.VALIDATION_ERROR` | 4 | Drill, spec, target, plan, or diagnostic validation failed. |
| `ExitCode.SAFETY_REFUSAL` | 5 | A safety gate refused execution. |
| `ExitCode.EXPERIMENT_FAILURE` | 6 | An experiment ran but did not complete successfully. |
| `ExitCode.RECOVERY_FAILURE` | 7 | Recovery or janitor work left dirty state. |
| `ExitCode.AGENT_ERROR` | 8 | Agent transport or runtime failure. |
| `ExitCode.TOOLKIT_ERROR` | 9 | An external tool invocation failed structurally. |
| `ExitCode.AMBIGUOUS_COMMAND` | 10 | A command abbreviation matched multiple commands. |
