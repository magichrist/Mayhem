# CLI reference

The executable CLI exposes the active workflow surface. Deprecated root commands and aliases have been removed; use the workflow commands below.

## Invocation

```bash
mayhem [ROOT OPTION]... COMMAND [COMMAND OPTION]... [ARGUMENT]...
```

Unique command prefixes remain available for active commands. Ambiguous prefixes exit with `ExitCode.AMBIGUOUS_COMMAND`.

## Root options

| Option | Effect |
|--------|--------|
| `--db PATH` | SQLite database path. |
| `--config PATH` | Configuration or drill-spec path. |
| `--profile NAME` | Configuration profile overlay. |
| `--policy NAME` | Named safety policy. |
| `--dry-run` | Evaluate policy without mutation. |
| `--allow-critical` | Acknowledge critical-risk faults. |
| `--skip-gate` | Run despite proved-inert faults. |
| `-p, --podman` | Select Podman. |
| `-k, --kubernetes` | Select Kubernetes. |
| `-d, --debug` | Re-raise unexpected errors. |
| `--target NAME` | Select a target profile. |
| `--format text\|json\|yaml` | Select output format. |
| `--no-color` | Disable ANSI color. |

## Active commands

### `mayhem discover`

Discover the execution surface and catalog before mutating anything.

- `mayhem discover engines`
- `mayhem discover topology -c COMPOSE`
- `mayhem discover faults`
- `mayhem discover capabilities`

### `mayhem prepare`

Prepare configuration, dependencies, and executable plans.

- `mayhem prepare config show [--json]`
- `mayhem prepare config explain [--json]`
- `mayhem prepare config validate`
- `mayhem prepare dependencies check|install|compile`
- `mayhem prepare check`
- `mayhem prepare validate [SPEC] -c COMPOSE`
- `mayhem prepare plan [SPEC] -c COMPOSE`

`validate` and `plan` resolve a missing spec from the directory containing the selected `-c/--compose` file before falling back to the current directory.

### `mayhem experiment`

Inspect authored experiments and run the active exploration loop.

- `mayhem experiment show SPEC`
- `mayhem experiment validate SPEC -c COMPOSE`
- `mayhem experiment explore [SPEC] -c COMPOSE`

### `mayhem run` and `mayhem maniac`

`run` compiles, gates, and executes a drill. `maniac` runs randomized fault-injection rounds. Use `run --execute` for explicit execution approval; use `--dry-run` where supported for previews.

### `mayhem inspect`

Inspect recorded execution and resilience data.

- `mayhem inspect runs [--json]`
- `mayhem inspect run RUN_ID`
- `mayhem inspect history RUN_ID [--json]`
- `mayhem inspect coverage`
- `mayhem inspect next`
- `mayhem inspect expert`
- `mayhem inspect leases [--json]`
- `mayhem inspect doctor`

`inspect runs` checks controller PIDs and projects dead or unowned `running` rows as `stale`.

### `mayhem recover` and `mayhem janitor`

Use `recover status`, `recover plan`, and `recover execute` for explicit run recovery. `janitor` previews lease cleanup by default; pass `-e` or `--execute` to apply it.

### `mayhem extend`

Inspect and extend provider, fault, and capability coverage.

- `mayhem extend faults`
- `mayhem extend capabilities`
- `mayhem extend dependencies check`
- `mayhem extend providers inspect|load`

### Other active commands

- `mayhem campaign` — create, inspect, and run chaos campaigns.
- `mayhem commands show` — print the active command map.
- `mayhem init` — detect a project and create a safe starter configuration.
- `mayhem doctor` — check configuration, database, engines, topology, capabilities, and permissions.
- `mayhem verify RUN_ID` — verify a recorded evidence envelope without mutation.

## Output and errors

Human output is the default. JSON and YAML are available through `--format` and compatible command-local flags. Errors use stable codes and map to the existing numeric exit codes. Machine errors are emitted on stderr; successful JSON output is not mixed with progress text.

## Exit codes

The existing exit-code enum remains unchanged: `SUCCESS`, `GENERAL_FAILURE`, `USAGE_ERROR`, `CONFIG_ERROR`, `VALIDATION_ERROR`, `SAFETY_REFUSAL`, `EXPERIMENT_FAILURE`, `RECOVERY_FAILURE`, `AGENT_ERROR`, `TOOLKIT_ERROR`, and `AMBIGUOUS_COMMAND`.
