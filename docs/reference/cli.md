# CLI Reference

The `mayhem` CLI is a Click application registered as a console-script entry point.
Every command is a Click command or group; all groups use **unique-prefix resolution**,
so `mayhem e v` resolves to `mayhem experiment validate` at every level of the tree.
Exact names and `--help` always work.

---

## Global options

```
mayhem [OPTIONS] COMMAND [ARGS]
```

| Flag | Description |
|---|---|
| `--db` | SQLite database path (default: `mayhem.db`) |
| `--config` | Path to `mayhem.yaml` |
| `--profile` | Configuration profile name |
| `--allow-critical` | Acknowledge critical-risk faults |
| `--debug` | Re-raise raw exceptions instead of rendering them |

---

## Lifecycle commands

### `mayhem validate EXPERIMENT`

Compile an experiment and run every safety gate without executing it.

**Topology options** (all lifecycle commands accept these):

| Flag | Description |
|---|---|
| `-p, --process` | Local process node as `name=pid` (repeatable) |
| `--service` | Logical service node name (repeatable) |
| `--host` | Host node name (default: `local`) |
| `--compose` | Path to `docker-compose.yaml` blueprint |

### `mayhem plan EXPERIMENT`

Plan an experiment against a topology and print the frozen plan as JSON.

### `mayhem run EXPERIMENT`

Plan then execute an experiment; prints a run summary on completion.
Non-zero exit if the run status is not `completed`.

---

## Status & history

### `mayhem status`

List recent runs from the database.

| Flag | Description |
|---|---|
| `--run` | Show one run in full detail (JSON) |
| `--limit` | Rows to list (default: 20) |

### `mayhem history RUN_ID`

Print steps, events, and leases recorded for one run as JSON.

---

## Recovery

### `mayhem recover RUN_ID`

Recover every orphaned fault lease belonging to a run.

### `mayhem janitor`

Sweep leases past their TTL: expire pending leases and compensate active ones.

---

## Groups

### `mayhem experiment`

Inspect and validate authored experiments.

| Subcommand | Description |
|---|---|
| `show EXPERIMENT` | Print the parsed experiment spec as JSON |
| `validate EXPERIMENT` | Same as top-level `validate` |

### `mayhem topology`

Discover and inspect target-system topology.

| Subcommand | Description |
|---|---|
| `discover --compose PATH` | Run the topology provider pipeline and print graph + drift JSON |

### `mayhem toolkit`

Inspect the fault catalog and local tool capabilities.

| Subcommand | Description |
|---|---|
| `faults` | List the fault catalog with risk and compensatability |
| `list` | Probe declared tool manifests on the host and report capabilities |

`list` accepts `--host` and `--json` flags.

### `mayhem config`

Inspect the effective layered mayhem configuration.

| Subcommand | Description |
|---|---|
| `show` | Print the effective configuration after all layers are merged |
| `validate` | Load every configuration layer; refuse unknown keys or versions |

`show` accepts `--json` to emit YAML→JSON instead of YAML.

---

## Prefix resolution

Any unambiguous prefix of a command name is accepted at every level of the tree:

```bash
mayhem e v experiments.yaml     # resolves to mayhem experiment validate
mayhem sta                      # resolves to mayhem status
mayhem tk f                     # resolves to mayhem toolkit faults
mayhem c s                      # resolves to mayhem config show
```

If a prefix matches more than one command, the CLI exits with code **10** and prints
the matching candidates.

---

## Exit codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `SUCCESS` | Command completed successfully |
| 1 | `GENERAL_FAILURE` | Runtime failure not covered by a specific code |
| 2 | `USAGE_ERROR` | Bad flags or arguments |
| 3 | `CONFIG_ERROR` | Configuration layering or validation failed |
| 4 | `VALIDATION_ERROR` | Experiment/spec/target validation failed |
| 5 | `SAFETY_REFUSAL` | A safety gate refused the operation |
| 6 | `EXPERIMENT_FAILURE` | Experiment ran and did not complete |
| 7 | `RECOVERY_FAILURE` | Recovery/janitor left dirty state behind |
| 8 | `AGENT_ERROR` | Agent transport/runtime failure |
| 9 | `TOOLKIT_ERROR` | External tool invocation failed structurally |
| 10 | `AMBIGUOUS_COMMAND` | Command prefix matched multiple commands |

Exit codes are defined in `src/mayhem/cli/exit_codes.py` and are a stable public contract.

---

## Project layout

```
src/mayhem/cli/
  __init__.py        # namespace only
  app.py             # root group, main() entry, error→exit-code mapping
  resolver.py        # PrefixGroup + unique-prefix resolution
  context.py         # CliContext dataclass (parsed once, shared via ctx.obj)
  services.py        # thin service layer (UI-framework-agnostic)
  lifecycle.py       # validate, plan, run, status, history, recover, janitor
  experiment.py      # experiment show/validate group
  topology.py        # topology discover group
  toolkit.py         # toolkit faults/list group
  config_cmd.py      # config show/validate group
  exit_codes.py      # ExitCode enum
```

Handlers are intentionally thin: they translate Click arguments into service calls
and format results. `services.py` is the single place CLI touches Mayhem internals,
making it reusable from a future REST or UI layer.
