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
| `--profile NAME` | Configuration profile overlay (`mayhem.{profile}.yaml`). Not a target profile. |
| `--policy NAME` | Named safety policy. |
| `--dry-run` | Evaluate policy without mutation. |
| `--allow-critical` | Acknowledge critical-risk faults. |
| `--skip-gate` | Run despite proved-inert faults. |
| `-p, --podman` | Select Podman. |
| `-k, --kubernetes` | Select Kubernetes. |
| `-d, --debug` | Re-raise unexpected errors. |
| `--target NAME` | Select a target profile from the configuration's `targets`. |
| `--format text\|json\|yaml` | Select output format. |
| `--no-color` | Disable ANSI color. |

## Active commands

### `mayhem discover`

Discover the execution surface and catalog before mutating anything.

- `mayhem discover engines`
- `mayhem discover topology --compose COMPOSE`
- `mayhem discover faults`
- `mayhem discover capabilities`

### `mayhem prepare`

Prepare configuration, dependencies, and executable plans.

- `mayhem prepare config show [--json]`
- `mayhem prepare config explain [--json]`
- `mayhem prepare config validate`

`config show` includes the `targets` section (the target profiles, under the
`profiles:` alias as well) and the `sources` map records which layer supplied
it. `config explain` reports `targets` as its own row.
- `mayhem prepare dependencies check|install|compile`
- `mayhem prepare check`
- `mayhem prepare validate [SPEC] -c COMPOSE`
- `mayhem prepare plan [SPEC] -c COMPOSE`

`validate` and `plan` resolve a missing spec from the directory containing the selected `--compose` file before falling back to the current directory. `discover topology` has no `-c` shorthand; use `--compose`.

### `mayhem experiment`

Inspect authored experiments and run the active exploration loop.

- `mayhem experiment show SPEC`
- `mayhem experiment validate SPEC -c COMPOSE`
- `mayhem experiment explore [SPEC] -c COMPOSE`

### `mayhem run` and `mayhem maniac`

`run` compiles, gates, and executes a drill. `maniac` runs randomized fault-injection rounds. Use `run --execute` for explicit execution approval; use `--dry-run` where supported for previews.

Execution is an approved act (v0.9.0). Without `--execute`, `run` previews the
preflight and stops before any run row or lease exists; `maniac` refuses
outright.

### `--dry-run` always wins

A global `--dry-run` is a promise that **the target is not mutated**, and it is
never an approval. It beats `--execute` on every command that can inject a
fault, install a package, or transition a lease, and
`MAYHEM_ALLOW_IMPLICIT_EXECUTION=1` cannot override it: each row below returns
before its mutating call, so nothing is executed, compensated, installed, or
applied.

| Command | Under `--dry-run` |
|---------|-------------------|
| `mayhem run SPEC` | Prints the preflight and the dry-run policy decisions; no run row, no lease. |
| `mayhem run --from-plan FILE` | Loads and previews the plan, then reports `nothing executed`. |
| `mayhem run --plan-id ID` | Loads and previews the stored plan, then reports `nothing executed`. |
| `mayhem run --diff FILE` | Prints the plan diff, then reports `nothing executed`. |
| `mayhem maniac` | Compiles and reports how many rounds were drawn, then reports `nothing injected`. |
| `mayhem campaign run ID` | Reports the experiment count and campaign status, then reports `nothing mutated`; the campaign row is not touched either. |
| `mayhem explore` (live) | Renders the ranked queue (same as `--dry-run`); no cell runs. |
| `mayhem prepare dependencies install` | Prints the dependency plan; nothing is installed. |
| `mayhem recover execute RUN_ID` | Prints the recovery plan, then reports `nothing compensated`. |
| `mayhem recover RUN_ID` (legacy shim) | Prints the recovery plan, then reports `nothing compensated`. |
| `mayhem janitor` | Plans only; no lease transition is applied and the JSON payload reports `"execute": false`. |

`--dry-run` needs no approval, so it previews whether or not `--execute` was
passed.

Two boundaries worth stating plainly:

- **`mayhem janitor` is already a preview** without `-e/--execute`; `--dry-run`
  only makes that non-negotiable when `-e` is also passed. It applies to
  *planned lease transitions*, not to the read-only planning.
- **Mayhem's own SQLite database is not a target.** `campaign create`,
  `add-experiment`, `start`, `pause`, `resume`, `archive`, `abort`, `delete`,
  plus `inspect` and `prepare`, write to that local store and are outside the
  execution-intent contract; `--dry-run` does not gate them. `campaign run` *is*
  inside the contract because it injects faults into the target — and its
  `--dry-run` preview happens to leave the campaign row untouched as well.

### Execution intent

Every mutating command requires an explicit approval flag, and a run is
authorized by an execution intent bound to the plan hash, engine, and target
that were reviewed. Refusals use stable codes and exit with
`ExitCode.SAFETY_REFUSAL` (5); no new exit code is introduced.

| Code | Meaning |
|------|---------|
| `execution_intent_required` | No explicit approval was given. |
| `approval_expired` | The approval existed but its deadline passed. |
| `execution_intent_mismatch` | The approval is bound to a different plan hash, engine, or target. |

| Command | Approval |
|---------|----------|
| `mayhem run SPEC` | `--execute` |
| `mayhem maniac` | `--execute` |
| `mayhem campaign run ID` | `--execute` |
| `mayhem explore` (live) | `--execute` |
| `mayhem recover execute RUN_ID` | the sub-command name |
| `mayhem recover RUN_ID` (legacy shim) | `--execute` |
| `mayhem janitor` | `-e` / `--execute` |
| `mayhem prepare dependencies install` | `--execute` or `-y` |

No approval is required for a `--dry-run` preview of any of the above; see
[`--dry-run` always wins](#--dry-run-always-wins).

`MAYHEM_ALLOW_IMPLICIT_EXECUTION=1` restores the pre-v0.9.0 implicit behaviour
for legacy automation. It is a compatibility escape hatch, not a second way to
skip approval, and it never overrides `--dry-run`. When it is in play no intent
is minted — by `run`, `maniac`, or `campaign run` alike — so the run's evidence
envelope records `execution_intent: null` and an auditor can still tell an
implicit run from an approved one.

The switch is read in exactly one place. `mayhem.cli.app.implicit_execution_allowed()`
resolves it, and every mutating surface passes the resulting boolean down as
`allow_implicit` (its own approval check, `engine_for` → `RunEngine`, and
`CellRunner` for `explore`). The domain validator takes it as a plain argument
and the controller never reads the environment or imports the CLI layer, so no
lower layer can answer that question differently from the CLI that started the
command.

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

- `mayhem campaign` — create, inspect, and run chaos campaigns (`campaign run` needs `--execute`).
- `mayhem commands show` — print the active command map.
- `mayhem init` — detect a project and create a safe starter configuration.
- `mayhem doctor` — check configuration, database, engines, topology, capabilities, and permissions.
- `mayhem verify RUN_ID` — verify a recorded evidence envelope without mutation.

`doctor` reports the target it resolved and the engines available for it:

- `config.target.selected` — the selected target profile and its engine. The
  same record is emitted whether the target came from `--target` or was the
  single configured profile.
- `config.target.ambiguous` — more than one target profile is configured and no
  `--target` was given. Nothing is selected; pass `--target NAME`.
- `config.target.mismatch` — the `--target` name is not a configured profile.
- `config.target_profile.<name>.policy_advisory` — the profile declares a
  `policy:` the run does not enforce; use `--policy` or the `policy:` block.
- `engine.target.available` / `engine.target.missing` — whether the selected
  target's engine binary (`docker`, `podman`, `kubectl`) is on `PATH`. This is
  file presence, checked without a subprocess, and does not claim the runtime is
  healthy.

`--profile` selects a configuration overlay (`mayhem.{profile}.yaml`) and is
never compared against target-profile names; a target profile is selected with
`--target`.

## Command inventory

This table is the checked inventory of the active root commands. It is compared
against `COMMAND_SPECS` in `src/mayhem/cli/command_registry.py` by
`tests/unit/test_release_contract.py`, so a registry change that is not
documented here fails the suite. `Workflow` is the owning workflow,
`Help group` is the `--help` grouping, and `Mutating` marks commands that can
change a target.

| Command | Workflow | Help group | Mutating |
|---------|----------|------------|----------|
| `campaign` | `run` | experiments | yes |
| `commands` | `inspect` | inspect | no |
| `discover` | `discover` | discovery | no |
| `doctor` | `inspect` | inspect | no |
| `experiment` | `experiment` | experiments | no |
| `extend` | `extend` | extension | no |
| `init` | `prepare` | preparation | no |
| `inspect` | `inspect` | inspect | no |
| `janitor` | `recover` | recover | yes |
| `maniac` | `run` | experiments | yes |
| `prepare` | `prepare` | preparation | no |
| `recover` | `recover` | recover | yes |
| `run` | `run` | run | yes |
| `verify` | `inspect` | inspect | no |

Sub-commands of the groups are documented in the group sections above. The
`mayhem recover RUN_ID` spelling resolves to `recover execute RUN_ID` through a
compatibility shim in `RecoverGroup`. Because that spelling hides a mutation
behind a bare run id, it also requires `--execute`; new automation should use
the explicit `recover status`, `recover plan`, or `recover execute` spelling.

## Output and errors

Human output is the default. JSON and YAML are available through `--format` and compatible command-local flags. Errors use stable codes and map to the existing numeric exit codes. Machine errors are emitted on stderr; successful JSON output is not mixed with progress text. Execution-intent refusals (`execution_intent_required`, `approval_expired`, `execution_intent_mismatch`) carry the offending action in `details` and the explicit approval to add in `remediation`.

## Exit codes

The existing exit-code enum remains unchanged: `SUCCESS`, `GENERAL_FAILURE`, `USAGE_ERROR`, `CONFIG_ERROR`, `VALIDATION_ERROR`, `SAFETY_REFUSAL`, `EXPERIMENT_FAILURE`, `RECOVERY_FAILURE`, `AGENT_ERROR`, `TOOLKIT_ERROR`, and `AMBIGUOUS_COMMAND`.
