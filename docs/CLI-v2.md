# Mayhem CLI Command Graph — Proposed Compact Interface

> **Status:** Proposed target interface, not a claim about the current implementation.
>
> This document replaces the large public command surface with a workflow-oriented CLI. It preserves the central Mayhem lifecycle—discover, prepare, execute, inspect, recover, and report—while moving diagnostic details and advanced capabilities into the commands where users need them.

## 1. Design goals

The public CLI should make five things obvious:

1. Discover the environment Mayhem can work with.
2. Validate and plan a drill without injecting faults.
3. Execute a drill only after explicit approval.
4. Inspect run history and manage run lifecycle.
5. Recover incomplete runs and export verifiable evidence.

The command line should expose complete user workflows, not every internal service, controller, provider, or information renderer.

### Public command count

The reorganized CLI exposes **10 namespaces** (workspace, environment, drill, runs, orchestration, governance, evidence, platform, extensions, developer) under the root `mayhem` group. All 40 existing command names remain available at root as compatibility aliases that invoke the same handler as their canonical namespace path.

```text
mayhem [GLOBAL OPTIONS] <NAMESPACE> <COMMAND> [COMMAND OPTIONS] [ARGS]
│
├── workspace                  Initialize projects and manage the local installation.
│   ├── init [PROJECT PATH]
│   ├── doctor [--json] [--quiet] [--category CATEGORY]
│   ├── config
│   │   ├── show
│   │   └── validate
│   ├── support
│   │   └── bundle
│   └── upgrade
│
├── environment                Discover topology, faults, capabilities and diagnostics.
│   ├── discover
│   │   ├── topology [--compose PATH]
│   │   ├── faults [-e | --explain FAULT_ID]
│   │   ├── capabilities [--runtime docker|podman|kubernetes]
│   │   └── engines
│   ├── boundary
│   ├── advisor
│   └── probe
│
├── drill                      Prepare, plan and execute chaos experiments.
│   ├── prepare
│   │   ├── validate SPEC [--compose PATH]
│   │   ├── plan SPEC [--compose PATH] [--explain]
│   │   ├── config
│   │   ├── dependencies
│   │   └── check
│   ├── experiment
│   ├── run [EXPERIMENT] [--compose PATH] [--execute] [--allow-critical]
│   ├── maniac
│   └── risk-preview
│
├── runs                       Inspect, control and recover runs.
│   ├── inspect
│   │   ├── run RUN_ID
│   │   ├── leases
│   │   ├── residual RUN_ID
│   │   ├── graph
│   │   ├── coverage-diff
│   │   ├── runs
│   │   ├── history
│   │   ├── coverage
│   │   ├── expert
│   │   ├── next
│   │   ├── doctor
│   │   └── replay
│   │       ├── export RUN_ID [--output PATH]
│   │       └── validate CAPSULE_PATH
│   ├── stop RUN_ID --execute
│   ├── extend RUN_ID --duration DURATION --execute
│   ├── recover RUN_ID --execute
│   └── janitor [--orphans] --execute
│
├── orchestration              Manage campaigns, schedules and game days.
│   ├── campaign
│   ├── schedule
│   └── game-day
│       └── step
│
├── governance                 Manage policy, secrets and certification.
│   ├── policy
│   ├── secrets
│   └── certify
│       ├── run
│       ├── matrix
│       └── regress
│
├── evidence                   Export, verify and inspect evidence and proofs.
│   ├── bundle
│   │   ├── build
│   │   ├── show
│   │   ├── verify
│   │   ├── keygen
│   │   ├── keys
│   │   ├── sign
│   │   └── signatures
│   ├── verify
│   └── prove
│
├── platform                   Manage agents and platform integrations.
│   ├── agent
│   │   ├── enroll
│   │   ├── list
│   │   ├── revoke
│   │   └── show
│   ├── ci
│   ├── cloud
│   ├── ha
│   └── enterprise
│
├── extensions                 Manage packs, marketplace and sandbox features.
│   ├── pack
│   │   ├── validate
│   │   └── load
│   ├── marketplace
│   └── sandbox
│
└── developer                  API, low-level, command registry and shell completion tools.
    ├── api
    │   ├── openapi
    │   ├── pages
    │   ├── parameters
│   │   ├── routes
    │   └── serve
    ├── lowlevel
    ├── commands
    └── completion
```

Each namespace is registered once under its canonical path; every old root path (e.g. `mayhem doctor`, `mayhem run`, `mayhem inspect`) still resolves to the same handler and produces equivalent output.

---

## 2. Root invocation

```text
mayhem [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS] [ARGS]
```

### Global options

| Option | Argument | Description |
|---|---|---|
| `--version` | — | Print the installed Mayhem version and exit. |
| `--config` | `PATH` | Select the runtime configuration file. Defaults to the supported auto-discovery behavior. |
| `--profile` | `NAME` | Select a configuration profile. |
| `--db` | `PATH` | Override the SQLite database path. |
| `--format` | `text\|json\|yaml` | Select output format where the command supports structured output. |
| `--no-color` | — | Disable colored terminal output. |
| `-d`, `--debug` | — | Enable diagnostic logging. |

### Removed from global options

| Previous option | Proposed treatment | Reason |
|---|---|---|
| `--policy` | Configure policy in `mayhem.yaml`; keep command-specific overrides only when justified. | Policy should have one predictable source of truth. |
| `--dry-run` | Remove as a global option. Use `prepare plan` for non-mutating preview. | Avoid overlap between dry-run, validation, and planning. |
| `--skip-gate` | Remove from the public CLI. | Safety gates are a core product guarantee and should not have a routine bypass flag. |
| `--podman` | Select `runtime: podman` in configuration. | Avoid a global runtime switch on every command. |
| `--kubernetes` | Keep Kubernetes selection in the runtime configuration and expose only supported workflows. | Avoid implying that all Kubernetes operations are live-supported. |
| `--target` | Make target selection part of the relevant discovery or drill input. | A global target flag is ambiguous across commands. |
| `--allow-critical` | Keep only on `run`, as an explicit execution opt-in. | Critical-risk approval belongs at the point of execution. |

Unknown root options should continue to be rejected. Global options should remain limited to configuration, output, and diagnostics.

---

## 3. Complete proposed command tree

```text
mayhem [GLOBAL OPTIONS] <COMMAND>
│
├── init
│   └── [PROJECT PATH]
│
├── doctor
│   ├── [--verbose]
│   └── [--check CHECK_NAME]
│
├── discover
│   ├── topology
│   │   └── [--compose PATH]
│   ├── faults
│   │   └── [-e | --explain FAULT_ID]
│   └── capabilities
│       └── [--runtime docker|podman|kubernetes]
│
├── prepare
│   ├── validate SPEC
│   │   └── [--compose PATH]
│   └── plan SPEC
│       ├── [--compose PATH]
│       └── [--explain]
│
├── run SPEC
│   ├── [--compose PATH]
│   ├── [--execute]
│   └── [--allow-critical]
│
├── runs
│   ├── list
│   ├── show RUN_ID
│   ├── stop RUN_ID --execute
│   └── extend RUN_ID --duration DURATION --execute
│
├── recover
│   ├── RUN_ID --execute
│   └── --orphans --execute
│
├── config
│   ├── show
│   └── validate
│
└── evidence
    ├── export RUN_ID [--output PATH]
    ├── verify BUNDLE_PATH
    └── replay
        ├── export RUN_ID [--output PATH]
        └── validate CAPSULE_PATH
```

This is the proposed public interface. Items such as `--verbose`, `--check`, `--runtime`, `--explain`, `--duration`, and output-path arguments are interface proposals; their exact names and availability must be reconciled with the implementation before release.

---

## 4. Command reference

### 4.1 `init` — Initialize a Mayhem project

```text
mayhem init [PROJECT PATH]
```

Purpose:
- Create a starter Mayhem configuration and project structure.
- Give users a clear starting point without requiring them to know the internal configuration layout.

Expected behavior:
- Do not overwrite an existing configuration silently.
- Explain which files were created.
- Keep generated configuration minimal and valid.

### 4.2 `doctor` — Check the local environment

```text
mayhem workspace doctor [--json] [--quiet] [--category CATEGORY]
```

Purpose:
- Check required dependencies and the selected runtime connection.
- Report missing tools, permissions, runtime reachability, and local configuration problems.
- Explain a failure and suggest the next useful command.

`doctor` is an information command. It must not inject faults, create leases, or mutate workloads.

Detailed diagnostics should be part of `doctor` output rather than separate top-level commands such as `advisor`, `boundary`, or `risk-preview`.

### 4.3 `discover` — Discover infrastructure and supported capabilities

#### Topology

```text
mayhem environment discover topology [--compose PATH]
```

Purpose:
- Build and display the topology graph from the available environment.
- Use the supplied Compose file or the documented Compose auto-detection behavior.
- Report discovered services, relationships, target identities, and unresolved dependencies.

Known Compose behavior:
- `--compose PATH` selects an explicit Compose file.
- When omitted, Mayhem can auto-detect `docker-compose.yml` or `compose.yml` in the current directory, as documented.

#### Fault catalog

```text
mayhem environment discover faults [-e | --explain FAULT_ID]
```

Purpose:
- List fault catalog entries and their maturity/support status.
- Explain a particular fault, including required capabilities, risk, applicable targets, parameter requirements, compensation information, and refusal reason where applicable.

Catalog discovery must not imply that every catalog entry is executable. `catalog_only`, `experimental`, and live-verification status must remain visible and accurately distinguished.

#### Capabilities

```text
mayhem environment discover capabilities [--runtime docker|podman|kubernetes]
```

Purpose:
- Report capabilities available to the selected runtime and environment.
- Explain which requirements are missing for a requested operation.
- Distinguish discovered, planned, executable, and live-verified support where those states apply.

The `--runtime` spelling is a proposal. Runtime selection may instead be read exclusively from configuration if that produces a more consistent interface.

### 4.4 `prepare` — Validate and plan a drill

#### Validate

```text
mayhem drill prepare validate SPEC [--compose PATH]
```

Purpose:
- Parse and validate a `kind: drill` specification.
- Resolve targets and validate fault parameters.
- Evaluate policy, capabilities, risk, blast radius, durations, and compensation requirements.
- Report all relevant refusals with actionable explanations.

Validation is non-mutating. It must not inject a fault or create an execution lease.

#### Plan

```text
mayhem drill prepare plan SPEC [--compose PATH] [--explain]
```

Purpose:
- Compile the specification into a frozen execution plan.
- Show the planned steps, target scope, fault order, durations, probes, success criteria, and recovery actions.
- Include safety-gate decisions and reasons in the same output.

`--explain` should expand the safety and impact explanation. It should not be a separate workflow or require users to run separate `advisor`, `boundary`, `risk-preview`, or `prove` commands.

Planning is non-mutating. It must not inject a fault or create an execution lease.

### 4.5 `run` — Execute a drill

```text
mayhem drill run [EXPERIMENT] [--compose PATH] [--execute] [--allow-critical]
```

Purpose:
- Compile or revalidate the requested drill against the current environment.
- Apply the safety and impact gates.
- Execute supported fault steps, observe the system, compensate, and record the verdict.

Execution rules:
- Without `--execute`, show the execution preview and perform no mutation.
- `--dry-run` is not required; `prepare plan` is the dedicated planning command.
- `--execute` is explicit approval to perform the run.
- Critical-risk faults require all existing approval conditions: `policy.allow_critical: true`, the per-fault acknowledgement in `policy.critical_fault_acks`, and `--allow-critical` at execution time.
- A failed injection, unavailable backend, failed compensation, or failed recovery must never be reported as a clean success.

The run command should be the primary user-facing entry point for execution modes that are genuinely supported. Randomized/maniac execution should become a run mode or drill configuration, not another top-level command.

### 4.6 `runs` — List, inspect, and manage runs

#### List

```text
mayhem runs list
```

Purpose:
- List recorded runs with their identifier, specification, status, verdict, runtime, and creation time where available.

#### Show

```text
mayhem runs inspect run RUN_ID
```

Purpose:
- Display the selected run's timeline, steps, probe observations, criteria evaluations, gate decisions, compensation results, and final verdict.
- Provide the useful functionality currently spread across generic inspection and reporting commands.

#### Stop

```text
mayhem runs stop RUN_ID --execute
```

Purpose:
- Request a controlled stop of an active run.
- Trigger the established stop and recovery behavior.
- Record the stop decision and resulting state.

#### Extend

```text
mayhem runs extend RUN_ID --duration DURATION --execute
```

Purpose:
- Extend an active fault or run only when the underlying execution model and safety policy permit it.
- Recheck duration ceilings, leases, and policy before applying the extension.

The exact duration syntax and whether extension is supported for every fault type must be defined by the implementation. Do not expose an extension that cannot be enforced safely.

### 4.7 `recover` — Recover incomplete runs and orphaned leases

```text
mayhem runs recover RUN_ID --execute
mayhem runs janitor --orphans --execute
```

Purpose:
- Recover an individual run's incomplete or orphaned work.
- Sweep expired or orphaned leases when `--orphans` is selected.
- Apply the declared compensation or workload-reconciliation behavior.
- Record the recovery actions and resulting state.

This consolidates the normal recovery workflow and the janitor sweep. There should not be separate everyday commands for `recover` and `janitor`.

Recovery must report partial or failed recovery honestly. It must not convert a dirty run into a clean run merely because a recovery request was accepted.

### 4.8 `config` — View and validate runtime configuration

#### Show

```text
mayhem workspace config show
```

Purpose:
- Print the resolved configuration and its provenance.
- Show which values came from defaults, YAML, profile overlays, allowlisted environment variables, and supported CLI overrides.

#### Validate

```text
mayhem workspace config validate
```

Purpose:
- Validate the selected runtime configuration.
- Refuse unknown keys, a missing or incorrect `apiVersion`, and out-of-range values before execution.

The existing configuration layering remains:

```text
built-in defaults
    → selected YAML
    → mayhem.{profile}.yaml
    → allowlisted environment values
    → programmatic CLI overrides
```

Configuration is distinct from a `kind: drill` specification. `mayhem.yaml` remains the runtime configuration file unless the project deliberately changes that convention.

### 4.9 `evidence` — Export, verify, and replay recorded evidence

#### Export a run bundle

```text
mayhem evidence bundle build RUN_ID [--output PATH]
```

Purpose:
- Export a run's recorded evidence into a portable bundle.
- Preserve the existing hash-chain and offline-verification behavior.
- Keep signing behavior and trust limitations explicit in the output.

#### Verify a bundle

```text
mayhem evidence verify BUNDLE_PATH
```

Purpose:
- Re-derive and verify bundle hashes from the bytes on disk.
- Perform offline verification without requiring the run database.
- Clearly distinguish integrity verification from signer authentication.

The currently documented pack/bundle signing limitations must not be obscured: a digest can establish integrity, but an unverified signer string is not cryptographic proof of authorship.

#### Replay capsules

```text
mayhem runs inspect replay export RUN_ID [--output PATH]
mayhem runs inspect replay validate CAPSULE_PATH
```

Purpose:
- Export a versioned, digest-checked replay capsule for a run.
- Validate a capsule offline.
- Replay operations live under `runs inspect replay`.

---

## 5. Information output belongs to the relevant workflow

The following capabilities should normally appear as sections in existing command output rather than independent public commands.

| Information | Where it should appear |
|---|---|
| Risk assessment | `drill prepare plan` and `drill run` preview |
| Blast-radius boundary | `drill prepare plan` and `drill run` preview |
| Capability gaps | `environment discover capabilities`, `drill prepare validate`, and `drill prepare plan` |
| Safety proof and gate obligations | `drill prepare plan` and `runs inspect` |
| Probe observations | `runs inspect` |
| Fault maturity and refusal explanation | `environment discover faults` and plan/validation output |
| Recommendations | `workspace doctor` or a contextual explanation after a refusal |
| Low-level diagnostic details | `workspace doctor --verbose` or debug logs |
| Run history and evidence | `runs list`, `runs inspect`, and `evidence bundle` |

A standalone command is justified only when it performs a distinct operation that users need to invoke independently—not simply because an internal service can render a report.

---

## 6. Mapping from the previous command surface

| Previous command or group | Proposed destination | Treatment |
|---|---|---|
| `init` | `workspace init` | Keep; available at root and under `workspace`. |
| `doctor` | `workspace doctor` | Keep; available at root and under `workspace`. |
| `discover` | `environment discover` | Keep; available at root and under `environment`. |
| `prepare` | `drill prepare` | Keep; expose `validate` and `plan`. |
| `prepare config show` | `workspace config show` | Configuration management under `workspace config`. |
| `prepare config validate` | `workspace config validate` | Configuration management under `workspace config`. |
| `run` | `drill run` | Keep as the primary execution interface. |
| `experiment`, `maniac` | `drill experiment`, `drill maniac` | Consolidate under `drill`. |
| `inspect` | `runs inspect` | Merge run inspection under `runs`. |
| `stop` | `runs stop` | Move under run lifecycle. |
| `extend` | `runs extend` | Move under run lifecycle; expose only where safe. |
| `recover` | `runs recover` | Keep and simplify. |
| `janitor` | `runs janitor` | Merge orphan cleanup into recovery. |
| `bundle`, `verify` | `evidence bundle`, `evidence verify` | Consolidate evidence operations. |
| `prove` | `drill prepare plan`, `runs inspect` | Render proof details in planning and run evidence. |
| `inspect replay` | `runs inspect replay` | Group replay under `runs inspect`. |
| `policy` | `governance policy` | Policy under `governance`. |
| `risk-preview`, `boundary` | `drill prepare plan` | Include risk and boundary in the plan explanation. |
| `advisor` | `environment advisor` | Keep under `environment`. |
| `probe` | `environment probe` | Present probe data under `environment`. |
| `campaign`, `schedule`, `game-day`, `game-day-step` | `orchestration campaign`, `orchestration schedule`, `orchestration game-day`, `orchestration game-day step` | Orchestration commands under `orchestration`. |
| `pack` | `extensions pack` | Pack management under `extensions`. |
| `secrets` | `governance secrets` | Secrets under `governance`. |
| `certify` | `governance certify` | Certification under `governance`. |
| `agent` | `platform agent` | Agent management under `platform`. |
| `api`, `lowlevel` | `developer api`, `developer lowlevel` | Developer interface under `developer`. |
| `ci` | `platform ci` | CI under `platform`. |
| `cloud`, `marketplace`, `enterprise`, `ha`, `sandbox` | `platform cloud`, `extensions marketplace`, `enterprise`, `platform ha`, `extensions sandbox` | Platform/extension commands under their namespaces. |
| `support-bundle`, `upgrade` | `workspace support bundle`, `workspace upgrade` | Support/package workflows under `workspace`. |
| `commands` | `developer commands` | Command registry under `developer`. |
| `completion` | `developer completion` | Shell completion under `developer`. |

---

## 7. Deferred and hidden command areas

These capabilities are not necessarily deleted from the codebase. They are simply excluded from the normal public CLI until their user workflows are complete and their support status is clear.

```text
future / advanced areas
├── campaign       # multi-drill orchestration, checkpoints, pause/resume
├── extensions     # fault packs and provider extensions
├── agents         # agent lifecycle and remote execution management
├── dev            # API inspection and low-level diagnostics
└── support        # support bundles and maintenance utilities
```

Rules:
- Do not advertise a future command as implemented merely because a module or service exists.
- Do not expose experimental or catalog-only faults as executable operations.
- Keep experimental commands out of default `mayhem --help`; when exposed, label them explicitly as experimental.
- Keep internal developer tools available to developers without making them part of the end-user workflow.
- Reintroduce a deferred command only when it has a complete purpose, validated behavior, documentation, tests, and a support statement.

---

## 8. Execution and safety semantics

The CLI should have one consistent mental model:

| Operation | Mutates workloads? | Creates execution lease? | Requires `--execute`? |
|---|---:|---:|---:|
| `discover` | No | No | No |
| `prepare validate` | No | No | No |
| `prepare plan` | No | No | No |
| `doctor` | No | No | No |
| `config show` / `config validate` | No | No | No |
| `run` preview | No | No | No |
| `run` execution | Yes, when supported | Yes, when required by the execution model | Yes |
| `runs list` / `runs show` | No | No | No |
| `runs stop` | Can affect active execution | Depends on the stop/recovery implementation | Yes |
| `runs extend` | Extends an active fault/run | Depends on the execution model | Yes |
| `recover` | May mutate workloads to restore them | May release or reconcile leases | Yes |
| `evidence export` / `verify` / `replay validate` | No | No | No |

Safety requirements:
- Preview and planning must never create an execution lease.
- Mutating operations require explicit approval.
- Critical-risk execution retains the existing triple opt-in.
- Safety gates remain mandatory in the public interface; no ordinary `--skip-gate` option is exposed.
- Recovery outcomes must distinguish fully recovered, partially recovered, and failed states.
- An unavailable backend must never be represented as a successful fault injection.

---

## 9. Output and interaction conventions

### Human output

- Keep default output concise and action-oriented.
- Put the decision first: `APPROVED`, `REFUSED`, `RUNNING`, `RECOVERED`, `DIRTY`, or another precise state.
- Follow the decision with the reason and the next useful action.
- Use consistent tables for plan steps, run timelines, probes, and evidence summaries.

### Machine output

- Support stable `json` and `yaml` output where appropriate.
- Keep field names and status values consistent across `prepare`, `run`, `runs`, `recover`, and `evidence`.
- Write diagnostics to stderr and machine-readable results to stdout.
- Use non-zero exit codes for validation failures, safety refusals, execution failures, and unsuccessful recovery.
- Do not use human-formatted terminal text as the machine interface.

### Help output

Normal `mayhem --help` should show only the nine public commands and a short description for each. Every command and subcommand should have concise, locally relevant help.

Proposed root help:

```text
Mayhem — Chaos Engineering for Docker and Podman

Usage:
  mayhem [OPTIONS] COMMAND

Commands:
  init       Initialize a Mayhem project
  doctor     Check the environment and dependencies
  discover   Discover infrastructure and capabilities
  prepare    Validate and plan drills
  run        Execute a drill
  runs       List, inspect, and manage runs
  recover    Recover incomplete runs and orphaned leases
  config     View and validate configuration
  evidence   Export, verify, and replay evidence

Options:
  --config PATH       Configuration file
  --profile NAME      Configuration profile
  --db PATH           SQLite database path
  --format FORMAT     text, json, or yaml
  --no-color          Disable colored output
  -d, --debug         Enable diagnostic logging
  --version           Show version and exit

Run 'mayhem COMMAND --help' for command-specific help.
```

---

## 10. Migration checklist

Before replacing the current CLI surface:

1. Inventory every current command handler, option, and behavior from `src/mayhem/cli/`.
2. Map each behavior to a retained command, a merged output section, an internal API, or a deferred feature.
3. Preserve useful functionality; do not delete implementation code solely because its command is no longer public.
4. Add compatibility aliases for frequently used commands only when the migration benefit outweighs long-term maintenance.
5. Ensure aliases emit a deprecation message and point to the replacement command.
6. Update the exhaustive CLI matrix so it tests the **new intended public surface**, not the previous command count.
7. Test root help, command help, unknown-option rejection, structured output, exit codes, and all mutating-command approval paths.
8. Update README examples, installation guidance, shell completion, tests, and release documentation together.
9. Verify that every advertised command is implemented and supported at the stated maturity level.

## 11. Source-of-truth and implementation notes

The source code remains authoritative for what is currently implemented. This document defines a proposed target interface based on the supplied README and command inventory; it does not establish that the proposed tree or every proposed option already exists.

In particular, reconcile these items against the actual CLI implementation before treating this document as an exact executable reference:
- Exact option names and types for `discover`, `prepare`, `run`, `recover`, and evidence operations.
- Whether run stop and extension can be safely exposed under `runs`.
- Whether recovery accepts a run ID, an orphan-sweep mode, or both.
- The supported output formats for each command.
- Whether Kubernetes capability discovery can be reported without implying live Kubernetes acceptance.
- The exact maturity labels and counts in the fault catalog at release time.

The goal is a small, dependable public CLI over a capable internal engine—not a one-to-one public command for every internal module.
