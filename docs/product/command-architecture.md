# Command architecture contract

## Context layers

Every command receives a resolved `CliContext` before it reaches a service. The context is assembled in this order:

1. Built-in defaults.
2. Root options such as database, config, profile, debug, and engine selection.
3. Command-specific options and arguments.
4. Explicit execution intent for mutating operations.

The CLI must not construct a second implicit context inside a command handler.

## Context fields

| Field | Purpose | Required behavior |
|-------|---------|------------------|
| `database_path` | SQLite store selection | Preserve current default and migration behavior. |
| `config_path` | Configuration or drill spec selection | Preserve `--config` semantics. |
| `profile_name` | Separate profile overlay | Preserve `mayhem.{profile}.yaml` semantics. |
| `engine` | Docker, Podman, or Kubernetes | Require explicit override when auto-detection is ambiguous. |
| `target_profile` | Named environment | Require it for mutations when multiple profiles exist. |
| `output_format` | `text`, `json`, or future `yaml` | Human output is default; machine output is explicit. |
| `safety_mode` | Validate, plan, or execute | Mutating commands default to plan/preflight. |
| `debug` | Error detail and traceback | Never changes stable error codes or machine schema. |

## Command delegation

New workflow commands must be thin adapters:

```text
CLI parser -> context builder -> application service -> domain/controller -> renderer
```

A CLI module may parse arguments, request services, and render results. It must not import infrastructure mutation code directly, implement safety policy, or duplicate planner logic.

Legacy commands delegate to the same application services. Their exact names, accepted flags, exit codes, and existing JSON keys remain available during the migration window.

## Error envelope

Every new machine-readable failure has this shape:

```json
{
  "error": {
    "code": "stable.error.code",
    "message": "human-readable message",
    "details": {},
    "remediation": "next action",
    "evidence_ref": "optional record or artifact reference"
  }
}
```

The envelope is additive. Existing human text and existing JSON fields remain unchanged during the migration window. `--debug` may add traceback information outside the stable fields.

## Mutation safety

Every operation that can affect a target follows:

```text
resolve -> compile -> safety -> diff -> approve -> execute -> verify -> evidence
```

The following require explicit execution intent:

- Fault injection and random execution.
- Dependency installation.
- Campaign execution.
- Recovery and janitor cleanup.
- Any future provider mutation.

`--skip-gate` is a safety override, not execution approval. It must be visible in preflight and evidence.

## Compatibility policy

| Surface | During migration | Breaking-change rule |
|---------|------------------|-----------------------|
| Exact command names | Preserved as aliases or wrappers | Remove only after a documented major release. |
| Unique command prefixes | Preserved where unambiguous | Ambiguity remains an error. |
| Exit codes | Numeric values preserved | New major version for incompatible meanings. |
| JSON keys | Additive changes only | Major version for removals or semantic changes. |
| Database schema | Migration-only changes | Backward-compatible reader/writer during migration window. |
| Fault ids | Existing ids preserved | New ids are additive; removed ids require migration guidance. |
| Engine behavior | Built-ins remain available | Provider changes follow extension API versioning. |

## Deprecation policy

A deprecated command:

- Emits one warning to stderr when used.
- Names its replacement command in the warning.
- Appears in the migration report.
- Retains its current exit behavior until its removal milestone.
- Is removed only after usage data, documentation, and compatibility tests support removal.

## Review gates

- **Compatibility gate:** exact legacy commands, exit codes, and JSON fixtures pass.
- **Safety gate:** mutating commands cannot bypass preflight without explicit intent.
- **Evidence gate:** execution and recovery records are complete and redacted.
- **Runtime gate:** external runtime claims require separate authorization and live validation.
- **Documentation gate:** help text, CLI reference, product direction, and plan status agree.
