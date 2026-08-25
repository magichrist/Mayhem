# 0014. Execution Context Model

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0005](0005-recovery-model-lease-journal-janitor.md) (lease lifecycle), [ADR-0012](0012-safety-gates-inventory.md) (safety gates)

## Context

Before this ADR, a fault's *where* was implicit — the planner resolved targets from selectors and the executor ran the fault wherever those targets lived. This worked for simple host-level faults but cannot support container-level execution, network-namespace isolation, or remote-host injection where the execution *location* differs from the target *identity*.

## Decision

Every fault may declare an optional `ExecutionContextSpec` that names where the fault runs:

| Context | Meaning |
|---|---|
| `host` | Run on the host OS |
| `container` | Run inside a container |
| `process` | Run as a process signal/injection |
| `network_namespace` | Run in an isolated network namespace |
| `remote_host` | Run on a different host |
| `remote_container` | Run inside a container on a different host |

**Compatibility matrix:** Each context is compatible with a subset of topology `NodeKind` values. The planner uses this to reject impossible combinations before execution.

**Backward compatibility:** The field is optional. When absent, the planner infers context from the target node kind (pre-0.2.0 behavior).

**Safety gate G4:** The safety engine validates execution context compatibility during plan validation, preventing accidental host-level execution when container-level was intended.

## Consequences

- The spec file gains an optional `execution:` block inside `inject_fault` steps.
- The planner propagates context to `PlannedFault.execution_context`.
- The safety engine rejects plans with incompatible contexts (G4).
- No runtime behavior change for experiments that omit the field.
