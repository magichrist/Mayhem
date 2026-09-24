# Mayhem CLI and product direction

## Product promise

Mayhem is a safe-by-construction chaos experimentation platform. It should make the safe path obvious, make the dangerous path explicit, and leave every run with enough evidence to explain what was planned, what changed, what was observed, and how the system recovered.

## Product experience

The CLI is progressive:

- **Guided:** `init`, `doctor`, discovery, and dry-run preflight help a new user reach a safe plan without understanding internals.
- **Precise:** named target profiles, explicit engine selection, typed plans, and stable flags support repeatability.
- **Automatable:** human output is the default, while JSON and future YAML output are stable machine contracts.
- **Expert-capable:** diagnostics, plan diffs, policy explanations, leases, raw evidence, and recovery remain available.

## Personas

| Persona | Primary need | Default path |
|---------|--------------|--------------|
| First-time experiment author | Safe starting point and clear next step | `init` → `doctor` → `prepare` → `plan` |
| SRE or incident responder | Diagnose impact, recovery, and residual risk | `inspect` → `recover` → `doctor` |
| Platform engineer | Repeatable policy, target profiles, and automation | `prepare` → `run --execute` → `inspect` |
| Builder agent | Stable contracts and evidence-rich implementation guides | `docs/new-plan/` and typed source contracts |

## Workflow map

| Workflow | User intent | Current command owner | Planned commands |
|----------|-------------|----------------------|------------------|
| `discover` | Understand targets, engines, and capabilities | `topology`, `toolkit` | `discover topology`, `discover engines`, `discover capabilities` |
| `prepare` | Make config, dependencies, and a plan executable | `config`, `dependency`, `plan` | `prepare config`, `prepare dependencies`, `prepare plan` |
| `experiment` | Author, inspect, validate, and diff experiments | `experiment`, `validate` | `experiment show`, `experiment validate`, `experiment diff` |
| `run` | Execute an approved plan | `run`, `maniac`, `campaign run` | `run plan`, `run execute` |
| `inspect` | Inspect runs, coverage, history, and evidence | `status`, `history`, `coverage`, `next`, `expert` | `inspect runs`, `inspect run`, `inspect coverage`, `inspect doctor` |
| `recover` | Restore leases and report dirty state | `recover`, `janitor` | `recover plan`, `recover execute`, `recover status` |
| `extend` | Inspect and extend the fault/provider system | `toolkit`, `dependency` | `extend faults`, `extend providers`, `extend dependencies` |

The workflow command tree is implemented with compatibility-preserving legacy aliases. Existing commands remain supported during the migration window.

## Core terminology

- **Logical target:** the stable thing the user wants to perturb, such as a workload or container.
- **Resolved runtime object:** the concrete object selected at execution time, such as a running pod or process.
- **Fault:** a typed, bounded failure scenario with parameters, risk, capability requirements, observable effect, and recovery semantics.
- **Plan:** an immutable, safety-checked description of intended execution.
- **Lease:** a durable ownership record for an injected fault and its compensation.
- **Run:** one execution of a plan with lifecycle, observations, and verdict.
- **Evidence:** the complete record connecting plan, safety decisions, leases, observations, recovery, and limitations.
- **Target profile:** a named environment definition selecting engine, target locator, policy, and safe defaults.

## Product outcomes

The roadmap is successful when:

- A new user reaches a safe first plan in one guided command sequence.
- Every public command has a documented human and machine output contract.
- Every advertised fault has typed parameters, an observable effect, safety metadata, compensation or explicit reconciliation, and unit evidence.
- A plan identifies the exact logical target and environment fingerprint used for execution.
- An operator can inspect, explain, and recover a run without reading source code.
- Kubernetes support clearly distinguishes offline manifest planning, live discovery, capability availability, execution, and refusal.
- Legacy scripts continue to work during the migration window.

## Non-goals

This direction does not promise live-cluster acceptance from mocked tests, remove the existing domain/controller/agent boundaries, or make a catalog entry executable without a safety and compensation contract.
