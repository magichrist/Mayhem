# v0.9.0 Release Roadmap

## Release objective

Ship a release that is safe to install, predictable to automate, honest about runtime capabilities, and useful for controlled local rehearsals before expanding to live conformance.

## Phase 0: Truth baseline

### Deliverables

- Inventory the active command registry and make docs, Justfile recipes, examples, and output schemas agree.
- Remove stale version, Kubernetes extra, and fallback-version references.
- Define v0.9.0 compatibility boundaries for CLI commands, exit codes, output schemas, fault IDs, provider contracts, and SQLite migrations.
- Add a capability status vocabulary and a generated capability matrix.

### Exit gate

- One command reference is generated or checked against the executable registry.
- No release documentation claims a live status without a conformance artifact.
- Packaging metadata and runtime dependency documentation agree.

## Phase 1: Safe execution foundation

### Deliverables

- Add `RuntimeContext` and propagate it through planning and execution.
- Add `ExecutionIntent` and require it for all mutating commands.
- Make target profiles first-class in `mayhem.yaml`.
- Add plan diff and approval token persistence.
- Reject ambiguous engine, target, namespace, and policy state before mutation.

### Exit gate

- A preview cannot mutate a target.
- A plan cannot execute under a different engine/target/policy than approved.
- A missing or expired approval token refuses deterministically.
- The full unit suite and a plan/execute/recover happy path pass.

## Phase 2: Evidence and recovery

### Deliverables

- Add replay capsules and deterministic dry-run validation.
- Add redacted evidence persistence and degraded-evidence status.
- Add proof-of-recovery and residual-impact states.
- Add campaign checkpoint/resume state.
- Add before/after topology and health comparison.

### Exit gate

- Every completed run has mutation, compensation, verification, and evidence states.
- Interrupted runs can be inspected and safely resumed or recovered.
- A replay capsule validates without live mutation.

## Phase 3: Runtime truth and conformance

### Deliverables

- Add typed executor admission for pod, node, container, service, and workload targets.
- Separate catalog registration, unit verification, and live conformance.
- Add opt-in Docker/Podman conformance profiles.
- Add Kubernetes manifest/dry-run conformance and separately authorized live conformance.
- Fix no-backend action outcomes and remove the legacy unavailable Kubernetes adapter path.

### Exit gate

- No known target-type mismatch reaches a lease or tool invocation.
- `live_verified` is impossible without a dated conformance artifact.
- Conformance failures identify environment, runtime, fault, and evidence path.

## Phase 4: Operator experience

### Deliverables

- Add capability truth dashboard and `discover capabilities --explain`.
- Add Resilience Coverage Graph.
- Add SLO-aware success criteria through provider-neutral observation contracts.
- Add scenario variables, time windows, and conditional branches.
- Add game-day mode with approvals, freeze windows, and operator acknowledgement.

### Exit gate

- An operator can move from goal to reviewed plan to campaign to evidence without editing internal JSON.
- Every recommendation explains why a fault was selected or excluded.
- Campaign resume never repeats a completed mutation without an explicit retry decision.

## Phase 5: Ecosystem and release hardening

### Deliverables

- Add OpenTelemetry spans and read-only Prometheus/Loki connectors.
- Add signed evidence bundle and independent verifier.
- Add provider sandbox and permission enforcement.
- Add remote agent mTLS/reconnect profile only after local execution is stable.
- Add SBOM, checksums, signed artifacts, PR CI, and security scans.

### Exit gate

- A clean checkout can build, install, test, and verify artifacts without hidden local state.
- Provider and agent permissions are enforced by tests, not documentation alone.
- Release evidence includes provenance and a reproducible verification command.

## Dependency graph

```text
Truth baseline
      |
      v
Runtime context -> Execution intent -> Target profiles -> Plan approval
      |                 |                 |                |
      +-----------------+-----------------+----------------+
                                |
                                v
                       Evidence and recovery
                                |
                                v
                       Conformance and capability truth
                                |
                                v
                       Operator workflows and ecosystem
```

## Release slices

| Slice | Outcome | Risk | Release disposition |
|---|---|---:|---|
| A | Truth baseline | Low | Required |
| B | Safe execution foundation | Medium | Required |
| C | Evidence/recovery | Medium | Required |
| D | Runtime conformance | High | Required for live claims |
| E | Operator experience | Medium | Required for product differentiation |
| F | Ecosystem integrations | High | Optional post-0.9.0 or preview |

## Explicitly deferred

- Hosted multi-tenant SaaS.
- Autonomous fault selection with mutation authority.
- Broad remote-agent mesh.
- Marketplace monetization.
- New fault families beyond a small set enabled by the new evidence and admission contracts.
