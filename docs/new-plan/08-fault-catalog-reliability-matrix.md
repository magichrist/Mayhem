# Plan 08 — Fault Catalog Reliability Matrix

## Builder brief

Grow the fault catalog systematically instead of adding isolated ids. Every fault must express a reliability scenario, target abstraction, risk, parameter contract, observable effect, capability, compensation, verification, and documentation status. The matrix should make gaps visible to users and builder agents.

## Matrix dimensions

| Dimension | Required values |
|-----------|-----------------|
| Engine | Docker, Podman, Kubernetes, host, multi-engine |
| Failure domain | process, CPU, memory, storage, network, application, dependency, platform |
| Target | container, process, service, pod, workload, node, cluster object, external dependency |
| Risk | low, medium, high, critical |
| Reversibility | reversible, reconciled, irreversible with explicit policy |
| Evidence | planner decision, executor result, observation, recovery result |

## Phase 1 — Define the catalog contract and coverage model

### Work

- Add fault metadata for failure domain, target kind, engine lanes, observable effect, verification method, and maturity.
- Add catalog validation that rejects incomplete definitions.
- Add a generated coverage view by engine, domain, risk, and reversibility.
- Add a `fault explain ID` command showing parameters, target, capability, expected symptom, undo, and evidence.
- Mark catalog-only entries explicitly instead of hiding them.

### Files

- `src/mayhem/domain/faults.py`
- `src/mayhem/domain/catalog.py`
- `src/mayhem/cli/toolkit.py`
- `src/mayhem/infra/catalog_report.py`
- `tests/unit/test_fault_catalog_all.py`
- `tests/unit/test_fault_catalog_metadata.py`

### Verification

- Catalog tests validate every definition and generated matrix entry.
- CLI tests pin explain output for representative Docker and Kubernetes families.
- No external runtime is required.

## Phase 2 — Add the next reliability families

### Work

Implement a prioritized vertical batch rather than a large horizontal catalog expansion:

1. HTTP request shaping: timeout, 5xx responses, rate limit, connection reset.
2. Network path: jitter, packet loss, duplicate, reorder, partition, bandwidth.
3. Storage: read-only, inode pressure, delayed I/O, permission failure.
4. Process lifecycle: pause, graceful stop, kill, crash loop, startup delay.
5. Application dependencies: DNS failure, upstream timeout, connection refusal, malformed response.
6. Kubernetes control-plane families already represented in the current plan, with evidence and target context.

For every family, add catalog definition, planner validation, impact gate, executor, compensation, tests, docs, and CLI explanation.

### Verification

- Each family has a named observable symptom and a deterministic refusal path.
- Every reversible family has a fake-executor undo round trip.
- Full unit tests remain deterministic and isolated from live services.

## Phase 3 — Add maturity and recommendation policy

### Work

- Define maturity levels: `experimental`, `verified-unit`, `verified-live`, `stable`.
- Require explicit promotion criteria and a recorded verification date.
- Add catalog recommendations by target profile and user goal.
- Add a deprecation path for unsafe or platform-specific families.
- Add coverage reports to CI without requiring external runtimes.

### Acceptance criteria

- Users can see what is safe, supported, experimental, and unavailable for their engine.
- Builder agents receive a clear definition of done for adding a fault.
- Catalog growth improves decision quality rather than merely increasing the id count.

### Verification

- Run fault catalog, CLI, documentation, and full unit tests.
- Run Ruff and report the result without claiming green if the repository baseline remains nonzero.
