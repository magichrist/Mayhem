# Plan 06 — Docker/Podman Reliability Slice

## Builder brief

Deliver the first complete end-to-end product slice for Docker and Podman. The goal is not to add every possible container fault; it is to make one realistic user journey excellent: discover topology, prepare dependencies, plan safely, execute a reversible fault, inspect evidence, and recover.

## Phase 1 — Make engine selection and discovery coherent

### Work

- Implement a shared engine descriptor for Docker and Podman: name, binary detection, compose support, process signals, network capabilities, and storage capabilities.
- Add engine auto-detection with explicit override and ambiguity refusal.
- Normalize topology output so Docker and Podman use the same logical node and target vocabulary.
- Add `discover engines` and `discover topology` views.
- Preserve the `discover topology` view, `--podman`, and compose flags.

### Files

- `src/mayhem/domain/runtime_adapter.py`
- `src/mayhem/topology/providers/docker_runtime.py`
- `src/mayhem/topology/providers/podman_adapter.py`
- `src/mayhem/cli/topology.py`
- `tests/unit/test_topology_providers.py`
- `tests/unit/test_cli_topology.py`

### Verification

- Unit tests use fake subprocess/tool seams; no Docker or Podman process is started.
- Both engines produce the same normalized logical topology shape.
- Ambiguous engine detection produces a remediation error.

## Phase 2 — Complete the reversible fault journey

### Work

- Select a small reliability matrix: process pause/stop, CPU stress, memory pressure, network latency/loss, filesystem pressure, HTTP load, and one irreversible-but-reconciled process fault.
- For each family, require typed parameters, risk, capability, max duration, observable effect, and compensation evidence.
- Add one `prepare dependencies` workflow for missing binaries/packages.
- Add plan output that shows dependency gaps and target fit before execution.

### Files

- `src/mayhem/domain/catalog.py`
- `src/mayhem/agents/executors.py`
- `src/mayhem/controller/compensation.py`
- `src/mayhem/cli/dependency.py`
- `tests/unit/test_container_fault_matrix.py`
- `tests/unit/test_compensation.py`

### Verification

- Every matrix family has a passing fake-executor inject/undo test.
- Unsupported tools produce a stable refusal, not a false success.
- No external runtime is required for the test suite.

## Phase 3 — Ship the operator experience

### Work

- Add `discover`, `prepare`, `run --execute`, `inspect run`, and `recover run` examples for Docker/Podman.
- Add a concise run summary with affected services, observed symptoms, recovery status, and next recommended action.
- Add engine-specific remediation text for missing compose, permission, binary, and capability problems.
- Record engine version and topology fingerprint in evidence.
- Add a Docker/Podman example that is safe by default and never auto-runs.

### Acceptance criteria

- A new user can go from project files to a safe plan with guided output.
- An operator can recover and explain a completed run without inspecting source code.
- Engine differences are visible but do not fragment the workflow.

### Verification

- Full unit suite, documentation consistency, example schema tests, and Ruff.
- External container execution remains outside automated verification and is explicitly labeled unverified.
