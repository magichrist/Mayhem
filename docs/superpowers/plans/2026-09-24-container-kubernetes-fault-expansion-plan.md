# Container and Kubernetes Fault Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 10 new executable Podman/container faults and 10 new executable Kubernetes faults with catalog metadata, safety, compensation, evidence, and deterministic mock tests.

**Architecture:** Extend the existing fault catalog and executor registries rather than creating a parallel runtime. Container faults use existing process/payload/network compensation seams, with focused handlers for HTTP and restart behavior. Kubernetes faults use existing pod/workload/service/node/HPA/PDB executors and snapshot-based compensation, with explicit target-kind routing.

**Tech Stack:** Python 3.12, Pydantic v2, Click CLI, pytest, Ruff, existing fake executor seams.

## Global Constraints

- Do not run Podman, Docker, kubectl, Minikube, E2E infrastructure, or any live cluster command.
- Preserve existing command names, exit codes, JSON keys, database schema, and legacy catalog IDs.
- Add only typed, validated parameters; reject unknown or secret-bearing values.
- Every new fault must have typed parameters, risk, duration, capabilities, target kinds, observable effect, compensation evidence, and maturity metadata.
- No inline code comments may be added.
- Run unit tests, the existing 100-case mock CLI E2E suite, and Ruff only.

---

## File Map

- Modify `src/mayhem/domain/catalog.py`: add 20 `FaultDefinition` entries and matrix metadata.
- Modify `src/mayhem/agents/executors.py`: add container and Kubernetes executor routing and focused mutation methods.
- Modify `src/mayhem/controller/k8s_runtime.py`: register Kubernetes IDs, family contracts, target routing, and undo operations.
- Modify `src/mayhem/controller/compensation.py`: add compensation templates/operations for new fault IDs.
- Modify `src/mayhem/domain/faults.py`: extend metadata validation if new maturity/observable fields require it.
- Modify `src/mayhem/cli/toolkit.py`: ensure new fault explanations and coverage expose the new IDs.
- Create `tests/unit/test_fault_expansion_catalog.py`: exact 20-ID catalog and parameter contract tests.
- Create `tests/unit/test_fault_expansion_container.py`: fake inject/undo/refusal tests for the 10 container IDs.
- Create `tests/unit/test_fault_expansion_kubernetes.py`: fake inject/undo/refusal tests for the 10 Kubernetes IDs.
- Modify `docs/reference/cli.md` and `docs/fault-catalog/`: document the new families and live-validation limitations.

---

### Task 1: Add the 20 catalog definitions

**Files:**
- Modify: `src/mayhem/domain/catalog.py`
- Modify: `src/mayhem/domain/faults.py`
- Test: `tests/unit/test_fault_expansion_catalog.py`

**Interfaces:**
- Produces: `definition_for()` entries for the 20 IDs in the design spec.
- Consumes: existing `FaultDefinition`, `ParamSpec`, `RiskLevel`, `CapabilityKind`, and catalog validation helpers.

- [ ] **Step 1: Write failing catalog tests**

Create tests that assert these exact IDs exist, are not `catalog_only`, have unique parameter names, and accept only typed parameters:

```python
CONTAINER_IDS = (
    "cpu.burst", "mem.freeze", "mem.swap_pressure", "fs.quota", "fs.write_delay",
    "net.corrupt", "net.congestion", "process.restart_delay",
    "http.upstream_timeout", "app.response_5xx",
)
K8S_IDS = (
    "k8s.pod_restart_churn", "k8s.sidecar_termination", "k8s.workload_stall",
    "k8s.service_5xx", "k8s.dns_timeout", "k8s.node_disk_pressure",
    "k8s.node_memory_pressure", "k8s.node_pid_pressure",
    "k8s.hpa_oscillation", "k8s.pdb_over_eviction",
)
```

For every definition assert `risk in RiskLevel`, `max_duration_s > 0`, `reversible is not None`, and `params_schema` names are unique. Assert the exact target-kind set for Kubernetes node, pod, service, workload, HPA, and PDB families.

- [ ] **Step 2: Run the focused tests and verify the expected failure**

Run: `python3 -m pytest tests/unit/test_fault_expansion_catalog.py -q`

Expected: failures for each missing `definition_for()` ID.

- [ ] **Step 3: Add catalog definitions**

Use the existing `FaultDefinition` constructor. Use these exact families and target kinds:

| ID family | Target kinds | Risk | Reversibility |
|---|---|---|---|
| `cpu.burst` | container, process | medium | reversible |
| `mem.freeze`, `mem.swap_pressure` | container, process | high | reversible |
| `fs.quota`, `fs.write_delay` | container, process | medium | reversible |
| `net.corrupt`, `net.congestion` | container, process, service | medium | reversible |
| `process.restart_delay` | container, process | high | reconciled |
| `http.upstream_timeout`, `app.response_5xx` | service, container, external dependency | medium | reversible |
| `k8s.pod_restart_churn`, `k8s.sidecar_termination` | pod | high | reconciled |
| `k8s.workload_stall` | workload, pod | high | reversible |
| `k8s.service_5xx`, `k8s.dns_timeout` | service, pod | medium | reversible |
| `k8s.node_disk_pressure`, `k8s.node_memory_pressure`, `k8s.node_pid_pressure` | k8s node | high | reversible |
| `k8s.hpa_oscillation` | workload, HPA target | medium | reversible |
| `k8s.pdb_over_eviction` | workload, pod, PDB target | high | reversible |

Use typed parameters with bounded ranges: integer percentages/counts, durations, byte sizes, and non-empty strings for service/endpoint names. Do not add free-form command or credential fields.

- [ ] **Step 4: Run catalog and whole-catalog tests**

Run: `python3 -m pytest tests/unit/test_fault_expansion_catalog.py tests/unit/test_fault_catalog_all.py tests/unit/test_fault_catalog_metadata.py -q`

Expected: PASS.

---

### Task 2: Implement the 10 container/Podman executor paths

**Files:**
- Modify: `src/mayhem/agents/executors.py`
- Modify: `src/mayhem/controller/compensation.py`
- Test: `tests/unit/test_fault_expansion_container.py`

**Interfaces:**
- Consumes: existing `executor_for()`, `PayloadExecutor`, `ProcPauseExecutor`, `StepOutcome`, and `compensated()`.
- Produces: executor resolution and deterministic inject/undo behavior for all `CONTAINER_IDS`.

- [ ] **Step 1: Write fake-executor tests**

For each `CONTAINER_IDS` entry, create a fake lease and tool result seam, call `executor_for(fault_id, runtime)`, then assert inject and undo outcomes. Assert that these IDs use the expected primitive families: CPU/memory/filesystem/network route through the existing payload compiler, process restart routes through the runtime executor, and HTTP/app faults route through a deterministic request/response seam.

Add refusal assertions for missing required capability and for an unsupported runtime.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python3 -m pytest tests/unit/test_fault_expansion_container.py -q`

Expected: failures until the new IDs are registered.

- [ ] **Step 3: Add executor mappings and parameter compilation**

Extend the existing registry mappings:

```python
_CONTAINER_EXECUTOR_ALIASES = {
    "cpu.burst": "cpu.saturate",
    "mem.freeze": "mem.exhaust",
    "mem.swap_pressure": "mem.exhaust",
    "fs.quota": "fs.fill",
    "fs.write_delay": "fs.io_stress",
    "net.corrupt": "net.partition",
    "net.congestion": "net.latency",
    "process.restart_delay": "process.crash_loop",
    "http.upstream_timeout": "http.error_injection",
    "app.response_5xx": "http.error_injection",
}
```

Implement focused argument/response handling for `http.upstream_timeout`, `app.response_5xx`, and `process.restart_delay`; do not merely rename existing catalog IDs. Keep the original parameter values in the lease and use them to construct the deterministic mutation command.

Add compensation templates for every new container ID. Reversible IDs must restore the prior runtime/network/filesystem state; `process.restart_delay` must expose a reconciled/no-live-undo marker.

- [ ] **Step 4: Run focused and existing executor tests**

Run: `python3 -m pytest tests/unit/test_fault_expansion_container.py tests/unit/test_compensation.py tests/unit/test_fault_catalog_all.py -q`

Expected: PASS.

---

### Task 3: Implement the 10 Kubernetes executor and compensation paths

**Files:**
- Modify: `src/mayhem/agents/executors.py`
- Modify: `src/mayhem/controller/k8s_runtime.py`
- Modify: `src/mayhem/controller/compensation.py`
- Test: `tests/unit/test_fault_expansion_kubernetes.py`

**Interfaces:**
- Consumes: `ResolvedPodTarget`, `ResolvedNodeTarget`, `k8s_executor_for()`, `K8sWorkloadExecutor`, `K8sServiceExecutor`, `K8sNode*Executor`, `K8sHpaExecutor`, and `k8s_undo_ops_for()`.
- Produces: `k8s_executor_for()` and `k8s_undo_ops_for()` support for all `K8S_IDS`.

- [ ] **Step 1: Write fake Kubernetes tests**

Use the existing fake Kubernetes object/client seams to test:

- pod restart churn and sidecar termination against a `ResolvedPodTarget`;
- workload stall against a workload target and a pod fallback;
- service 5xx and DNS timeout against service/pod targets;
- node disk, memory, and PID pressure against a `ResolvedNodeTarget`;
- HPA oscillation against an HPA/workload target;
- PDB over-eviction against a workload/PDB target.

For each supported ID assert snapshot capture before mutation, deterministic fake mutation, and restore during undo. For each target-kind mismatch assert a typed `k8s.unsupported` refusal.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python3 -m pytest tests/unit/test_fault_expansion_kubernetes.py -q`

Expected: failures for missing registry/family entries.

- [ ] **Step 3: Add family contracts and executor routing**

Add the exact IDs to the existing Kubernetes mutation/reversible/family maps. Route:

```python
_K8S_ROUTES = {
    "k8s.pod_restart_churn": "workload",
    "k8s.sidecar_termination": "workload",
    "k8s.workload_stall": "workload",
    "k8s.service_5xx": "service",
    "k8s.dns_timeout": "service",
    "k8s.node_disk_pressure": "node",
    "k8s.node_memory_pressure": "node",
    "k8s.node_pid_pressure": "node",
    "k8s.hpa_oscillation": "hpa",
    "k8s.pdb_over_eviction": "disruption",
}
```

Use existing snapshot annotation and undo operation mechanisms. For pressure and oscillation faults, use bounded parameters and deterministic patch payloads. For PDB over-eviction, restore the original PDB and workload state exactly.

- [ ] **Step 4: Run focused and existing Kubernetes tests**

Run: `python3 -m pytest tests/unit/test_fault_expansion_kubernetes.py tests/unit/test_kplan6_runtime.py tests/unit/test_k8s_plan1.py tests/unit/test_k8s_plan2.py -q`

Expected: PASS.

---

### Task 4: Documentation, whole-catalog verification, and mock E2E regression

**Files:**
- Modify: `docs/reference/cli.md`
- Modify: `docs/fault-catalog/` matrix/explanation documents
- Test: existing `tests/e2e/test_cli_e2e.py`

- [ ] **Step 1: Add catalog explanation and coverage assertions**

Update the fault matrix and CLI toolkit explanation so the 20 new IDs show engine lane, target kind, risk, maturity, compensation, and verification method. State that unit-verified behavior is not live-cluster verified.

- [ ] **Step 2: Run the whole catalog and focused suites**

Run: `python3 -m pytest tests/unit/test_fault_expansion_catalog.py tests/unit/test_fault_expansion_container.py tests/unit/test_fault_expansion_kubernetes.py tests/unit/test_fault_catalog_all.py -q`

Expected: PASS.

- [ ] **Step 3: Run the full unit suite**

Run: `python3 -m pytest tests/unit/ -q`

Expected: all unit tests pass.

- [ ] **Step 4: Run the existing 100-case mock CLI E2E suite**

Run: `python3 -m pytest tests/e2e/ -q`

Expected: `100 passed`.

- [ ] **Step 5: Run Ruff on changed source and test files**

Run: `ruff check src/mayhem/domain/catalog.py src/mayhem/domain/faults.py src/mayhem/agents/executors.py src/mayhem/controller/k8s_runtime.py src/mayhem/controller/compensation.py tests/unit/test_fault_expansion_catalog.py tests/unit/test_fault_expansion_container.py tests/unit/test_fault_expansion_kubernetes.py tests/e2e/test_cli_e2e.py`

Expected: `All checks passed!`.

- [ ] **Step 6: Verify no prohibited runtime commands ran**

Review shell/test output and confirm no `kubectl`, `minikube`, Docker, Podman, or live cluster command was invoked. Do not claim live behavior from the mock results.
