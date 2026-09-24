# Plan 07 — First-Class Kubernetes Engine

## Builder brief

Promote Kubernetes from an advanced seam to a coherent engine experience without pretending that source presence equals cluster acceptance. The user-facing contract must clearly separate manifest planning, live discovery, capability availability, execution, evidence, and refusal.

## Phase 1 — Define engine modes and target contexts

### Work

- Define Kubernetes engine modes: `manifest`, `live`, and `dry-run`.
- Define context selection using profile, explicit context, and namespace without relying on ambiguous flags.
- Add `discover kubernetes` with manifest inspection and live-readiness checks separated.
- Add target profile fields for context, namespace, workload selectors, and capability policy.
- Keep the legacy `KubernetesAdapter` compatibility seam but make its unavailable state visible in doctor output.

### Files

- `src/mayhem/agents/k8s_resolve.py`
- `src/mayhem/domain/k8s_adapter.py`
- `src/mayhem/topology/providers/k8s_manifest.py`
- `src/mayhem/topology/providers/kubernetes.py`
- `src/mayhem/cli/topology.py`
- `tests/unit/test_k8s_discovery.py`
- `tests/unit/test_k8s_cli.py`

### Verification

- Unit tests cover manifest, missing client, wrong context, namespace filtering, and blueprint placeholder behavior.
- No live cluster is contacted in unit tests.

## Phase 2 — Complete the Kubernetes fault execution contract

### Work

- Audit every Kubernetes catalog entry against a family matrix: workload, pod, node, service, storage, DNS, autoscaling, disruption, and image lifecycle.
- Require each family to have a target kind, capability, safety decision, executor or refusal, compensation, and evidence expectations.
- Add explicit support labels to `mayhem toolkit faults --engine kubernetes`.
- Reject catalog-only families from execution surfaces while keeping them visible for planning and education.
- Add a stable `k8s.unsupported` remediation path with missing capability/context details.

### Files

- `src/mayhem/domain/catalog.py`
- `src/mayhem/controller/k8s_runtime.py`
- `src/mayhem/agents/executors.py`
- `src/mayhem/controller/safety.py`
- `tests/unit/test_fault_catalog_all.py`
- `tests/unit/test_capability_safety.py`
- `tests/unit/test_k8s_plan1.py`
- `tests/unit/test_k8s_plan2.py`

### Verification

- Catalog and executor registers are compared by unit test.
- Every new family has a mocked inject/undo or explicit refusal test.
- No test claims live-cluster success.

## Phase 3 — Deliver Kubernetes preflight, run, and recovery UX

### Work

- Add Kubernetes-specific preflight sections: context, namespace, target scope, resolved pod/node, capability verdict, compensation, and wait strategy.
- Add `run --engine kubernetes --target NAME --execute`.
- Add `inspect run` evidence showing logical target versus resolved object and drift status.
- Add recovery guidance for node, workload, DNS, and service mutations.
- Add an authorization checklist for live validation; keep that checklist outside automated tests until explicitly approved.

### Acceptance criteria

- A user can tell whether Kubernetes is unavailable, merely unconfigured, capability-gated, or ready to execute.
- A dry run is complete and useful without a cluster.
- A live run has a clear evidence and recovery trail.

### Verification

- Run Kubernetes unit, CLI, safety, and documentation tests.
- Run Ruff only; do not run Minikube, kubectl, Podman, Docker, or E2E tests without explicit authorization.
