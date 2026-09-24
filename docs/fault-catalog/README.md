# Fault catalog documentation

The runtime-free reliability contract, coverage report, maturity policy, recommendations, and Plan 08 family status are documented in [`reliability-matrix.md`](reliability-matrix.md).

The current Kubernetes catalog snapshot is maintained at [`../reference/fault-catalog.md`](../reference/fault-catalog.md). Definitions are sourced from `src/mayhem/domain/catalog.py`; runtime status is sourced from `src/mayhem/controller/k8s_runtime.py`.

## Container and Kubernetes expansion

The approved expansion adds these executable IDs:

| Runtime | IDs |
|---------|-----|
| Container | `cpu.burst`, `mem.freeze`, `mem.swap_pressure`, `fs.quota`, `fs.write_delay`, `net.corrupt`, `net.congestion`, `process.restart_delay`, `http.upstream_timeout`, `app.response_5xx` |
| Kubernetes | `k8s.pod_restart_churn`, `k8s.sidecar_termination`, `k8s.workload_stall`, `k8s.service_5xx`, `k8s.dns_timeout`, `k8s.node_disk_pressure`, `k8s.node_memory_pressure`, `k8s.node_pid_pressure`, `k8s.hpa_oscillation`, `k8s.pdb_over_eviction` |

Each definition has bounded typed parameters, risk and duration, required capabilities, target kinds, maturity, observable effect, verification method, and compensation evidence. Container families use the existing payload/tool undo contracts. Kubernetes families use resolved pod/node targets and existing snapshot, workload, service, DNS, HPA, and PDB seams.

The unit and mock CLI suites verify deterministic injection, undo, refusal, and evidence contracts. They do not claim live Podman, Docker, kubectl, Minikube, or cluster verification; those runtimes are intentionally not invoked by the tests.
