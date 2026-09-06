# Kubernetes drill example (planning-only)

This directory is the **forward-looking Kubernetes example** for the Mayhem
fault catalog's `k8s.*` family. It pairs a declarative Kubernetes blueprint
(`kubernetes.yaml`) with a `kind: drill` spec (`mayhem.yaml`) that exercises
the nine `k8s.*` faults.

> **Status: planning-only (ADR-M7 / M8).** Kubernetes execution is
> interface-only in the current milestone. The `KubernetesAdapter` contract
> exists as a stable seam (`mayhem.domain.k8s_adapter`), but **no live-cluster
> fault injection driver is wired yet**. The planner and the `SafetyRefusedError`
> gate (`k8s.unsupported`) deliberately refuse a plan that targets `pod` /
> `k8s_node` kinds until that driver lands. This spec is therefore **not yet
> runnable** — it documents *how* the `k8s.*` faults are expressed so every
> catalog fault has an example, and it becomes executable when M8 is completed.

The nine Kubernetes faults are the only catalog entries not exercisable against
a Docker/Podman compose blueprint (they require `kubernetes_engine` and
`pod`/`k8s_node` node kinds):

- `k8s.network_policy`
- `k8s.node_drain`
- `k8s.node_pressure`
- `k8s.pod_evict`
- `k8s.pod_kill`
- `k8s.pod_latency`
- `k8s.pod_oom`
- `k8s.pod_partition`
- `k8s.pod_pressure`

Every other fault in the catalog is exercised against the compose example in
[`examples/testCase/mayhem.yaml`](../testCase/mayhem.yaml).
