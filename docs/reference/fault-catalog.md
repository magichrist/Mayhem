# Kubernetes fault catalog reference

The executable source of truth is [`src/mayhem/domain/catalog.py`](../../src/mayhem/domain/catalog.py) together with the Kubernetes runtime registers in [`src/mayhem/controller/k8s_runtime.py`](../../src/mayhem/controller/k8s_runtime.py). The table below is the current checked-in status snapshot.

`executable` means the fault is in the Kubernetes executor dispatch register. It does not mean that a live cluster is reachable or that the required capability is present. `catalog-only` means the definition is schema-valid and plannable but has no executable dispatch.

| Fault | Risk | Status |
|-------|------|--------|
| `k8s.node_pressure` | high | executable |
| `k8s.pod_oom` | medium | executable |
| `k8s.pod_pressure` | medium | executable |
| `k8s.network_policy` | high | executable |
| `k8s.pod_latency` | medium | executable |
| `k8s.pod_partition` | high | executable |
| `k8s.pod_evict` | high | executable |
| `k8s.pod_kill` | high | executable |
| `k8s.node_drain` | critical | executable |
| `k8s.pod_readiness_fail` | medium | executable |
| `k8s.pod_liveness_fail` | medium | executable |
| `k8s.pod_startup_fail` | medium | executable |
| `k8s.pod_unschedulable` | high | executable |
| `k8s.schedule_delay` | medium | executable |
| `k8s.image_pull_failure` | high | executable |
| `k8s.image_pull_slow` | medium | catalog-only |
| `k8s.replica_reduce` | high | executable |
| `k8s.rollout_pause` | medium | executable |
| `k8s.rollout_failure` | high | executable |
| `k8s.pod_delete_uncontrolled` | high | executable |
| `k8s.service_no_endpoints` | high | executable |
| `k8s.service_endpoint_flap` | high | executable |
| `k8s.service_port_mismatch` | high | executable |
| `k8s.configmap_corrupt` | high | executable |
| `k8s.secret_unavailable` | high | executable |
| `k8s.persistent_volume_delay` | high | executable |
| `k8s.persistent_volume_error` | high | executable |
| `k8s.persistent_volume_detach` | critical | executable |
| `k8s.node_not_ready` | high | executable |
| `k8s.pod_crash_loop` | high | executable |
| `k8s.pod_pending` | high | executable |
| `k8s.node_network_partition` | critical | executable |
| `k8s.deployment_scale_failure` | high | executable |
| `k8s.statefulset_scale_failure` | high | executable |
| `k8s.resource_quota_exhaust` | high | executable |
| `k8s.persistent_volume_mount_failure` | high | executable |
| `k8s.persistent_volume_claim_pending` | high | executable |
| `k8s.kube_proxy_failure` | critical | executable |
| `k8s.pod_image_pull_delay` | medium | executable |
| `k8s.container_termination_delay` | medium | executable |
| `k8s.preemption_failure` | high | executable |
| `k8s.pdb_violation` | high | executable |
| `k8s.eviction_block` | medium | executable |
| `k8s.dns_failure` | high | executable |
| `k8s.dns_delay` | medium | executable |
| `k8s.service_dns_mismatch` | high | executable |
| `k8s.hpa_scale_delay` | medium | executable |
| `k8s.hpa_scale_failure` | high | executable |
| `k8s.node_cordon` | medium | executable |
| `k8s.taint_evict` | high | executable |
| `k8s.nvidia_smi_error` | high | executable |
| `k8s.crash_loop` | high | executable |
| `k8s.pod_restart_churn` | high | executable |
| `k8s.sidecar_termination` | high | executable, reconciled |
| `k8s.workload_stall` | high | executable |
| `k8s.service_5xx` | medium | executable |
| `k8s.dns_timeout` | medium | executable, DNS_CONTROL |
| `k8s.node_disk_pressure` | high | executable, node target |
| `k8s.node_memory_pressure` | high | executable, node target |
| `k8s.node_pid_pressure` | high | executable, node target |
| `k8s.hpa_oscillation` | medium | executable, HPA/workload target |
| `k8s.pdb_over_eviction` | high | executable, PDB/workload target |

## Capability gates

- Critical faults require the existing policy and CLI critical acknowledgement path.
- Node-control families refuse with `k8s.unsupported` when `NODE_CONTROL` is unavailable.
- DNS families refuse with `k8s.unsupported` when `DNS_CONTROL` is unavailable.
- Network-namespace families refuse when the runtime capability matrix does not report `NETNS`.
- Unavailable resources, missing workloads, missing annotations, and failed snapshots return explicit failure outcomes.

## Compensation

Mutable Kubernetes families use the executor lease and restore annotation contract. The owning workload, object, node worker, or CoreDNS ConfigMap carries the evidence needed to undo the mutation. Unit tests use fake Kubernetes clients and tool runners; they do not establish live-cluster acceptance.
