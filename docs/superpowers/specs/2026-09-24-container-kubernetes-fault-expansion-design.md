# Container and Kubernetes Fault Expansion Design

## Goal

Add 10 new Podman/container faults and 10 new Kubernetes faults with real planner and executor paths, compensation metadata, safety decisions, evidence support, and deterministic unit tests. The implementation must not require Podman, Docker, kubectl, Minikube, or a live cluster.

## Scope

### Container and Podman

- `cpu.burst`
- `mem.freeze`
- `mem.swap_pressure`
- `fs.quota`
- `fs.write_delay`
- `net.corrupt`
- `net.congestion`
- `process.restart_delay`
- `http.upstream_timeout`
- `app.response_5xx`

These faults target containers, processes, or service workloads and use the existing container-runtime, payload, network, and compensation seams. New IDs are distinct catalog entries; existing IDs and JSON behavior are unchanged.

### Kubernetes

- `k8s.pod_restart_churn`
- `k8s.sidecar_termination`
- `k8s.workload_stall`
- `k8s.service_5xx`
- `k8s.dns_timeout`
- `k8s.node_disk_pressure`
- `k8s.node_memory_pressure`
- `k8s.node_pid_pressure`
- `k8s.hpa_oscillation`
- `k8s.pdb_over_eviction`

Pod, workload, service, DNS, node-pressure, autoscaling, and disruption families must select the correct resolved target kind. Every entry has an executor or a typed refusal, explicit compensation behavior, and evidence expectations.

## Architecture

1. Extend the catalog definitions with typed parameter schemas, risk, duration, capability requirements, target kinds, maturity, observable effects, and compensation evidence.
2. Extend executor registries with stable ID-to-executor mappings.
3. Reuse proven primitives for CPU, memory, filesystem, network, and process mutations. Add focused executor methods for HTTP response shaping, restart cadence, Kubernetes workload/service/DNS mutations, node pressure, HPA oscillation, and PDB behavior.
4. Keep target resolution, safety validation, lease acquisition, and undo operations in the existing domain/controller/agent boundaries.
5. Emit stable evidence fields for the logical target, resolved target, fault parameters, injection result, observation, and recovery result.

## Safety and failure behavior

- Existing safety gates remain authoritative.
- Unsupported capabilities, unavailable engines, stale targets, and undeclared permissions return typed refusals before mutation.
- Reversible faults restore their original state. Irreconciled faults use the existing no-undo or handoff markers and are visible in evidence.
- No secret values or credentials are accepted as fault parameters.
- Existing exit codes and command JSON fields remain unchanged; additions are additive only.

## Testing

- Add catalog tests for all 20 new definitions and parameter validation.
- Add fake-executor inject/undo tests for each container fault and each Kubernetes fault family.
- Add refusal tests for missing capabilities, unavailable Kubernetes context, and non-executable target kinds.
- Add evidence and compensation completeness assertions.
- Run the full unit suite, existing 100-case mock CLI E2E suite, and Ruff. No external runtime or E2E cluster command is permitted.
