# Fault catalog reliability matrix

The catalog contract is defined by `FaultDefinition` in `src/mayhem/domain/faults.py` and enforced by `validate_catalog` in `src/mayhem/domain/catalog.py`. Every definition carries a failure domain, target kind set, engine lanes, observable effect, verification method, reversibility, maturity, and verification date. The singular `target_kind` remains the execution anchor for compatibility; `target_kinds` records the complete approved routing set.

## Coverage

Generate a runtime-free coverage report with:

```bash
mayhem discover faults --coverage --json
```

The report is grouped by engine, failure domain, risk, reversibility, and maturity. It is generated from catalog metadata and does not probe Docker, Podman, Kubernetes, or any other external runtime.

## Explanations

Explain a definition without planning or executing it:

```bash
mayhem discover faults -e proc.pause
mayhem discover faults -e k8s.image_pull_slow --engine kubernetes
```

The explanation includes parameters, target, capability, observable effect, verification method, undo or refusal, evidence, maturity, and deprecation path.

## Reliability families

The prioritized batch uses existing IDs where the repository already has a truthful executor and compensation contract:

| Family | Catalog IDs |
|--------|-------------|
| HTTP request shaping | `http.latency`, `http.error_injection`, `dependency.rate_limit`, `net.connection_reset` |
| Network path | `net.latency`, `net.packet_loss`, `net.duplicate`, `net.reorder`, `net.partition`, `net.bandwidth` |
| Storage | `fs.read_only`, `fs.inode_exhaust`, `fs.io_stress`, `fs.permission_failure` |
| Process lifecycle | `proc.pause`, `process.stop`, `process.kill`, `process.crash_loop`, `process.startup_delay` |
| Application dependencies | `dns.timeout`, `dependency.timeout`, `dependency.connection_refuse`, `dependency.malformed_response` |
| Kubernetes control plane | `k8s.*` families in `docs/reference/fault-catalog.md` |
| Container expansion | `cpu.burst`, `mem.freeze`, `mem.swap_pressure`, `fs.quota`, `fs.write_delay`, `net.corrupt`, `net.congestion`, `process.restart_delay`, `http.upstream_timeout`, `app.response_5xx` |
| Kubernetes expansion | `k8s.pod_restart_churn`, `k8s.sidecar_termination`, `k8s.workload_stall`, `k8s.service_5xx`, `k8s.dns_timeout`, `k8s.node_disk_pressure`, `k8s.node_memory_pressure`, `k8s.node_pid_pressure`, `k8s.hpa_oscillation`, `k8s.pdb_over_eviction` |

`fs.permission_failure`, `process.startup_delay`, and `dependency.malformed_response` are catalog-only entries. They have complete metadata and deterministic planner refusal; Mayhem does not claim an executor for them until a capability-aware implementation exists. `k8s.image_pull_slow` follows the same catalog-only policy. The 20 expansion IDs are executable and carry typed refusal and compensation contracts, but their maturity remains unit-verified rather than live-verified.

## Maturity

Maturity levels are `experimental`, `verified-unit`, `verified-live`, and `stable`.

- `experimental`: metadata is complete, planner validation is deterministic, and unsupported execution refuses safely.
- `verified-unit`: all experimental criteria pass and deterministic unit tests cover parameters, refusal, and compensation.
- `verified-live`: a supported live runtime completed injection and recovery with recorded evidence.
- `stable`: the supported engine and platform matrix is verified and rollback/deprecation policy is documented.

Only non-catalog-only definitions with unit coverage are currently marked `verified-unit`; the catalog does not claim live or stable verification without recorded runtime evidence.

## Recommendations

`mayhem.infra.catalog_report.recommend_faults` ranks executable families for a target profile and user goal. Supported goals are availability, latency, network-resilience, storage-resilience, process-lifecycle, dependency-resilience, and recovery. Recommendations never return catalog-only or unavailable families.

## Deprecation

Platform-specific or unsafe families remain catalog-only until a replacement runtime is verified. The explanation includes the current refusal and migration path. `k8s.image_pull_slow` is retained as a catalog-only registry-pacing archetype and points to `k8s.image_pull_failure` when deterministic pull failure is sufficient; it is not presented as supported latency shaping.

## Builder definition of done

A new fault is complete only when it has a stable ID, parameter contract, failure domain, target kind, engine lanes, risk, reversibility, observable effect, verification method, maturity and date policy, planner validation, impact-gate behavior, executor/compensation or explicit refusal, CLI explanation, focused unit tests, and a documentation entry. No external runtime is required for the catalog test and coverage commands.
