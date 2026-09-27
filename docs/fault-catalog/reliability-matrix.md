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

The prioritized batch uses existing IDs where the repository already has a truthful executor and compensation contract. Where a mechanism is reachable through a parameter rather than its own ID, the parameter is named in the row so the concept stays discoverable without inventing a new fault id.

| Family | Catalog IDs |
|--------|-------------|
| HTTP request shaping | `http.latency`, `http.error_injection` (`status` selects the code), `dependency.rate_limit`, `net.connection_reset` |
| Network path | `net.latency` (`jitter_ms` is jitter; `direction` selects the side), `net.packet_loss` (`direction: ingress` or `egress`; a full block is `percent: 100`), `net.duplicate`, `net.reorder`, `net.partition`, `net.bandwidth` |
| Clock | `clock.skew` — `offset_ms` is signed and applied as a step, so a positive offset is a forward jump and a negative offset is a backward jump |
| Database | `db.query_error` (`error`: `deadlock` / `lock_timeout` / `serialization_failure`, with `timeout_ms` bounding the wait), `db.slow_query` (`mode: latency` for real added latency, `mode: timeout` for a blackhole), `db.connection_exhaust` |
| Descriptors | `fd.exhaust` (`mode: exhaust` holds the table full, `mode: leak` acquires and never releases) |
| Memory | `mem.exhaust` (`mode`: `allocate` / `reclaim` / `freeze`), `mem.leak` |
| Storage | `fs.read_only`, `fs.inode_exhaust`, `fs.io_stress` (`op`: `read` / `write` / `both`, selecting which of `read_mb_s` and `write_mb_s` are driven), `fs.fill` (`path` selects the filesystem, e.g. `/tmp` or `/var/log`), `fs.permission_failure` |
| Process lifecycle | `proc.pause`, `process.stop`, `process.kill`, `process.crash_loop`, `process.startup_delay` |
| Application dependencies | `dns.timeout`, `dependency.timeout`, `dependency.connection_refuse`, `dependency.malformed_response` |
| Kubernetes control plane | `k8s.*` families — see the catalog table in [`drill-spec.md`](../drill-spec.md#fault-catalog) |
| Container expansion | `cpu.burst`, `mem.freeze`, `mem.swap_pressure`, `fs.quota`, `fs.write_delay`, `net.corrupt`, `net.congestion`, `process.restart_delay`, `http.upstream_timeout`, `app.response_5xx` |
| Kubernetes expansion | `k8s.pod_restart_churn`, `k8s.sidecar_termination`, `k8s.workload_stall`, `k8s.service_5xx`, `k8s.dns_timeout`, `k8s.node_disk_pressure`, `k8s.node_memory_pressure`, `k8s.node_pid_pressure`, `k8s.hpa_oscillation`, `k8s.pdb_over_eviction` |

`fs.permission_failure`, `process.startup_delay`, and `dependency.malformed_response` are catalog-only entries. They have complete metadata and deterministic planner refusal; Mayhem does not claim an executor for them until a capability-aware implementation exists. `k8s.image_pull_slow` follows the same catalog-only policy. The 20 expansion IDs are executable and carry typed refusal and compensation contracts, but their maturity remains unit-verified rather than live-verified.

## Parameterized mechanisms

The rows above name the parameter that carries a mechanism, so a mechanism is never spelled as a separate fault id. Three of them are worth stating explicitly because the id someone reaches for first does not exist:

- A **forward or backward clock jump** is `clock.skew` with a positive or negative `offset_ms` — one signed parameter, not two fault ids.
- **Network jitter** is `net.latency` with `jitter_ms`; it is a second token on the same netem delay, not a separate fault.
- An **ingress or egress block** is `net.packet_loss` with the matching `direction`; `percent: 100` is a total block.

The same pattern covers the storage and descriptor families: filling `/tmp` versus `/var/log` is `fs.fill` with a different `path`, and a descriptor table that fills versus one that leaks is `fd.exhaust` with a different `mode`. New mechanisms should extend a parameter axis before a new id is added.

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
