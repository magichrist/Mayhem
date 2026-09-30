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
| HTTP response shaping | `http.response_truncate` (a `Content-Length` the body never delivers, then a close), `http.header_inject` (a response header the client did not expect; `headers` is validated, never escaped), `http.stream_stall` (the head arrives, then the body waits `stall_ms` mid-flight), `dependency.response_truncate` (the same short body on the dependency lane) |
| Network path | `net.latency` (`jitter_ms` is jitter; `direction` selects the side), `net.packet_loss` (`direction: ingress` or `egress`; a full block is `percent: 100`), `net.duplicate`, `net.reorder`, `net.partition`, `net.bandwidth` |
| Network path — the link itself | `net.interface_down` (the link loses carrier, so the stack reports it down), `net.mtu_mismatch` (MTU dropped so large packets must fragment; the original MTU is captured and restored), `net.tcp_half_open` (the SYN-ACK is dropped, so the connection is opened and then hangs; `port` is required because there is no safe default) |
| Connection and port exhaustion | `net.conn_exhaust` (`mode: ephemeral` consumes outbound ephemeral ports so nothing new can be sourced; `mode: accept` fills a listener's accept queue, and only that mode reads `port`), `db.connection_exhaust` (the client's own connection pool, a different ceiling) |
| Clock | `clock.skew` — `offset_ms` is signed and applied as a step, so a positive offset is a forward jump and a negative offset is a backward jump |
| Database | `db.query_error` (`error`: `deadlock` / `lock_timeout` / `serialization_failure`, with `timeout_ms` bounding the wait), `db.slow_query` (`mode: latency` for real added latency, `mode: timeout` for a blackhole), `db.connection_exhaust` |
| Descriptors | `fd.exhaust` (`mode: exhaust` holds the table full, `mode: leak` acquires and never releases) |
| Memory | `mem.exhaust` (`mode`: `allocate` / `reclaim` / `freeze`), `mem.leak` |
| Storage | `fs.read_only`, `fs.inode_exhaust`, `fs.io_stress` (`op`: `read` / `write` / `both`, selecting which of `read_mb_s` and `write_mb_s` are driven), `fs.fill` (`path` selects the filesystem, e.g. `/tmp` or `/var/log`), `fs.permission_failure`, `fs.corrupt` (a file is overwritten with deterministic garbage; `path` must be absolute, and the original is copied aside and **restored** on undo rather than reconciled) |
| Process lifecycle | `proc.pause`, `process.stop`, `process.kill`, `process.crash_loop`, `process.startup_delay`, `process.thread_exhaust` (worker threads are spawned and parked until the thread pool is spent), `process.child_exhaust` (fork until the container's **pid cgroup** refuses — the cgroup, not `RLIMIT_NPROC`) |
| Application dependencies | `dns.timeout`, `dependency.timeout`, `dependency.connection_refuse`, `dependency.malformed_response`, `dependency.circuit_open` (the upstream is never dialled; the caller gets a 503 carrying `Retry-After`), `dependency.response_truncate` (the upstream response is cut short mid-body) |
| Kubernetes control plane | `k8s.*` families — see the catalog table in [`drill-spec.md`](../drill-spec.md#fault-catalog) |
| Container expansion | `cpu.burst`, `mem.freeze`, `mem.swap_pressure`, `fs.quota`, `fs.write_delay`, `net.corrupt`, `net.congestion`, `process.restart_delay`, `http.upstream_timeout`, `app.response_5xx` |
| Kubernetes expansion | `k8s.pod_restart_churn`, `k8s.sidecar_termination`, `k8s.workload_stall`, `k8s.service_5xx`, `k8s.dns_timeout`, `k8s.node_disk_pressure`, `k8s.node_memory_pressure`, `k8s.node_pid_pressure`, `k8s.hpa_oscillation`, `k8s.pdb_over_eviction` |

`app.deadlock`, `app.exception`, `clock.freeze`, `cpu.interrupt_storm`, `cpu.steal`, `dependency.malformed_response`, `fs.permission_failure`, `fs.read_error`, `k8s.image_pull_slow`, `mem.fragment`, `mem.oom_kill`, `process.oom_kill`, and `process.startup_delay` are the **thirteen** catalog-only entries. They have complete metadata and deterministic planner refusal, and mayhem claims no executor for them. Their `refusal_reason` names the specific mechanism that is missing — an IRQ control path, a hypervisor, a device-mapper error target, a FUSE shim requiring `SYS_ADMIN`, an in-process bytecode-injection or `ptrace` hook, a `libfaketime` preload, a buddy-allocator or `MADV_FREE` control, a protocol-aware response proxy, an application-aware readiness hook, or a registry-pacing runtime — and points at a documented alternative. The refusal is the deliverable; a weaker substitute fault is deliberately not offered in its place. The 20 expansion IDs are executable and carry typed refusal and compensation contracts, but their maturity remains unit-verified rather than live-verified.

Every one of those thirteen needs a primitive mayhem's substrate does not have. Most of them need a kernel-level, in-process, or hypervisor-level control. **Mayhem has no eBPF injection, no kernel module, and no in-kernel fault primitive of its own**; the substrate is `tc`/netem, `toxiproxy`, container-engine cgroup knobs, userspace allocators and writers, and the Kubernetes API. See the README's "What mayhem cannot do" for the full account.

The container-lane and proxy-backed ids added since — the response-shaping, link, connection-exhaustion, storage-corruption and thread/pid-exhaustion rows above — are executable on the same terms: each resolves to an undo operation **and** a verification probe, and each is `verified-unit`. None of them is `verified-live` or `stable`, because no recorded runtime evidence exists for any of them. Per-fault parameter contracts are in [`drill-spec.md`](../drill-spec.md#fault-catalog).

## Parameterized mechanisms

The rows above name the parameter that carries a mechanism, so a mechanism is never spelled as a separate fault id. Three of them are worth stating explicitly because the id someone reaches for first does not exist:

- A **forward or backward clock jump** is `clock.skew` with a positive or negative `offset_ms` — one signed parameter, not two fault ids.
- **Network jitter** is `net.latency` with `jitter_ms`; it is a second token on the same netem delay, not a separate fault.
- An **ingress or egress block** is `net.packet_loss` with the matching `direction`; `percent: 100` is a total block.
- **No outbound ports left** versus **no accept capacity left** is `net.conn_exhaust` with `mode: ephemeral` or `mode: accept`. They are two different ceilings, and only `accept` reads `port` — the default is not a claim about your listener.

The same pattern covers the storage and descriptor families: filling `/tmp` versus `/var/log` is `fs.fill` with a different `path`, and a descriptor table that fills versus one that leaks is `fd.exhaust` with a different `mode`. New mechanisms should extend a parameter axis before a new id is added.

## Maturity

Maturity levels are `experimental`, `verified-unit`, `verified-live`, and `stable`.

- `experimental`: metadata is complete, planner validation is deterministic, and unsupported execution refuses safely.
- `verified-unit`: all experimental criteria pass and deterministic unit tests cover parameters, refusal, and compensation.
- `verified-live`: a supported live runtime completed injection and recovery with recorded evidence.
- `stable`: the supported engine and platform matrix is verified and rollback/deprecation policy is documented.

**The level is derived at read time, not stamped onto the catalog entry.**
`mayhem.infra.promotion.evaluate_maturity` is a pure function of
`(definition, probe, evidence_store)`. It reads no registry, no clock of its
own, and no filesystem, and it grants no rung by default. Every criterion it
checks — catalog completeness, an executable parameter grammar, a deterministic
refusal path, a registered compensation contract, recorded unit coverage, a
recorded verification date — can fail, and a failure is reported as a refusal
naming the criterion, the observed value, and the value that would have been
required. Delete a fault's evidence and its reported level drops with it.

Two consequences that a reader of a report should hold onto:

- **`verified-unit` is a claim about mayhem's own code.** It means the
  parameter grammar, refusal path, and compensation contract for that fault id
  are deterministic and covered by recorded unit evidence. It is not evidence
  that the fault has ever perturbed a running system.
- **The live rungs are unreachable without a record.** `verified-live` and
  `stable` require a `LiveRunRecord`, which cannot be constructed without an
  injected effect that moved a signal, an undo that ran, and a probe that
  confirmed the pre-injection baseline was restored within tolerance, on the
  required engines. An observation that moved nothing, or an undo that did not
  restore the baseline, is rejected at construction rather than recorded as
  passing evidence.

**Current counts: 141 catalog faults — 128 `verified-unit`, 13 `experimental`,
0 `verified-live`, 0 `stable`.** The zero is a *missing* verification program,
not a *failed* one: no fault here has been shown to work against a real
system, and none has been shown not to. The `experimental` and `verified-unit`
populations together are a catalogue of contracts, not a reliability claim.

`mayhem discover faults --coverage` groups by maturity, and
`mayhem discover faults -e FAULT_ID` shows the level for one fault together
with the criteria that were evaluated.

## Recommendations

`mayhem.infra.catalog_report.recommend_faults` ranks executable families for a target profile and user goal. Supported goals are availability, latency, network-resilience, storage-resilience, process-lifecycle, dependency-resilience, and recovery. Recommendations never return catalog-only or unavailable families.

## Deprecation

Platform-specific or unsafe families remain catalog-only until a replacement runtime is verified. The explanation includes the current refusal and migration path. `k8s.image_pull_slow` is retained as a catalog-only registry-pacing archetype and points to `k8s.image_pull_failure` when deterministic pull failure is sufficient; it is not presented as supported latency shaping.

## Builder definition of done

A new fault is complete only when it has a stable ID, parameter contract, failure domain, target kind, engine lanes, risk, reversibility, observable effect, verification method, maturity and date policy, planner validation, impact-gate behavior, executor/compensation or explicit refusal, CLI explanation, focused unit tests, and a documentation entry. No external runtime is required for the catalog test and coverage commands.
