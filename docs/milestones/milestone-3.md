# Milestone 3 — Runtime Adapters, Rootless Matrix, NetworkPath Model (P2, §12–16)

> **Verdict basis:** `docs/answer2.md` §12 (capability verdict matrix), §14 (remote-agent interface), §15 (first-class NetworkPath), §16 (network operation fingerprints).
> **Decision locks (grill Q4, Q5, Q11, Q12, Q18):** refactor the existing single `ContainerRuntimeProvider` into a real `RuntimeAdapter` interface with docker+podman behaviors; docker primary / podman secondary (real impl); **remote + k8s = ADR/interface only**; full `CapabilityRequirements` schema here; three-locus ExecutionContext here; `NetworkPath` model + fingerprints here (archetypes → M6).

## 1. Goal

Turn the current engine-parameterized `ContainerRuntimeProvider` (which already takes `"docker"|"podman"` and has `id()`, `best_effort()`, `is_available()`) into a **normalized `RuntimeAdapter` contract** with distinct, tested docker and podman behaviors, a fully specified `CapabilityRequirements` model with a `SUPPORTED/_WITH_ALTERNATIVE/UNSUPPORTED/UNKNOWN` verdict matrix, a three-locus ExecutionContext, and a first-class `NetworkPath` model with ownership fingerprints. Remote-execution and Kubernetes are locked as interfaces here but **not implemented** (no SSH transport, no cluster faulting).

## 2. ADR lock (freeze before code)

- **ADR-M3-1 — RuntimeAdapter contract.** Normalize `ContainerRuntimeProvider` into `RuntimeAdapter` with: `id()`, `is_available()`, `inspect(id)→RuntimeIdentity+Metadata`, `ps()`, `exec`, `pid`, `capabilities()`, `netns()`, `signals`. Docker and Podman are `RuntimeAdapter` implementations. The current single class is refactored, not preserved as a god-object.
- **ADR-M3-2 — CapabilityRequirements + verdict matrix.** New `CapabilityRequirements(platforms, runtimes, target_kinds, privileges, namespaces, tools, kernel_features, permissions)`. Adapter answers per requirement with `SUPPORTED | _WITH_ALTERNATIVE | UNSUPPORTED | UNKNOWN` (a proper matrix, not boolean). Feasibility is evaluated at **plan time and re-validated at run time** (M2 pattern preserved via adapter).
- **ADR-M3-3 — Three-locus ExecutionContext.** Replace the single-locus enum with target-locus / agent-locus / tool-locus. `PlannedFault` keeps a required plan context; the agent/tool loci let the engine reason about *where the mutation lands* vs *where the tool runs* (local vs remote vs container). Drift detection compares the target locus identity.
- **ADR-M3-4 — Rootless matrix.** Podman-rootless is verified per capability (exec, netns, pid, resource limits, port) and recorded in the capabilities matrix. Implement the *verdicts* for docker-primary + podman-secondary behavior; do **not** build unsupported workarounds for rootless gaps — mark `UNSUPPORTED`/`_WITH_ALTERNATIVE` and let the planner refuse or degrade per policy.
- **ADR-M3-5 — Remote execution: interface only.** `RemoteAgentInterface` contract (connect, capability handshake, target resolution, tool run, cancel, teardown) is defined and ADR'd; **no SSH transport is implemented** (Q11). A remote target in a spec fails-planning with `UNSUPPORTED` until a future milestone implements a transport.
- **ADR-M3-6 — Kubernetes: interface only.** Kubernetes `RuntimeAdapter` interface + `NodeKind.POD`/`K8S_NODE` extensions + fault categories (capacity, network, preemption) are ADR'd; no cluster execution (see M7).
- **ADR-M3-7 — NetworkPath is first-class.** `NetworkPath(source_id, dest_id, network, namespace, interface, protocol, ports, direction)` models a connectivity relation; a network fault targets a `NetworkPath`, not a bare "partition these container names". Every network operation carries an **ownership/identity fingerprint** (§16) so it is attributable, journaled, and recoverable.
- **ADR-M3-8 — Fault registry keyed by adapter + target kind.** Each fault resolves its mutation/undo/probe implementation per (adapter, target kind) with clear precedence (definition default → per-kinds → adapter-specialized). This is why a compose SERVICE backing a container is targetable by `container.kill`/`clock.skew` (the planner selects the node kinds a fault can act on).

## 3. Phases

### Phase 3.1 — Refactor RuntimeAdapter interface (docker + podman)

**Tasks**
- Introduce `RuntimeAdapter` abstract base; move `ContainerRuntimeProvider` docker path into `DockerAdapter`, add `PodmanAdapter` (both thin over the existing engine-parameterized helpers: `_ps`, `_inspect_pid`, `_inspect_name`, exec, signals, netns).
- Keep `best_effort()` semantics (docker preferred, podman fallback) but route through the adapter registry.
- Adapter exposes `capabilities()` snapshots consumed by feasibility.

**Acceptance criteria**
- Unit `test_topology_providers.py`: docker provider resolves/executes via `DockerAdapter`; podman (if installed) via `PodmanAdapter`; both expose `RuntimeAdapter` methods; legacy `ContainerRuntimeProvider` call sites migrated (no god-object).
- `best_effort(None)` still prefers docker over podman.

### Phase 3.2 — CapabilityRequirements + verdict matrix

**Tasks**
- Add `CapabilityRequirements` model + `CapabilityVerdict` enum (`SUPPORTED/_WITH_ALTERNATIVE/UNSUPPORTED/UNKNOWN`).
- Adapters produce a per-capability verdict matrix; planner consumes it for feasibility; M2's execution-time revalidation now queries the adapter verdict (not just the old `CapabilityReport`).

**Acceptance criteria**
- Unit `test_capability_registry.py`/`test_agent_capabilities.py`: matrix evaluation returns correct verdicts per adapter; `UNSUPPORTED` blocks planning with a clear refusal; `_WITH_ALTERNATIVE` informs a planner degradation choice.
- Plan-time + run-time revalidation both use the verdict matrix (regression: M2 behavior preserved).

### Phase 3.3 — Three-locus ExecutionContext

**Tasks**
- Generalize ExecutionContext into target/agent/tool loci; keep the required plan context (ADR-M2-5) as the target locus.
- Update planner validation + drift detection to compare target-locus identity; tool-locus used to choose *which adapter/command* injects.
- Migration: single-locus models in specs are interpreted as "all three loci = the target" for backward compat.

**Acceptance criteria**
- Unit `test_execution_context.py`: plan context required; three-locus model parses; inference rule (single-locus spec → all-three-same) matches pre-0.3.0 behavior.
- Drift detection uses target-locus identity (regression from M2).

### Phase 3.4 — Rootless/remote/k8s capability matrix (data + refusal)

**Tasks**
- Populate the matrix rows for: rootless podman (rootful docker as baseline), remote targets (`UNSUPPORTED` this milestone), k8s (`UNSUPPORTED` until M7).
- Where a capability is `_WITH_ALTERNATIVE`, implement the *documented alternative* if cheap (e.g., degraded exec); otherwise mark and refuse cleanly.

**Acceptance criteria**
- Matrix table unit-tested (`test_capability_registry.py`); remote/k8s → `UNSUPPORTED` with a consumer-friendly refusal message; no partial/unsafe degradation without an ADR note.

### Phase 3.5 — Remote-agent + k8s interface ADRs (no code)

**Tasks**
- Write the `RemoteAgentInterface` contract + k8s adapter interface + node-kind extensions as ADRs; add spec-level validation that a remote/k8s target fails planning with `UNSUPPORTED` (no dead code paths).

**Acceptance criteria**
- ADRs exist in `docs/adr/`; a spec targeting remote/k8s fails planning cleanly (unit `test_planner.py`); no transport/cluster execution code added.

### Phase 3.6 — NetworkPath model + fingerprints

**Tasks**
- Add `NetworkPath` model (§15) + `NetworkFault → NetworkPath → impairment`.
- Add network-operation ownership/identity fingerprint (§16) to the resource/ownership backbone (M2 `OwnedResource`), so a network fault is journaled and recoverable.
- Refactor `DrillFault.targets` from "container names to partition" toward `network_path` references (kept additive/non-breaking, Q2).

**Acceptance criteria**
- Unit `test_resources.py`/`test_fingerprint.py`: NetworkPath round-trips; network ops carry a stable fingerprint; journaling + cleanup work for network actions.
- `tc`/netem *archetypes* are **not** implemented here (→ M6); only the model + fingerprint.

### Phase 3.7 — Migration freeze prep + e2e

**Tasks**
- Since remote/k8s are interface-only and this milestone introduces adapters, run the full unit/integration suite.
- `tests/e2e`: a docker-compose drill exercises the DockerAdapter end-to-end incl. capability verdict + network-path fingerprint bookkeeping; podman path gated on podman availability.

**Acceptance criteria**
- Unit + integration green; e2e green (docker required, podman optional).
- No Mypy/ruff regressions on touched modules.
- Freeze marker for the execution/identity schema set in place (M4 will formalize versioned migrations — Q9).

## 4. Testing / DONE stance (Q18)

**Unit + e2e-where-live.** M3 touches live mutation (adapter exec/netns), so it requires the e2e compose drill. Adapters without a live docker/podman must unit-test against a fake adapter proving the interface contract + verdicts.

## 5. Risks / open items

- **Rootless gaps are real:** don't try to make rootless podman do everything; `UNSUPPORTED` + clear refusal beats a broken workaround. Revisit when a rootless min podman target is in active use.
- **Remote/k8s deliberately unimplemented:** a user with remote needs will hit `UNSUPPORTED` until a transport milestone; this is the agreed trade (Q11).
- **NetworkPath is model-only this milestone:** operators should not expect `tc` faults yet — M6 delivers the archetypes.
- **Duration-string typing bug:** pre-existing `Duration` is `float` but specs pass `"3s"`/`"30m"` — defer resolution to M4 (DSL duration parsing), do not patch here as it touches spec parsing.
