# Milestone 7 — Kubernetes: Interface + Model (kruntime forward-lock)

> **Verdict basis:** `docs/answer2.md` rework items: k8s RuntimeAdapter, node-kind extensions, capacity-stress / network / preemption fault categories.
> **Decision locks (grill Q11, Q17, Q18):** **interface + model only** — k8s RuntimeAdapter contract, `NodeKind.POD`/`K8S_NODE` extensions, ResourceConnectionProvider for k8s, fault *categories* (capacity / network / preemption) as ADR + capability matrix; optional KinD/minikube test-harness stub; **no live-cluster execution required**. Acceptance = unit + (optionally) integration-skips-when-no-cluster.

## 1. Goal

Lock the Kubernetes surface so a future implementation can ship cleanly against stable, ADR'd interfaces — without pretending to run a cluster today. k8s is the furthest from your daily target blast-radius (Q11), so this milestone is contractual and preparatory, not operational.

**Out of scope (now):** any live cluster fault injection; pod/node pressure execution; network-policy mutation. (Those become an M8/extension.)

## 2. ADR lock (freeze before code)

- **ADR-M7-1 — k8s RuntimeAdapter interface.** A `KubernetesAdapter` (RuntimeAdapter) contract: list-nodes/pods, inspect → `RuntimeIdentity` (name/namespace/node), exec, capability verdicts per k8s scenario, resource accounting, eviction/preemption hooks. No implementation required.
- **ADR-M7-2 — Node-kind extensions.** Add `NodeKind.POD` and `NodeKind.K8S_NODE` to the topology model so the planner + capability matrix can reason about k8s targets (planning may enumerate k8s targets; execution is gated).
- **ADR-M7-3 — k8s fault categories.** Define capacity stress (node/pod pressure), network (policy/latency between pods), preemption (kill/evict a pod) as *categories + capability verdicts*, NOT executing archetypes. Each carries fingerprints compatible with the M2/M3 ownership/journal backbone so execution can reuse it later.
- **ADR-M7-4 — Capability matrix rows for k8s.** k8s capability entries default `UNSUPPORTED` (no cluster driver) with the adapter contract the seam for a future `_WITH_ALTERNATIVE`/`SUPPORTED` implementation. A spec targeting k8s fails planning with a clear "k8s execution not yet supported, adapter contract at ADR-M7-1" message.
- **ADR-M7-5 — Optional harness.** A KinD/minikube smoke *harness stub* may be scaffolded to prove adapter-interface wiring compiles/connects, but the acceptance bar never requires a live cluster to pass.

## 3. Phases

### Phase 7.1 — Topology node-kind extensions

**Tasks**
- Add `NodeKind.POD` / `NodeKind.K8S_NODE` to the topology model + any validation/locus mapping (plan-only; no execution).
- Ensure planner/capability code paths handle the new kinds without crashing (refuse gracefully).

**Acceptance criteria**
- Unit `test_topology.py`: new node kinds parse/validate; a k8s target in a spec plans/enumerates but fails execution with `UNSUPPORTED`.
- Existing node kinds unaffected (non-breaking).

### Phase 7.2 — k8s adapter interface contract

**Tasks**
- Author the `KubernetesAdapter` interface (ADR-M7-1) as a typed abstract contract (not concrete) in the runtime-adapter module; a `UNSUPPORTED` placeholder implementation exists so wiring/imports are valid.
- Document the capability + ownership mapping for each k8s scenario.

**Acceptance criteria**
- Unit: plugin/import a k8s target → clean `UNSUPPORTED` refusal with the ADR reference; adapter contract type-checks; no dead execution code.

### Phase 7.3 — Fault categories + capability matrix

**Tasks**
- Add capacity/network/preemption *categories* (ADR-M7-3) + k8s capability matrix rows (ADR-M7-4) defaulting `UNSUPPORTED`.
- Fingerprints defined (reuse M2/M3) so a future driver records + cleans up correctly.

**Acceptance criteria**
- Unit `test_capability_registry.py`: k8s categories carry verdicts + fingerprints; `UNSUPPORTED` blocks planning-execution with the clear message.

### Phase 7.4 — Optional harness stub + regression

**Tasks**
- (Optional) a KinD/minikube smoke stub proving the adapter interface wires; all such tests marked `@pytest.mark.k8s` and skipped cleanly absent a cluster (never silently failing).
- Full unit/integration suite unaffected (non-breaking); no Mypy/ruff regressions.

**Acceptance criteria**
- Full suite green; k8s tests absent a cluster skip cleanly.
- k8s execution counts as fully out-of-scope and ADR-documented.

## 4. Testing / DONE stance (Q18)

**Unit + e2e-where-live.** M7 has no live k8s mutation, so the DONE bar is: unit tests green, no lint/Mypy regressions, optional cluster-gated tests skip cleanly when no cluster.

## 5. Risks / open items

- **Contract-only risk:** a future k8s implementer may find the ADR under-specified; keep the interface + fingerprint + capability rows concrete enough to implement without re-opening ADR-M7-X.
- **Scope guard:** do not let "interface prep" creep into writing cluster code — that belongs to the execution extension (M8), and only once a k8s target is actually in use.
- **UNSUPPORTED must be loud:** a user expecting k8s support must get an actionable message pointing to ADR-M7-1, not a silent no-op.
