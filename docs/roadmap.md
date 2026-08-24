# Roadmap

Phased plan from this documentation baseline to v1.0. Each phase ends with a verifiable exit
criterion — no phase is "done" by declaration. MVP = end of Phase 6.

---

## Phase 0 — Foundations (no product behavior)

- Package skeleton per [repository-layout](reference/repository-layout.md); import-linter
  contracts green; CI (3.12/3.13 × ubuntu + macOS) with ruff/mypy strict.
- Domain models + state machines; migration runner with first schema
  ([sqlite-schema](reference/sqlite-schema.md)).
- **Exit:** `pytest` empty-but-green pipeline; domain invariants property-tested.

## Phase 1 — Toolkit arsenal

- Manifests, adapters, executor guarantees ([toolkit](architecture/toolkit.md)); fake binaries;
  contract tests.
- **Exit:** every bundled adapter passes contract suite against fakes.

## Phase 2 — Agents & transport

- `AgentRuntime`, local stdio + SSH transports, handshake/capability probe, watchdog thread.
- Roles: process, cpu, memory, storage, network, container (3 attack levels), load(k6), validation.
- **Exit:** controller↔agent round-trip on real host + one SSH host; capability refusals work.

## Phase 3 — Topology & safety gates

- Compose/Docker providers, merge+drift, external-dependency inference
  ([topology-discovery](architecture/topology-discovery.md)).
- Safety engine G1–G5, risk ladder, blast-radius computation, abort matrix
  ([safety](architecture/safety.md)).
- **Exit:** `mayhem validate` refuses every unsafe plan in the adversarial test corpus.

## Phase 4 — Experiment engine

- DSL compiler ([experiment-dsl](reference/experiment-dsl.md)), lifecycle scheduler, steady-state
  windows, load composition.
- **Exit:** db-partition example runs end-to-end against fixture stack with journal + summary.

## Phase 5 — Recovery machinery

- Leases with write-ahead undo, verification probes, janitor reconciliation, `mayhem recover`.
- **Exit:** chaos-of-the-chaos tier green: kill-controller/kill-agent scenarios converge to zero
  non-terminal leases ([testing-strategy](architecture/testing-strategy.md) §6).

## Phase 6 — Maniac Engine → **MVP**

- Planner pipeline, seeded weighted sampling, decision audit ([maniac-engine](architecture/maniac-engine.md)).
- Config layering complete ([configuration-schema](reference/configuration-schema.md)).
- **MVP definition:** deterministic multi-fault experiments + random generation + full recovery
  guarantees + audit trail on compose stacks, single or multi-host over SSH, with ~30 faults
  test-covered via the coverage matrix.

## Phase 7 — Hardening & evidence quality

- Remaining roles: http-api (toxiproxy+schemathesis), database, node, fuzz.
- Observation polish: timeline rendering, MTTR stats, run comparison.
- Podman parity; multi-host integration expansion.

## Phase 8 — Coverage depth

- Grow catalog toward ~100 faults; coverage-matrix CI gate enforced for every claimed fault
  ([fault-taxonomy](architecture/fault-taxonomy.md), [testing-strategy](architecture/testing-strategy.md) §7).

## Phase 9 — Ecosystem seams (v1.0)

- Observer sinks: Prometheus, OTel, Slack/webhook ([observation](architecture/observation.md) §6).
- K8s provider preview behind provider seams ([ADR-0013](adr/0013-kubernetes-readiness-via-provider-seams.md)).
- Contextual-bandit scorer replacing fixed weights (schema already supports it).

## Explicit non-goals until after v1.0

Plugin/third-party code execution ([ADR-0011](adr/0011-toolkit-as-extension-point-no-plugin-system.md)),
ML-driven experiment selection claims, Kubernetes fault execution (discovery only),
production-class defaults beyond the hard guardrails.
