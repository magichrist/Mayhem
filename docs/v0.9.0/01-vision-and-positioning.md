# v0.9.0 Vision and Positioning

## North star

Mayhem is the operator-facing control plane for rehearsing failure safely. It takes a declarative experiment, resolves the real target, explains the expected blast radius, obtains the required approval, applies only the faults the runtime can actually perform, verifies the effect, compensates it, and emits evidence that another operator or auditor can replay.

The product promise is not “run chaos.” It is:

> **Know what will break. Prove what happened. Leave the system recoverable.**

## Primary users

### Application and platform engineer

Needs fast, local-to-shared experiments, clear plan diffs, portable Docker/Podman execution, and actionable recovery instructions.

### Site reliability engineer

Needs target profiles, blast-radius controls, approval windows, campaign checkpoints, SLO-aware checks, and durable evidence.

### Kubernetes platform owner

Needs namespace/context pinning, typed target admission, PDB/RBAC awareness, resourceVersion/UID drift evidence, and explicit live-readiness status.

### Security and governance reviewer

Needs redacted artifacts, immutable approvals, tamper-evident evidence, reproducible inputs, retention controls, and a clear separation between unit-tested and live-verified capabilities.

### Chaos practitioner

Needs a broad fault vocabulary, exploration, coverage gaps, recommendation by goal, and a way to graduate an experiment from a local rehearsal to a controlled campaign.

## Product principles

1. **Truth over catalog size.** A registered fault is not the same as a supported, reachable, and live-verified fault.
2. **Plan before mutation.** Every mutating command has an explicit intent and an inspectable plan artifact.
3. **One resolved context.** Engine, target, namespace, policy, and fingerprints are resolved once and carried unchanged.
4. **Safe by construction.** Missing capability, uncertain target, stale plan, or incomplete compensation is a refusal, not a best-effort mutation.
5. **Evidence is a first-class output.** A run is incomplete if the effect is not verified or evidence persistence is degraded.
6. **Recovery is part of the experiment.** A fault without a tested compensation path is catalog-only until its undo contract is complete.
7. **Local first, cloud-ready later.** The default install remains useful without a cloud account; optional integrations deepen the product.
8. **No hidden mutation.** Dependency installation, extension loading, remote agents, and report generation expose permission boundaries and confirmation requirements.

## Positioning statement

Mayhem is not a generic test runner, not a Kubernetes operator, and not an APM replacement. It is the safety and evidence layer between an operator’s failure hypothesis and a real runtime mutation.

## v0.9.0 success outcomes

- A user can run `prepare plan`, inspect the resolved engine/target/policy, and understand exactly what will happen before `--execute`.
- A plan is rejected if engine selection, target type, policy, or evidence requirements are ambiguous.
- A successful run can be replayed from an immutable input bundle and compared with a later run.
- A failed or interrupted run has a machine-readable recovery state and an operator-ready recovery report.
- A capability report distinguishes `registered`, `available`, `unit_verified`, `live_verified`, `blocked`, and `catalog_only`.
- A release can be reproduced from a clean checkout with unit, integration, packaging, schema, and documentation checks.
- A Kubernetes operator can use dry-run and manifest inspection without live-cluster access and can opt into a separately authorized live conformance suite.

## Non-goals for v0.9.0

- Claiming live verification for every fault ID.
- Building a hosted multi-tenant control plane.
- Replacing Prometheus, OpenTelemetry, Grafana, Loki, or a full incident-management platform.
- Making every possible runtime mutation available through a remote agent.
- Adding a large number of new fault families before the existing truth and evidence model is trustworthy.
