# Documentation authority

This page is the authority index for Mayhem documentation. It classifies every
Markdown document tracked in the repository and records which source files
control current behavior. Historical evidence, design reports, and forward plans
must not be read as a statement of the current executable contract.

## Source authority

| Contract | Executable authority |
|----------|----------------------|
| Layered configuration | [`src/mayhem/config.py`](../src/mayhem/config.py) |
| CLI commands and global options | [`src/mayhem/cli/app.py`](../src/mayhem/cli/app.py) and [`src/mayhem/cli/`](../src/mayhem/cli/) |
| Stable exit codes | [`src/mayhem/cli/exit_codes.py`](../src/mayhem/cli/exit_codes.py) |
| Drill schema | [`src/mayhem/domain/experiments.py`](../src/mayhem/domain/experiments.py) and [`src/mayhem/spec.py`](../src/mayhem/spec.py) |
| Fault catalog and support declarations | [`src/mayhem/domain/catalog.py`](../src/mayhem/domain/catalog.py) and [`src/mayhem/controller/k8s_runtime.py`](../src/mayhem/controller/k8s_runtime.py) |
| Kubernetes planning and execution seams | [`src/mayhem/controller/planner.py`](../src/mayhem/controller/planner.py), [`src/mayhem/agents/k8s_resolve.py`](../src/mayhem/agents/k8s_resolve.py), and [`src/mayhem/agents/executors.py`](../src/mayhem/agents/executors.py) |

When prose disagrees with one of these sources, the source is current and the
prose needs correction. The consistency tests in
[`tests/unit/test_documentation_consistency.py`](../tests/unit/test_documentation_consistency.py)
guard relative links and documented exit-code identifiers.

## Document inventory

The inventory below covers the repository Markdown set: the previously tracked
documents plus the two new current references created by this synchronization.
Untracked working notes are not part of the documentation authority.

| Document | Classification | Current-use rule |
|----------|----------------|------------------|
| [`../README.md`](../README.md) | user guide | Start here for the supported compose-oriented workflow. Its Kubernetes status section is a capability summary, not cluster-validation evidence. |
| [`../CHANGELOG.md`](../CHANGELOG.md) | historical audit | Release history up to the last generated tag; it does not describe uncommitted behavior. |
| [`product/cli-product-direction.md`](product/cli-product-direction.md) | current product direction | Locked user experience, workflow map, terminology, and product outcomes. |
| [`product/command-architecture.md`](product/command-architecture.md) | current architecture contract | Context layering, mutation safety, output, error, and compatibility rules. |
| [`new-plan/README.md`](new-plan/README.md) | forward-looking plan | Builder-agent roadmap for the next CLI and platform product direction. |
| [`reference/experiment-dsl.md`](reference/experiment-dsl.md) | current reference | Duration grammar used by the drill schema. |
| [`reference/sqlite-schema.md`](reference/sqlite-schema.md) | current reference | Store schema and migration source map. |
| [`reference/fault-catalog.md`](reference/fault-catalog.md) | current reference | Current Kubernetes fault catalog status and capability gates. |
| [`architecture/fault-taxonomy.md`](architecture/fault-taxonomy.md) | current reference | Fault definition and dispatch authority. |
| [`architecture/safety.md`](architecture/safety.md) | current reference | Plan-time safety gate order and refusal contract. |
| [`architecture/toolkit.md`](architecture/toolkit.md) | current reference | Toolkit resolution and execution boundary. |
| [`k8s-new.md`](k8s-new.md) | historical audit | Older workload-lane milestone reference; current catalog/runtime wins. |
| [`fault-catalog/README.md`](fault-catalog/README.md) | current reference | Compatibility location for the catalog snapshot. |
| [`config.md`](config.md) | current reference | Authoritative checked-in summary of `src/mayhem/config.py`. |
| [`reference/cli.md`](reference/cli.md) | current reference | Authoritative checked-in command and exit-code summary of the executable CLI. |
| [`drill-spec.md`](drill-spec.md) | current reference | Drill DSL reference; validate examples against the current Pydantic models. |
| [`compensation.md`](compensation.md) | current reference | Compensation lifecycle reference; executor behavior remains authoritative in source and tests. |
| [`adr/adr-m7-1-k8s-executor.md`](adr/adr-m7-1-k8s-executor.md) | implemented design record | The dated decision and rollout design. Later source may extend or supersede its snapshots. |
| [`grounding-rules.md`](grounding-rules.md) | implemented design record | Binding product rules for commands and gates; not a runtime API reference. |
| [`grounding-log.md`](grounding-log.md) | historical audit | Snapshot dated 2026-09-10. Its `verified` rows are not current behavior claims. |
| [`m7-k8s-executor-discovery.md`](m7-k8s-executor-discovery.md) | historical audit | Dated discovery report; its pre-implementation descriptions are retained for traceability. |
| [`adr-adr-m7-1-k8s-executor-flip.md`](adr-adr-m7-1-k8s-executor-flip.md) | historical audit | Duplicate discovery/flip report retained as a historical artifact, not as the ADR of record. |
| [`k8s-plan-1.md`](k8s-plan-1.md) | implemented design record | Ten plan-1 families are implemented and unit-tested through mocked Kubernetes seams; live-cluster behavior remains unverified. |
| [`k8s-plan-2.md`](k8s-plan-2.md) | implemented design record | Ten plan-2 families are implemented and unit-tested through mocked Kubernetes seams; DNS and node-control behavior remains capability-gated. |
| [`../examples/k8s/README.md`](../examples/k8s/README.md) | unsupported/catalog-only | Manifest-backed planning example and capability warning. It is not proof of live-cluster execution. |

## Kubernetes status vocabulary

These states are intentionally separate. Possessing one does not imply the
next.

| State | Current meaning | Source evidence |
|-------|-----------------|-----------------|
| Kubernetes manifest planning | A multi-document Kubernetes manifest can produce an offline blueprint graph. Workload pods are placeholders, not live pod selections. | [`k8s_manifest.py`](../src/mayhem/topology/providers/k8s_manifest.py) |
| Planner support | `targets:` drills normalize Kubernetes scopes, preserve logical target identity, and compile frozen plans. Plan-time resolution is best-effort for manifest workloads. | [`planner.py`](../src/mayhem/controller/planner.py) |
| Executor support | Kubernetes-routed fault families have dedicated dispatch registers, undo contracts, and executor classes. A registered executor does not prove that a cluster is reachable or a required capability is available. | [`executors.py`](../src/mayhem/agents/executors.py) and [`k8s_runtime.py`](../src/mayhem/controller/k8s_runtime.py) |
| Live resolution | A resolver seam can select eligible live Running pods or nodes and record resolved-target evidence when a usable client exists. No checked-in document should claim that a particular external cluster passed validation. | [`k8s_resolve.py`](../src/mayhem/agents/k8s_resolve.py) |
| Legacy adapter availability | `KubernetesAdapter` remains a registered compatibility seam with `is_available() == False`; do not use its advertised capabilities as proof that the separate resolver/executor path is available. | [`k8s_adapter.py`](../src/mayhem/domain/k8s_adapter.py) |
| Catalog-only fault | A fault can be defined, typed, and planned without being in `k8s_available_faults()`. `k8s.image_pull_slow` is the current catalog-only Kubernetes example and refuses before mutation. | [`catalog.py`](../src/mayhem/domain/catalog.py) and [`k8s_runtime.py`](../src/mayhem/controller/k8s_runtime.py) |

The Kubernetes unit suite exercises these seams with fake clients and
in-memory data. Documentation does not promote those tests into a claim of live
cluster acceptance.
