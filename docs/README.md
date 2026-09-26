# Documentation authority

This page is the authority index for Mayhem documentation. It classifies every
Markdown document tracked in the repository and records which source files
control current behavior. When prose disagrees with one of those sources, the
source is current and the prose needs correction.

## Source authority

| Contract | Executable authority |
|----------|----------------------|
| Layered configuration | [`src/mayhem/config.py`](../src/mayhem/config.py) |
| CLI commands and global options | [`src/mayhem/cli/app.py`](../src/mayhem/cli/app.py) and [`src/mayhem/cli/`](../src/mayhem/cli/) |
| Stable exit codes | [`src/mayhem/cli/exit_codes.py`](../src/mayhem/cli/exit_codes.py) |
| Command inventory | [`src/mayhem/cli/command_registry.py`](../src/mayhem/cli/command_registry.py) |
| Drill schema | [`src/mayhem/domain/experiments.py`](../src/mayhem/domain/experiments.py) and [`src/mayhem/spec.py`](../src/mayhem/spec.py) |
| Execution intent and approval | [`src/mayhem/domain/execution_intent.py`](../src/mayhem/domain/execution_intent.py) |
| Typed admission | [`src/mayhem/domain/admission.py`](../src/mayhem/domain/admission.py) |
| Capability truth | [`src/mayhem/domain/capability_status.py`](../src/mayhem/domain/capability_status.py) and [`src/mayhem/infra/catalog_report.py`](../src/mayhem/infra/catalog_report.py) |
| Replay capsules | [`src/mayhem/domain/replay.py`](../src/mayhem/domain/replay.py) |
| Evidence and redaction | [`src/mayhem/domain/evidence.py`](../src/mayhem/domain/evidence.py) and [`src/mayhem/domain/redaction.py`](../src/mayhem/domain/redaction.py) |
| Evidence bundles | [`src/mayhem/domain/evidence_bundle.py`](../src/mayhem/domain/evidence_bundle.py) |
| Provider sandbox and packs | [`src/mayhem/providers/permissions.py`](../src/mayhem/providers/permissions.py) and [`src/mayhem/providers/pack.py`](../src/mayhem/providers/pack.py) |
| Fault catalog and support declarations | [`src/mayhem/domain/catalog.py`](../src/mayhem/domain/catalog.py) and [`src/mayhem/controller/k8s_runtime.py`](../src/mayhem/controller/k8s_runtime.py) |
| Kubernetes planning and execution seams | [`src/mayhem/controller/planner.py`](../src/mayhem/controller/planner.py), [`src/mayhem/agents/k8s_resolve.py`](../src/mayhem/agents/k8s_resolve.py), and [`src/mayhem/agents/executors.py`](../src/mayhem/agents/executors.py) |

## Document inventory

| Document | Classification | Current-use rule |
|----------|----------------|------------------|
| [`../README.md`](../README.md) | user guide | Start here: quickstart, CLI surface, safety model, status, and what v0.9.0 added. |
| [`../CHANGELOG.md`](../CHANGELOG.md) | historical audit | Release history up to the last generated tag; it does not describe uncommitted behavior. |
| [`drill-spec.md`](drill-spec.md) | current reference | Drill DSL reference, including the v0.9.0 `slo:` block and the scenario document format. |
| [`config.md`](config.md) | current reference | Authoritative checked-in summary of `src/mayhem/config.py`. |
| [`compensation.md`](compensation.md) | current reference | Compensation lifecycle reference; executor behavior remains authoritative in source and tests. |
| [`fault-catalog/README.md`](fault-catalog/README.md) | current reference | Fault catalog and capability snapshot. |
| [`fault-catalog/reliability-matrix.md`](fault-catalog/reliability-matrix.md) | current reference | Per-fault reliability and compensation matrix. |

Planning packages, dated discovery reports, and per-release readiness notes were
removed once their content was implemented and folded into the references above.
They remain in git history if a historical record is ever needed.

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
