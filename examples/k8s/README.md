# Kubernetes example: manifest planning, not live acceptance

This directory contains a multi-document Kubernetes blueprint
(`kubernetes.yaml`) and a cross-runtime drill (`mayhem.yaml`). The pair is a
**manifest-backed planning example**. It is not a claim that a live cluster,
Minikube deployment, Kubernetes executor, or every catalog fault has been
validated end to end.

## Current status layers

| Layer | What this repository provides | What this example proves |
|-------|-------------------------------|---------------------------|
| Manifest topology | `KubernetesManifestProvider` creates an offline graph from supported manifest kinds. Workload pods are `blueprint` placeholders and are not eligible live selections. | The checked-in YAML can describe a logical workload/service graph for planning. |
| Planner | Kubernetes `targets:` are normalized into logical scopes and preserved on planned faults and steps. | A drill can be authored for logical Kubernetes workloads or nodes. |
| Executor | Dedicated Kubernetes fault executors and undo contracts exist for most registered families. | Source and fake-client unit contracts exist. Registration alone is not runtime availability. |
| Live resolution | `KubernetesRuntimeResolver` can resolve eligible Running pods and nodes when a usable client is present. | No particular external cluster is certified by this directory. |
| Legacy adapter | `KubernetesAdapter` is still a compatibility seam and reports `is_available() == False`. | Its capabilities must not be used as evidence about the separate resolver/executor path. |
| Catalog-only | `k8s.image_pull_slow` is defined in the catalog but excluded from `k8s_available_faults()` and refuses before mutation. | A catalog definition alone is not execution support. |

The full status vocabulary and source anchors are in the
[documentation authority index](../../docs/README.md#kubernetes-status-vocabulary).
The [root README](../../README.md#kubernetes-status) summarizes the same
distinction for users.

## What is in the example

`mayhem.yaml` began with nine `k8s.*` families and also includes portable
container-runtime families that have Kubernetes execution registrations. It is
not an exhaustive inventory of the current catalog, which also contains newer
workload, service, storage, scheduling, and node families.

The manifest declares example Deployments and a Service. Do not infer from its
historical comments that it is automatically applied to a cluster; this
documentation does not prescribe or claim a live deployment workflow.

For a current compose example, use
[`../testCase/mayhem.yaml`](../testCase/mayhem.yaml). The Kubernetes files remain
planning and capability-status fixtures until a caller supplies and validates
the required external environment.
