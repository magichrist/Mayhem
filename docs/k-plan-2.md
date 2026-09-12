# k-plan-2 — Kubernetes topology provider and deterministic `selection: one`

> **Phase 2 of 5**. Predecessor: k-plan-1 (TargetRef DSL, `--runtime`,
> vocabulary). Exit: a live cluster graphs into Mayhem's topology graph,
> `topology discover --runtime kubernetes` works, and `mode: one` selects a
> stable, reproducible Pod behind a workload.

---

## Goal

Ship the first real cluster-facing code: a `kubernetes` **topology provider**
(discovery only — no fault execution) and the **deterministic single-Pod
selection** behind the `selection: mode one` contract from k-plan-1. Also the
moment the `kubernetes` SDK dependency enters the project.

---

## Locked decisions (k-plan-1 interview)

- **[interview] Selection timing** — full grammar already schema-accepted
  (k-plan-1); this plan implements `mode: one` only. `all/count/percentage/
  random` stay reserved until k-plan-4.
- **[interview] Driver strategy** — `kubernetes` Python SDK for discovery/
  read/watch; `kubectl exec` for injection (k-plan-3).
- **[interview] Testing** — fake-client unit tests (no cluster needed) + a live
  e2e suite that autoskips when no reachable cluster (KUBECONFIG / kind /
  minikube) is detected.
- **[interview] Identity** — topology preserves **both** stable (workload) and
  ephemeral (Pod) identities; the provider keys by stable identity; Pod facts
  ride along as child metadata, never as the primary node name.

---

## 2.1 Dependency

`pyproject.toml` gains `kubernetes` (current stable). It is an optional-bundle
extra at this stage (`mayhem[k8s]`) so the docker/podman install path stays
lean, and the provider import is guarded — `is_available()` returns False and
the CLI prints an install hint when the extra is missing.

---

## 2.2 The provider (`src/mayhem/topology/providers/kubernetes.py`)

Implements the existing `TopologyProvider` protocol (base.py):

```python
class KubernetesProvider:
    @property
    def id(self) -> str: ...           # "kubernetes"
    def is_available(self) -> bool: ...  # in-cluster OR kubeconfig resolves
    def discover(self) -> PartialGraph: ...
```

`is_available()` **and** `discover()` resolve the cluster through standard
resolution (in-cluster env → KUBECONFIG/`~/.kube/config` → `context` override
from the new config block). A reachable cluster (a single `CoreV1`/`AppsV1`
list call succeeds) flips `is_available()` true.

Discovery materializes the full hierarchy from k-plan-1 vocabulary:

```text
Cluster
 ├── Node          → K8sNode (topology.py:124-138)  + roles/ips/capacity
 ├── Namespace
 ├── Deployment    → stable target; owner of ReplicaSet
 │    └─ReplicaSet
 │        └─ Pod   → PodNode (topology.py:107-122), populated with:
 │                     namespace, node_name, pod_ip, image, labels, state
 │                     + owner_kind/owner_name, containers tuple, uid
 ├── StatefulSet   → same shape (controller revision naming ≠ ReplicaSet)
 ├── DaemonSet     → same shape (one Pod per Node)
 ├── Service       → label-selector ⊆ Pod edges
 └── Container     → attributed to its Pod (folded into PodNode.containers,
                     no standalone container nodes in this phase)
```

Builder of node ids keeps stable identity primary:

```python
node_id = f"k8s::{namespace}/{kind}/{name}"        # Deployment/production/checkout
pod_id  = f"k8s::pod/{namespace}/{name}"           # Pod/production/checkout-…-x7z9k
```

Edges (`Edge`/`EdgeKind`, topology.py:257-264) added for:
- workload → pod (owned_by)
- service → pod (selector; weight = health-gated semantics reused)
- pod → node (scheduled_on)
- node → cluster (member_of)

These are the dependency edges `explore`/`next`/`coverage` already consume —
no new edge model required.

---

## 2.3 Node model extensions (`domain/topology.py`)

`PodNode` gains (backward compatible, defaults):

```python
owner_kind: str | None = None      # "Deployment" | "StatefulSet" | "DaemonSet" | …
owner_name: str | None = None
containers: tuple[str, ...] = ()   # container names, "app", "sidecar", …
pod_uid: str | None = None
restart_count: int = 0
```

`K8sNode` keeps its fields. No new node kinds — the closed union is
intentionally *not* extended: workload and Service are resolved as
**logical targets** (k-plan-1 TargetScope), and a deployment target is
targetable through the Pods it owns, not as a phantom node kind.

---

## 2.4 Registration and CLI

- `adapter_registry.register("kubernetes", KubernetesAdapter)` already exists
  (adapter_registry.py:58). The provider registers itself beside the Docker
  provider in the topology service when `--runtime kubernetes` is selected.
- CLI:
  ```bash
  mayhem topology discover --runtime kubernetes [--context prod] [--namespace production]
  ```
  `--runtime` from k-plan-1 selects the provider set; `--context`/`--namespace`
  override the config block for one command.
- `topology show --runtime kubernetes` reuses service.py rendering untouched.

---

## 2.5 `selection: mode one` (`src/mayhem/domain/target_selector.py`)

Deterministic contract (same inputs → same Pod, reproducible plans):

1. Collect eligible Pods for the resolved workload:
   - Deployment/StatefulSet/DaemonSet → `owner_kind+owner_name` match;
   - Service → selector-resolved pods;
   - Pod target → itself (only candidate);
   - k8s_node target → refused in this phase (k-plan-5).
2. Filter: `phase == Running`, zero pending deletionTimestamp, readiness
   unknown allowed but Running required.
3. Pick: **sort by (namespace, name, uid), first**. Hash-stable across
   re-discovery; deterministic even when one Pod is replaced by another
   (sort tie-breaks by uid, so the *same* logical target stays, the concrete
   Pod flips only when truly necessary).
4. No eligible Pod → plan error `selection.no_eligible_pods` (not a silent
   no-op).

The pick is **plan-time recorded** (which Pod is expected) and
**impact-gate re-run** at execution (k-plan-3); `mode: one` tolerates the
re-resolve always.

`SelectionSpec.mode` values other than `one` → `selection.reserved_mode`
plan error, pointing at k-plan-4 (moves the k-plan-1 compile-time refusal to
here once the TopologyGraph is available, and `next`/`explore` can seed it).

---

## 2.6 Adapter capability snapshot (no flip yet)

`KubernetesAdapter` (domain/k8s_adapter.py) still reports UNSUPPORTED and
`is_available() == False` for *execution*. The topology provider is a sibling
discovery path, intentionally not gated behind the executor capability. The
`discover` path reads its own availability from the live reachability probe.

---

## 2.7 Task breakdown (ordered)

1. Add `kubernetes` optional extra + guarded import; `doctor`/`init` report
   the missing extra with one-line install hint.
2. `PodNode` field extensions + round-trip tests (topology JSON unchanged for
   docker fixtures).
3. `KubernetesProvider` skeleton: resolution, reachability probe,
   `is_available()`, partial discover of Nodes + Namespaces only.
4. Full discovery: Deployments → ReplicaSets → Pods (container names, uids,
   node, ips, labels, state, owner refs); StatefulSets; DaemonSets; Services
   + selector edges; Pod→Node + workload→Pod edges.
5. Provider registration in topology service; `topology discover/show
   --runtime kubernetes --context --namespace`.
6. Fake-client unit suite (`kubernetes.config` mock or `FakeClient`/recorded
   fixtures): assert node ids, stable-key naming, service→pod edges, namespace
   scoping, context override, unavailability path.
7. Live e2e (autoskip): `pytest -m e2e` detects a cluster via `kubectl
   cluster-info`/SDK probe; asserts discover lists ≥1 node and the expected
   kind/pod counts for a test namespace.
8. `mode: one` selector + eligibility filter, reproducibly-identical double
   call; `selection.no_eligible_pods` and `selection.reserved_mode` errors.
9. Docs: `docs/config.md` (--context/--namespace), k-plan-2 section in
   `docs/features.md`, examples/k8s README touched to reflect "discovery
   live, execution k-plan-3".

## 2.8 Acceptance criteria

- `mayhem topology discover --runtime kubernetes` runs against a real cluster
  and prints PodNode/K8sNode inventory with stable `k8s::…` ids and workload
  owner relationships.
- The full docker quickstart still discovers identically (no flag → docker
  first, unchanged).
- `mode: one` returns the identical Pod across repeated calls for an
  unchanged cluster; selecting a Deployment with zero Running pods yields
  `selection.no_eligible_pods`.
- Fake-client units run with no cluster and no network (mock on top of the
  fake client — zero external calls); e2e autoskips cleanly.
- `uv run pytest`, `ruff`, `mypy` all green; `pip install "mayhem[k8s]"`
  resolves.

## 2.9 Out of scope

- Execution-time resolution wiring (k-plan-3 — impact gate uses `mode: one`
  against live pods).
- Container/node faults, capability flips (k-plan-3 … 5).
- Multi-instance selection (`all|count|percentage|random`, k-plan-4).
- Maniac/explore/coverage over k8s targets (k-plan-5).