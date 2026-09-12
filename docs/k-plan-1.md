# k-plan-1 — Runtime abstraction, logical targets, and the `targets:` DSL

> **Phase 1 of 5** (interview 2026-09-12). Decisions marked **[interview]**.
> Predecessor seam: ADR-M7 / ADR-M1 / ADR-0013 / ADR-0019 / ADR-0021.
> Exit: `mayhem plan`/`validate` compiles a Kubernetes drill end-to-end and
> refuses to execute it with a capability-gated message (not a schema error).

---

## Goal

Make Mayhem's logical target identity **runtime-independent**, introduce the
`targets:` DSL without breaking `containers:`, land the unified `--runtime`
flag, and put the full target vocabulary on paper. Nothing here executes
against a live cluster — that is k-plan-3.

The governing principle (from the design review):

> Mayhem's logical target identity must become runtime-independent; Docker
> happens to resolve that identity to `container_name`, while Kubernetes
> resolves it to a workload/resource → Pod → container at execution time.

---

## Locked decisions (k-plan-1 interview)

- **[interview] DSL shape** — add a `targets:` top-level block *beside*
  `containers:`. `containers:` stays docker/podman-only and fully backward
  compatible. Both normalize to one internal `TargetRef`.
- **[interview] Runtime selection** — unified `--runtime docker|podman|kubernetes`;
  `-p/--podman` remains an alias for `--runtime podman`. Config gains a
  `runtime:` key; environment layer honouring is extended with
  `MAYHEM_RUNTIME`.
- **[interview] Driver strategy** — official `kubernetes` Python SDK for
  discovery/read/watch (dependency added in k-plan-2, schema prepared here);
  `kubectl exec` for in-pod mutation.
- **[interview] Selection policy** — full grammar documented and schema-accepted
  in this plan; `mode: one` (deterministic) is the only *implemented* mode
  (k-plan-2). The rest stay reserved until k-plan-4.
- **[interview] Evidence model** — frozen plan pins the **logical** target
  (kind/namespace/name/container); execution records the **resolved** target
  (pod name, uid, container id, node) as separate evidence. `RuntimeIdentity`
  equality is untouched.

---

## 1.1 Target vocabulary (core concepts)

Locked names, used by all five plans ([interview] §19 of the design review):

| Term | Meaning | Docker example | Kubernetes example |
|------|---------|----------------|--------------------|
| **Target** | the logical thing the user wants to perturb | `testcase-api` | `checkout` |
| **Resource** | the concrete runtime object | container `abc123` | `Pod/checkout-7b8d9f…` UID `…` |
| **Locator** | how Mayhem finds the resource | `container_name=testcase-api` | `Deployment/production/checkout` |
| **Resolution** | logical Target → concrete Resource | compile-time + exec-time | two-stage (see §1.4) |
| **Locus** | where the fault executes | container / process / netns | Pod+container / process / netns |
| **Selection** | which instances are chosen | — (always the single container) | `mode: one` (k-plan-2) |
| **Observation** | what happened | probe samples | probe samples |
| **Compensation** | how the system is restored | undo op | reconciliation verification |

---

## 1.2 The `targets:` DSL

`containers:` is untouched. New top-level `targets:` is the cross-runtime
abstraction — a dict keyed by **logical id**:

```yaml
apiVersion: mayhem/v1
kind: drill
name: checkout-resilience

config:
  risk_ceiling: high
  max_faults: 1
  timeout: 10m

targets:
  checkout:
    runtime: kubernetes
    kubernetes:
      kind: deployment          # deployment | statefulset | daemonset | service | pod | k8s_node
      namespace: production
      name: checkout            # stable workload name, never a generated pod name
      container: app            # optional single container; required for container-level faults
    selection:                  # full grammar documented here; only `one` implemented (k-plan-2)
      mode: one                 # one | all | count | percentage | random
    faults:
      - fault: proc.pause
        duration: 10s
```

After normalization (shared `TargetRef`, §1.3), the same identity is usable in
`execution:` steps and success criteria:

```yaml
execution:
  - sequential:
      - checkout
```

**Backward compatibility.** A spec that uses only `containers:` compiles to a
plan whose selectors resolve exactly as they do today. A spec may not mix
`containers:` and `targets:` that reference the same logical id, and may not
use both top-level blocks in one spec (compile error, code `targets.mixed_sources`).

### Selection grammar (schema, reserved modes)

```text
selection:
  mode: one          # deterministic stable pick (implemented k-plan-2)
  # reserved (schema-accepted, compile-refused until k-plan-4):
  #   all | count (count: int) | percentage (percentage: 0..100) | random
```

`mode: one` must resolve identically under the same inputs (sorted candidate
Pods, stable hash) so `plan` output is reproducible — same rule as the
deterministic planner.

---

## 1.3 `TargetRef` — the normalized identity (new: `src/mayhem/domain/target.py`)

Internal model both DSL paths desugar into. The planner, executor, and
recovery code touch **only** this — never `Pod.name == container_name`.

```python
class ResourceKind(StrEnum):
    CONTAINER = "container"      # docker/podman (from containers:)
    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    DAEMONSET = "daemonset"
    SERVICE = "service"
    POD = "pod"
    K8S_NODE = "k8s_node"

class TargetScope(BaseModel):
    model_config = ConfigDict(frozen=True)
    logical_id: str
    runtime: RuntimeLabel          # "docker" | "podman" | "kubernetes"
    kind: ResourceKind
    authority: dict[str, str]      # docker: {"container_name": …}
                                   # k8s:    {"api_group":…, "kind":…,
                                   #          "namespace":…, "name":…}
    container: str | None = None   # k8s: container within the pod
    selection: SelectionSpec | None = None
```

- `RunTimeLabel` lives in `identity.py` next to `RuntimeIdentity` (currently a
  free string; lock it to a `StrEnum` — docker/podman/kubernetes — without
  breaking persisted rows, since the enum values equal today's strings).
- `selectors` on `InjectFault` (experiments.py:71) are **replaced** by
  `target: TargetRef` for `targets:`-authored faults; `containers:`-authored
  faults keep `selectors` and desugar to a container-kind `TargetRef` at plan
  time. This keeps compilation the single normalization point.
- `PlannedFault` gains `target: TargetRef` alongside its resolved node ids
  (see §1.5).

---

## 1.4 Two-stage Kubernetes resolution (contract, not implementation)

Documented here; implemented in k-plan-2 (topology) and k-plan-3 (execution):

```text
compile / validate            impact gate, immediately before injection
────────────────────          ──────────────────────────────────────────
Deployment/production/       Deployment/production/checkout
  checkout                     ↓ discover current ReplicaSet
     ↓                         ↓ discover live Pods
"potentially injectable"       ↓ choose eligible Pod (selection)
     ↓                         ↓ resolve container "app"
frozen logical target          ↓ PID / netns / node / IP
                               ↓ inject
```

The frozen plan holds the logical target; the impact gate re-resolves against
the live cluster every round, so a Pod replaced mid-drill never leads a fault
to target a stale process. Same principle already applied to Docker restarts.

---

## 1.5 Compile-time and safety changes

- **Planner** (`src/mayhem/controller/planner.py`): accept `targets:` specs.
  Frozen plan pins `TargetRef`; node resolution against the topology graph
  remains (PodNode/K8sNode already exist, topology.py:107-138). k8s drills
  compile even though the driver is unsupported — that is the point of this
  plan.
- **Safety gate `_check_k8s_targets`** (`controller/safety.py:203`): the
  blanket `k8s.unsupported` refusal stays for **execution**, but the error
  message becomes capability-graded per fault family (container-exec family:
  "unsupported until k-plan-3"; pod-lifecycle family: "unsupported until
  k-plan-4"; node family: "unsupported until k-plan-5"). The gate is keyed on
  `Capability.KUBERNETES_ENGINE` (catalog.py:620) and the plan's resolved
  node kind, unchanged mechanics.
- **Maniac** already excludes `KUBERNETES_ENGINE` (`planner.py:73`) — that
  exclusion moves behind the runtime check (k-plan-5 re-enables k8s draws).

---

## 1.6 CLI and configuration

- New global option `--runtime {docker,podman,kubernetes}` (default: unset →
  auto-detect docker → podman; `-p` maps to `--runtime podman`, kept as an
  alias so existing scripts do not change meaning).
- `mayhem.yaml` gains:
  ```yaml
  runtime: docker            # docker | podman | kubernetes
  kubernetes:                # connection info — never credentials
    context: production
    namespace: production
    kubeconfig: ~/.kube/config
  ```
  - `kubernetes.*` is **configuration, not drill content**: drill specs can
    reference targets and a runtime label but carry no cluster connection
    details. Credentials stay in kube files / cluster RBAC, resolved exactly
    like the kubernetes SDK's standard resolution.
  - `MAYHEM_RUNTIME` joins the allowlisted env layer (config.py), mirroring
    the existing three variables.
- `tools/…` no changes; `config show`/`validate` automatically cover the new
  keys once added to the schema.

---

## 1.7 Task breakdown (ordered)

1. Vocabulary doc §1.1 extracted into `docs/drill-spec.md` forward-reference
   stub and linked from k-plan-1.
2. `RuntimeLabel` enum in `identity.py`; verify persisted `RuntimeIdentity.runtime`
   strings still parse (docker/podman), migration no-op.
3. New `src/mayhem/domain/target.py` with `ResourceKind`, `TargetScope`,
   `SelectionSpec`; full pydantic validation for the documented grammar
   (`one` allowed; reserved modes schema-valid but compile-refused with a
   "reserved until k-plan-4" plan error).
4. `DrillSpec` gains `targets: dict[str, DrillTarget] | None` and
   `_targets_or_containers` model validator (`targets.mixed_sources`); report
   `targets` and `containers` in `experiment show --json`.
5. `containers:` → `TargetRef` desugar in the planner (container-kind, docker
   runtime) so *all* planned faults carry a `TargetRef`; existing selection
   translation (TargetSelector grammar, topology.py:266) left intact.
6. `--runtime` flag, `-p` alias, `config.runtime`, `MAYHEM_RUNTIME`, config
   schema + docs (docs/config.md table update).
7. `kubernetes:` config block (context/namespace/kubeconfig) — schema,
   validation, `config show` output; DSL-side rejection of k8s connection keys
   in drills.
8. Safety-gate reclassification per §1.5; `k8s.unsupported` message upgrade.
9. Unit tests: DSL parse round-trip both blocks, mixed-source refusal, reserved
   selection modes, runtime flag layering (`--runtime` beats `-p` beats config
   beats env), config validation of the `kubernetes:` block.

## 1.8 Acceptance criteria

- `mayhem validate examples/testCase/mayhem.yaml` unchanged (exit 0) — byte
  identical behaviour for the existing docker quickstart.
- A new `examples/k8s-runbook/` drill with `targets:` compiles under
  `mayhem plan --runtime kubernetes`; the frozen plan JSON pins a logical
  `TargetRef` and no generated pod name appears anywhere.
- Executing that plan fails with the **capability-graded** `k8s.unsupported`
  message (not a schema or selection error).
- `mayhem run old-drill.yaml --ctr testcase-api` still works (documented
  `--ctr` = docker/podman container selector semantics preserved).
- Full test suite green: `uv run pytest` (+ new units), `ruff`, `mypy`.

## 1.9 Explicitly out of scope (later plans)

- Any live-cluster discovery / adapter (`k-plan-2` or 3).
- `mode: one` resolution logic (k-plan-2).
- Executors, capability matrix UNSUPPORTED flips, compensation (k-plan-3, 4).
- Node-level faults, maniac/explore re-enable (k-plan-5).