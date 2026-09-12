# k-plan-5 — Maniac/Explore/Coverage over targets, node faults, and hardening

> **Phase 5 of 5**. Predecessors: k-plan-1…4. Exit: node-level faults execute
> with the reconciliation compensation model, `maniac`/`explore`/`next`/
> `coverage` randomize over *logical targets* (not pod names), and the k8s
> surface is documentation-complete and janitor-hardened.

---

## Goal

Complete the M8 story: the last fault category (node), the last selection
mechanism (netns latency), the randomization surfaces (`maniac`,
`explore`/`next`, `coverage`) talking to k8s targets, and the operational
slack (janitor, cancellation, evidence replay, docs, README). This plan also
re-opens the k-plan-4 cage and spends the node-level budget.

---

## Locked decisions (k-plan-1 interview)

- **[interview] Fault scope** — node category (`k8s.node_drain`,
  `k8s.node_pressure`) is the last live category.
- **[interview] Selection** — full grammar already live (k-plan-4);
  `random` is what maniac uses.
- **[interview] Compensation** — reconciliation verification is the universal
  k8s compensation; node faults follow the same template (drain re-enables
  scheduling: cordon → drain → **uncordon** is the node-rate inverse — the one
  case where undo is *not* NOOP).
- **[interview] Evidence** — logical + resolved recorded everywhere; resolved
  evidence becomes the replay/comparison key for `compare`/`cover`.

---

## 5.1 The k-plan-4 cage resolution

k-plan-4 deferred `k8s.pod_latency` (netns mechanism) and node faults here:

- `k8s.pod_latency` — implemented via **node-side netns entry** (`nsenter`
  into the pod's network namespace using the pod's pid from the node) when the
  operator has node access; otherwise capability-UNSUPPORTED with the same
  `policy`-style message pattern. `pod_partition` may also gain this route as
  the strong-netns alternative to NetworkPolicy.
- Node faults mechanism contract for this plan:
  - **`k8s.node_drain`** — `cordon` the node + `drain` (grace_period,
    `poddisruptionbudgets` honoured) → compensation **uncordons** and verifies
    `Ready=True`, `Unschedulable=False`; if the node drains nothing (no
    pods), record `node_drain_empty` note, still verify.
  - **`k8s.node_pressure`** — capacity stress on the node (param
    `pressure_kind: cpu|memory|disk`), reversible via the existing
    capacity-undo pattern; verified by node `Allocatable` signal returning
    toward baseline.
- Node selection reuses `mode: one` (deterministic by node name/uid).
- Adding node faults this late is deliberately narrow — blast radius is a
  whole node, so they stay behind `config.risk_ceiling` elevation AND an
  explicit per-fault `ack: true` (the `--allow-critical` surface), mirroring
  `container.kill`'s critical risk handling.

---

## 5.2 Maniac over logical targets

`mayhem maniac` (infra/maniac.py) today draws `(container, fault)` within a
docker topology. Scope change (k-plan-1 §1.5 finally lands):

```text
random(target, fault)
  target  →  TargetRef of any live node-kind in scope:
             Deployment | StatefulSet | DaemonSet | Service | Pod | K8sNode
  target resolver + selection strategy (mode: one deterministic; random draws
             re-roll per round like the docker path)
  fault    → drawn only from families whose capability is now live
             (exec / pod-lifecycle / policy / node) and whose node-kind
             matches the resolved kind
```

- Draw space is the **topology inventory** (k-plan-2), not pod-name strings —
  a `Deployment/checkout` is one drawable target, Pods are only reachable
  through the selection policy.
- Guards preserved: `risk_ceiling`, `max_faults`, blast radius, conflict
  rules, `Capability.KUBERNETES_ENGINE` re-admitted for maniac draws now that
  live capability exists (`_MANIAC_EXCLUDED_CAPS`, planner.py:73, drops the
  blanket k8s exclusion and instead consults the adapter capability matrix).
- `maniac --target checkout` (proposal §8) narrows draws to one target scope
  — the new `--target` CLI flag (`--ctr` remains the docker/podman container
  selector).

---

## 5.3 Explore / Next / Coverage over targets

- `mayhem explore --runtime kubernetes` and `next`: walk the topology graph
  (service→pod→node edges from k-plan-2) proposing *logical* targets exactly
  as it proposes container targets today; the same candidate gating
  (`candidate_gates.py`) cross-checks capability/permission before offering.
- `coverage`: coverage keys become target-scoped (`k8s.deployment/checkout`,
  `k8s.node/worker-3`), and the coverage repository aggregates over
  resolved_target evidence (k-plan-3/4) — pod-level instances roll up into
  their logical owner so coverage is measured on stable identity, not on
  epfigmeral pod names (this is the whole point of §10 of the design review).
- `compare`/`report` pick up resolved evidence automatically (report JSON
  unchanged shape, new source values).

---

## 5.4 Hardening pass

- **Janitor** (`controller/janitor.py`): intakes k8s leases in every state —
  `compensation_timeout` (k-plan-4) plus orphaned `injecting` leases when an
  operator kills mayhem mid-round; verifies "did the target actually get
  perturbed / did the controller reconcile" from API state instead of only
  from local lease rows.
- **Cancellation** (`domain/cancellation.py`): mid-drain / mid-reconcile
  cancellation keeps the run honest — for k8s it waits for the in-flight
  compensation template rather than skipping it (matching abort semantics).
- **Kubeconfig safety**: `doctor` prints resolved context/cluster/RBAC gaps
  (missing exec/patch/policy permissions surface as capability refusals, not
  as confusing 403s mid-run); `--context` override validated before any
  injection round.
- **Docs/README**: features.md M8 fully "done"; drill-spec.md k8s full
  reference; README CLI table (`--runtime`, `--target`, k8s examples);
  examples/k8s runbook upgraded to cover all five fault categories.
- **Grounding log**: k-plan-1…5 decision + cage resolutions appended to
  docs/grounding-log.md.

---

## 5.5 Task breakdown (ordered)

1. Node executors: `K8sNodeDrainExecutor` (cordon→drain→uncordon) +
   `K8sNodePressureExecutor` (capacity undo); `--allow-critical` ack wiring.
2. Netns mechanism: pod-latency/partition strong route; node capability flag
   (`netns`) and its UNSUPPORTED refusal path.
3. Node compensation: uncordon + Ready/Unschedulable verify; `node_drain_empty`
   note; blast-radius/risk integration for whole-node targets.
4. Maniac re-enable: `KUBERNETES_ENGINE` out of excluded caps (consult matrix
   instead); target-scoped draws; `--target` flag; seedable random.
5. Explore/next over target-graph; coverage keyed by logical owner (pod-level
   rollup), candidate-gate cross-check.
6. Janitor + cancellation + kubeconfig/RBAC doctor checks.
7. Unit tests (fake client): drain state machine (empty node, PDB-blocked,
   uncordon verify), netns capability refusal, maniac draw reproducibility +
   guard refusals, coverage roll-up math.
8. Live e2e (autoskip): node_drain on a worker with a ReplicaSet pod →
   drained → pod rescheduled → uncordoned+Ready; netns latency measured
   (where permitted), else capability-skipped; maniac 5-round seeded drill
   against a test ns.
9. Docs + README + features.md final state; grounding-log append.

## 5.6 Acceptance criteria

- `k8s.node_drain` and `k8s.node_pressure` run on a live cluster, end
  reconciled, and are refused pre-execution under the default risk ceiling
  without `--allow-critical`.
- `mayhem maniac mayhem.yaml --target checkout` runs N rounds over
  `Deployment/checkout` only; un-narrowed maniac draws never name a pod.
- `mayhem coverage --runtime kubernetes` reports per-logical-target coverage
  from pod-level resolved evidence (replacement pods roll into the same
  logical owner).
- `mayhem next`/`explore` propose logical targets that pass the gate; janitor
  resolves a simulated abandoned `injecting` lease against the fake client.
- CircleCI/GitHub-zero-dep job: all fake-client units green; e2e autoskip.
- `uv run pytest`, `ruff`, `mypy` green; README/features/drill-spec reflect
  the finished M8 surface.

## 5.7 Deliberately out of scope (k8s forever-edge)

- Cross-cluster / multi-context drills (one context per run; the plan + leases
  pin the context string, so multi-context stays possible later without a DSL
  change).
- Service-downtime-only faults (e.g. deleting the Service itself) — Service
  remains a *logical endpoint* target for observability/policy, not a
  delete-audience (proposal §6 separation preserved).
- Chaos-Mesh/CRD-driven injection — exec/API-driven only; documented as a
  future alternative adapter.