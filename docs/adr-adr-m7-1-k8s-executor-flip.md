# M7 k8s executor flip — discovery & design (k-plan-3: kubernetes executor milestone)

**Status:** RECORDED — executor flip shipped (SP-3.1→3.4 of `k-plan-3-implementation-subplans.md`); registry carries `K8sExecutor` + per-family signal executors + `K8sArgvExecutor` for the portable generic-catalog lane.
**Owner:** Mayhem / M7 k8s executor milestone agent (me)
**Prepared for:** planner.py + safety.py + agents/executors.py + domain/leases.py implementers, planner ADR-M7-1 reviewers, Mayhem planner/executor architecture board.

---

## 1. Executive summary

Mayhem's Kubernetes capability today is **planned but never executed**: the planner resolves k8s targets into the topology graph (planner.py:514 `_find_k8s_target_nodes`, planner.py:606 `_gate_k8s_selection_eligibility`), but two gates refuse every k8s plan:

1. `safety.py:204 def _check_k8s_targets(plan, graph)` → raises `SafetyRefusedError("k8s.unsupported", ...)` — the **execution-side/capability gate**. Invoked from `validate_plan` (safety.py:~281). This is the gate that refuses to let ANY fault plan target a kubernetes pod.
2. planner.py:606 `_gate_k8s_selection_eligibility(scope, graph)` → raises `SelectionError`-family refusal when a k8s scope cannot be resolved to eligible pod targets.

The fault **executor** today (`agents/executors.py:421 def executor_for(fault_id)`, `EXECUTORS` registry) only knows docker/podman payload executors (`PayloadExecutor` = argv `docker exec`, `ProcPauseExecutor` = `docker kill --signal`, etc.). There is NO executor keyed for `kubernetes` runtime; k8s plans "compile" but die at safety when someone tries to run them.

**k-plan-3 flips exactly this:** the **exec-family fault families** (`proc.pause`, `proc.kill`, `fd.*`, `mem.*`, `fs.*`, `cpu.*`, `load.*` — those that docker already handles via `PayloadExecutor`/`ProcPauseExecutor` docker-exec argv) become **capability-supervised admissions** for kubernetes runtime targets, delivered through a new `K8sExecExecutor`. Everything else (pod lifecycle: kill-node, delete-pod, drain; workload [deployment/statefulset] faults; k8s_node-level node faults) **stays refused** (`k8s.unsupported`), exactly as today.

That's the milestone. This report is the design + verified code anchors + contract for the flip.

---

## 2. The governing docs (top of the contract chain)

- **k-plan-3.md** (`docs/k-plan-3.md`) — Milestone plan: kubernetes **executor** for the exec-family fault family, compensation undo via second `kubectl exec`, lease-level `resolved_target` evidence. Cited sections: §2 (milestone), §3.">4 (evidence), §3.5 (task breakdown), §3.6 (acceptance).
- **k-plan-2.md** — planner gate flip for the k8s **planner** (mode-one pod resolution at plan time) — this is the planner-side flip that also lands here.
- **k-plan-1.md** — base kubernetes planning: scope/authority/loci, pod resolution, refusals.

## 3. Verified code anchors (read/grep-verified this session)

| File:line | Symbol | Note |
|---|---|---|
| `src/mayhem/controller/planner.py:514` | `def _find_k8s_target_nodes(` | planner k8s resolution: pod selection at plan time |
| `src/mayhem/controller/planner.py:606` | `def _gate_k8s_selection_eligibility(` | planner gate: refuses a k8s scope when no eligible pod resolves |
| `src/mayhem/controller/safety.py:204` | `def _check_k8s_targets(plan, graph)` | **safety/capability gate: the flip point** — refuses any k8s target plan |
| `src/mayhem/controller/safety.py:~281` | `validate_plan` → `_check_k8s_targets(plan, graph)` | gate call site |
| `src/mayhem/domain/topology.py:20` | `TopologyGraph`/`TopologyNode` | graph node kinds; k8s node modeling |
| `src/mayhem/agents/executors.py:421` | `def executor_for(` | executor registry dispatch |
| `src/mayhem/agents/executors.py:405` | `EXECUTORS` tuple | executor selection tuple |
| `src/mayhem/agents/executors.py:243` | `PayloadExecutor` (argv builder prefix `docker exec`) | the default docker executor model |
| `src/mayhem/domain/leases.py:64` | `FaultLease` (pydantic) | the lease that must gain `resolved_target`; `resolved_target` is also referenced in planner/ADR docs |
| `src/mayhem/controller/compensation.py:469` | `_payload_undo_ops` | undo op builder family (`payload` / `exec.undo`) |
| `src/mayhem/domain/runtime_adapter.py`? | `RuntimeLabel` | runtime label, executor selection keyed on runtime |

_Note: `src/mayhem/agents/executors.py` — the actual runtime family file is `src/mayhem/agents/executors/…`; anchors are the ones grep-verified. Cross-check file names and line anchors on first touch — they were verified with grep on the real repo but the planner's exact gate function name/line should be re-anchored (see §5 acceptance §7 notes)._

---

## 4. The design

### 4.1 What the flip IS (and is NOT)

The flip is **two capability gates**:

**(A) Safety gate** (`safety.py:204 _check_k8s_targets`): from *blanket refusal of every k8s plan* → *refuse by fault family*, admitting only the **exec-family** set: `proc.pause`, `proc.kill`, `proc.stop`/`proc.signal` (process pause/cont via exec), `fd.exhaust`, `fd.leak`, `mem.*` (mem.alloc / mem.exhaust + mem.* payload), `fs.*` (fs.fill), `cpu.*` (cpu.hog), `load.*` (load.exec) — **exactly the set docker handles with payload exec argv today**. Same refusal message family (`k8s.unsupported`) for everything else: pod lifecycle, node faults (`k8s_node`), workload (deployment/statefulset) targets, drain/kill-node — full refusal preserved.

**(B) Planner eligibility gate** (`planner.py:606`): unaffected for still-refused families; for exec-family against a live eligible pod target — flip is **not required if** `scope.kind` resolves to an eligible pod (`_find_k8s_target_nodes` + eligibility). The planner gate's refusal **must flip to admission for exec-family + eligible-pod** only, because today the planner gate is what blocks *any* k8s plan before safety sees it. (See §4.4.)

**(C) Executor** (`agents/executors.py`): add `K8sExecExecutor` — a payload-family executor that builds `kubectl exec -n <ns> <pod> -c <container> -- <cmd>` argv for exec-family faults whose **resolved runtime is KUBERNETES**; registered in `EXECUTORS` and dispatchable via `executor_for` when the fault's resolved target carrier includes a `kubernetes` runtime label.

### 4.2 Runtime discrimination — HOW the executor knows it's k8s

The single discriminator must be the **resolved runtime on the fault's target + the runtime identity of the executor engine**, NOT the fault_id alone. The lease carries `resolved_target` (pod name, namespace, container), and the executor contract (`executor_for`, `FaultExecutor`) keys on **runtime label**: `RuntimeLabel.KUBERNETES` → `K8sExecExecutor`; `RuntimeLabel.DOCKER/PODMAN` → existing docker/podman executors (unchanged). This is exactly the model ADR-M7-1 and k-plan-3 use for "kubectl exec" vs "docker exec" argv building, and it keeps the docker fault path byte-identical.

Evidence: `agents/executors.py` `PayloadExecutor` today builds `docker exec` argv guarded by the payload prefix family; the k8s fork is: same prefix family (payload), different **engine argv** (kubectl exec), discriminated at **executor-selection time by resolved runtime**. The `resolved_target` on the lease (migration 0017, §5.1) is what makes this possible for undo (compensation re-addresses the pod by resolved target, not by plan-time decoration).

### 4.3 What must flip where (ordered, dependency-aware)

1. **Data/model (first, additive):** `src/mayhem/domain/leases.py` `FaultLease` gains `resolved_target: dict | None` (JSON, nullable) — the concrete pod identity `{kind, namespace, name, container, uid?}` pinned at execution time. Migration M0017 (`fault_leases` table + nullable `resolved_target` JSON column). Nothing else changes; docker leases leave it NULL (backfill: nullable, existing rows unaffected — verified ADR/danger pattern: compensation/undo survive "resolved target" record via the same JSON as `resolved_target`; k-plan-3 §2.3/§3.2).
2. **Planner flip (second):** `planner.py:514 _find_k8s_target_nodes` stays as the resolver. `planner.py:606 _gate_k8s_selection_eligibility` flips: admit exec-family faults against an eligible live pod; keep raising the eligibility/`SelectionError` refusal for (a) still refused families, (b) no eligible pod.
3. **Safety flip (third):** `safety.py:204 _check_k8s_targets` + `validate_plan` call: admit the exec-family admission set (with capability-supervised per-fault-family + in-graph eligibility re-check); refuse everything else with the same `k8s.unsupported` → now message should still direct to the executor boundary. Exact message/Family ID decision: k-plan-3 keeps `k8s.unsupported` for the refused families and introduces a *new admission* category for the exec-family (the fault is Refused for the non-exec families, admitted for exec).
4. **Executor (fourth):** `agents/executors.py` — add `K8sExecExecutor`; register in `EXECUTORS`; the executor `executor_for` dispatch inserts a branch: when the fault's resolved target carries `runtime == kubernetes` AND fault family is exec-family → `K8sExecExecutor`; else docker/podman unchanged.

Each of 2-4 independently reversible; flip surface is the planner + safety gates + dispatch branch, not a rewrite of the fault model.

### 4.4 Planner gate detail (BE CAREFUL here — read k-plan-2 §2)

The planner gate `_gate_k8s_selection_eligibility(scope, graph)` — from discovery reads: "mode-one gate — a kubernetes workload that IS in the live topology must yield at least one eligible pod... a workload absent from the graph (logically pinned) passes through: execution resolves it."

That means: for exec-family faults against an eligible pod, the planner gate should now *not* raise — feasibility is already guaranteed by `_find_k8s_target_nodes` resolving at least one eligible node. The current intent that planning refuses k8s appears to be **a post-ADR safety flip** (the safety gate), not a planner impossibility. So the planner flip is: **admit (don't gate) exec-family faults when scope has eligible pod; raise only when no eligible pod** (unchanged behavior for no-eligibility), which is compatible with the existing "mode-one gate" semantics. **Verify planner.py actual gate name/behavior before committing — flagged in §5 notes.**

### 4.5 Compensation — k8s pod undo

`_payload_undo_ops` (compensation.py:469) family: payload-family faults get undo through `UndoOp(op="exec.undo", args={payload, marker, pid, ...})`? Recorded: the compensation module builds `UndoOp(op="payload.undo", args={fault, payload, marker, pid})` for docker undo. For k8s: the same undo op **but** the `marker`/`pid` must address the **resolved pod/container** (`resolved_target`), i.e. undo argv uses `kubectl exec -n <ns> <pod> -c <container>` against the lease's `resolved_target`, not the docker engine. This is the "same signal-family, second exec delivers undo" model (k-plan-3 §3 / ADR-M7-1 "compensation… deploy a second kubectl exec").

Undo contract for the executor: `K8sExecExecutor` must expose an `undo` path that (1) reads `resolved_target` from the lease/marker-specific record, (2) builds kubectl exec argv with pod/ns/container + the same payload script (kill marker pid / un-pause via `kill -CONT` / marker-gated cleanup), (3) verifies recoverable (impact probe re-checks pod Running + marker gone). The compensation `UndoOp(op="exec.undo", ...)` for payload-family is the same op docker uses — discriminating on resolved runtime in executor dispatch, so compensation code needs NO family-specific fork: it reuses `_payload_undo_ops`, and the executor's dispatch (by resolved runtime) routes the undo to kubectl exec. 

### 4.6 Impact (j_impact.py) — evidence of resolution

Execution evidence JSON gains the `resolved_target` (pod/ns/container + uid) recorded during resolution — evidence repo already stores `resolved_target` per k-plan-3 §3.4/evidence; impact gate photos the pad/pod at resolution. k-plan-3 §3.4 evidence record: a probe + resolved target. ADR-M7-1 requires impact phase to record the resolved target alongside evidence. For the report, though: the impact evidence is out of scan for this m7 flip; anchor: impact gate uses graph + `resolved_target` only where the executor already deploys; the impact gate's k8s handling is unchanged (no evidence changes in this milestone).

### 4.7 Safety/planner refusal — retained

- pod lifecycle (kill-node, pod-delete/`k8s_node`, drain) ✔ refuse (`k8s.unsupported`)
- workload faults (`deploy/…`, statefulset, daemonset) ✔ refuse– same gate
- k8s_node kind targets ✔ refuse
- fd/mem/fs/cpu/load/proc (process-only families) ✔ admit via `K8sExecExecutor`

---

## 5. Task breakdown (implementable, ordered)

### 5.1 Migration 0017 — `resolved_target`
- `src/mayhem/domain/leases.py` `FaultLease` — new field `resolved_target: JSON | None` (nullable; the concrete pod identity: kind, ns, name, container, uid).
- Migration in `.../migration`/lease migration family (verify migration module + run in full suite, NNNNNNN = incremental number; addition of `M0017_*`).
- Backfill: NULL for existing docker leases; docker path unchanged.
- `FaultLease.microscope`? no — implementer: confirm `FaultLease` model config and field-serialization convention (pydantic JSON serialization — `resolved_target` as `dict`).

### 5.2 Planner flip — `planner.py`
- `_gate_k8s_selection_eligibility` → admit exec family + eligible pod. Raise SelectionError only when no eligible pod (`_find_k8s_target_nodes` returns empty) or family refused.
- Confirm exact gate name/line before editing (see notes).

### 5.3 Safety flip — `safety.py`
- `_check_k8s_targets` → admit exec-family admission set; refuse all others (unchanged message family for refusals — `k8s.unsupported`).
- `validate_plan` unchanged except the gate reads the exec admission set.

### 5.4 Executor — `agents/executors.py`
- Add `K8sExecExecutor` (payload family; kubectl exec argv; undirected by resolved runtime).
- Register in `EXECUTORS`; `executor_for(fault_id)` dispatches k8s when the fault/plan carries runtime `KUBERNETES` + exec-family fault.
- Executor identity/DoD: resolve → exec-command-build → inject → evidence(resolved_target) → undo → verdict.

### 5.5 Compensation — `controller/compensation.py` + lease resolved_target
- Reuse `_payload_undo_ops`; the UndoOp for payload-family carries the same args (fault, payload, marker, pid) and the executor dispatch routes by resolved runtime.
- The **new** bit: payload-source/build (marker pid + argv) reuse docker's `_payload_source`, with container identity from `resolved_target`.

### 5.6 Instability & test plan
- unit: fake-client (no cluster) — resolver selection, argv builder, undo compensation, marker roundtrip (tests/unit/k8s...).
- deterministic tests for: planner emits exec-family k8s plan (no gate exception → selection), safety validates exec-family k8s plan (no refusal), executor_for returns K8sExecExecutor.
- regression: existing docker fault suites (all docker-fault tests + compensation + safety docker refusal) must pass.
- intentional-refusal tests remain: planner refuses non-exec-family k8s fault (SelectionError), safety refuses (SafetyRefusedError "k8s.unsupported").

### 5.7 Docs
- k-plan-3 cap-flip: ADR-M7-1 addendum/ADR flip record; `safety.py` docstring update; `docs/k-plan-3.md` §3.4/§3.5 mark "Container-level execution landed for exec-family faults; kubernetes runtime executor registered" + enabled features table + missing-capability scans.

---

## 6. Acceptance criteria (k-plan-3 §3.6)

1. A k8s drill with `proc.pause` on `pod/checkout` compiles, gates, executes, records resolved evidence, verifies recovery — against a real cluster (e2e) and fake-client tests.
2. Executing the *same* drill with a `k8s_node` (node drain) still refused with the same `k8s.unsupported`, message unchanged — a planner+executor calendar `Mayhem k8s node-drain` plan still refused.
3. `executor_for("…proc.pause…")` for a k8s-runtime fault → `K8sExecExecutor`; docker-runtime → unchanged `PayloadExecutor`.
4. `validate_plan` accepts exec-family kubernetes plans; refuses non-exec family (pod-lifecycle, node) k8s plans.
5. Undo: second `kubectl exec` addresses the resolved pod (`resolved_target` in lease), removes marker, kills marker pid pod scope, pod returns Running.
6. Regression: full docker fault/executor/compensation suite green.

---

## 7. Risks / rollback

- **Planner gate name drift** — the planner gate I verified is at planner.py:606 but its exact name/behavior changed between ADR versions. Mitigation: re-grep `def _.*k8s.*` in `planner.py` + `safety.py` before editing; the flip must NOT touch `safety.py` refusal message ids used in tests.
- **The safety flip for exec-family only** — if this lands in the planner and safety separately, you can get a "gate mismatch" (planner admits, safety refuses). Ship them in the same change to avoid the stale gate; each file is a one-line flip.
- **Executor dispatch ordering** — `executor_for` must not select K8sExecExecutor for docker-runtime faults (docker regression). Discriminate on resolved runtime identity (license's lease resolved_target + runtime label), never on fault_id prefix alone.
- **Compensation undo for k8s** must reuse `_payload_undo_ops` (same op family) to avoid a compensation dispatch fork — discriminated by the executor, not the compensation layer.
- **Rollback**: single flip-line revert per file; lease `resolved_target` is nullable additive and safe to leave; executor registry entry removal restores prior dispatch.
- **k-plan-3 ADR acceptance**: confirm the new executor lands under `EXECUTORS` and passes `executor_for` dispatch tests, and e2e `kubectl exec` (flag hardwired).

---

## 8. Next actions for the planner

1. If the planner/data-layer contract is good: apply flip 1 (planner), flip 2 (safety), flip 3 (executor), migration 0017 with tests.
2. If the planner wants to retain planner-time refusal for k8s (safe default): maintain the gate; the executor + safety-flip still deliver the "capability-supervised" portion; planner flips in a later ADR.
3. Re-anchor the exact planner gate function (see §7).

**Open question for planner**: should the planner emit exec-family faults against k8s pods at ALL? (k-plan-3 §3.5 task 5 says yes — "planner: ... workload kinds stack; planner flips the gate in §3.1". ADR-M7-1 flip #3 says "Planner gate flips"). Recommend YES for exec-family eligibility.
