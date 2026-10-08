# Plan 02 — Kubernetes-Native Runtime

**Priority:** P0. Gap item 2.

## Objective
Make Kubernetes a first-class Mayhem execution environment rather than only a planning target.

## Builds on (existing code — extend, do not rebuild)
- `agents/k8s_resolve.py` `KubernetesRuntimeResolver` (locate workload → eligible Running pods → deterministic pick with drift recorded → named container → `ResolvedPodTarget` evidence) becomes the live-selection path; manifest placeholders stay ineligible by construction.
- `agents/executors.py` k8s dispatch registers (`k8s_executor_for`, `_K8S_EXECUTORS`) and undo contracts stay the injection path.
- `controller/k8s_runtime.py` `k8s_available_faults()` stays the executability boundary; `k8s.image_pull_slow` stays catalog-only.
- `topology/providers/kubernetes.py` (live discovery) and `k8s_manifest.py` (offline blueprint) stay the two graph sources.
- `domain/k8s_adapter.py` `KubernetesAdapter.is_available() == False` stays false; nothing here rehabilitates it as evidence.

## Scope
- Live cluster discovery (API-driven, RBAC-scoped)
- Pod / container / init-container / node targeting
- Workload-aware targeting (Deployment, StatefulSet, DaemonSet, Job)
- Namespace, label, and annotation selection; percentage and random selection; zone/region selection
- CRDs for Drill/Experiment/Run plus a controller
- Node agent integration via the 03 fabric (DaemonSet form of `mayhem-agent`)
- Kubernetes events and status reporting
- Helm deployment and a `kubectl mayhem` plugin

## Target model
```text
Cluster
  -> Namespace
     -> Workload
        -> Pod
           -> Container
```

Target selectors must support: name, namespace, labels, annotations,
workload kind, node, percentage/random selection, topology zone/region.
Resolution output is frozen into the `ExecutionPlan` as resolved-target
evidence; anything resolved after freeze is drift, not a target.

## Phase 1 — Domain model: selectors and workload safety facts
Add `domain/k8s_targets.py`: `K8sSelector` (all dimensions above), `WorkloadFacts` (replicas, PDB `minAvailable`, readiness/liveness, workload kind semantics), `K8sAdmissionVerdict`. Pure types; the PDB rule ("kill 4 of 10 with minAvailable 8 → DENY with the arithmetic shown") is a pure function over these types. Acceptance: property tests over selector combinations; the PDB denial test shows expected availability vs. required.

## Phase 2 — Engine: live resolution and workload-aware admission
Wire the resolver to a real cluster client through the existing 5-step flow; extend `controller/safety.py` with a K8s admission check (PDB, StatefulSet semantics, DaemonSet awareness, anti-affinity, topology spread, cluster health, active incidents, recent deployments) that refuses before mutation. Acceptance: unsafe workload plans refused with the reason naming the violated rule and the observed numbers.

## Phase 3 — Surface: CRDs, controller, Helm, plugin
Ship CRDs (Drill/Experiment/Run), a controller that compiles CRs through `plan_drill` (never a parallel planner), a Helm chart, RBAC roles, and the kubectl plugin as a thin client over the 08 API. Acceptance: CR-created runs produce the same frozen plan objects as CLI-created runs.

## Phase 4 — Safety and evidence integration
Node-agent execution goes through the 03 fabric (leases, fencing, signed commands); agent loss triggers the fencing/recovery policy; controller restart cannot orphan active experiments (reconciliation on startup via the lease sink). Kubernetes events emitted per run phase; namespace protection and RBAC integration enforced at admission. Acceptance: controller-kill mid-fault recovers with evidence proving it.

## Phase 5 — Tests, regression guards, negative controls
Fake-client unit suites (existing pattern) plus live cells via the 01 pipeline; PDB-denial regression tests; a negative control asserting manifest-blueprint pods can never become live selections. Acceptance: first live-cluster cells certified in 01 before any "first-class" claim ships.

## Phase 6 — Docs, honesty gates, rollout
Update the Kubernetes status vocabulary in docs/README.md (a new "live execution" row only when cells certify), the examples/k8s README, and the competitive matrix. No checked-in document may claim a particular external cluster passed validation. Rollout: discovery and read-only paths first, single-pod faults, then workload-aware faults.

## Dependencies
01 (live cells), 03 (fabric/agents), 07 (policy dimensions), 08 (API backing the plugin), 09 (RBAC/approvals).

## STATUS
- Phase 1 (domain model): DONE — `domain/k8s_targets.py` landed `K8sSelector` (name, namespace, labels, annotations, workload kind/name, node, zone/region, and `one`/`all`/`count`/`percentage`/`random` selection with an *injected* seed), `WorkloadFacts` (replicas, PDB `minAvailable`/`maxUnavailable`, readiness/liveness, workload-kind semantics, anti-affinity, topology spread, cluster health), `K8sAdmissionVerdict`, and the six pure refusal rules — the PDB rule shows its arithmetic ("replicas=10, PDB minAvailable=8, requested kill 4 → DENY, expected availability after fault = 6, PDB requires >= 8"); unresolved candidates land as drift, manifest blueprint placeholders are never live-eligible, and an empty selection is explicit; 74 tests.
- Phase 2: DONE — `controller/k8s_admission.py` collects `WorkloadFacts` for a planned Kubernetes target through an injected client and refuses the plan *inside* `validate_plan` (one optional `SafetyContext.k8s_admission` field, placed after the identity/environment checks and before the generic `k8s.unsupported` placeholder) — the six Phase-1 rules are now reachable from the real gate and their refusals name the violated rule and the observed numbers, the injected authorization predicate is consulted before any cluster read (namespace protection ships as its worked example; the RBAC half is plan 09's), and the facts Phase 1 carried but no rule read are consumed: `updated_replicas` refuses an in-flight rollout, `ready_replicas` refuses an already-unready workload when a readiness probe makes it a health signal, and an absent liveness/startup probe is recorded as a warning; 40 tests.
- Phase 3: DONE — `controller/k8s_controller.py` compiles `MayhemDrill`/`MayhemExperiment`/`MayhemRun` CRs through `plan_drill` (the single planner; no parallel planner exists in the module) over `deploy/mayhem/crds/` (three CRDs), `deploy/mayhem/rbac/roles.yaml` (controller ClusterRole with workload-write-free rules; per-namespace agent Role), a Helm stub (`deploy/mayhem/helm/mayhem`, version `0.1.0-stub`, images required via `--set`, CRDs deliberately untemplated), and `cli/k8s_plugin.py` (thin `kubectl mayhem` client mapping each subcommand to exactly one 08 API route; never plans/admits); 20 tests in `tests/unit/test_k8s_crds.py` pin CR↔CLI frozen-shape parity, the `drillRef`-needs-informer refusal, and the deploy surface.
- Phase 4: **PARTIAL** — the safety-and-evidence half landed (below); the fabric half is wired, and its *verification* gap is now closed, but the transport and the live cell are not. `controller/k8s_fabric.py` dispatches k8s steps through the 03 `FabricEngine` over the lease sink (`K8sFabricDispatcher`: mint → dispatch → settle), orphans a lost agent's ACTIVE leases and mints a successor fence on agent loss (`handle_agent_loss`), and aggregates the crash window on restart (`reconcile_on_startup` over journal + sink); 11 tests in `tests/unit/test_k8s_fabric.py` prove dispatch/settle, deposed-epoch refusal, and crash-window visibility with fakes. **Verification is no longer a claim.** `build_k8s_verifier`/`build_k8s_signer` join plan 19 Phase 2's `AgentCommandVerifier` to the durable store — real HMAC-SHA256 over the canonical envelope, replay checked against the `agent_command_nonces` table, identity checked against the real repository — so a signature is now a proof for any caller that uses the factory, and the previous default (nothing bound, signature as claim) has to be requested explicitly. `build_k8s_verifier` refuses at construction when a required key id does not resolve, naming the key and the deliberate opt-out. 19 tests in `tests/unit/test_k8s_verifier_binding.py` run against a real migrated store and real HMAC; no cluster is involved. The phase acceptance ("controller-kill mid-fault recovers with evidence proving it") is still **not met**: no DaemonSet transport exists and no live cell has run it.
- Phase 5: PARTIAL — the fake half landed: `tests/unit/test_k8s_regression.py` pins the PDB-denial arithmetic at rule and gate level (kill 4 of 10, minAvailable 8 → DENY, expected 6 vs required 8, both PDB forms), the manifest-blueprint never-live negative control (blueprint/unresolved candidates never select; gate refuses as `k8s.no_live_target`), and a fake-`K8sClusterClient` resolution suite feeding admission seam-to-seam. The live half (first live-cluster cells certified in 01) is open debt.
- Phase 6: DONE — rollout order documented below; `docs/README.md` vocabulary and `examples/k8s/README.md` reviewed with no live-execution claim added (the "live execution" row ships only with certified cells); no checked-in document claims any external cluster passed validation; competitive matrix (26) makes no live k8s claim.

Overall: 4 of 6 phases complete (1, 2, 3, 6). Phases 4 and 5 remain PARTIAL and the count is deliberately **not** inflated: both name a live-cluster acceptance that has not run. What Phase 4 no longer carries is the verifier gap — that half is closed and tested, and what remains is the transport plus the cell.

## Phase 4 — what landed, and what did not

**Landed (the safety-and-evidence integration).** `controller/k8s_evidence.py` plus one additive hook in `executor.execute`:

1. **The gap Phase 2 recorded is closed.** `resolve_admission_requests` turns `KubernetesRuntimeResolver.resolve_many`'s output into the `K8sAdmissionInput.requests` map the gate consumes, and `plan_phase_admission` is the one call that installs it around `safety.validate_plan`. `requests` stays keyed by **plan step id**: a two-step plan carrying `k8s.pod_kill` twice against the same namespace/workload kind resolves each step against its own scope and each request names its own pods, because a fault-id key would silently apply step 1's pods to step 2. What made the gate unreachable is now reachable from production: with a `k8s_admission` on the context and a Kubernetes resolver attached, the gate reads real resolved targets instead of refusing every step as `k8s.no_live_target`.
2. **Kubernetes events, in the existing vocabulary.** `K8S_PHASE_KINDS` maps each run phase (`plan`/`run`/`step`/`fault`/`admission`/`drift`) onto a `domain.events.EventKind` that **already existed** — no new `EventKind` was added, because none was needed: the decision rides on `CHECK_EVALUATED`, the drift observation on `DRIFT_REPORTED`, and a refusal additionally on `SAFETY_REFUSED`, all three of which `domain/api.py`'s timeline already maps to a phase. `drift_events` fires only for a step that drifted or that could not be resolved, because a drift report on every healthy step teaches a reader to ignore it. The lane builds its events and the executor journals them **after** `_open_run`, because `events.run_id` references `runs(id)` and admission runs before the run row exists; the ordering is pinned by a test that shows the insert failing without it.
3. **The decision is sealed.** `seal_k8s_admission` writes the refusal *or* the allow, its rule id, the observed numbers, the resolved target keys and all six rule verdicts through `infra/attestation_store.AttestationRepository` — plan 12's own persistence, evidence-boundary gate, and verifier. No second sealer and no second verifier was built: the events are `domain.attestation.AttestedEvent` values sealed by `seal_events` and re-verified by `verify_chain`. `verify_k8s_admission_chain` makes an unsealed decision **detectable** (absent or tampered ⇒ `valid=False`, never a silent pass), and an unsealed manifest stays visibly `unsigned_no_signing` with the reason plan 12 records. The chain row is written under the namespaced key `<run_id>:k8s-admission`, because `attestation_chains.run_id` is a primary key already claimed by `seal_run_evidence` at run close — under the bare run id the admission decision would replace the evidence chain, or be replaced by it, and be lost either way. The events themselves still name the real run.
4. **Namespace protection and the injected authorizer are now reachable at admission**, because a configured context finally gets past the "no live target" refusal to the authorization step it was written for. The RBAC/identity half is still plan 09's to supply as a predicate; nothing here claims to have read RBAC from a cluster.

**Not landed (the fabric half).** The phase also names "node-agent execution goes through the 03 fabric (leases, fencing, signed commands)", "agent loss triggers the fencing/recovery policy", and "controller restart cannot orphan active experiments (reconciliation on startup via the lease sink)". None of that is here: this phase built the evidence integration and did not touch lease acquisition, fencing, agent-loss recovery, or startup reconciliation, all of which belong to the 03 fabric lane. Consequently the phase's acceptance criterion — **"controller-kill mid-fault recovers with evidence proving it"** — is **not met and was not tested**. The evidence produced above is a *pre-mutation* decision record; it says what was allowed and why, and says nothing about recovery.

**Known limitation, restated.** The gate is now *driven*, but only by a caller that configures it. No production caller builds a `K8sAdmissionInput` yet — `cli/services.py` does not — so in production today every run still reaches the gate with `k8s_admission=None`, and `plan_phase_admission` is a no-op wrapper (it does not even call the resolver factory, so a Docker-only run still never probes for kubectl). Nothing implements `K8sAdmissionClient` against a real cluster: the seam is a protocol, and every request, fact set, and refusal in the 37 tests of `tests/unit/test_k8s_evidence.py` came from a fake client. **No live cluster has been accepted by this phase, or by any phase of this plan.** `KubernetesAdapter.is_available()` is still `False`.

Also unchanged, deliberately: manifest-blueprint pods remain ineligible for live selection, and a resolved record with no pod uid is refused rather than trusted.

Known limitation (Phase 2's, restated after Phase 4): **the gate is wired, now drivable, and still no live cluster has been accepted.** The executor constructs `requests` from the resolver's output and installs them around `validate_plan` (Phase 4), but no production caller builds the `K8sAdmissionInput` it wraps — `cli/services.py` still does not — so in production today every run reaches the gate with `k8s_admission=None`, which is a single `is not None` test and leaves every existing decision, refusal, and message exactly where it was. Nothing implements `K8sAdmissionClient` against a real cluster either: the seam is a protocol, and every refusal tested here came from a fake client, so what has been certified is *the gate and its evidence*, not any cluster. `SdkK8sClient` implements the resolver's `K8sClusterClient` (pods/exec), not the admission's fact read; wiring that is the live-cell work plan 01 owns.

Also unchanged, deliberately: manifest-blueprint pods remain ineligible for live selection. An offline `k8s_manifest.py` placeholder resolves to no `ResolvedPodTarget`, so admission refuses such a step as `k8s.no_live_target` naming the blueprint bucket; a manifest graph can still plan, never select. Node-scoped faults (`k8s.node_drain` / `k8s.node_pressure`) stay with `resolve_node` and `ResolvedNodeTarget` — workload admission does not model them, because a node fault's safety is not a replica count's.

Live resolution is still Phase 1 of the existing resolver: admission consumes the `ResolvedPodTarget` records that flow produced and never calls `workload()`/`pods_for()`. A resolved record carrying no pod uid is refused (`k8s.no_live_target`) rather than trusted, because without that uid admission cannot tell a deposed pod from a live one and deliberately does not re-read pods to find out.

One more deliberate limit: a fact of `0` is read as *not observed* rather than as evidence — a client that does not populate `updated_replicas` would otherwise refuse every plan, which is a check that is unusable rather than safe. A populated-but-incomplete rollout (`0 < updated_replicas < replicas`) and a populated health signal (`ready_replicas > 0`) are the shapes that do refuse.

## Phase 3 — what landed (surface: CRDs, controller, Helm, plugin)

`controller/k8s_controller.py` is translation only: envelope validation
(group/version/kind, `metadata.name`, `spec` mapping) then `DrillSpec`
construction then `plan_drill`. `MayhemDrill.spec` is the drill body;
`MayhemExperiment.spec.drill` is the reusable template; `MayhemRun` takes
inline `spec.drill` only — `spec.drillRef` is refused as
`k8s.cr_drillref_requires_cluster`, because resolving a reference needs a live
informer over `MayhemDrill` objects, which is live-cluster work this phase
does not do. Parity is pinned as frozen *shape* (fault identity, target
authority, params, durations, order), not byte equality: `_plan_target_faults`
mints `grp-<uuid>` per compilation, so two compilations of one spec differ in
group ids by construction, and a byte-equality test would fail on correct
code. `cli/k8s_plugin.py` maps `plan -f` → `POST /api/v1/plans`,
`get runs` → `GET /api/v1/runs`, `stop run ID` →
`POST /api/v1/runs/{id}/stop`, `health` → `GET /api/v1/health`; the file is
read, never interpreted client-side, so there is exactly one validator (the
gateway's). The Helm chart ships `0.1.0-stub` with empty image defaults that
`required` refuses — no silent `:latest`. 20 tests in
`tests/unit/test_k8s_crds.py`. **No live cluster has been accepted by this
phase.** `KubernetesAdapter.is_available()` is still `False`.

## Phase 4 — fabric half: what landed, and what did not

**Landed (wired, fake-proven).** `controller/k8s_fabric.py` over the 03
`FabricEngine` with the lease sink behind it:

1. **Dispatch through the fabric.** `mint_k8s_command` builds the envelope
   with every field required — including `signature`, which has no default
   signer here on purpose (the signature must come from the agent
   credential's real signer, plan 19). `K8sFabricDispatcher.dispatch_step`
   runs the engine's preflight → claim → provider → settle path, and the
   agent-returned lease is persisted through the sink (single writer).
2. **Agent-loss fencing policy.** `handle_agent_loss` mints the successor
   fence (strictly newer than the highest claimed epoch) and marks the lost
   agent's *ACTIVE* leases `ORPHANED` through the sink so the janitor
   reclaims them. `PENDING` leases are untouched — nothing was injected under
   them, so there is nothing to fence. Compensation itself stays with the
   janitor/watchdog; this method surfaces, never performs.
3. **Startup reconciliation.** `reconcile_on_startup` aggregates
   `open_claims` + `unreconciled_leases` + `unrecovered_steps` from journal +
   sink. A new dispatcher over the same durable objects *is* a restarted
   controller — no instance memory is read — and the crash signature (open
   claim plus unreconciled lease) is pinned by a test that kills the
   controller mid-settle.

**Not landed.** The **verifier** gap is now closed: `build_k8s_verifier(store, keys=…, controller_id=…)` binds plan 19's `AgentCommandVerifier` over the real `AgentIdentityRepository` and `SqliteNonceLedger`, so the signature on a dispatched command is a proof rather than a claim, and `build_k8s_signer` mints the matching one over the same key port and the same canonicaliser. `build_k8s_verifier` refuses at construction when a required key id does not resolve rather than handing back a verifier that refuses every command at dispatch. 19 tests in `tests/unit/test_k8s_verifier_binding.py` prove it against a real migrated store: a signed command verifies; a stub signature, a tampered envelope, a replayed nonce, and a foreign plan digest are each refused **by name**; the durable-nonce binding and the algorithm report are asserted; and a control proves a pass is actually reachable, so the refusal tests cannot be satisfied by a verifier that refuses everything. What that proves is unchanged: a holder of the shared key produced these bytes. HMAC is symmetric, there is no handshake, and no X.509 chain is validated.

**Still not landed.** No DaemonSet agent transport exists (`FabricSession` is injected, faked in tests); the in-memory journal is not crash-safe across processes (production binds `SqliteFabricJournal`). Consequently the phase acceptance —
**"controller-kill mid-fault recovers with evidence proving it"** — is
**still not met**. 11 tests in `tests/unit/test_k8s_fabric.py`.

## Phase 5 — fake half landed, live half open

`tests/unit/test_k8s_regression.py` (13 tests): PDB denial at rule level
(kill 4 of 10, `minAvailable` 8 → DENY, expected 6 vs required 8, both PDB
forms, plus the admitted fitting kill), the same refusal through the real
gate (`admit_k8s_fault`, rule id plus observed/required numbers), the
manifest-blueprint never-live negative control (blueprint/unresolved
candidates never select; gate refuses as `k8s.no_live_target`), and a
fake-`K8sClusterClient` resolution suite (mode-one evidence with pod uids,
terminating pods excluded, resolved records feeding admission seam-to-seam).
**Open debt, requiring a cluster:** live cells via the 01 pipeline, and the
first "first-class" claim only after 01 certifies them.

## Phase 6 — docs, honesty gate, rollout

- **Status vocabulary:** `docs/README.md` reviewed; no "live execution" row
  added — that row ships only with certified cells, per the phase text.
- **Examples:** `examples/k8s/README.md` reviewed; its planning-not-acceptance
  stance stands. Appended below is the only change: this phase's surface now
  exists as code (CRDs/controller/fabric wiring), still with no live claim.
- **Competitive matrix (26):** makes no live k8s claim; unchanged.
- **Honesty gate:** no checked-in document claims any external cluster passed
  validation. `KubernetesAdapter.is_available()` remains `False`, asserted in
  `test_k8s_crds.py`, `test_k8s_evidence.py`, and `test_k8s_regression.py`.
- **Rollout order (unchanged from the plan):** discovery and read-only paths
  first, single-pod faults, then workload-aware faults — each step gated on
  01 live cells, not on this plan's unit suites.

## Open debt register (needs a live cluster; owned by plan 01 cells)

1. `K8sAdmissionClient` against a real cluster (fact read: replicas, PDB,
   rollout, probes, topology, node health).
2. `drillRef` informer over `MayhemDrill` objects.
3. DaemonSet agent transport for the fabric half. (The plan-19 verifier
   binding half of item 3 is **closed** — `build_k8s_verifier`, see Phase 4.)
4. Controller-kill mid-fault recovery with evidence (Phase 4 acceptance).
5. First live-cluster cells + the `docs/README.md` "live execution" row
   (Phase 5 acceptance).
