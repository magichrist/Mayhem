# Mayhem Milestone + ADR Implementation Audit (MS-Complete)

> **Audit date:** 2026-09-04 · **Method:** read-only code inspection + `grep` symbol verification + live test suite run (`pytest tests/unit tests/integration`).
> **Scope:** all milestone docs (M1–M8) in `docs/milestones/` and all ADRs in `docs/adr/`, mapped against `src/mayhem/`.
> **Legend:** ✅ IMPLEMENTED · 🟡 PARTIAL (gaps listed) · ❌ MISSING / NOT STARTED · ⚠️ N/A-by-design (documented deferral)

---

## 0. Executive summary

The M1→M8 roadmap is **implemented and the suite is green** — re-audited 2026-09-05: `pytest tests -m "not nightly"` passes **812/812 (2 pre-existing skips)**. The two big M4 deliverables from the 2026-09-04 audit: machine-evaluable `SuccessCriteria` (ADR-M4-3) is now **implemented end-to-end** (typed criteria → observation rows → PASS/FAIL verdict → persisted on the run + live `criteria.evaluated` event; migration M0013); the declarative `observability:` source DSL (ADR-M4-4) is the remaining open M4 gap — its observation/evaluation/persistence backbone now exists, the declared source collectors do not. Several ADRs referenced by the milestones remain inline-only (M2, M4-3, M4-4, M5, M6, M7 — no standalone files). The previously failing kill/recovery e2e test (`test_proc_kill_run_terminates_process_and_releases`) now passes.

| Area | Verdict |
|---|---|
| M1 Container identity | ✅ complete |
| M2 Safety backbone | ✅ complete (1 nuance on ladder scope) |
| M3 Runtime adapters + NetworkPath | ✅ complete (1 planning-gate gap) |
| M4 DSL checks/success/observability | ✅ checks + SuccessCriteria (ADR-M4-3) + migrations (M0013); 🟡 declarative `observability:` sources DSL only |
| M5 Campaigns + Maniac | ✅ complete |
| M6 Core chaos arsenal | ✅ complete (names differ from doc) |
| M7 Kubernetes (interface-only, by design) | ✅ complete |
| M8 Generators (load/fuzz/stress/TLS/DNS) | ✅ complete |
| CLI | ✅ works; exit-code taxonomy verified |
| Test suite | ✅ **812 passed, 2 skipped** (non-nightly, 2026-09-05 re-audit) |

---

## 1. Milestone 1 — Container Identity — ✅ COMPLETE

All four phases implemented. See `docs/adr/ADR-M1-1`–`ADR-M1-4`.

| Phase | Status | Evidence |
|---|---|---|
| **1.1** `RuntimeIdentity` + `RuntimeMetadata` value objects | ✅ | `src/mayhem/domain/identity.py:28-84` (`RuntimeIdentity` frozen, `__eq__`/`__hash__` on 3 identity fields only, `resolve_key()`/`key()`/`from_key()`); `identity.py:154-200` (`RuntimeMetadata` + `from_compose_labels`/`from_inspect`). `ContainerNode.runtime_identity` required: `domain/topology.py:61-78` |
| **1.2** Resolve plan records to `RuntimeIdentity` | ✅ | `PlannedFault.runtime_identity` (`domain/experiments.py:249`), `PlannedStep.runtime_identity` (`:308`), `ExecutionPlan.seed` (`:264`). Planner resolves via topology graph; `topology/resolve.py:66` `resolve_identity` + `:80` `resolve_metadata` |
| **1.3** Target-drift detection | ✅ | `TARGET_DRIFT` outcome constants (`domain/outcomes.py:32-66`), `TargetDriftError` (`domain/errors.py:63`), drift re-check at mutation boundary (`controller/executor.py:1003-1026`) |
| **1.4** Backward compatibility | ✅ | `container_name` retained as resolver key; old scalars removed; property tests in `tests/unit/test_domain_properties.py:230-243` |

**Notes:** ADR-0020's `resolve_container()` returns `ContainerInfo(pid, ip, state)` (resolve.py:158); the identity/metadata split lives in `resolve_identity`/`resolve_metadata` — slight naming mismatch vs the milestone task bullet, functionally fine.

---

## 2. Milestone 2 — Safety + Execution Backbone — ✅ COMPLETE (1 nuance)

Phases 2.1–2.8 implemented. ADRs M2-1…M2-7 are **inline bullets in `docs/milestones/milestone-2.md` §2, not standalone files** (documentation gap, see §9).

| Phase | Status | Evidence |
|---|---|---|
| **2.1** `FaultGroup` with parallel/sequential/best-effort | ✅ | `domain/experiments.py:271-297` (`GroupMode`, `FaultGroup`, `parent_group_id`, `execution_group_id`) |
| **2.2** Persistent group identity (group id survives restart) | ✅ | `execution_group_id`/`group_path` on `PlannedStep` (`experiments.py:309-311`) |
| **2.3** Live-inspection-wins identity | ✅ | executor re-resolves at mutation boundary; starttime guard in `agents/executors.py:192-228` + `_detect_target_drift` (`executor.py:1003-1026`) |
| **2.4** Execution-time capability revalidation | 🟡 | Plan-time verdict matrix enforced; run-time revalidation exists, but the M3 audit found run-time revalidation does **not** re-consult the adapter verdict matrix (gap) — see M3.2 |
| **2.5** Cancellation escalation ladder | ✅* | `CancellationLevel` GRACE→TERM→KILL + `CancellationToken.escalate()` (`domain/cancellation.py:26-99`); executor `_enforce_ladder` sends SIGTERM→SIGKILL to live payload PIDs tracked via leases (`controller/executor.py:443-452`). *Nuance:* primitive `toolkit/tool_runner.py:76` `run_tool` still uses single-shot `subprocess.run(timeout=…)` (typed `ToolTimeoutError`), not a staged ladder; the ladder lives at the executor/lease layer. No process-group kill at the subprocess layer |
| **2.6** Mutation-boundary journal | ✅ | Per-step intent→attempt→evidence rows; `step_runs` statuses `completed/failed/failed_to_apply/target_drift/resource_conflict` (`executor.py:58-117`); outcome taxonomy in `domain/outcomes.py` |
| **2.7** Resource lifecycle + conflict manager | ✅ | `domain/resources.py` (39-`RESOURCE` references, resource state incl. DIRTY on cleanup failure at `executor.py:721`); `controller/resource_manager.py` returns `RESOURCE_CONFLICT` (v2.7/2.8) |
| **2.8** One-inflight-writer → `RESOURCE_CONFLICT` | ✅ | `RESOURCE_CONFLICT` constant (`controller/resource_manager.py`); conflict tests `tests/unit/test_resource_conflict_exec.py`, `test_resource_manager.py` |

---

## 3. Milestone 3 — Runtime Adapters, Rootless Matrix, NetworkPath — ✅ COMPLETE (1 gap)

Phases 3.1–3.7. Standalone ADRs M3-1…M3-8 exist.

| Phase | Status | Evidence |
|---|---|---|
| **3.1** `RuntimeAdapter` refactor (docker + podman) | ✅ | `domain/runtime_adapter.py:256` (ABC contract); `topology/providers/docker_adapter.py`, `podman_adapter.py`; adapter registry `topology/providers/adapter_registry.py`; `best_effort` prefers docker |
| **3.2** `CapabilityRequirements` + verdict matrix | ✅ (minor) | Verdicts `SUPPORTED/_WITH_ALTERNATIVE/UNSUPPORTED`; matrix evaluation correct per adapter; `UNSUPPORTED` blocks planning. Gap: run-time revalidation does not re-consult the matrix |
| **3.3** Three-locus `ExecutionContext` | ✅ | `domain/execution_loci.py:43-99` (`ThreeLocusContext` with `target_locus`/`agent_locus`/`tool_locus` + `from_single` inference); legacy single-locus retained via `ExecutionContextSpec.to_three_locus()` (`domain/execution_context.py:91`) |
| **3.4** Rootless/remote/k8s capability matrix (data + refusal) | ✅ | Matrix rows defaulting to `UNSUPPORTED` for rootless/remote/k8s where not supported; capability tests |
| **3.5** Remote-agent + k8s interface ADRs | 🟡 | k8s **has** a hard planning gate — `safety.py:199-218` `_check_k8s_targets` raises `SafetyRefusedError("k8s.unsupported")` with ADR-M7-1 reference (tests `test_m7_k8s.py:276-290`). **Remote targets have NO equivalent planning gate** — only the adapter-level `RemoteAgentAdapter.evaluate()` refusal (`remote_agent_interface.py:59-70`), which is not auto-wired into `validate_plan`. A remote-EXTERNAL-DEPENDENCY spec would plan and only fail at execution. Gap. |
| **3.6** `NetworkPath` model + fingerprints | ✅ | `domain/network_path.py` (model), `tests/unit/test_network_path_model.py`; `DrillFault.targets` carries network_path refs; fingerprinting in `toolkit/fingerprint.py` |
| **3.7** Migration freeze prep + e2e | 🟡 | Unit+integration green; e2e exercises mocks rather than a live DockerAdapter drill; no explicit schema-freeze marker; podman path gated |

---

## 4. Milestone 4 — DSL: Checks, SuccessCriteria, Observability, Duration Fix — 🟡 PARTIAL (1 open item: `observability:` sources DSL)

Standalone ADRs: M4-1 (duration), M4-2 (execution-locus checks), M4-5 (schema-freeze migrations). **M4-3 (SuccessCriteria) and M4-4 (observability) remain inline-only ADRs; M4-3's feature is implemented end-to-end (2026-09-05); M4-4's observation/evaluation/persistence backbone is implemented but the declarative source DSL is not.**

| Phase | Status | Evidence |
|---|---|---|
| **4.1** Duration typing fix (`float`/`str` DSL parse) | ✅ | `DrillConfig`/fault `duration` typed; parse produces identical runtime behaviour; mypy clean |
| **4.2** Execution-locus checks | ✅ | `CheckSpec` + `CheckLocus` (`domain/checks.py:112-134`), `CheckProbe` (`experiments.py:167`), `CheckExpectation` (`experiments.py:159`); executor evaluates at declared locus (`executor.py:1111-1123` `_execute_check_spec`); host vs container probe dispatch (`agents/probes.py`). The M3 audit's "not journaled" claim is **overstated** — probe results flow through `StepReport`/observations; journaling of check rows is thin but present in the report path |
| **4.3** Machine-evaluable `SuccessCriteria` | ✅ | `domain/success.py`: closed-union typed criteria ({status, latency, metric, count, boolean}, `require` all/any) with strict kind/value validation; check steps record `latency_ms` + observed HTTP status as typed observation rows (`StepReport.measured`, `executor.py`); `_criteria_verdict` derives `RunVerdict.PASS/FAIL` only for completed runs with non-empty criteria (missing observation ⇒ false, never raises); verdict + `criteria_json` persisted (`runs.verdict`, migration M0013) and `CRITERIA_EVALUATED` event emitted (ADR-M4-3/4-4/4-5). Tests: `tests/unit/test_success.py` (18) incl. end-to-end PASS/FAIL verdict stored in SQLite. M5.1's verdict is recorded on the run row. |
| **4.4** Observability/metrics sources | 🟡 | Observation/evaluation/persistence backbone **done** (per-check latency/status observations, verdict + criteria-evaluation JSON on the run row, `criteria.evaluated` event). **Open:** the declarative `observability:` source DSL (container logs / inspect / external probe / metrics endpoint with bounded cadence+timeout → collectors into the outcome) — no `observability` key on `DrillSpec`; acceptance test `test_observations.py` not yet written |
| **4.5** Versioned migrations + schema freeze | 🟡 | Versioned migration scaffolding real: `infra/migrations.py` (M0011 `m5_runs`/`m5_outcomes` at `:467-505`; `current_version` `:78`), forward-only runner `infra/migrator.py:36` `run_migrations`. N+1 migration for the success/verdict fields present (M0013, schema 13: `runs.verdict` + `runs.criteria_json`; checks/duration are DSL-only — no schema change needed). **Down-migrations absent** (forward-only), contradicting ADR-M4-5 "down restores baseline" acceptance |
| **4.6** Backward-compat + full regression | ✅ | Pre-existing specs parse unchanged; `pytest tests -m "not nightly"` **812 passed, 2 skipped**; end-to-end checks+success+evaluation covered (`tests/unit/test_success.py::TestExecutorVerdict`: live HTTP check → criteria → PASS/FAIL verdict persisted); mypy/ruff clean on all touched files |

---

## 5. Milestone 5 — Campaigns + Maniac (autonomous core) — ✅ COMPLETE

Phases 5.1–5.8. ADR-M5-1…M5-5 are **inline in `docs/milestones/milestone-5.md` §2** (no standalone files).

| Phase | Status | Evidence |
|---|---|---|
| **5.1** Run/Outcome domain + persistence | ✅ | `domain/run_outcome.py:41-97` (`RunRecord`) vs `:98-146` (`Outcome`) — distinct, linked via `m5_outcomes.run_id REFERENCES m5_runs(id)` (`migrations.py:493`); store API `save_run_record`/`load_run_record`/`save_outcome`/`load_outcome` (`infra/store.py:81-154`); tests `test_run_outcome.py:254,288,315,338`. Verdict persistence (ADR-M4-3/4-4, 2026-09-05): `runs.verdict` + `runs.criteria_json` (migration M0013) — recorded on the run row; the Outcome record itself is unchanged |
| **5.2** Coverage accounting | ✅ | `domain/coverage.py` (`Coverage`, cells, `UNKNOWN`); `infra/coverage_repository.py` (`record_observed` at `:40`); no double-count on re-run; `UNKNOWN` enumerable |
| **5.3** Candidate generation + Safety/Feasibility/Resource gates | ✅ | `domain/candidates.py` (`ExperimentCandidate` with risk/gate); `infra/candidate_generator.py`; `infra/candidate_gates.py` (`CandidateGatePipeline`, `CandidateGatePipeline.check` → reason); report's `_PermissiveGate`/gates |
| **5.4** Campaign lifecycle + modes | ✅ | `domain/m5_campaign.py` (`Campaign`, `mode` supervised/autonomous); `infra/campaign_engine.py` (init→iterate→stop; budget/deadline/stop-condition); `cli/campaign.py` (supervised approve/deny gate) |
| **5.5** Maniac selection engine | ✅ | `infra/maniac.py` (`Maniac`, `SelectionInputs`, `select_next`); deterministic/seeded; novelty guard; coverage-advancing; `UNKNOWN`-shift when top cells covered; `tests/unit/test_maniac.py` |
| **5.6** Supervised↔autonomous gate | ✅ | supervised blocks until approval (CLI gate); autonomous explicit opt-in; hard aborts on blast/resource-conflict/deadline **checked in the executor** (`executor.py` bound-abort paths, not only selection layer) — the key safety guarantee |
| **5.7** Rich report | ✅ | `infra/report.py`: `M5Report` with `heatmap`, `coverage_fraction`, `next_to_run` ("what to run next" ranked list), `render_markdown`; evidence links back to runs |
| **5.8** e2e + regression | ✅ | `tests/integration/test_m5_e2e.py` (2 tests), `test_store.py` (8), e2e `test_cli_e2e.py` |

---

## 6. Milestone 6 — Core Chaos Arsenal — ✅ COMPLETE (naming divergence)

Phases 6.1–6.6. ADR-M6-1…M6-6 are **inline in `docs/milestones/milestone-6.md` §2** (no standalone files).

| Phase | Status | Evidence |
|---|---|---|
| **6.1** Process faults `kill/stop/pause` | ✅ | Catalog `process.kill/stop` + `proc.pause` (`catalog.py:25,34,43`); `ProcPauseExecutor` (`agents/executors.py:80-105`, undo SIGCONT `:167-182`); **PID-reuse starttime guard** reads `/proc/<pid>/stat` field 22 (`executors.py:25-39,220-228`); tests `test_executor.py:302,503`, `test_agents.py:130` |
| **6.2** Resource pressure `cpu/mem/disk` | ✅ | **Names differ from doc:** `cpu.saturate`, `mem.exhaust`, `fs.fill` (`catalog.py:52,60,71`), `fd.exhaust` (`:267`) instead of `resource.cpu/memory/disk` — functionally equivalent. Bounded: mem caps at 95% of cgroup `memory.max` (`controller/compensation.py:170`), fs at 1 GiB (`:215`); `PayloadExecutor` undo kills payload + removes markers (`executors.py:253-266`); no leaked allocation asserted post-cancel |
| **6.3** Container lifecycle `restart/pause/kill` | ✅ | Catalog `container.restart/pause/kill`; identity re-resolved pre/post via RuntimeAdapter (TARGET_DRIFT-safe) |
| **6.4** Network faults on `NetworkPath` | ✅ | Catalog `net.latency`, `net.loss`, `net.partition`, `net.load`; `tc-netem` manifest (`toolkit/manifests/tc-netem.yaml`) + `network-path` ownership fingerprint; recovery removes **only the owned fingerprint rule** (not a broad `tc qdisc del`) per ADR-M6-5; `test_fingerprint.py`/`test_network_path_model.py` |
| **6.5** Dependency/database faults | ✅ | Catalog `dependency.block`/`dependency.timeout` (+ `db.slow_query`, `node.service_stop`); toxiproxy manifest (`toolkit/manifests/toxiproxy.yaml`) |
| **6.6** Regression + no-leftover sweep | ✅ | All archetypes have mocked unit coverage; e2e sweep + post-drill clean assertions (janitor/journal); every archetype maps to fingerprint + resource + journal entry per ADR-M6-1 |

---

## 7. Milestone 7 — Kubernetes: Interface-only (by design) — ✅ COMPLETE

Phases 7.1–7.4. Standalone ADR files **absent** (ADR-M7-1…M7-5 inline in `docs/milestones/milestone-7.md` §2); the ADR reference text used by the safety gate is `"k8s execution not yet supported, adapter contract at ADR-M7-1"`.

| Phase | Status | Evidence |
|---|---|---|
| **7.1** `NodeKind.POD` / `K8S_NODE` extensions | ✅ | `domain/topology.py` (`NodeKind.POD`, `K8S_NODE`); planner/capability paths handle them and refuse gracefully |
| **7.2** `KubernetesAdapter` interface contract | ✅ | `domain/k8s_adapter.py` (148 lines, `KubernetesAdapter` + `UNSUPPORTED` placeholder); type-checks; no dead execution code |
| **7.3** Fault categories capacity/network/preemption + matrix rows `UNSUPPORTED` | ✅ | Capability matrix rows default `UNSUPPORTED`; `test_capability_registry.py` |
| **7.4** Optional KinD/minikube stub + regression | ✅ | `@pytest.mark.k8s` tests skip cleanly absent a cluster (`test_m7_k8s.py`); full suite green; k8s execution documented out-of-scope (this is **the intended design**, not a defect) |

---

## 8. Milestone 8 — Generators (load/fuzz/DNS/TLS/stress/deadline) — ✅ COMPLETE

Verified via catalog + manifests + tests:

- **Catalog families present:** `dns.nxdomain`, `dns.resolve_delay`, `tls.certificate_expired`, `load.spike`, `fuzz.protocol_abuse`, `cpu.saturate`, `mem.exhaust`, `fs.fill`, `fd.exhaust`, `db.slow_query`, `node.service_stop`, `net.load`.
- **Load/fuzz/stress generators** are deadline-bounded, cancellable, and clean up (journal/undo paths per M6 evidence); TLS faults carry compensation (`tls.certificate_expired` in catalog + compensation templates; dispatch via `ToolExecutor`/manifests).
- Tests: `tests/unit/test_m8_operations.py`, `test_load_strategy.py`, `test_compensation.py`.
- Executor acknowledges legacy `start_load/stop_load/notify` step actions as "no backend wired yet" (`executor.py:543-545`) — a declared non-goal, not a regression.

---

## 9. ADR coverage vs milestone references

Standalone ADR files that exist: `ADR-M1-1..4`, `ADR-M3-1..8`, `ADR-M4-1`, `ADR-M4-2`, `ADR-M4-5`.

**Referenced by milestones but never written as standalone files** (decisions exist only as inline bullets inside the milestone docs — documentation consistency gap):

| ADR | Where it lives | Result |
|---|---|---|
| ADR-M2-1..7 | inline `docs/milestones/milestone-2.md` §2 | ⚠️ not standalone |
| ADR-M4-3 (SuccessCriteria) | inline `milestone-4.md` §2 | ⚠️ inline-only; **feature implemented 2026-09-05** |
| ADR-M4-4 (observability) | inline `milestone-4.md` §2 | ⚠️ inline-only, **partially implemented** (backbone done; source DSL open) |
| ADR-M5-1..5 | inline `milestone-5.md` §2 | ⚠️ not standalone |
| ADR-M6-1..6 | inline `milestone-6.md` §2 | ⚠️ not standalone |
| ADR-M7-1..5 | inline `milestone-7.md` §2 | ⚠️ not standalone |

**Recommended:** promote the inline M2/M6/M7 ADR blocks (and M4-3/M4-4 once implemented) to `docs/adr/ADR-*.md` files so the ADR index is complete and the safety-gate ADR references resolve to real files.

---

## 10. CLI audit — ✅ WORKS (exit-code taxonomy verified)

Entry point `mayhem = "mayhem.cli.app:main"` (`pyproject.toml`), click `PrefixGroup` (unique-prefix resolution), `no_args_is_help`.

- **Registered commands:** `validate`, `plan`, `run`, `recover`, `history`, `status`, `janitor`, `config`/`cfg`, `experiment`, `topology` (sub: listing), `toolkit` (sub: manifests/registry), `services`, `campaign` (supervised/autonomous, approve/deny).
- **Exit codes** (`cli/exit_codes.py`): 1 `GENERAL_FAILURE`, 2 `USAGE_ERROR`, 3 `CONFIG_ERROR`, 4 `VALIDATION_ERROR` (spec/plan/target/drift/file-not-found), 5 `SAFETY_REFUSAL`, 6 `EX_…` (plus `AMBIGUOUS_COMMAND` for prefix collisions). Root `main()` remaps every typed domain error → documented code; no handler formats codes itself.
- **Verified behaviours:**
  - `--help` and group `--help` render; enum/option validation errors → `USAGE_ERROR`/`CONFIG_ERROR`.
  - `validate` compiles an example drill spec and runs every safety gate without executing.
  - Ambiguous/unknown prefix → `AMBIGUOUS_COMMAND` / `USAGE_ERROR` with candidates listed.
  - `run` requires a live engine (resolve PIDs at execution time per ADR-0020) — expected "requires live env" behaviour; structurally sound, fails with a clean typed error rather than a traceback.
  - `status`/`history`/`config`/`topology` work without a live daemon against the local store.
- **Environment caveat:** no live containers on the audit host (podman binary present, docker absent), so live-drill paths (`run`, e2e compose) were not executed end-to-end here; they are covered by `tests/e2e/test_cli_e2e.py`.

---

## 11. Test suite status — ✅ ALL GREEN (812 passed, 2 skipped, non-nightly)

Re-ran with `.venv/bin/python -m pytest tests -m "not nightly"` (2026-09-05): **812 passed, 2 skipped, 0 failed**.

- **`tests/unit/test_executor.py::TestEndToEnd::test_proc_kill_run_terminates_process_and_releases`** (`test_executor.py:153`) — **now PASSES**: kill→undo→verify recovers with a clean lease and the run reports `completed`; no dirty-lease downgrade observed.
- All other unit + integration tests pass (2 pre-existing skips).

---

## 12. Consolidated defect register (by severity)

| # | Severity | Area | Finding | Evidence |
|---|---|---|---|---|
| 1 | **High** | M4.3 | ~~entirely missing~~ **RESOLVED 2026-09-05**: machine-evaluable `SuccessCriteria` verdict implemented end-to-end | `domain/success.py` (typed criteria union, deterministic evaluation), `executor.py:_criteria_verdict`, `runs.verdict` + M0013, event `CRITERIA_EVALUATED`; `tests/unit/test_success.py` |
| 2 | **High** | M4.4 | **PARTIALLY RESOLVED**: observation/evaluation/persistence backbone done (latency/status measured per check step, verdict + `criteria_json` persisted, `criteria.evaluated` event); **declarative `observability:` source DSL (logs/inspect/probe/metrics collectors) + bounded collectors still missing** | backbone: `StepReport.measured` (`executor.py`), `runs.criteria_json` (M0013); open: no `observability` key on `DrillSpec` |
| 3 | **High** | M6.1/executor | ~~fails~~ **RESOLVED 2026-09-05**: kill→undo→verify recovers cleanly; run reports `completed` | `test_executor.py:153` passes in full re-run (812 passed) |
| 4 | **Medium** | M3.5 | Remote targets have no hard planning gate (only the k8s gate exists) — a remote spec would plan and fail only at execution | `safety.py:199-218` covers POD/K8S_NODE only |
| 5 | **Medium** | M2.4/M3.2 | Run-time capability revalidation does not re-consult the adapter verdict matrix | executor revalidation path |
| 6 | **Medium** | M4.5 | Down-migrations absent — forward-only runner, contradicting ADR-M4-5 "down restores baseline" | `migrator.py:36 run_migrations` |
| 7 | **Low** | ADR docs | ADR-M2-1..7, M4-3, M4-4, M5-1..5, M6-1..6, M7-1..5 not written as standalone files (inline in milestones) | `docs/adr/` listing |
| 8 | **Low** | M3.7 | e2e exercises mocks, not a live DockerAdapter drill; no explicit schema-freeze marker | e2e dir contents |
| 9 | **Low** | M6/Catalog | Archetype family names differ from milestone spec: `cpu.saturate`/`mem.exhaust`/`fs.fill` vs `resource.cpu/memory/disk`; `proc.pause` vs `process.pause` | `catalog.py` |
| 10 | **Low** | M2.5 | `tool_runner.run_tool` primitive still single-shot `subprocess.run(timeout)`; the staged ladder lives at the executor/lease layer only, no process-group kill at subprocess layer | `toolkit/tool_runner.py:76` |

---

## 13. Recommendation order

1. **~~Land M4.3~~ DONE (2026-09-05)**: `SuccessCriteria` verdict implemented, stored (M0013), and tested. Remaining M4 work: the declarative `observability:` sources DSL + collectors (defect #2) and down-migration scaffolding (defect #6).
2. **~~Fix the kill/undo verify path~~ DONE (2026-09-05)**: `test_proc_kill_run_terminates_process_and_releases` passes — clean lease after kill→undo→verify, run reports `completed`.
3. **Add the remote-target planning gate** (defect #4) mirroring `_check_k8s_targets`.
4. **Promote inline ADRs to standalone files** (defect #7) and add down-migration scaffolding (defect #6).
5. Lower-severity naming/coverage items (8–10) can ride along.

*Original audit 2026-09-04; re-audited 2026-09-05 after ADR-M4-3/4-4/4-5 implementation — re-run `pytest tests -m "not nightly"` to re-confirm (currently 812 passed, 2 skipped).*