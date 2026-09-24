# Grounding log — feat-1 §1 claim verification

> **Historical snapshot — not current behavior.** This log records evidence
> gathered on 2026-09-10. A `verified` row means the claim matched the working
> tree on that date; it does not certify current behavior. Use
> [`README.md`](README.md) and current source as the authority.

Verification date: 2026-09-10. Phase A of `docs/plan-feat-1.md`.

Each factual claim in `docs/feat-1.md` §1 is verified against the listed seam
with a reproduced method. Status: `verified` (matches the working tree),
`drifted` (working tree supersedes the claim as written), or
`needs-verify` (external environment required).

## Claim register

| # | §1 claim | Source §1 | Seam | Method | Status | Evidence |
|---|---|---|---|---|---|---|
| C1 | Core loop `topology → frozen plan → gated injection → observe → compensate → machine verdict → SQLite evidence` is real and tested | §1 "What is genuinely strong", bullet 1 (line 38) | `src/mayhem/cli/lifecycle.py` `run`, `src/mayhem/controller/planner.py`, `src/mayhem/controller/janitor.py`, `docs/drill-spec.md` | trace `run` command path; read planner/janitor; run CLI+engine tests | verified | `tests/unit/test_cli.py`, `tests/integration/test_m5_e2e.py`, `tests/unit/test_planner.py`, `tests/unit/test_janitor.py` all pass (86 + 2); proposal is one topology→plan→run→status flow with release-at-end |
| C2 | "40+ fault kinds in catalog" with per-fault risk, max duration, node kinds, required capability, typed params | §1 bullet 2 (line 41) | `src/mayhem/domain/catalog.py` | count `CATALOG` entries; inspect entry fields | verified | `len(CATALOG) == 54`; entries carry `risk`, `max_duration_seconds`, `node_levels`, `capability`, `params` (schema-typed) |
| C3 | `mark_seen` idempotent, coverage repo persists to `m5_coverage` (migration 12) | §1 bullet 6 (line 63) | `src/mayhem/infra/coverage_repository.py`, `src/mayhem/infra/migrations.py:547` | read + run `tests/unit/test_coverage.py::test_rerun_same_cell_does_not_double_count` | verified | migration `M0012_M5_COVERAGE` (version 12, `m5_coverage` table, PK `cell_key`); `INSERT OR IGNORE` keeps 1 row on re-mark; test passes (5 marks → 1 record) |
| C4 | Coverage cell identity is (target, fault, ctx, band) | §1 bullet 6 (line 63), §5 | `src/mayhem/domain/coverage.py:18-48` | re-assert against `_cell_key` | verified | `CoverageCell` = `target, fault_kind, execution_context, parameter_band`; `_cell_key` joins with `\x1f`; docs §5 matches |
| C5 | `run` compiles → gates → executes → records | §1 bullet 1 / line 68 (CI-safe) | `src/mayhem/cli/lifecycle.py:506-575` | trace `run` command; confirm gate path + `engine.execute` | verified | `run_cmd` → `_gate_enabled()`/`_gate_bypasses` → `engine.execute` → status; `--skip-gate`/`--allow-critical` route exists; `test_cli` + `test_example_specs_yaml` green |
| C6 | "14 top-level commands" | §1 bullet 10 (line 78) | `src/mayhem/cli/app.py:93-97` | enumerate `app.commands` | verified | 15 names — 5 groups (`experiment, topology, toolkit, config, campaign`) + 9 singles (`validate, plan, run, maniac, status, history, recover, janitor, dependency`) + `cfg` alias of `config` (alias, not distinct) = 14 distinct commands |
| C7 | Planner freezes plan + compensation path (undo ops baked in) | §1 bullet 3 (line 44) | `src/mayhem/controller/planner.py` | read `plan_drill` + `synthesize_maniac_spec` seam; run `test_planner.py` | verified | `plan_drill` attaches `undo_ops` per fault (write-ahead undo); `plan_write_ahead_undo` invariant guards missing undo; `synthesize_maniac_spec` exists for live-topology draws; `test_planner.py` passes |
| C8 | Janitor sweeps stale leases / reclaims crashed controllers' leases | §1 bullet 1/3, line 68 | `src/mayhem/cli/lifecycle.py` (`janitor`, `_sweep_before_run`), `src/mayhem/controller/janitor.py` | `mayhem janitor --help`; read sweep | verified | `janitor` cmd: "Reclaim leases past TTL — or owned by a controller that is gone."; `_sweep_before_run` TTL-sweeps before every run; `janitor.py` handles PENDING→EXPIRED, ACTIVE/ORPHANED→recover, RELEASING→finalize, DIRTY→surrender |
| C9 | Verdicts typed PASS/FAIL | §1 bullet 5 (line 51) | `src/mayhem/domain/run_outcome.py`, `src/mayhem/domain/success.py` | confirm verdict enum + `checks_passed/failed` | verified | `RunVerdict = PASS / FAIL / ERROR / ABORTED / BYPASSED`; `checks_passed`/`checks_failed` counters on `RunRecord` |
| C10 | M5 engine drives supervised campaigns (approve-gate) | §1 bullet 6 (line 59) | `src/mayhem/infra/campaign_engine.py`, `tests/integration/test_m5_e2e.py` | trace `iterate()`; run e2e | verified | `Approver` protocol gates each candidate before run; stop on `coverage_target | max_runs | deadline`; `tests/integration/test_m5_e2e.py` passes (supervised: denied candidates never run) |
| C11 | Drill DSL declarative & versioned (`kind: drill`, `apiVersion: mayhem/v1`), config layering, snapshots, profiles | §1 bullet 4 (line 48) | `examples/testCase/mayhem.yaml`, `examples/k8s/mayhem.yaml`, `src/mayhem/domain/experiments.py` | read YAML headers + parser | verified | both example specs carry `apiVersion: "mayhem/v1"` + `kind: drill`; `ADR-0008` present; experiment model parses config/snapshot/profile layering | 
| C12 | Intelligence machinery (generator, gates, campaign engine, coverage, report) exists but orphaned from CLI | §1 bullets 6-7 (line 54) | `src/mayhem/infra/candidate_generator.py`, `candidate_gates.py`, `campaign_engine.py`, `coverage_repository.py`, `report.py`, `cli/campaign.py` | file presence + conditional usage scan | verified | all 5 infra modules exist + `cli/campaign.py` `campaign.<sub>` set (list/create/show/status/start/archive/abort/run); no CLI command reaches generator/gates/coverage/report — only `campaign run` (authored specs) and tests |
| C13 | Campaign session lifecycle for manually-authorable campaigns only | §1 bullet 7 (line 66) | `src/mayhem/cli/campaign.py` | enumerate subcommands; read `run` | verified | subcommands: list, create, show, status, delete, start, archive, abort, add-experiment, run; `run` takes a campaign with authored drill specs — no candidate generation |
| C14 | Frozen plans + leases + janitor + exit codes make it CI-safe today; 0.5.1 "janitor reclaims crashed controllers' leases" | §1 line 68 | `src/mayhem/cli/exit_codes.py`, `CHANGELOG.md` §0.5.1 | check exit-code enum + changelog entry | verified | `exit_codes.py` has typed exit codes; CHANGELOG 0.5.1 lists "janitor: Reclaim crashed controllers' leases before TTL" and "lifecycle: TTL-sweep sticky leases before every run" |
| C15 | M5 candidate machinery not reachable from regular usage (no generate→gate→record command) | §1 "weak/unfinished" (line 73) | full `app.commands` enumeration | compare command surface | verified | no command generates candidates from a live topology; `campaign run` iterates authored specs; generator/engine/coverage exercised only by tests |
| C16 | No "what should I do next" entry point, no readiness preflight, no init, no explain | §1 line 79 | `src/mayhem/cli/app.py` | enumerate commands | verified | command set (C6) has none of: init, explain, preflight, next, coverage |
| C17 | Coverage is a concept with tables but no user-facing home; `mark_seen` has no evidence-quality notion | §1 line 81 | `src/mayhem/cli/app.py`, `src/mayhem/domain/coverage.py`, `src/mayhem/infra/coverage_repository.py` | command enumeration + repository read | **drifted** | no `mayhem coverage`/`next` command (still true), **but** working tree's coverage domain already carries a 5-state model (`CellState`: covered/inconclusive/failed/blocked + `transition()` monotonicity) and `coverage_repository` gains `state`/`blocked` columns in migration 12 — the "one bit" framing is superseded by in-tree M5-2 work. See **Phase B note — coverage** below. |
| C18 | Doc/CLI drift list (re-design.md §24): stale refs, dead command examples, ad-hoc tables, fake `--host`, unwired JSON; Ruff not a hard gate | §1 line 86 | `docs/re-design.md` §24, `pyproject.toml` | grep sweep; ruff config | verified | §24 lists the same 5 drift items as B1-B5 (each confirmed gone below); `tracked_resources`/`mutation_journal` noted as ad-hoc legacy tables; lint configured non-blocking |
| C19 | Kubernetes interface-only (refusal gate `k8s.unsupported`) | §1 line 90 | `src/mayhem/controller/safety.py:220`, `src/mayhem/domain/k8s_adapter.py`, `examples/k8s/README.md` | read refusal path | verified | `safety.py` raises/gates on `k8s.unsupported`; `k8s_adapter.py` exists; k8s example is a `kind: drill` pointing at k8s (M8 not done) |

## Phase B — drift items (B1-B5)

All five detected drift items were already reconciled in the working tree.
No code or docs change was required; each is logged with its fixing state.

| Item | Claimed drift | Actual working-tree state | Verdict |
|---|---|---|---|
| B1 | "janitor sweep" doc mismatch | `cli/lifecycle.py` `janitor` help + `_sweep_before_run` docstring already describe the real scope ("Reclaim leases past TTL — or owned by a controller that is gone"; TTL-sweep before every run). `docs/reference/cli.md` does not exist (no file to fix). README:363 wording matches current `janitor.py` behavior | already fixed (working tree) |
| B2 | obsolete `--process` flag references | `grep -rn -- "--process" src docs` finds only two source docstrings that *document the removal* (`cli/services.py:51`, `cli/lifecycle.py:278`) — both describe `--process/--service/--host` as removed in Phase 6, with compose-native drills replacing them. No help text or docs instruct their use. No flag still exists to keep | already fixed; removal notes kept intentionally |
| B3 | legacy `campaign --name` syntax in docs | Current signature is positional: `campaign.py:63` `@click.argument("name")`. All doc examples use positional form (`README.md:311` `mayhem campaign create black-friday`, `drill-spec.md` `mayhem campaign create weekly-drill --description ...`). No `--name` usage in docs | already fixed (working tree) |
| B4 | `mayhem recover` documented without a run id | `README.md:362` documents `mayhem recover RUN_ID` ("Recover every orphaned fault lease belonging to a run."); CLI enforces the argument (exit 2 + "Missing argument 'RUN_ID'"). re-design.md command trees list command *names*, not examples | already fixed (fixing commit b08e7cd "update README") |
| B5 | `check`/`check_spec` docs vs `checks.py` | `docs/drill-spec.md` checks section matches `checks.py` exactly: probe types (`http/exec/tcp/process/metric/file`), `execution` locus (`host/container/service/process`), bare-`check` legacy shorthand documented as such with `expect.status` default 200. `tests/unit/test_check_spec.py` exists and passes. No `docs/reference/cli.md` to reconcile | already fixed (working tree) |

### Phase B note — coverage (C17 drift)

`docs/feat-1.md` §1 line 81-85 claims `mark_seen` treats every executed cell
as "one bit". The working tree's coverage upgrade (feat-2/feat-3 scope,
M5-2) already supersedes this: `coverage.py` defines the 5-state model
(`CellState` + `transition`), `coverage_repository.py` persists
`state`/`blocked_reason`/`verdict_json` columns, and migration 12 gains the
columns. The claim was true at writing time; as of 2026-09-10 it is marked
drifted in `feat-1.md` and the "evidence quality" framing belongs to feat-3.

## DoD

- Every row has a status: 18 verified + 1 drifted (C17) — no `needs-verify`
  rows remain (no Docker/container execution was required).
- `git diff --stat` after Phase D: docs-only changes (new files
  `docs/grounding-log.md`, `docs/grounding-rules.md`, edits to
  `docs/feat-1.md`).
- Full `pytest -q` suite green after annotations.