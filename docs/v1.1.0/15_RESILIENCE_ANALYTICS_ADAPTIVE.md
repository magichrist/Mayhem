# Plan 15 — Resilience Analytics and Adaptive Experiments

**Priority:** P1/P2. Gap items 25, 52, 53, 90, 91, 92, 93, 94, 95, 96.

## Objective
Move from binary chaos testing toward quantitative resilience characterization: statistics, causal chains, progressive delivery, and bounded search for resilience limits — with the AI strictly unable to reach execution authority.

## Builds on
- The graded verdict plus `no-effect`/`not-recovered` semantics and percentile-based baseline reduction stay the statistical core; new analytics extend them.
- `infra/kpi.py`, `infra/ranking.py` (RNG-free), and the M5 report builder stay the analysis substrate.
- Existing steady-state phases (pre/during/post) gain warm-up/cooldown handling; they are not replaced.

## Analytics
Baseline distributions, percentile comparison, effect size, confidence
intervals, noise estimation, sample sufficiency, warm-up/cooldown,
change-point/anomaly detection. A verdict reads like "p99 moved 5.2%
with overlapping 95% CI — NO MATERIAL EFFECT", never "520ms → FAIL".

## Resilience boundary search
Start with a small impairment and increase until the declared tolerance
is crossed (`1% loss -> 5% -> 10% -> 20%`), then minimize the boundary
(`20 -> 10 -> 5 -> 2.5 -> 3.75 -> 3.1 ...`).

## Counterexample minimization
When a complex experiment fails, automatically search for the smallest
fault/target combination that reproduces the failure.

## Progressive delivery (gaps 90, 91)
Single target → 5% → 10% → 25% → 50% stage gates (canary faulting),
each stage requiring SLO health before promotion, with automatic stop
on breach. Stages are plan-level constructs compiled from one
experiment, not ad-hoc reruns.

## Outputs
Tolerance boundary, minimal failure case, recovery curve, resilience
trend over releases, confidence/uncertainty.

## Phase 1 — Domain model: statistics and search policies
Add `domain/analytics.py`: distribution summaries, comparison results with confidence intervals, sufficiency predicates; add `domain/search.py`: `SearchPolicy` (start, step, stop-on-breach, minimization strategy, combination budget for gap 95), all pure over recorded observations. AI-generated candidates (gap 25) modeled as untrusted drafts: same type as authored plans, zero authority. Acceptance: statistics tests on fixture streams; search-policy determinism tests.

## Phase 2 — Engine: analysis service and adaptive runner
Analysis service computes boundaries, curves, and causal chains (gap 53: fault → target → dependency → metric change → customer impact as a traced path over observations plus topology). Adaptive runner executes search policies as sequences of approved micro-plans, each through full admission with remaining-budget checks — search respects safety budgets at every step, and budget exhaustion halts with findings so far. Progressive stages compile to gated step groups. Acceptance: a search that breaches tolerance stops and reports the boundary; an AI draft that fails compilation never reaches policy evaluation.

## Phase 3 — Surface: boundary reports and candidate review
Boundary reports (service tolerates latency ≤ X, loss ≤ Y with confidence), minimal-failure-case reports, candidate review flows where generated plans face identical validation, policy, impact, approval, and evidence gates as authored ones. Acceptance: generated and authored plans are indistinguishable downstream of compilation (same types, same gates).

## Phase 4 — Safety and evidence integration
Every search step individually admitted, budgeted, and evidenced; AI assistance cannot bypass safety or approval gates (architectural rule, tested not asserted); causal claims cite the observations plus topology edges that support them. Acceptance: an end-to-end adaptive run whose every step traces to evidence and budget entries.

## Phase 5 — Tests, regression guards, negative controls
Statistics unit tests (CI overlap logic, sufficiency thresholds), search tests on simulated response surfaces (finds planted boundaries; minimizes planted counterexamples), AI-boundary tests (draft with embedded approval token rejected; direct-execution attempt from advisor context refused). Negative controls: a search without a remaining budget refuses its next step; a causal claim over missing edges is withheld, not guessed. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Statistics interpretation guide (what "no material effect" does and does not mean), boundary-report reading guide, advisor methodology doc (priority from declared customer criteria, never opaque ranking). Rollout: analytics first, progressive stages second, boundary search third, minimization and AI candidates last. Acceptance: no doc presents a boundary as a guarantee across releases (that claim belongs to 22 regression tracking).

## Dependencies
07 (budgets per step), 11 (observations, tolerances), 14 (topology edges for causal paths), 21 (advisor inputs), 22 (trend storage).

## STATUS
- Phase 1 (domain model): DONE — `domain/analytics.py` (distribution summaries, effect size, 95% CIs, sufficiency, warm-up/cooldown) and `domain/search.py` (`SearchPolicy`, pure step planning with stop conditions, untrusted AI drafts) landed with unit and negative-control tests
- Phase 2 (engine): DONE — `controller/analytics_service.py` (boundary brackets with a confidence statement, recovery curves, minimal failure cases, gap-53 causal chains where an uncited hop is withheld, the adaptive runner with per-step approval + admission + budget, and `compile_stages` for the single-target → 5% → 10% → 25% → 50% gated ladder)
- Phase 3 (surface): DONE — `cli/boundary_report_cmd.py` landed as the `mayhem boundary` group with two read-only commands: `boundary report --search FILE [--signal NAME]` renders a recorded search (each declared metric gets its **own** boundary, from one `boundary_report` call over that metric's own ladder) with the engine's own confidence sentence attached and the minimal-failure-case reduction, and `boundary review --candidate --policy --spec --graph [--deny-fault]` compiles an untrusted draft through `compile_candidate` and then takes the authored drill *and* the derived micro-drill through a single `_gate(spec, ...) -> plan_drill → compile_safety_evidence → simulate_plan_policy` core that has **no origin parameter**. The acceptance criterion is structural rather than a string comparison: both arms leave `_gate` holding the same `ExecutionPlan` type, the suite spies the three gate functions and asserts the recorded sequence is exactly `GATE_PATH` twice, and `plan_shape_digest` — the plan's digest with the planner's per-call `execution_group_id` held out, because no two `plan_drill` calls are ever byte-identical — is equal for a candidate proposing the rung the authored drill already encodes. A boundary whose confidence is insufficient never renders as a tolerance: `_tolerates` is the only thing that can emit that word, it gates on the domain's own `Comparison.sufficient`/`graded`, and it refuses when the ladder crossed without a separable measurement behind it. A refusal at the view-model layer raises `BoundaryViewRefused` with a stable rule id (unknown document field, blank/non-finite/unknown ladder value, undeclared signal, a spec that will not compile) and the Click callback only reports it. 88 tests in `tests/unit/test_boundary_report_surface.py` cover the documented invocations, the two negative controls on confidence and on support-withholding, the identical-code-path spy, the identical-shape-digest proof, the AST checks that this surface never constructs a `SearchPlan` with an approval and never re-declares an authority scan, six refusals on a draft that tries to carry authority, and mutation evidence measured against the caller's own `SafetyContext` (both probes run on clones, so `ctx.decisions` stays empty and the view reports the length) plus a filesystem assertion that neither command opens a store
- Phase 4 (safety and evidence): DONE — the runner's own per-step budget check is live via a documented `planner_budget` (the budget the planner plans against, separate from the budget the runner spends) with the divergence recorded on the run and in the step's own stamped reading; every boundary report, recovery curve, minimal failure case, and causal chain now carries its support (trial digests, sample digest, tried-case digests, observation citations plus topology edges) and seals through `infra/attestation_store` with `require_sealed_claim` refusing an unsealed report; a claim with no support cannot be constructed (`analytics.evidence_unsupported`) and a report with no support is sealed as a withholding beside the claims that survived; an adaptive run carries a `SearchRecord` and `record_boundary_search` writes it to `infra/audit_stream` as `audit.resilience_boundary.searched` with the policy digest and the escalating ladder, and `require_recorded_search` refuses a search the stream cannot show; the AI boundary is unchanged — `AUTHORITY_FIELDS`/`_authority_keys` are still the single authority scan and neither `AnalyticsClaim` nor `SearchRecord` has a field an approval could travel in
- Phase 5: DONE — **the phase's named list was already covered by five existing suites**, and the `not started` status was stale rather than the work being absent: CI overlap logic (`test_interval_overlap_is_symmetric_and_touching_counts_as_overlap`), the sufficiency threshold (`test_sufficiency_threshold_is_the_five_sample_floor`, `test_a_comparison_on_too_few_samples_is_marked_insufficient_not_scored`), search over a simulated response surface with a planted boundary (`test_a_planted_boundary_is_found_and_narrowed_onto`) and planted counterexample minimisation (`test_counterexample_minimization_needs_a_reproducer`, `test_counterexample_minimization_starts_from_a_known_reproducer`), the AI boundary (`test_a_draft_with_an_embedded_approval_token_is_rejected`, `test_a_nested_approval_token_is_rejected_too`, `test_a_compiled_candidate_is_never_constructed_with_an_approval`) and both of the phase's own negative controls (`test_a_search_with_no_remaining_budget_refuses_its_next_step`, `test_a_chain_over_a_missing_edge_is_withheld_not_guessed`). What was genuinely missing is the discipline the completed plans record — proving those properties are **load-bearing** — so `tests/unit/test_analytics_negative_controls.py` (12) supplies it: the **materiality floor decides**, shown in both directions on identical data (material rise at a 5% floor, no material effect at 95%), which is what makes every "no material effect" sentence a statement about the reader's threshold rather than the data's mood; **per-series overlap decides nothing**, shown as a matched pair disagreeing in opposite directions (disjoint intervals yet immaterial, overlapping intervals yet material), each phrase naming the difference interval that decided it; **insufficient data withholds rather than widens**, asserted from below the five-sample floor (no effect size, no interval, no delta, phrase ends `— NOT GRADED`) against five samples where the same comparison is graded, and against four where it is *still* insufficient — the floor is per series, and getting that wrong would have made the pair look like a crossed threshold; the **budget backstop** pinned from both sides (identical policy and history, exhausted refuses with `no-remaining-budget`, unexhausted proceeds, so a search that refused everything could not pass); a **missing** budget refused rather than read as unlimited; and the **planted boundary is bracketed, not landed on** — minimization narrows toward 8.0 without walking it, so the test asserts a clean value below and a breached value above, and a surface that never breaches stops `ladder-exhausted` rather than reporting a boundary. The two properties living behind the engine's ports (causal-chain withholding, approval-token rejection) are guarded by **name-pin** rather than rebuilt, and the test docstring says so rather than dressing a weaker check up as the real thing.
- Phase 6: DONE — three guides written into this document below the ledger and asserted rather than left to review. **Statistics interpretation guide**: that "no material effect" is a statement about the *declared threshold* (identical data, material at a 5% floor and immaterial at 95%), that it is not "no effect" (7.7% material against a 5% floor, 14.9% immaterial against 15%), that the graded verdict follows the **difference** interval and never the per-series overlap, and that insufficient data is **no answer** rather than low confidence — with the reason a point estimate plus a widening interval would be the dishonest shape. **Boundary-report reading guide**: read the bracket rather than the last value, read the stop reason (all nine `StopReason` values enumerated, with `ladder-exhausted` called out as the one most often misread as a clean bill of health), and the explicit limit that a missing bracket is not a safe service — a boundary is scoped to *this fault, these values, this budget, this surface* and is not a guarantee across releases, which belongs to plan 22. **Advisor methodology doc**: priority as the weighted mean of declared criteria with a mandatory customer question, no score field to inject into, three reading refusals so no priority is imputed, read-only by structure rather than procedure. **Rollout order** as the phase specifies. The acceptance criterion "no doc presents a boundary as a guarantee across releases" is met and enforced: `tests/unit/test_analytics_plan_docs.py` (7) parses this document, cross-checks the `Overall:` count against the `DONE` lines, requires the three guides, and refuses four literal claims — including any sentence calling a boundary a guarantee across releases — with each checker proven to bite against a mutated copy.

Overall: 6 of 6 phases complete.

### Open items Phase 4 could not close in its own files
(one of the two has since been closed by the plan-30 integration pass; the other is still open)
- `KIND_RESILIENCE_BOUNDARY_SEARCHED` is declared in `controller/analytics_service.py`, not in `infra/audit_stream.py`'s closed `KIND_*` vocabulary. It belongs there; the audit module is not owned by this phase.
- Four new gate rule ids needed entries in `controller/safety_proof.py`'s `OBLIGATION_FOR_RULE` and `controller/check_gate.py`'s `RULE_CHECK`, or a refusal carrying them voids the proof by that module's own fail-closed rule. **CLOSED** — all four rows landed, in both tables, in the plan-30 integration pass:

  | rule id | obligation | check scope |
  | --- | --- | --- |
  | `analytics.planner_budget_diverged` | `damage_budget` | `DAMAGE_BUDGET` |
  | `analytics.step_unaffordable` | `damage_budget` | `DAMAGE_BUDGET` |
  | `analytics.evidence_not_sealed` | `required_approvals` | `SAFETY_POLICY` |
  | `analytics.search_not_recorded` | `required_approvals` | `SAFETY_POLICY` |

  Each obligation is as this section proposed. Two notes the tables record rather than leave to be inferred. First, the two budget rules are `damage_budget` because `step_affordable` spends `BudgetKind.DAMAGE_SECONDS` unless a caller asks for another kind — with `STEPS` or `COMBINATIONS` the quantity is a search budget rather than a damage quota, and `damage_budget` is still the only budget line in the nine-name spine. Second, the two evidence rules are `required_approvals` but not for the plan-09 reason: `require_sealed_claim` and `require_recorded_search` refuse a *decision* or a *search* whose backing claim is not in a verified chain and not in the cross-run audit stream. Nobody signed anything in either case, and both are about the question that line reports — may this decision proceed on what stands behind it.

  Proved by `tests/unit/test_owed_rule_mappings.py` (40 tests), which asserts each of the four rows against both tables **and** reads every module under `src/mayhem` to prove the rule id is one the code actually spells. The second assertion is the one that matters: it is what would fail if one of these ids were a docstring-only spelling rather than a real refusal.

  `analytics.evidence_unsupported` is still correct and is still unmapped: it is raised in `AnalyticsClaim.__post_init__` and the report constructors, so an unsupported claim is never *built*, and there is no gate decision for a proof line to report.

### Open items Phase 3 could not close in its own files
- **The group is not registered.** `cli/boundary_report_cmd.py` exports `boundary` and nothing imports it; integration has to add `from mayhem.cli.boundary_report_cmd import boundary` to `command_registry.register_commands`, a `CommandSpec("boundary", "run", help_group="experiments")` row, a `COMMAND_HELP["boundary"]` entry, and the `command_map` line. Until then `mayhem boundary` does not dispatch and `test_command_inventory.py` / `test_cli_active_surface.py` / `test_cli_exhaustive_matrix.py` (which pin the top-level command set to exactly 19 names) will fail on the new name and need the matching allowlist line each. This phase's own suite invokes the group directly for exactly that reason.
- **No persistence.** Neither command reads or writes a database, so a boundary report is rendered from a document the caller supplies, not from a stored run. `infra/migrations.py` is not owned here, and the four documents (`--search`, `--policy`, `--spec`, `--graph`) are the surface's whole input surface until a store table exists. The search document is deliberately the raw ladder-plus-samples shape rather than a finished report; giving it a store home is Phase 5's call.
- **Recovery curves are not rendered.** `boundary report` renders the boundary, the per-metric tolerances, and the minimal-failure-case reduction. `recovery_curve` is Phase 2's and this phase's acceptance names neither recovery nor the causal chain, so the recovery section of `ResilienceAnalysis` is left empty here and `analyze_run` says so in its own notes ("no recovery curve was supplied: recovery is unreported, not clean"). A report that never claimed recovery is not one that reported it clean.
- **The plan-09 approval gate is not reachable.** `boundary_review_safety_context` configures no `approval_gate` and no `policy_gate`, so the proof's `required_approvals` line reports *requirements* and nothing more, and the policy state renders as `no_bundle_configured` rather than "allowed". That is the same standing `cli/advisor_cmd.py` takes and for the same reason; a context carrying either would have to come from a caller that has witnesses, which a CLI does not.
- **No `--force`, no ceiling flags, no store.** A candidate that would fail a gate is refused by that gate and the refusal names its rule id; `--deny-fault` exists because it can only *tighten*; the four blast-radius ceilings are module constants because a caller handed the ceiling is handed the gate that checks it.


## Statistics interpretation guide — what "no material effect" does and does not mean

This is the sentence operators will quote in an incident review, so it is worth
being exact about what it claims.

**"No material effect" is a statement about your declared threshold.** The same
two series read as a material rise at a 5% floor and as no material effect at a
95% one. Nothing about the data changes between those verdicts; only the number
the customer declared does. So the phrase is never "nothing happened" — it is
"nothing cleared the bar you set", and the bar travels with the report
(`materiality_pct` is echoed in the note, so a reader can see which one was used).

**"No material effect" is not "no effect".** A 7.7% move that clears a 5% floor
is reported as a material rise; a 14.9% move against a 15% floor is reported as
no material effect. An effect large enough to care about can be called immaterial
by a threshold chosen deliberately high, which is a legitimate configuration and
not a contradiction. Read the floor first, then the verdict.

**The graded verdict follows the *difference* interval, never the overlap.** Two
fixtures disagree with the per-series overlap in opposite directions: one where
the per-series confidence intervals are disjoint and the difference interval
contains zero (no material effect), and one where they overlap and the difference
interval excludes zero (material rise). `intervals_overlap` is reported because
operators want to see it, and it grades nothing. Each verdict phrase names the
interval that decided it — "on the difference containing zero", or "difference CI
excluding zero" — so the sentence carries its own reasoning.

**Insufficient data is not low confidence — it is no answer.** Below five samples
in either series the comparison reports **no quotable number at all**: no effect
size, no difference interval, no baseline interval, not even the movement
percentage, and the phrase ends `— NOT GRADED`. This is deliberate. An
insufficient comparison rendered as a point estimate with a wider interval would
give a reader a number to quote, one whose confidence interval becomes
comfortable only as the sample grows past a threshold the comparison was never
allowed to cross. Absence is the honest output; "not graded" is the honest word.
A zero baseline is likewise reported without a relative scale rather than as a
percentage against nothing.

## Boundary-report reading guide

A boundary report answers one question: **where does this service stop
tolerating this fault?**

**Read the bracket, not the last value.** The search brackets the boundary
between a clean value below it and a breached value above it; it does not land
on it. Minimization narrows toward the planted value, so the reported boundary
is an interval you can defend, and the walk that produced it is recorded. A
report quoting a single "boundary = 8.0" is over-claiming relative to what the
search measured.

**Read the stop reason.** The search ends for a named reason and every value of
the vocabulary is a stop *with findings attached*: `boundary-resolved` (a
boundary was bracketed and narrowed), `ladder-exhausted` (the declared ladder ran
out before anything breached — **not** a finding of safety), `breach-found` (a
sweep past the boundary with no narrowing), `no-reproducer` (minimization asked
for and could not start), `no-remaining-budget`, `combination-budget-exhausted`,
`insufficient-measurement`, `no-further-value`, and `max-steps`. A ladder that
ran out is the one most often misread as a clean bill of health.

**A missing bracket is not a safe service.** If the ladder was exhausted with no
breach, the search learned that *this fault, at these values, within this
budget, on this surface* did not breach. It is not a guarantee across releases,
across fault variants, or across a different environment — that claim belongs to
plan 22's regression tracking, which compares sealed runs, and this document
does not make it.

**Budget is part of the result.** The remaining budget travels with each planned
step, and a search with no remaining budget refuses its next step rather than
proceeding. An exhausted budget is a stop reason, not a silent truncation: a
boundary found at 80% of the budget is a real boundary, and one *not* found at
100% is an absence of evidence.

## Advisor methodology doc — priority from declared criteria, never opaque ranking

The boundary report's ranking, and the advisor's priority, come from the same
principle: **a number a reader cannot interrogate is a number they must trust
blindly**, and a resilience tool whose output must be trusted blindly is a
black box with a decimal point.

- Priority is the **weighted mean of customer-declared criteria**, and the
  declaration carries a question per criterion — "how many customers meet this
  failure in a normal week?", not "impact". An empty declaration is refused
  rather than defaulted, and there is no score field anywhere in the type, so
  there is nothing for a ranking to be injected into or frozen at.
- A reading without evidence is refused; so is a reading about a criterion the
  declaration does not name, and a criterion nobody supplied a reading for.
  Mayhem does not impute a customer's priorities, because an imputed value would
  be indistinguishable from a stated one.
- The advisor runs **read-only**, and that is structural rather than procedural:
  its execution context holds no mutation backend and no lease sink, so there is
  no call site through which it could dispatch anything.
- A generated candidate faces the identical compilation, safety-proof and policy
  gates as one a human typed, and a draft carrying an embedded approval token —
  or a nested one — is rejected before it reaches any of them.

## Rollout order

Analytics first, progressive stages second, boundary search third, minimisation
and AI-generated candidates last. Each stage is worth more than the one after it,
and the order is chosen so that the tool earns trust with the boring arithmetic
before it proposes anything.

**Honest limits.** No boundary in this plan has been measured on a production
system; the suites search a *simulated* response surface with a boundary planted
in it, which proves the search finds a boundary it is given and does not report
one when there is none. Statistical independence is assumed by these intervals
and is not verified here. Nothing in this document presents a boundary as a
guarantee across releases — that claim belongs to plan 22.
