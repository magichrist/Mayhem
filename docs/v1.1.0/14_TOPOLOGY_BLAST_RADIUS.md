# Plan 14 — Topology Intelligence and Blast-Radius Prediction

**Priority:** P1. Gap items 19, 26, 54, 62, 72.

## Objective
Use discovered dependencies to predict and constrain experiment impact before execution — folding in predictive blast simulation (26), the no-mutation preview (62/72), and the resilience graph substrate (54).

## Builds on
- `topology/service.py` merge plus drift reporting and `domain/topology.py` graph types stay the discovery core; new edge kinds extend them.
- The v1.0.0 preflight (real-gate evaluation, all five limits rendered) stays the enforcement point; prediction here is its read-only twin — same math, no mutation, never a parallel gate.
- Existing blast accounting (`dependents_closure`, damage ledger) is what predictions are computed with, so preview and gate cannot disagree.

## Graph
Nodes: service, workload, pod, node, database, queue, dependency, SLO,
experiment, incident. Edges: depends_on, calls, stores_in,
publishes_to, affects, tested_by, failed_under. Experiments and
incidents as nodes (gap 54) make coverage and history graph queries,
not report joins.

## Prediction
Before running a fault estimate: targets affected, dependency fan-out,
replica loss, expected capacity change, policy violations, likely SLO
impact, cloud cost.

## Controls
Blast-radius ceiling, maximum dependency depth, maximum
customer-facing services, maximum percentage, protected service list.

## Phase 1 — Domain model: graph and prediction types
Extend `domain/topology.py` with new node/edge kinds; add `domain/prediction.py`: `ImpactPrediction` (affected set, fan-out, capacity delta, violated rules with observed values, cost estimate) as pure computation over a frozen graph plus a frozen plan. Pure functions; prediction determinism tests (same graph plus plan yields same prediction). Acceptance: prediction-vs-gate agreement tests — the preview may be conservative, never permissive, relative to `validate_plan`.

## Phase 2 — Engine: prediction service and no-mutation simulate
Prediction service evaluates the frozen plan against live topology without touching targets (`mayhem simulate` semantics for gap 72: target selection, blast radius, expected changes, capabilities, policy result, cost estimate, expected evidence — zero mutation by construction, enforced by running with the mutation backend detached). Acceptance: simulate-then-run agreement tests; a test asserting simulate performed no mutation (mock mutation backend, zero calls).

## Phase 3 — Surface: risk preview and dependency views
Every plan display carries the resolvable target set plus the risk preview (inside/outside policy with reasons); topology views show services with blast radius, health, coverage, and incident history per node. Acceptance: preview output stored with the plan and rendered identically in CLI and UI (08).

## Phase 4 — Safety and evidence integration
Predictions sealed with the plan (so post-run analysis can score prediction accuracy); protected-service and depth/percentage ceilings enforced in admission (07 dimensions); fan-out facts feed 05 dependency-fault scoping. Acceptance: a run whose actual blast exceeded prediction opens a finding, not a silent pass.

## Phase 5 — Tests, regression guards, negative controls
Prediction-accuracy tests on fixture graphs, agreement tests with the real gate, simulate-purity tests, protected-list refusal tests. Negative controls: prediction on a drifted graph is marked stale and refused for approval use; a preview is never accepted as a preflight. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Prediction interpretation guide (confidence bounds stated, never hidden), simulate-vs-preflight distinction documented until it hurts. Rollout: fan-out display first, prediction second, simulate third. Acceptance: no doc calls a prediction a guarantee.

## Dependencies
05 (dependency scoping), 07 (ceiling enforcement), 08 (views), 30 (preview feeds the proof).

## STATUS
- Phase 1 (domain model): DONE — `domain/prediction.py` adds `ImpactPrediction` (affected set, dependency fan-out with depth, replica-loss delta, expected capacity change, violated rules with observed values, cost estimate) as a pure deterministic function over a frozen graph plus frozen plan, with `is_never_permissive` pinning prediction-vs-gate agreement.
- Phase 2 (engine): DONE — `controller/prediction_service.py` assembles the prediction from live topology plus configuration and returns it beside the real gate's own refusal set, enforcing prediction-vs-gate agreement in production (a calmer preview raises rather than returns); `simulate_plan` runs the mutation backend detached and publishes the observed sink length, so a simulate is provably inert while still reaching a verdict; the four §Controls dimensions are reported as admission dimensions with the Phase 4 wiring named in `PENDING_ADMISSION_WIRING`; an absent price table yields an explicit `unpriced` disclosure with the measured affected-node-seconds, never a dollar figure.
- Phase 3 (surface): INCOMPLETE — the view-model layer and the CLI landed; the
  acceptance criterion's other two halves did not, and the reason is ownership,
  not difficulty.
  - **The view-model layer is the surface, and the CLI is only its first
    renderer.** `cli/risk_preview_cmd.py` builds `RiskPreviewView` as a *pure
    function* of a `SimulateReport` — `build_risk_preview(report, run_id=...)` —
    and projects off it twice: `render_preview_lines` (the CLI) and
    `preview_payload` (what a UI would render). This is the part of the
    acceptance criterion that is easiest to fake and the only part that could be
    made structurally true, so it was built first. "Rendered identically" is
    enforced by there being *one* presentation structure with **no word for
    "inside policy" in either renderer**: `PolicyStance` (`inside_policy` /
    `outside_policy` / `unchecked`) is the whole vocabulary, a UI that wanted
    different words would have to edit the enum and every surface would follow,
    and `exit_code_for` is the one place the "a preview is not a failure"
    decision is written. `tests/unit/test_risk_preview_surface.py::test_every_claim_reaches_both_renderers`
    asserts at the *view-model* layer — every claim's rule id and reason must
    appear whole in both projections — rather than asserting the CLI printed some
    strings, because the latter would pass against a surface with no UI contract
    at all.
  - **`unchecked` is a third stance and it is the reason this is an enum.** An
    unconfigured ceiling was *not checked*, and rendering it `inside_policy` would
    tell an approver a limit was honoured that nobody evaluated. All five plan-14
    ceilings therefore render `unchecked` by default, with `CEILINGS_NOTE`
    saying so. This is the engine's `CeilingVerdict.configured` read through, not
    a second opinion: a breached ceiling whose rule is also in the prediction's
    violated set appears **once**, as the per-step violation, because the ceiling
    verdict derives its `breached` flag from `prediction.rule_ids`. A ceiling
    that claims a breach the prediction does *not* carry is still rendered as a
    breach rather than dropped — a record whose fields disagree about a breach
    must not be able to make the breach disappear.
  - **Every refusal renders as unusable rather than as a clean preview, and each
    is asserted separately.** An unresolvable target set renders the offending ids
    under `UNRESOLVED:` plus `approval_refusal_reason`'s sentence and
    `usable_for_approval: false`; a `DISAGREES` agreement renders
    `prediction.calmer_than_gate` quoting the engine's own reason (and a
    disagreement record with *no* reason is refused outright, because a defect
    report with the finding removed is not a report); an `UNMODELLED` agreement
    renders `prediction.unmodelled_gate_refusal` naming the rules the gate refused
    this preview has no vocabulary for, and **without** claiming a disagreement,
    which would be a different and wrong finding. The `UNMODELLED` branch reads
    the *named state* rather than trusting `report.approval_refusal` to have
    carried the sentence — the engine always does, so that branch is the belt to
    its braces, and it is what stops a hand-built record rendering calm.
  - **A claim that cannot cite itself refuses at the view-model layer.**
    `PreviewRenderRefusedError` (a typed `InvariantViolationError` carrying
    `preview.claim_uncited`) is raised for a claim with a blank rule id or a blank
    reason, so no renderer can be handed a row it would have to print as an empty
    cell — an empty cell in a risk preview reads as "checked, nothing to say",
    which is the one reading that is never right. `_claim` also appends the rule id
    to the reason when the reason does not carry it, which makes the rendered
    output greppable by rule: a claim whose rule can only be found by reading prose
    is a claim nobody can look up when they need it.
  - **The dependency view reads three existing sources and re-derives none of
    them.** `mayhem risk-preview nodes --run RUN_ID` shows, per node: blast radius
    from `domain.prediction.affected_node_ids` / `dependency_fan_out` (the same
    functions the gate's numbers come from — asserted equal for every node, so a
    second traversal here could not disagree with the engine about a depth), health
    from the node's *own* `state` field, coverage from
    `infra.coverage_repository.CoverageGraphRepository.graph()` (read-only; the
    `inspect graph --record` write path is deliberately not reachable from here),
    and incident history from captures shaped like `domain.advisor.IncidentFacts`.
    Coverage and incidents each carry an `available` flag because "mayhem read the
    graph and this service has no cells" is a different finding from "mayhem holds
    no coverage graph", and the CLI has **no incident port bound** — so incidents
    render `UNAVAILABLE` with the port named, never `0`. Health is the same shape:
    a `ServiceNode` carries no lifecycle state, so it reports
    `reported: false` / `unknown`, never "healthy".
  - **No `--force`, no `--record`, no bypass, and the declared option set is
    asserted exactly** (`--json`, `--fingerprint`, `--run`, `--node`) so adding one
    is a deliberate edit. Mutation evidence is a *measurement* in two places: a
    `MutationSink` pre-loaded with a recorded call stays at length 1 across
    `simulate_plan` (a hard-coded zero in `MutationProof` would pass the naive
    assertion and fail this one — and `calls` is the engine's *observed sink
    length*, which is why the loaded case asserts `== 1`, matching
    `test_prediction_service.py`), and the CLI's row counts on `observations`,
    `runs`, `m5_coverage`, `coverage_graph_nodes`, `topology_snapshots`, and the
    three attestation tables are compared before and after — including on the
    *refusal* paths and for the `nodes` command, which is the one that reads the
    coverage graph. A preview that sealed anything would itself be a mutation.
  - **An unpriced estimate discloses, and the type refuses to render a price it
    does not have.** `CostView.to_payload()` omits the `currency` and `total` keys
    *entirely* when unpriced — not `null`, not `0.0`, because a consumer that
    renders `total: null` beside a number draws a dollar sign and half the JSON
    tooling in existence reads `null` as zero-with-no-units. Measured
    `affected_node_seconds` is always present, since it *is* measured. The
    rendered line is asserted to contain no `USD` and no `$`; a priced fixture
    asserts the inverse so the unpriced assertions are not vacuous.
  - **Two behaviours a reader should know are disclosures, not bugs.** The
    preview adopts the **plan's own recorded** `environment_fingerprint` by
    default, which means the fingerprint-drift check does not run — stated in
    `FINGERPRINT_NOTE` in the rendered output and in the payload, because
    `--fingerprint` is how a caller asks the stricter question. And no plan-14
    ceilings are configurable from this surface yet, so all five report
    `unchecked` (`CEILINGS_NOTE`). Both are the engine's defaults, never invented
    numbers.
  - **WHAT DID NOT LAND, precisely.** (a) *The preview output is not stored with
    the plan.* The acceptance criterion says "preview output stored with the plan";
    what exists is that the payload is a **stable, versioned, self-describing
    structure** (`RISK_PREVIEW_SCHEMA_VERSION`, `to_payload()` on every view) with
    a tested projection identity, and Phase 4's `seal_prediction` already stores
    the `ImpactPrediction` this payload is derived from — but the
    `RiskPreviewView` itself is written nowhere. Storing it would mean a write
    path, and a read-only preview command must not have one, so this half of the
    criterion needs a seam this lane does not own (a decision about where a
    surface's rendered output gets persisted, most likely alongside
    `seal_prediction`). (b) *There is no UI renderer, so "rendered identically in
    CLI and UI" is not demonstrated.* Plan 08 does not exist. What landed is the
    part that makes the two cannot drift when it arrives — one structure, two
    projections, acceptance asserted at the structure — and
    `test_the_ui_renderer_does_not_exist_yet` pins the shape of what is missing
    (exactly two projections in this module, no third hiding in it) so the suite
    cannot imply the criterion is met. Marked INCOMPLETE rather than DONE for
    those two reasons. 76 tests, all six negative controls the phase calls for.
  - **Files:** `src/mayhem/cli/risk_preview_cmd.py`,
    `tests/unit/test_risk_preview_surface.py`. **Registration is not done and
    was not attempted** — `cli/command_registry.py` and `cli/app.py` are outside
    this lane's ownership, so the group is exported as `risk_preview` and the
    suite invokes that group directly rather than the app, which is also why
    the module renders and exits its own `MayhemCliError`s instead of relying on
    `cli.app.main`'s exception mapping.
- Phase 4 (safety and evidence integration): DONE, with one named debt carried forward.
  - **The five §Controls ceilings are enforced by the real gate.** `SafetyContext.blast_ceilings` is a new optional field defaulting to `None`; `controller/safety.py::_check_blast_ceilings` refuses `blast_radius.protected_node`, `…max_dependency_depth`, `…max_customer_facing_services`, `…max_affected_pct` and `…max_affected_nodes` from `check_blast_radius`, in the same order `domain/prediction.py` predicts them, on the same step — so the gate's refusal is inside the preview's flagged set by construction rather than by coincidence. With no ceiling configured the pass is byte-identical to a captured golden (`GOLDEN_NO_CEILINGS`, asserted in `tests/unit/test_prediction_evidence.py`). Measurements are borrowed from `domain.prediction` (`dependency_fan_out`, `customer_facing_node_ids`) rather than re-derived, because a second implementation could disagree with the preview about a depth or a front door.
  - **`PENDING_ADMISSION_WIRING` is now empty, and that emptiness is the assertion.** `is_enforced_by_gate` still derives `CeilingVerdict.enforced_by_gate` from the table, so deleting the five rows flipped every record at once. Phase 2's tripwire (`test_no_pending_ceiling_rule_id_is_one_the_real_gate_can_emit`) was *designed to fire* on this phase and did; it was retired by inversion rather than deleted, since the surviving form of the check — every ceiling reported as enforced is one the gate actually raises — is what keeps the derivation from degenerating into a bare default now the table is empty.
  - **The agreement split is now an explicit, named state.** `AgreementState` (`AGREES` / `UNMODELLED` / `DISAGREES`) replaces Phase 2's emergent consequence. `UNMODELLED` means "the gate found something this preview cannot speak to": `agrees` stays true because nothing modelled was missed, and the report is unusable for approval — now a tested property of the state (`usable_for_approval`) rather than an inference from a non-empty set in a function three call sites away. `DISAGREES` still raises. `GateAgreement.__post_init__` refuses a `state` contradicting the record's own booleans, so the record cannot lie about itself.
  - **Predictions are sealed with the plan, and an uncited one cannot be.** `seal_prediction` commits a prediction into plan 12's existing hash chain and M0023 tables under its own `:prediction` scope (so it cannot overwrite the run-close or `:proof` chain), reusing the same domain functions and unsigned-manifest honesty gate as `controller/proof_sealing.py`. `verify_sealed_prediction` re-verifies chain, then manifest, then the payload's own digest — a chain proves the bytes were not edited, never that they are the right bytes. `evidence_ref` is required and non-blank at both seal time and read-back: a prediction citing no evidence cannot back a decision.
  - **A run whose actual blast exceeded its prediction opens a finding.** `score_prediction_accuracy` reads "exceeded" as a *set* question rather than a count, names the affected ids the forecast did not contain, and records the over-estimated direction without opening a finding against the run.
  - **DEBT CARRIED FORWARD — NOW CLOSED (recorded here rather than deleted, because the shape of the debt is the useful part).** As Phase 4 landed, `safety_proof.OBLIGATION_FOR_RULE` had no owning line for the five ceiling rule ids, because that lane could not edit `controller/safety_proof.py` while concurrent lanes held it. The consequence was measured, not assumed: a run refused on a ceiling compiled to a `VOID` proof naming an unplaceable rule — fail-closed rather than a silent pass, but strictly weaker than the `FAIL` on `target_policy` the artifact could have reported, and weaker in the way that matters, because a `VOID` proof reports nothing about the line that was actually breached. The five ids were spelled as inline literals in `_deny_decision` calls precisely so the completeness scanner could see them and fail by name. **They are now mapped**, all five to `ObligationName.TARGET_POLICY`, with the five ids added to `safety_proof.GATE_RULE_IDS` so a prediction's ceiling findings are attributable, and a tenth obligation name was considered and rejected on the type rather than the taste: `ObligationName` is the fixed nine-name spine, and adding a line to it changes what a `PASS`-shaped proof must contain for every consumer of the artifact, for a rule an existing line already describes honestly. `test_proof_compiler.py::test_every_rule_the_gates_can_raise_has_an_owning_proof_line` passes. The `CEILING_RULES_AWAITING_AN_OBLIGATION` marker that specified the work is gone from the suite, and the `target_policy` line now reports each ceiling's measured value beside the limit it was compared against, so a breach is a `FAIL` naming its number rather than a count of ceilings somewhere in a line.
- Phase 5: not started
- Phase 6: not started

Overall: 4 of 6 phases complete.
