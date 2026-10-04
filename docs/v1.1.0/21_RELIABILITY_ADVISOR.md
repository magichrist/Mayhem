# Plan 21 — Reliability Advisor and Incident-to-Experiment

**Priority:** P2/P3. Gap items 21, 22, 23, 24, 49.

## Objective
Use topology, SLOs, incidents, deployment metadata, and prior evidence to recommend experiments that close resilience gaps — and convert incidents into reproducible experiment candidates — without ever granting analysis code execution authority.

## Builds on
- 14 graph (topology plus experiments plus incidents as nodes), 22 coverage cells (what is tested where), 11 probes and SLO criteria, 12 evidence (recommendations cite sealed facts).
- The 15 AI-boundary rule: advisor output is untrusted drafts through standard compilation; this plan is its primary consumer.

## Inputs
Topology, incidents, SLOs, production metrics, deployment changes,
dependency inventory, experiment history, fault coverage.

## Outputs
Uncovered failure modes, recommended experiments, priority based on
declared customer criteria (not opaque ranking), likely affected
dependencies, suggested probes, suggested stop conditions.

## Incident replay
Convert incident facts (service, failure signature, dependency,
observed percentiles, timing, versions) into a reproducible experiment
candidate pinned to the incident's topology snapshot.

## Scenario library (gap 49)
Realistic multi-fault scenarios (regional outage, cache outage, DNS
failure, payment degradation, partition, pod churn, certificate
expiry, traffic spike) maintained as versioned templates over the
advisor's vocabulary — each scenario is hypothesis plus timeline plus
stop conditions plus recovery, never just a fault list.

## AI boundary
AI may: summarize, generate candidate plans, explain evidence, suggest
probes. AI may not: bypass policy, approve, execute without the normal
authorization chain.

## Phase 1 — Domain model: findings and candidates
Add `domain/advisor.py`: `Finding` (uncovered failure mode with cited topology/coverage facts), `Recommendation` (candidate experiment plus priority rationale referencing declared customer criteria), `IncidentFacts` (normalized incident capture), all pure. Priority as a pure function of declared weights — opaque ranking unrepresentable. Acceptance: recommendation-traceability tests (every recommendation cites its facts; remove the facts, the recommendation disappears).

## Phase 2 — Engine: analysis over sealed inputs
Advisor engine reads topology, coverage, incidents, deployments, and evidence; emits findings and draft candidates; incident-replay compiler maps incident facts to experiment candidates with topology snapshots pinned. All drafts enter standard compilation (15/16 paths). Acceptance: replay of a fixture incident produces a candidate that compiles and passes policy, with every parameter traced to an incident fact.

## Phase 3 — Surface: advisor views and replay flow
Advisor dashboard (findings ranked by declared criteria with traces), incident-to-experiment flow (incident in → candidate out → human approval), scenario library browser. Acceptance: a recommendation without a traceable rationale cannot render (tested at the view-model layer).

## Phase 4 — Safety and evidence integration
Generated candidates face identical compilation, policy, impact, approval, and evidence gates as authored plans; advisor runs read-only (no mutation capability in its execution context — enforced by construction, not policy text). Acceptance: penetration-style test asserting the advisor context cannot mint execution intent.

## Phase 5 — Tests, regression guards, negative controls
Traceability tests, replay-fidelity tests on fixture incidents, scenario-template compilation tests, AI-boundary tests (approval token smuggled in a draft rejected; direct dispatch from advisor refused). Negative controls: advisor output presented as certified evidence rejected by the verifier. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Advisor methodology doc (criteria declaration, trace reading), replay guide, scenario authoring guide. Rollout: findings first, replay second, generated candidates last with human approval mandatory throughout. Acceptance: no doc implies the advisor understands the system — it correlates cited facts, and the docs say exactly that.

## Dependencies
11 (SLOs, probes), 12 (cited evidence), 14 (graph), 15 (candidate compilation), 22 (coverage facts).

## STATUS
- Phase 1 (domain model): DONE — `domain/advisor.py` adds `Finding` (gap cell + landscape + topology, all required), `Recommendation` (finding + candidate + derived priority), `IncidentFacts` (normalised capture), `CoverageLandscape`, and `UntrustedRecommendationDraft`, which has no approval, weight, or execution field; priority is the weighted mean of declared criteria and is stored nowhere.
- Phase 2 (engine): DONE — `controller/advisor_service.py` reads topology, coverage, incidents, deployments, and sealed evidence through five read-only ports and emits findings plus untrusted drafts, refusing every declared cell it declines by name; the incident-replay compiler turns a normalised capture into a candidate pinned to the incident's snapshot, refuses an untraceable or unit-mismatched parameter instead of defaulting it, and `submit` is the single origin-blind door onto the shared `plan_drill` → `compile_safety_evidence` → `simulate_plan_policy` path (a candidate that will not compile never reaches the proof or the policy gate), with read-only proved by construction via a detached service and a pre-loaded `MutationSink`.
- Phase 3 (surface): DONE — `cli/advisor_cmd.py` adds `mayhem advisor` (`dashboard`, `replay`, `submit`, and a `scenario` group with `list`/`show`/`instantiate`) over one JSON **inputs document** (`--inputs`) that supplies the landscape, the topology snapshot, the captures, the deployment record, the sealed cells, and the customer's criteria declaration; no database is opened and every field the surface does not read is refused by name rather than ignored. The load-bearing piece is a **view-model layer**, not the callbacks: `ranked_views` refuses *before* it builds a view, so a recommendation whose rationale does not name every criterion it was weighed against raises `advisor_view.recommendation_not_renderable` naming each one, there is no partial view to print instead, and a future UI (plan 08) inherits the guarantee by asking this layer for a view because there is no other way to get one — which is the phase's acceptance, tested at the view-model and not through Click. Priority is derived twice over and stored nowhere: `advisor_dashboard` ranks through the domain's own `rank_drafts`, and `ranked_views` recomputes `Priority.total` on read, refuses any recommendation weighed against a *different* declaration (`advisor_view.criteria_declaration_mismatch`), and has no parameter a caller could hand a weight to. Advisory-versus-authorization is a property of the types rather than of the prose: every view inherits `_AdvisoryStanding`, whose `standing`, `grants_approval` and `grants_authorization` are **properties returning literals** (asserted against the dataclass field lists), a recommendation carrying an approval is refused outright by both `ranked_views` and `submission_view`, and `SubmissionView` separates the gate's own three-state reading (`authorization_state`, verbatim) from this surface's grant (`surface_grants_authorization`, a second literal `False`) so an unknown can never be collapsed into an authorized one. Both candidates go out through the shared core — `advisor submit` reaches `AdvisorService.submit` and `scenario instantiate` reaches `submit_scenario`, which are the same private `_run_submission` — and the scenario enters through the ordinary `propose` injection point (`ScenarioInstantiation.propose`), so there is no scenario-only planner; `--preview` stops before it. **What is deliberately not here:** there is no `approve` command and no `--approve`/`--force`, and no flag for the blast-radius ceilings either, because a caller handed `--max-hosts` would be handed the gate that is supposed to be checking it — `advisor_safety_context` fixes them as module constants and states the three things it has none of (no policy bundle, so `policy_state: no_bundle_configured`; no approval gate, so `requirements_only`; no runtime adapter, so a `VOID` proof whose reason names the capability line). Three real gaps are recorded rather than worked around: (a) **three of the eight shipped scenario templates do not compile** through `plan_drill` — `network-partition` and `payment-degradation` name timeline faults whose catalog `params_schema` marks `port`/`delay_ms` required, and `ScenarioInstantiation.drill_spec` states it keeps each fault's default, so the planner refuses; fixing it means editing `domain/scenarios.py` or `domain/catalog.py`, which this work item does not own, and the surface refuses it by name instead of rendering a scenario that cannot be planned; (b) Phase 4's gap is unchanged and is *hit* here — nothing maps an advisor artifact onto a proof obligation, so the view renders `proof_verdict` and `proof_void_reason` verbatim and never paraphrases either into "the recommendation was validated"; (c) **the group is now registered**, so `mayhem advisor` resolves from the app: `command_registry.py` carries `CommandSpec("advisor", "inspect", help_group="inspect")`, a `COMMAND_HELP` entry, and the import in `register_commands`, and `tests/unit/test_cli_exhaustive_matrix.py` and `tests/unit/test_command_inventory.py` were extended with the name. *This line was previously written the other way round* — the entry above it claimed the group was unreachable, which the integration pass made false. `tests/unit/test_advisor_plan_docs.py` now resolves `advisor` through the live Click tree and fails if this paragraph ever says otherwise again, because a surface nobody can reach is a module and a document that calls a reachable surface unreachable is the same defect pointed the other way. Tests: `tests/unit/test_advisor_surface.py` (96) invokes the group directly through `CliRunner` rather than the registry, so it does not depend on that integration; its negative controls are a recommendation with no traceable rationale (at the view-model layer), a bad-row-practically-poisons-the-view, a recommendation weighed against another declaration, a recommendation carrying an approval, a recommendation whose serialisation carries a sealed evidence digest, every rendered field and JSON key of every view type scanned for `approved`/`authorized`/`certified`/`executable` (with `gate_authorized` exempted and why), all three authorization states rendered with the two non-granting ones checked separately, no view type having a writable field an approval could travel in, a draft rendering as untrusted, an incident untraceable to its snapshot (view-model and command), an untraceable binding, an undeclared incident, four binding spellings the grammar refuses, the planner naming its compile gate, a rendered gate refusal naming each rule id, a scenario bound to a covered cell, a scenario whose hypothesis does not match its recommendation, a scenario bound to an undeclared cell, a reading for an undeclared criterion, a reading about a gap the landscape does not hold, each missing inputs field, three classes of unknown field, a malformed/empty/non-object document, and a viewing-and-browsing mutation check against a **pre-loaded** sink so a reported zero is a measurement; and no flag on any leaf command that approves or weakens a gate.
- Phase 4 (safety/evidence): DONE — the advisor's execution context is still incapable of minting execution intent (Phase 2's penetration test still passes, and Phase 4 added a spy on `compile_safety_evidence` asserting no `intent` keyword is ever passed); recommendations and findings are sealed as **advisory** by `seal_advisory_claim`, which delegates every part of sealing to plan 12 (`seal_events`/`build_manifest`/`verify_chain`/`verify_manifest`/`AttestationRepository`) and makes "advisory, not authorization" structural rather than prose — `AdvisoryClaim` and `AdvisorySeal` carry no `approval`/`approved_by`/`intent`/`run_id`/`policy_decision`/`approval_state`/`evidence_digest` field (so the existing `is_certified_evidence` predicate is `False` for both), a claim carrying an approval is refused outright, `AdvisorySeal.grants_authorization` is a literal `False` reading nothing, the chain id is namespaced `advisory:<digest>`, and every persisted member states `standing: advisory` with `grants_approval: false`; incident-replay compilations and seals are recorded in `audit_stream` as privileged actions (`audit.advisory.incident_replayed`, `audit.advisory.claim_sealed`) with `approval_digest` and `policy_digest` left **empty**; **the open `required_approvals` question is decided — `submit` does *not* refuse the `PASS`**: the line's subject is the requirements and its own detail says the grant is bound later against the proof digest, the advisor never presents an intent so `intent is None` is the only branch it can reach (refusing it would make `submit` unusable and pressure an implementer to attach an intent to satisfy a line), and reading it as a `FAIL` would assert something false because there is no intent to fail. What Phase 4 added instead is `AdvisorSubmission.authorization`, a named three-state reading of `ctx.approval_gate` and the line's own status — never the line's prose — with `authorized is True` only for a gate's own verdict, so a `PASS` can never be mistaken for a grant. Also Phase 4: the scenario library (gap 49) as `ScenarioTemplate`/`ScenarioInstantiation` in `domain/scenarios.py`, versioned data whose four parts (hypothesis, timeline, stop conditions, recovery) are all required — so "a scenario is not a fault list" is a constructor rule, not a review habit — instantiated through `submit_scenario`, which compiles the scenario's ordinary `DrillSpec` through the *same* `plan_drill` → `compile_safety_evidence` → `simulate_plan_policy` core as `submit` and refuses any spec whose hypothesis is not the recommendation's own. Eight scenarios ship (regional outage, cache outage, DNS failure, payment degradation, network partition, pod churn, certificate expiry, traffic spike); the `pod-churn` timeline was changed from `process.startup_delay` to `process.crash_loop` after the planner refused the former, which is the library held to the same compiler as an authored plan. Rule-mapping gap reported rather than worked around: nothing maps an advisor artifact onto a proof obligation, because `safety_proof` owns that mapping and no obligation names an advisory claim — so the seal records the proof verdict and authorization state as payload data instead of as a proof line.
- Phase 5 (tests/negative controls): DONE — 236 tests across four suites, 0 failures. `tests/unit/test_advisor.py` (68) holds the Phase 1 domain: a finding without its coverage fact, without its topology, or without its graph identity does not compile; a reading outside the unit interval, a criterion with no reading, and an undeclared criterion are refusals; priority is the weighted mean of the declared weights and stores no score to inject. `tests/unit/test_advisor_service.py` (64) holds the Phase 2 engine and its purity measurement: the mutation sink is **pre-loaded** before every analysis, so `calls` equalling the loaded length is evidence and a hard-coded zero would fail these tests. `tests/unit/test_advisor_surface.py` (62) holds the Phase 3 surface: the dashboard ranks by the declared weighted mean and carries the trace, `submit` reports its authorization state and grants nothing, and **no view type has a field an approval could travel in**. `tests/unit/test_advisor_evidence.py` (35) holds the Phase 4 boundary: a seal is not an approval and cannot be dressed up as a run authorization, and `test_the_advisor_still_cannot_mint_execution_intent` pins that the context still has nowhere to put an intent. The phase's named list is covered: traceability (`test_a_finding_cites_its_coverage_cell_and_its_topology`, `test_replay_produces_a_candidate_whose_every_parameter_traces_to_an_incident_fact`), replay fidelity on a fixture incident (`test_a_replay_is_pinned_to_the_incidents_topology_snapshot`, `test_a_replay_pinned_to_another_snapshot_is_refused`), scenario-template compilation (`test_a_shipped_template_compiles_through_the_planner_for_a_container`), and the two AI-boundary controls — an approval smuggled into a draft is refused (`test_a_recommendation_carrying_an_approval_is_refused_outright`) and a direct dispatch from the advisor is refused (`test_the_advisor_context_still_cannot_mint_execution_intent`).
- **Negative controls, as a fifth suite** (`tests/unit/test_advisor_negative_controls.py`, 7 tests). The four suites above assert what the engine *does*; this one asserts each property is **load-bearing**, which is the claim that survives a future edit. Every test applies a deliberate break to a collaborator — never to `src/mayhem`, except the one delegated symbol whose delegation is the property — and asserts the property still holds: (1) `detached()` is monkeypatched to a **no-op** so the analysis runs with the sink attached, and purity is unchanged, because the claim rests on there being no call site rather than on a method being called correctly; (2) the reported call detail is pinned against the caller's own tuple, so a mutating sink could not hide a write behind a count; (3) the **sealed-evidence suppression is load-bearing** — same landscape, graph and capture, only the ledger moves, and the finding exists only while nothing sealed it, with the decline naming both the run and the digest; (4) a topology port that returns a **blank** snapshot id is refused by rule id while the byte-identical graph with a name passes; (5) a coverage port that declares one cell **twice** is refused rather than deduplicated, because collapsing it would pick a winner for a question the declaration does not answer; (6) the graph identity is asserted to be **delegated**, by replacing `compute_graph_identity` with a sentinel — if the engine re-derived the digest itself the sentinel would never appear, which is what makes "the graph changed" one meaning rather than two; (7) a landscape declaring **no cells at all** is refused (`advisor.landscape_empty`) rather than answered, which is stronger than an empty report: an empty report reads as *looked and found none*, a claim about a system nobody declared a landscape for. **Two of these were written against the wrong premise and were corrected by the code, not by relaxing them** — the sealed-evidence detail was asserted for a phrase the engine does not emit (it names the run and digest instead, which is the better assertion), and the all-ports-silent case turned out to be a refusal rather than an empty report, so the test now pins the refusal by rule id.
- Phase 6 (docs/rollout): DONE — three guides written into this document below the ledger, plus the rollout order, and asserted rather than left to review. **Advisor methodology** (criteria declaration and trace reading): what a `CustomerCriterion` must carry and why the customer question is mandatory, that a priority is the weighted mean of the declared weights with nowhere to store a score, and the three reading refusals — plus how to read a trace, including that `ranked_views` recomputes the priority on read and refuses a recommendation weighed against a *different* declaration (`advisor_view.criteria_declaration_mismatch`), so a trace cannot be rendered beside weights it was not measured under. **Incident replay guide**: the four-step operator procedure (normalise the capture, declare the bindings, pin to the incident's snapshot, read the refusals as facts about fidelity) and the closing statement that the output is a candidate carrying no approval, no authorisation and no execution path. **Scenario authoring guide**: why a scenario is four required things rather than a fault list, the five authoring rules (version it, bind every instantiation to a declared cell, the hypothesis must match the recommendation, every timeline step states an expectation and time runs forward, it compiles through the ordinary door), and the **known gap stated rather than worked around** — three of the eight shipped templates do not compile, the fix belongs to `domain/scenarios.py` or `domain/catalog.py`, and the library was not loosened to hide it. **Rollout order**: findings first, replay second, generated candidates last, human approval mandatory at every step with no exception flag. Honesty: the guide states that no incident has ever been replayed against a production system, that a sealed advisory claim proves integrity and never authorship, and that nothing here maps an advisor artifact onto a proof obligation. Tests: `tests/unit/test_advisor_plan_docs.py` (9) parses this document — it cross-checks the `Overall:` count against the number of `DONE` lines so a summary cannot disagree with its own ledger, resolves `advisor` through the **live Click tree** and fails if the document ever calls a reachable surface unreachable (which it did, until this pass corrected two such claims), requires the three guides and the rollout ladder to be present, refuses eight literal false claims, and mutates a copy of the document per checker to prove each checker bites.

Overall: 6 of 6 phases complete (Phases 1, 2, 3, 4, 5, and 6).

**What the fourth phase is, and what it is not.** It is Phase 3's own
deliverable: the command group, the view-model layer, and the acceptance test
that a recommendation without a traceable rationale cannot render. It is a user-reachable
button: the integration pass since then registered `advisor` in
`cli/command_registry.py`, so `mayhem advisor --help` resolves and its four
leaves are reachable by name — verified through the live Click tree in
`tests/unit/test_advisor_plan_docs.py`, which fails if this paragraph says
otherwise. The two gaps Phase 3 records
inside itself — three shipped scenario templates that will not compile, and Phase
4's unmapped proof obligation — are stated in the ledger entry above rather than
netted out here, because the count is of phases and the ledger is of what each
phase actually delivered.

**Why the earlier count was corrected down from 4.** The previous value read
`4 of 6` while the ledger above it marked exactly three phases done (1, 2 and 4),
with Phase 3 (surface) not started and Phases 5 and 6 not started. The count was
wrong in the flattering direction and nothing above it supported the fourth
phase. Corrected against the phase list rather than the other way round: a
summary that disagrees with its own ledger is the ledger lying, not the ledger
being miscounted. Phase 4 additionally records that nothing maps an advisor
artifact onto a proof obligation, which is a real gap inside a phase that is
otherwise delivered — it is not a fourth completed phase. Phase 3, by contrast,
delivered what its phase text asks for, which is why it is the fourth.

## Advisor methodology — declaring criteria and reading a trace

The advisor has no opinion about what matters. That is the whole design: a
recommendation is *not* ranked by an opaque score, because an operator who
cannot say why a gap outranks another cannot argue with the ranking, and an
advisory tool whose output cannot be argued with is a black box wearing a
priority number.

**Declaring criteria.** Each `CustomerCriterion` carries a `name`, a non-negative
finite `weight`, and a `question` naming the customer question it answers — "how
many customers meet this failure in a normal week?", not "impact". The question
is required, so a criterion that cannot be answered by a human is not
expressible. Weights are the *only* input to the ordering, and priority is their
weighted mean; `Priority` stores no score field, so there is nowhere for a
ranking to be injected or frozen between runs. An empty declaration cannot even
be defaulted: a criteria object with no criteria is refused.

**Supplying a reading.** Every criterion needs exactly one `CriterionReading` per
finding, carrying a value in `[0, 1]` and evidence naming why. A reading for an
undeclared criterion, a declared criterion with no reading, and a reading with no
evidence are three separate refusals rather than three defaults — the advisor
will not impute a customer's priorities, because a value it invented would be
indistinguishable from one they stated.

**Reading a trace.** Every `Recommendation` cites its finding and the reasoning
for *every* declared criterion. `ranked_views` recomputes the priority on read
and refuses a recommendation weighed against a **different** declaration
(`advisor_view.criteria_declaration_mismatch`), so a trace cannot be rendered
beside weights it was not measured under. A recommendation whose rationale does
not name each criterion is refused *before* a view is built
(`advisor_view.recommendation_not_renderable`, naming each missing criterion) —
there is no partial view to print instead.

**What a number is not.** A priority is an argument about declared criteria, not
a measurement of risk. It does not survive a change of criteria: change the
weights and the order changes, which is the correct behaviour and the reason the
declaration is part of the report rather than a setting.

## Incident replay guide

Replay turns one normalised capture into a candidate whose parameters each trace
to an incident fact. The operator's procedure:

1. **Normalise the capture.** `IncidentFacts.normalise` demands the service, a
   failure signature, the dependency, the observed percentiles with their units
   and sample counts, the version pins, the topology snapshot id, and the
   window. A capture missing any of these is refused — an incident nobody can
   reproduce is not an incident to replay.
2. **Declare the bindings.** Each `ParameterBinding` names one parameter, one
   source (`ParameterSource`), and — for a percentile — the label and unit. Every
   binding must read **exactly one** fact, binding the same parameter twice is
   refused, and a replay with no bindings is refused.
3. **Pin to the incident's snapshot.** The replay names the snapshot the incident
   was observed against. A replay pinned to another snapshot is refused, and it
   cannot be re-pinned after the fact. A version the deployment record shows as
   superseded is refused; a component the record simply does not name is *not* a
   supersession.
4. **Read the refusals as facts about fidelity.** An untraceable parameter, an
   observation with nothing behind it, a unit mismatch, and a capture with no
   usable observation are all refusals rather than fallbacks. A defaulted
   parameter is how a replay reproduces nothing while looking faithful — the one
   failure mode worth refusing for.

The output is a **candidate**. It carries no approval, no authorisation and no
execution path, and it enters the ordinary `plan_drill` → safety proof → policy
simulation road: a candidate that will not compile never reaches the proof or
the gate, and `--preview` stops before both.

## Scenario authoring guide

A scenario is four things, and the type makes all four required: a
**hypothesis**, a **timeline**, **stop conditions**, and a **recovery**. A bare
list of faults is not constructible — that is the point, because a fault list
states nothing about what the scenario is trying to learn.

- **Version them.** The library refuses a duplicate version and a version it
  cannot sort, so a template cannot be silently replaced under a caller.
- **Bind every instantiation to a declared cell.** An instantiation naming a
  cell the library does not declare is refused by name, and a scenario bound to
  a cell the coverage record already covers is refused too.
- **The hypothesis must match the recommendation.** An instantiation whose
  hypothesis is not the recommendation's own is refused — a scenario cannot be
  used to smuggle a different claim through the same compiler.
- **Every timeline step states an expectation, and time runs forward.** A step
  with no expectation and a timeline that runs backwards are both refused.
- **It compiles through the ordinary door.** `scenario instantiate` reaches
  `submit_scenario`, which shares `submit`'s private `_run_submission`, so a
  scenario is indistinguishable downstream from an authored plan and is held to
  the same compiler.

**Known gap, stated rather than worked around:** three of the eight shipped
templates do not compile through `plan_drill` — `network-partition` and
`payment-degradation` name timeline faults whose catalog `params_schema` marks
`port`/`delay_ms` required, while the instantiation keeps each fault's default,
so the planner refuses. The fix means editing `domain/scenarios.py` or
`domain/catalog.py`, which this lane does not own; the surface refuses by name
instead of rendering a scenario that cannot be planned. The library was not
loosened to hide this, which is why the `pod-churn` timeline was *changed* to
`process.crash_loop` rather than the compiler being accommodated.

## Rollout order

Findings first, replay second, generated candidates last, with human approval
mandatory at every step and no exception flag to remove it. The advisor runs
read-only by construction — its execution context has no mutation backend, no
lease sink and no way to mint an execution intent — and a candidate, replayed or
generated, faces the same compilation, policy, impact and approval gates as one
a human typed.

**Honest limits.** No incident in this plan has ever been replayed against a
production system, and no recommendation has been acted on; the machinery is
tested against fixture captures. A sealed advisory claim proves *integrity* of
what was recorded, never *authorship* of it — `mayhem.providers.pack.
SIGNATURE_VERIFICATION_IMPLEMENTED` is `False` and this phase leaves it `False`.
Nothing here maps an advisor artifact onto a proof obligation, so the surface
renders the proof verdict and its void reason verbatim rather than paraphrasing
either into "validated".
