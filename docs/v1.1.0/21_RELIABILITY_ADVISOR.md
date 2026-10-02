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
- Phase 3 (surface): DONE — `cli/advisor_cmd.py` adds `mayhem advisor` (`dashboard`, `replay`, `submit`, and a `scenario` group with `list`/`show`/`instantiate`) over one JSON **inputs document** (`--inputs`) that supplies the landscape, the topology snapshot, the captures, the deployment record, the sealed cells, and the customer's criteria declaration; no database is opened and every field the surface does not read is refused by name rather than ignored. The load-bearing piece is a **view-model layer**, not the callbacks: `ranked_views` refuses *before* it builds a view, so a recommendation whose rationale does not name every criterion it was weighed against raises `advisor_view.recommendation_not_renderable` naming each one, there is no partial view to print instead, and a future UI (plan 08) inherits the guarantee by asking this layer for a view because there is no other way to get one — which is the phase's acceptance, tested at the view-model and not through Click. Priority is derived twice over and stored nowhere: `advisor_dashboard` ranks through the domain's own `rank_drafts`, and `ranked_views` recomputes `Priority.total` on read, refuses any recommendation weighed against a *different* declaration (`advisor_view.criteria_declaration_mismatch`), and has no parameter a caller could hand a weight to. Advisory-versus-authorization is a property of the types rather than of the prose: every view inherits `_AdvisoryStanding`, whose `standing`, `grants_approval` and `grants_authorization` are **properties returning literals** (asserted against the dataclass field lists), a recommendation carrying an approval is refused outright by both `ranked_views` and `submission_view`, and `SubmissionView` separates the gate's own three-state reading (`authorization_state`, verbatim) from this surface's grant (`surface_grants_authorization`, a second literal `False`) so an unknown can never be collapsed into an authorized one. Both candidates go out through the shared core — `advisor submit` reaches `AdvisorService.submit` and `scenario instantiate` reaches `submit_scenario`, which are the same private `_run_submission` — and the scenario enters through the ordinary `propose` injection point (`ScenarioInstantiation.propose`), so there is no scenario-only planner; `--preview` stops before it. **What is deliberately not here:** there is no `approve` command and no `--approve`/`--force`, and no flag for the blast-radius ceilings either, because a caller handed `--max-hosts` would be handed the gate that is supposed to be checking it — `advisor_safety_context` fixes them as module constants and states the three things it has none of (no policy bundle, so `policy_state: no_bundle_configured`; no approval gate, so `requirements_only`; no runtime adapter, so a `VOID` proof whose reason names the capability line). Three real gaps are recorded rather than worked around: (a) **three of the eight shipped scenario templates do not compile** through `plan_drill` — `network-partition` and `payment-degradation` name timeline faults whose catalog `params_schema` marks `port`/`delay_ms` required, and `ScenarioInstantiation.drill_spec` states it keeps each fault's default, so the planner refuses; fixing it means editing `domain/scenarios.py` or `domain/catalog.py`, which this work item does not own, and the surface refuses it by name instead of rendering a scenario that cannot be planned; (b) Phase 4's gap is unchanged and is *hit* here — nothing maps an advisor artifact onto a proof obligation, so the view renders `proof_verdict` and `proof_void_reason` verbatim and never paraphrases either into "the recommendation was validated"; (c) **the group is not registered**, so `mayhem advisor` does not resolve from the app yet — `command_registry.py` needs a `CommandSpec("advisor", "inspect", help_group="inspect")` row, a `COMMAND_HELP` entry, and the import in `register_commands`, and `tests/unit/test_cli_exhaustive_matrix.py` needs `advisor` in `ACTIVE_ROOTS` with `dashboard`/`replay`/`submit`/`scenario` in `ACTIVE_GROUP_PATHS` (`scenario` → `list`/`show`/`instantiate`) and `tests/unit/test_command_inventory.py` needs the name on its allowlist. Tests: `tests/unit/test_advisor_surface.py` (96) invokes the group directly through `CliRunner` rather than the registry, so it does not depend on that integration; its negative controls are a recommendation with no traceable rationale (at the view-model layer), a bad-row-practically-poisons-the-view, a recommendation weighed against another declaration, a recommendation carrying an approval, a recommendation whose serialisation carries a sealed evidence digest, every rendered field and JSON key of every view type scanned for `approved`/`authorized`/`certified`/`executable` (with `gate_authorized` exempted and why), all three authorization states rendered with the two non-granting ones checked separately, no view type having a writable field an approval could travel in, a draft rendering as untrusted, an incident untraceable to its snapshot (view-model and command), an untraceable binding, an undeclared incident, four binding spellings the grammar refuses, the planner naming its compile gate, a rendered gate refusal naming each rule id, a scenario bound to a covered cell, a scenario whose hypothesis does not match its recommendation, a scenario bound to an undeclared cell, a reading for an undeclared criterion, a reading about a gap the landscape does not hold, each missing inputs field, three classes of unknown field, a malformed/empty/non-object document, and a viewing-and-browsing mutation check against a **pre-loaded** sink so a reported zero is a measurement; and no flag on any leaf command that approves or weakens a gate.
- Phase 4 (safety/evidence): DONE — the advisor's execution context is still incapable of minting execution intent (Phase 2's penetration test still passes, and Phase 4 added a spy on `compile_safety_evidence` asserting no `intent` keyword is ever passed); recommendations and findings are sealed as **advisory** by `seal_advisory_claim`, which delegates every part of sealing to plan 12 (`seal_events`/`build_manifest`/`verify_chain`/`verify_manifest`/`AttestationRepository`) and makes "advisory, not authorization" structural rather than prose — `AdvisoryClaim` and `AdvisorySeal` carry no `approval`/`approved_by`/`intent`/`run_id`/`policy_decision`/`approval_state`/`evidence_digest` field (so the existing `is_certified_evidence` predicate is `False` for both), a claim carrying an approval is refused outright, `AdvisorySeal.grants_authorization` is a literal `False` reading nothing, the chain id is namespaced `advisory:<digest>`, and every persisted member states `standing: advisory` with `grants_approval: false`; incident-replay compilations and seals are recorded in `audit_stream` as privileged actions (`audit.advisory.incident_replayed`, `audit.advisory.claim_sealed`) with `approval_digest` and `policy_digest` left **empty**; **the open `required_approvals` question is decided — `submit` does *not* refuse the `PASS`**: the line's subject is the requirements and its own detail says the grant is bound later against the proof digest, the advisor never presents an intent so `intent is None` is the only branch it can reach (refusing it would make `submit` unusable and pressure an implementer to attach an intent to satisfy a line), and reading it as a `FAIL` would assert something false because there is no intent to fail. What Phase 4 added instead is `AdvisorSubmission.authorization`, a named three-state reading of `ctx.approval_gate` and the line's own status — never the line's prose — with `authorized is True` only for a gate's own verdict, so a `PASS` can never be mistaken for a grant. Also Phase 4: the scenario library (gap 49) as `ScenarioTemplate`/`ScenarioInstantiation` in `domain/scenarios.py`, versioned data whose four parts (hypothesis, timeline, stop conditions, recovery) are all required — so "a scenario is not a fault list" is a constructor rule, not a review habit — instantiated through `submit_scenario`, which compiles the scenario's ordinary `DrillSpec` through the *same* `plan_drill` → `compile_safety_evidence` → `simulate_plan_policy` core as `submit` and refuses any spec whose hypothesis is not the recommendation's own. Eight scenarios ship (regional outage, cache outage, DNS failure, payment degradation, network partition, pod churn, certificate expiry, traffic spike); the `pod-churn` timeline was changed from `process.startup_delay` to `process.crash_loop` after the planner refused the former, which is the library held to the same compiler as an authored plan. Rule-mapping gap reported rather than worked around: nothing maps an advisor artifact onto a proof obligation, because `safety_proof` owns that mapping and no obligation names an advisory claim — so the seal records the proof verdict and authorization state as payload data instead of as a proof line.
- Phase 5 (tests/negative controls): not started
- Phase 6 (docs/rollout): not started

Overall: 4 of 6 phases complete (Phases 1, 2, 3, and 4).

**What the fourth phase is, and what it is not.** It is Phase 3's own
deliverable: the command group, the view-model layer, and the acceptance test
that a recommendation without a traceable rationale cannot render. It is **not**
a user-reachable button yet — `advisor` is absent from
`cli/command_registry.py`, which this work item does not own, so `mayhem advisor`
does not resolve from the app until that integration pass lands. If it does not,
this line is wrong in the same way the previous count was wrong in the flattering
direction: a surface nobody can reach is a module, not a phase. The three gaps
Phase 3 records inside itself — three shipped scenario templates that will not
compile, Phase 4's unmapped proof obligation, and the missing registration — are
stated in the ledger entry above rather than netted out here, because the count
is of phases and the ledger is of what each phase actually delivered.

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
