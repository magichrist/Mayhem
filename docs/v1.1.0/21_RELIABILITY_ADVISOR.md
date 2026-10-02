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
- Phase 3 (surface): not started
- Phase 4 (safety/evidence): DONE — the advisor's execution context is still incapable of minting execution intent (Phase 2's penetration test still passes, and Phase 4 added a spy on `compile_safety_evidence` asserting no `intent` keyword is ever passed); recommendations and findings are sealed as **advisory** by `seal_advisory_claim`, which delegates every part of sealing to plan 12 (`seal_events`/`build_manifest`/`verify_chain`/`verify_manifest`/`AttestationRepository`) and makes "advisory, not authorization" structural rather than prose — `AdvisoryClaim` and `AdvisorySeal` carry no `approval`/`approved_by`/`intent`/`run_id`/`policy_decision`/`approval_state`/`evidence_digest` field (so the existing `is_certified_evidence` predicate is `False` for both), a claim carrying an approval is refused outright, `AdvisorySeal.grants_authorization` is a literal `False` reading nothing, the chain id is namespaced `advisory:<digest>`, and every persisted member states `standing: advisory` with `grants_approval: false`; incident-replay compilations and seals are recorded in `audit_stream` as privileged actions (`audit.advisory.incident_replayed`, `audit.advisory.claim_sealed`) with `approval_digest` and `policy_digest` left **empty**; **the open `required_approvals` question is decided — `submit` does *not* refuse the `PASS`**: the line's subject is the requirements and its own detail says the grant is bound later against the proof digest, the advisor never presents an intent so `intent is None` is the only branch it can reach (refusing it would make `submit` unusable and pressure an implementer to attach an intent to satisfy a line), and reading it as a `FAIL` would assert something false because there is no intent to fail. What Phase 4 added instead is `AdvisorSubmission.authorization`, a named three-state reading of `ctx.approval_gate` and the line's own status — never the line's prose — with `authorized is True` only for a gate's own verdict, so a `PASS` can never be mistaken for a grant. Also Phase 4: the scenario library (gap 49) as `ScenarioTemplate`/`ScenarioInstantiation` in `domain/scenarios.py`, versioned data whose four parts (hypothesis, timeline, stop conditions, recovery) are all required — so "a scenario is not a fault list" is a constructor rule, not a review habit — instantiated through `submit_scenario`, which compiles the scenario's ordinary `DrillSpec` through the *same* `plan_drill` → `compile_safety_evidence` → `simulate_plan_policy` core as `submit` and refuses any spec whose hypothesis is not the recommendation's own. Eight scenarios ship (regional outage, cache outage, DNS failure, payment degradation, network partition, pod churn, certificate expiry, traffic spike); the `pod-churn` timeline was changed from `process.startup_delay` to `process.crash_loop` after the planner refused the former, which is the library held to the same compiler as an authored plan. Rule-mapping gap reported rather than worked around: nothing maps an advisor artifact onto a proof obligation, because `safety_proof` owns that mapping and no obligation names an advisory claim — so the seal records the proof verdict and authorization state as payload data instead of as a proof line.
- Phase 5 (tests/negative controls): not started
- Phase 6 (docs/rollout): not started

Overall: 3 of 6 phases complete (Phases 1, 2, and 4).

**Why the count was corrected down from 4.** This line previously read `4 of 6`
while the ledger above it marked exactly three phases done (1, 2 and 4), with
Phase 3 (surface) not started and Phases 5 and 6 not started. The count was
wrong in the flattering direction and nothing above it supported the fourth
phase. Corrected against the phase list rather than the other way round: a
summary that disagrees with its own ledger is the ledger lying, not the ledger
being miscounted. Phase 4 additionally records that nothing maps an advisor
artifact onto a proof obligation, which is a real gap inside a phase that is
otherwise delivered — it is not a fourth completed phase.
