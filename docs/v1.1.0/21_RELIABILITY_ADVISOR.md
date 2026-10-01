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
- Phase 2 (engine): not started
- Phase 3 (surface): not started
- Phase 4 (safety/evidence): not started
- Phase 5 (tests/negative controls): not started
- Phase 6 (docs/rollout): not started

Overall: 1 of 6 phases complete.
