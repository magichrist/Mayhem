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

## STATUS — planning only, 0%
