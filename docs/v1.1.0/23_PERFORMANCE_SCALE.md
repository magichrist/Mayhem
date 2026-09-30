# Plan 23 — Performance, Scale, and Cost Engineering

**Priority:** P1. Gap items 68, 82, 83.

## Objective
Prove the Mayhem control plane and agents remain efficient at enterprise scale — and fold in resource budgets (68) so cost and consumption are governed, not merely measured.

## Builds on
- Existing performance-relevant seams: planner compilation, topology discovery, policy evaluation, agent command latency over the 03 protocol, evidence throughput into the bundle store, SQLite growth characteristics under the 08 replication scheme.
- 07 budgets (damage, cost ceilings) and 06 cost estimates: measurement here becomes enforcement there.

## Benchmarks
Plan compilation latency, target discovery latency, policy evaluation
latency, controller throughput, agent command latency, evidence
throughput, database growth, probe overhead, network overhead.

## Scale targets
10 / 100 / 1,000 / 10,000 / 100,000 targets; 10 / 100 / 1,000
concurrent runs where architecture permits. Targets are ranges to
characterize, not promises to hit on day one — each range ships with
its measured numbers or stays unclaimed.

## Cost controls and resource budgets (gap 68)
CPU, memory, network, storage, cloud spend, API-call counts, target
counts, concurrent-experiment caps as budget dimensions with
pre-execution estimates and continuous enforcement alongside damage
budgets.

## Phase 1 — Domain model: budgets and benchmark descriptors
Add `domain/budgets.py`: `ResourceBudget` (dimension, limit, window, scope) and `BenchmarkSpec` (workload shape, target scale, measured outputs) as pure types. Pre-execution estimate vs. continuous actual as comparable records. Acceptance: budget-arithmetic tests; benchmark-spec determinism tests.

## Phase 2 — Engine: metering and enforcement hooks
Metering at the existing seams (compilation timing, discovery timing, per-command agent latency, evidence bytes per run, store growth per run); resource-budget checks in admission (07 dimensions) plus continuous re-check during execution (a run exceeding its API-call budget pauses for review, never silently continues). Acceptance: a benchmark run reproduces its workload shape exactly from its spec.

## Phase 3 — Surface: benchmark reports and budget views
Published benchmark reports with methodology attached; budget configuration and consumption views in CLI/UI. Acceptance: every published number links to the spec plus the raw outputs that produced it.

## Phase 4 — Safety and evidence integration
Benchmark and metering records sealed as evidence-class data (comparable across releases via 22); cloud-action cost estimates (06) checked against cost budgets before mutation. Acceptance: an experiment that would breach its resource budget is refused with the breaching dimension named.

## Phase 5 — Tests, regression guards, negative controls
Benchmark-harness tests (deterministic workload generation), budget-enforcement tests per dimension, scale-soak tests at each claimed range, performance-regression tests (a release that regresses compilation latency beyond threshold fails CI). Negative controls: an unmeasured scale claim cannot render on any dashboard; a benchmark without its methodology attached is rejected at publish time. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Benchmark methodology doc, scale-characterization pages per range (measured numbers or silence — never projections presented as results), budget-configuration guide. Rollout: metering first, budgets second, published scale claims last and only for measured ranges. Acceptance: the "what overhead does Mayhem add?" question answered with numbers plus methodology, not adjectives.

## Dependencies
06 (cloud cost estimates), 07 (budget enforcement), 08 (store growth under replication), 22 (cross-release comparison).

## STATUS
- Phase 1 (domain model): DONE — `domain/budgets.py` adds ResourceDimension (8 cost dimensions), ResourceBudget/BudgetConsumption with half-open windows, pure estimate-vs-actual comparison, and a digest-pinned BenchmarkSpec whose workload regenerates exactly from the spec
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.
