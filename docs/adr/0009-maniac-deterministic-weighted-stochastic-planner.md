# 0009. Maniac Engine: Deterministic Weighted-Stochastic Experiment Planner

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0004](0004-toolkit-capability-registry.md),
  [architecture/maniac-engine.md](../architecture/maniac-engine.md)

## Context

`maniac.enabled: true` permits the framework to autonomously choose experiments. The spec forbids
`random.choice()` over a fault list: selection must consider discovered architecture, dependencies,
capabilities, risk, configured limits, history, diversity, and blast radius — and remain safe,
explainable, and reproducible. ML/adaptive behavior is explicitly out of scope initially but the
door must stay open.

## Options considered

1. **Uniform random over faults.** Rejected by spec; also unsafe (ignores capabilities/policy) and
   uninteresting (repeats).
2. **Fully deterministic rotation schedule.** Rejected: predictable coverage, no exploration of
   combinations; "controlled randomness" is the point.
3. **Bandit/RL selection now.** Rejected for MVP: no trustworthy reward signal until observation
   and evaluation mature; premature optimization.
4. **Filter → score → seeded weighted sample → compose, with full decision audit.** Chosen.

## Decision

Pipeline (all stages recorded per run):

1. **Candidate generation** = FaultDefinitions ∩ agent capabilities ∩ policy allowlist/risk ceiling
   ∩ topology applicability ∩ current blast-radius budget fit ∩ cooldowns/recency window.
2. **Scoring** = weighted mix: risk-fit to policy posture, topology relevance (dependency depth,
   target criticality), history novelty (never-tried bonus, recent-run penalty), coverage-gap bonus
   from the fault-catalog matrix, minus penalties (forbidden-combo adjacency, budget overrun).
3. **Selection** = seeded `random.Random(seed)` weighted sampling; `seed: null` derives and
   *records* one per run.
4. **Composition** = multi-fault plans respecting `max_concurrent`, forbidden-pairs matrix,
   dependency sanity.
5. **Gate** = generated plan passes the same compiler validation as hand-written YAML
   (`kind: RandomExperiment`), honors dry-run-first policy, optional approval gate.
6. **Audit** = every run stores candidates, scores, weights, RNG state, and choice in the
   `maniac_decisions` table — replayable and challengeable.

The history tables already record `(fault_id, target_class, outcome, time_to_recover)`, so a
contextual-bandit replacement for fixed weights slots in later with zero schema change.

## Consequences

- **Positive:** autonomy with accountability — any experiment can be explained after the fact;
  identical seeds reproduce identical plans; safety policy cannot be routed around because
  candidate generation *is* policy evaluation.
- **Negative / accepted trade-offs:** fixed weights encode judgment calls that may be wrong
  (tunable via config); scoring adds compute trivial in magnitude; adaptive learning deferred —
  acceptable because honest observation must exist before learning means anything.
