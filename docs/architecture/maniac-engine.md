# Maniac Engine

Controlled-random experiment generation ([ADR-0009](../adr/0009-maniac-deterministic-weighted-stochastic-planner.md)).
The Maniac Engine produces `ExecutionPlan`s through the same compiler/validation path as
hand-written experiments — it never executes anything itself.

---

## 1. Pipeline

```text
allowed fault universe (policy)
        ↓
capability filtering          # can any agent actually run it right now?
        ↓
safety filtering              # risk ceiling, forbidden faults, env class
        ↓
target relevance              # topology has fitting nodes? dependency depth/criticality
        ↓
budget fit                    # blast radius: services %, hosts, concurrent slots free?
        ↓
cooldown / recency window     # diversity enforcement
        ↓
weighted scoring
        ↓
seeded weighted sampling      # 1..K faults
        ↓
composition                   # max_concurrent, forbidden_pairs, dependency sanity
        ↓
plan synthesis (kind: RandomExperiment)
        ↓
dry-run validation → [approval gate if policy demands] → experiment engine
```

## 2. Scoring function

```
score(c) = w_r · risk_fit(c)            # alignment with configured posture
         + w_t · topology_relevance(c)  # dependency depth, target criticality
         + w_n · novelty(c)             # never-tried bonus; recent-run penalty
         + w_g · coverage_gap(c)        # under-tested cells of the catalog matrix
         − penalty(combo_conflict)      # adjacency to forbidden/known-bad pairs
```

Default weights ship balanced (`randomness: low|balanced|high` scales exploration vs stability);
weights are config-visible and every score component is recorded per candidate.

## 3. Selection & composition rules

| Rule | Default |
|---|---|
| Seed | `null` ⇒ derived per run and **recorded** |
| Faults per generated plan | 1 (configurable to K) |
| Max concurrent faults | policy `blast_radius.max_concurrent_faults` |
| Forbidden pairs | e.g. `[storage.fill, db.conn_exhaust]` |
| Diversity | same fault not repeated within `diversity_window` runs |
| Cooldowns | per-fault minimum spacing after high-risk runs |

## 4. Auditability

Every decision persists to `maniac_decisions`: candidates with scores, active weights, RNG state,
and the chosen plan reference. Post-incident review can answer *"why did the robot do that?"* —
a hard requirement for autonomy.

## 5. Future adaptive behavior (out of MVP scope)

History tables already store `(fault_id, target_class, outcome, time_to_recover)` per invocation.
The planned evolution replaces fixed weights with a contextual-bandit scorer over these features —
zero schema change, same pipeline, same gates. No ML claims are made until honest observation and
evaluation exist to learn from.

## 6. Safety interaction

Candidate generation **is** policy evaluation: a fault that fails any gate never becomes a
candidate, so no post-hoc veto is needed. Random mode additionally honors `require_dry_run_first`
and optional human approval for plans containing `high`-risk selections.
