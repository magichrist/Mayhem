# Mayhem Implementation Milestones

Phase-gated, decision-locked, code-with-tests implementation plans derived from the
verdict in `docs/answer2.md` and locked through a grill-me decision session.

## Rule of every milestone

- **ADR-lock first, then code, then tests** (all addresses the review verdict "lock these,
  then implement").
- **Non-breaking** at every step (existing `kind: drill` specs keep working).
- **DONE bar = unit tests + e2e-where-live** per milestone (e2e required wherever live
  mutation occurs; model-only milestones need unit coverage).
- **In-place schema until M4, then frozen + versioned migrations** (Q9).
- Execution-gated autonomy by default (supervised), opt-in autonomous within bounds.

## Dependencies / build order

```
M1 identity ──▶ M2 execution engine ──▶ M3 runtime adapters (+NetworkPath model)
                                                │
M4 DSL ◀────────────────────────── needs M2/M3 locus + M3 verdicts
                                                │
M5 intelligence/campaigns/Maniac ── needs M4 checks/SuccessCriteria (verdict) + M2 conflict + M3 feasibility
                                                │
M6 core chaos arsenal ── needs M2 (fn/journal/cancel) + M3 (NetworkPath) + M4 (checks)
                                                │
M7 k8s interface ── needs M3 adapter contract + M2/M3 fingerprint backbone
M8 operations arsenal (deferred; needs M5 coverage + M6 no-leftover + M2 cancel)
```

## Milestone index

| File | Scope | Key phase sequence |
|------|-------|--------------------|
| [`milestone-1.md`](milestone-1.md) | Container identity (P0 §1/§2-container) | RuntimeIdentity/Metadata → plan resolution → store → TARGET_DRIFT state → bc verify |
| [`milestone-2.md`](milestone-2.md) | Execution engine (P1) | FaultGroup v1 → live re-resolution/TARGET_DRIFT → capability revalidation → process identity → cancellation ladder → mutation journal → conflict mgr |
| [`milestone-3.md`](milestone-3.md) | Runtime adapters + rootless + NetworkPath (P2) | RuntimeAdapter → CapabilityRequirements+verdicts → 3-locus ctx → rootless/remote/k8s matrix → remote/k8s ADR → NetworkPath |
| [`milestone-4.md`](milestone-4.md) | DSL: additive checks/SuccessCriteria/observability + Duration fix (P3) | Duration typing bug → locus checks → SuccessCriteria → observability sources → versioned migrations |
| [`milestone-5.md`](milestone-5.md) | Intelligence: Run/Outcome, coverage, campaigns, autonomous Maniac (P4) | Run/Outcome → coverage → candidates+gates → campaigns → Maniac engine → supervised/autonomous gate → report |
| [`milestone-6.md`](milestone-6.md) | Core chaos arsenal | process → resource pressure → container lifecycle → network (NetworkPath) → dependency/db → no-leftover sweep |
| [`milestone-7.md`](milestone-7.md) | Kubernetes: interface + model | node-kinds → adapter contract → categories+matrix → optional harness |
| [`milestone-8.md`](milestone-8.md) | Operations arsenal (deferred): DNS/TLS/app + load/fuzz + k8s-exec | outline only, expanded when scheduled |

## Decisions locked (grill session)

Q0 deliverable=ADR+code+tests · Q1 M1=container identity only · Q2 full non-breaking ·
Q3 TARGET_DRIFT ADR-in-M1/detect-in-M2 · Q4 revalidation-in-M2, schema-M3 ·
Q5 plan-non-null-ctx, locus-M3 · Q7 ~7 milestones · Q8 one-M2-many-phases ·
Q9 hybrid-migrations (in-place→M4) · Q10 cancellation-framework-in-M2 ·
Q11 docker-primary/podman-secondary, remote+k8s ADR-only · Q12 NetworkPath-model-M3/archetypes-M6 ·
Q13 DSL additive · Q14 full autonomous Maniac · Q15 hybrid-gated · Q16 core-chaos-set ·
Q17 k8s-interface-only · Q18 unit+e2e-where-live · Q19 short-M8.
