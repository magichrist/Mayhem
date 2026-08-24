# 0012. Safety Model: Environment Identity, Triple-Gated Allowlists, Risk Ladder, Topology-Derived Blast Radius

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0005](0005-recovery-model-lease-journal-janitor.md), [ADR-0009](0009-maniac-deterministic-weighted-stochastic-planner.md),
  [architecture/safety.md](../architecture/safety.md) (full design)

## Context

Mayhem intentionally kills processes, exhausts resources, partitions networks, and generates
overload traffic. The spec demands a serious safety model and forbids uncontrolled randomness,
irreversible-by-default destruction, and surviving faults. It also mixes offensive vocabulary with
resilience goals — which must be resolved into a hard scope boundary.

## Options considered

1. **Trust the operator ("you ran it, you own it").** Rejected: fat-fingered production runs are
   the canonical chaos-engineering horror story.
2. **Interactive confirmation per fault.** Rejected as sole mechanism: useless for scheduled/random
   experiments; annoying for legitimate staging loops.
3. **Layered mechanical gates enforced between planner and executor.** Chosen.

## Decision

1. **Scope charter:** Mayhem tests *authorized* systems only. No scanning or exploitation
   primitives exist; "fuzzing" means schema-aware API fuzzing (Schemathesis) of owned services;
   saturation experiments are load-generation faults behind the risk ladder. This is a resilience
   tool, not a penetration-testing tool.
2. **Environment identity fingerprint** = hash(host set + compose digest + configured
   `environment.name`), stamped into every run; mismatch ⇒ refuse.
3. **Triple-gated allowlists:** config policy → plan validation → pre-execution assertion against
   live topology. Denylist beats allowlist beats selector.
4. **Risk ladder** (`low|medium|high|critical`) on faults and tools; `critical` additionally
   requires explicit config opt-in + CLI `--allow-critical`; `node.reboot` class defaults to
   forbidden.
5. **Blast radius budgets computed from the topology graph** (max % services affected, max hosts,
   max concurrent faults) and enforced by the scheduler — Maniac candidates are filtered by the
   same budgets, so autonomy cannot exceed them.
6. **Abort matrix:** SIGINT = graceful (finish current step → recover all);
   SIGUSR1 / ABORT file = immediate recover-all leases.
7. **Audit log:** append-only record of every privileged argv written *before* execution;
   env captures redacted.

## Consequences

- **Positive:** destructive power requires deliberate configuration at multiple layers; random mode
  inherits every gate structurally (not by convention); post-incident review has complete evidence.
- **Negative / accepted trade-offs:** setup friction for first-time users (mitigated by `mayhem
  init` generating safe defaults: dry-run-first, non-production environment class); determined
  operators can still configure unsafe policies — the model makes that loud and auditable, not
  impossible.
