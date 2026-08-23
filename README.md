# Tgondi

A general-purpose chaos engineering and resilience-testing framework: a *chaos experiment
orchestration engine* — not a collection of chaos commands.

```
DISCOVER → UNDERSTAND SYSTEM → SELECT TARGET → SELECT FAULT → SELECT TOOL
        → EXECUTE → OBSERVE → EVALUATE → RECOVER → LEARN → NEXT EXPERIMENT
```

Tgondi builds an understanding of your system (docker-compose topology today, Kubernetes-ready),
plans experiments against that model, executes faults through per-host agents and a capability-
oriented toolkit, observes effects with steady-state checks, guarantees recovery through leases +
write-ahead undo + a janitor, and records honest evidence — journals, evaluations, and full audit.

## Status

**Pre-implementation planning baseline.** The `docs/` tree is the contract the first
implementation must satisfy. Start at [docs/README.md](docs/README.md) for the reading order;
[docs/roadmap.md](docs/roadmap.md) defines the phased build from Phase 0 to v1.0.

## Highlights

- **Maniac Engine** — controlled-random experiment generation: deterministic, seeded, fully
  auditable selection ([ADR-0009](docs/adr/0009-maniac-deterministic-weighted-stochastic-planner.md)).
- **Recovery guarantee** — a fault is never silently left behind; watchdogs self-heal even if the
  controller dies ([ADR-0005](docs/adr/0005-recovery-model-lease-journal-janitor.md)).
- **Mechanical safety** — environment fingerprints, triple-gated allowlists, risk ladder,
  topology-derived blast-radius budgets ([ADR-0012](docs/adr/0012-safety-model-environment-identity-and-risk-gates.md)).
- **Toolkit arsenal** — agents invoke capabilities (`net.latency`), not binaries; tools form
  fallback groups ([ADR-0004](docs/adr/0004-toolkit-capability-registry.md)).

## License / contributing

To be decided at first implementation cut; see roadmap Phase 0.
