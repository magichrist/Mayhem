# Mayhem

A general-purpose chaos engineering and resilience-testing framework: a *chaos experiment
orchestration engine* — not a collection of chaos commands.

```
DISCOVER → UNDERSTAND SYSTEM → SELECT TARGET → SELECT FAULT → SELECT TOOL
        → EXECUTE → OBSERVE → EVALUATE → RECOVER → LEARN → NEXT EXPERIMENT
```

Mayhem builds an understanding of your system (docker-compose topology today, Kubernetes-ready),
plans experiments against that model, executes faults through per-host agents and a capability-
oriented toolkit, observes effects with steady-state checks, guarantees recovery through leases +
write-ahead undo + a janitor, and records honest evidence — journals, evaluations, and full audit.

## Status

**Core implemented.** Domain models, lease/recovery machinery, deterministic + seeded-random
planners, a durable run engine, and the `mayhem` CLI are working with unit and integration
coverage (`pytest`). The `docs/` tree remains the architectural contract; see
[docs/roadmap.md](docs/roadmap.md) for what is next.

## Quickstart

```console
$ pip install -e .

# What can the toolkit do?
$ mayhem faults

# Dry-run: plan an experiment against your topology, print the plan as JSON
$ mayhem plan examples/experiments/proc-pause-drill.yaml --process api=4242

# Execute it for real (SIGSTOP the process, verify, resume, journal everything)
$ mayhem run examples/experiments/proc-pause-drill.yaml --process api=$(pgrep -f myapi)

# Inspect history; repair anything left behind by a crashed controller
$ mayhem status
$ mayhem recover r-proc-pause-drill
$ mayhem janitor
```

Experiment specs are YAML (see [examples/experiments](examples/experiments/)); durations accept
`10s` / `5m`; targets select nodes from the topology graph you pass on the command line.

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
