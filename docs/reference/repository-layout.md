# Repository Layout

Single Python package, layered monorepo ([ADR-0002](../adr/0002-python-single-package-layered-monorepo.md)).
Import direction is enforced downward only (`domain ← everything`; `infra ← services ← cli`).

```
mayhem/
├── docs/                          # this documentation tree
│   ├── adr/
│   ├── architecture/
│   ├── reference/
│   └── fault-catalog/             # generated coverage matrix (Phase 8+)
├── src/mayhem/
│   ├── domain/                    # pure models, invariants, state machines — zero IO
│   │   ├── topology.py            # Node union, Edge, TargetRef
│   │   ├── faults.py              # FaultDefinition, FaultInvocation
│   │   ├── leases.py              # FaultLease + state machine
│   │   ├── experiments.py         # ExperimentSpec, ExecutionPlan, StepAction union
│   │   ├── checks.py              # SteadyStateCheck, EvaluationResult
│   │   ├── events.py              # Event union
│   │   └── capabilities.py        # CapabilityReport, ToolManifest types
│   ├── toolkit/                   # capability registry + adapters (ADR-0004)
│   │   ├── manifests/*.yaml       # tool manifests (in-tree)
│   │   ├── adapters/              # native + external tool adapters
│   │   └── executor.py            # the 8 executor guarantees
│   ├── agents/                    # runtime + roles (ADR-0003)
│   │   ├── runtime.py             # AgentRuntime base: tasks, watchdog, heartbeat
│   │   ├── protocol.py            # JSON-RPC framing (shared with controller)
│   │   └── roles/                 # process, cpu, memory, storage, network,
│   │                              # container, load, http_api, database, node,
│   │                              # fuzz, validation
│   ├── controller/                # orchestration services
│   │   ├── cli/                   # Typer app (reference/cli.md)
│   │   ├── engine/                # experiment lifecycle scheduler
│   │   ├── maniac.py              # planner pipeline (ADR-0009)
│   │   ├── safety/                # gates G1–G5, blast radius, abort matrix (ADR-0012)
│   │   ├── recovery/              # lease manager, janitor, verification
│   │   ├── topology/              # providers + merge/drift (ADR-0006)
│   │   ├── observation/           # event hub, journal writer, artifact store
│   │   ├── config/                # layered loader, migrations (ADR-0008)
│   │   └── transport/             # local_stdio, ssh_exec; agent supervisor
│   ├── infra/                     # sqlite store, migrations, subprocess runner
│   └── py.typed
├── tests/
│   ├── unit/                      # domain, planner math, compiler, config layering
│   ├── contract/                  # adapters vs fake binaries; protocol framing
│   ├── integration/               # controller↔agent; docker/podman fixture stacks
│   ├── chaos_of_the_chaos/        # kill-controller/agent scenarios (nightly tier)
│   └── fixtures/
│       ├── bin/                   # scriptable fake tools (tc, iptables, stress-ng…)
│       └── composes/              # web_db, multihost_sim, podman_parity
├── examples/experiments/          # runnable sample YAML per fault family
├── pyproject.toml                 # hatchling; deps: typer, pydantic, pyyaml, structlog;
│                                  # dev: pytest, hypothesis, ruff, mypy, pytest-asyncio
└── README.md
```

## Rules

| Rule | Enforcement |
|---|---|
| No IO in `domain/` | import-linter contract; CI check |
| Container-runtime types only inside providers/adapters | import-linter ([ADR-0013](../adr/0013-kubernetes-readiness-via-provider-seams.md)) |
| Agents never import controller modules | shared code lives in `domain`/`toolkit`/`agents.protocol` only |
| New tool = manifest + adapter (+ contract test) | checklist in [toolkit.md](../architecture/toolkit.md) §7 |
