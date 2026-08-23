# CLI Reference

Single entrypoint `tgondi` (Typer). Every command honors `--config`, `--dry-run` where meaningful,
and prints structured output (`--json` flag on read commands).

---

## Lifecycle

```bash
tgondi init                          # scaffold .tgondi/tgondi.yaml + sample experiment;
                                     # safe defaults: dry-run-first, empty allowlist
tgondi validate [EXPERIMENT]         # compile plan; run all safety gates G1–G2
tgondi run EXPERIMENT.yaml           # execute; streams journal to stdout
tgondi run --fault net.latency --target service:api \
           --params '{"delay":"200ms"}' --duration 30s   # manual single fault (dev)
tgondi watch RUN_ID                  # tail an active run
```

Common `run` flags: `--seed N`, `--dry-run` (compile+validate+print plan only),
`--allow-critical` (required for critical faults), `--yes` (skip approval prompts when policy
allows).

## Agents

```bash
tgondi agents install --host user@bm-1 [--host …]   # bootstrap over SSH (venv, systemd unit)
tgondi agents status                 # table: host, roles, state, capabilities summary
tgondi agents probe --host bm-1      # refresh CapabilityReport
```

## Topology

```bash
tgondi topology show [--format graph|table|json]    # merged TopologyGraph
tgondi topology drift                # blueprint vs live diff
tgondi topology targets 'service:api'   # resolve a selector, show what it matches
```

## Recovery & ops

```bash
tgondi recover [--dry-run]           # sweep non-terminal leases (janitor escape hatch)
tgondi abort RUN_ID                  # write ABORT signal (equivalent of SIGUSR1)
tgondi db prune --older-than 90d
```

## Maniac

```bash
tgondi maniac generate               # produce a RandomExperiment plan (no execution)
tgondi maniac explain RUN_ID         # candidates, scores, weights, RNG state — why this fault?
tgondi maniac run                    # generate → gate → execute (respects approval policy)
```

## Introspection

```bash
tgondi faults list [--category net] [--risk medium]
tgondi faults describe net.partition  # schema, backends, caps, risk ladder position
tgondi tools status                  # per-host tool availability matrix
tgondi config show | validate | migrate
tgondi runs list | tgondi runs show RUN_ID [--timeline] [--evaluations]
tgondi dev coverage-matrix           # regenerate docs/fault-catalog/matrix.md
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime failure (fault/step error) |
| 2 | validation/safety refusal |
| 3 | recovery incomplete (`dirty`) |
| 130 | interrupted (SIGINT) — after graceful recovery |

All refusals print the failing gate ([safety.md](../architecture/safety.md) §2) and the exact rule
that refused.
