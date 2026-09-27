# Fault expansion plan — 72 requested ids

Status: **plan only.** No code in this directory has been implemented.

## Headline finding

The 72 requested ids were checked one-by-one against the live catalog
(`python3 -c "from mayhem.domain.catalog import CATALOG; ..."`, 120 entries).
**Zero of them exist today**, but that is not the interesting number:

| Bucket | Count | Meaning |
| --- | --- | --- |
| `EXISTS_ALREADY` | **0** | exact id already in the catalog |
| `NEAR_DUPLICATE` | **31** | a different existing fault already implements the mechanism — usually via a param that is already declared |
| `GENUINELY_NEW` | **20** | no existing fault covers the mechanism |
| `PREFIX_INVALID` | **21** | the id prefix has no `FaultCategory`; the id cannot even be constructed |

So the real work is **20 new mechanisms, not 72 new ids.** Adding all 72 as
distinct fault ids would produce a catalog with 31 pairs of ids that compile to
the same `tc`/`iptables`/`python` argv, and 21 ids under prefixes the
architecture has no place for.

Three concrete examples of the duplication, each verified against the actual
params and compensation code:

- `net.jitter` — `net.latency` already declares `jitter_ms: int` and appends it
  to the netem argv as a second token (`netem delay <d>ms <j>ms`).
  `compensation.py:702-712`
- `clock.jump_forward` / `clock.jump_backward` — `clock.skew` declares
  `offset_ms: int` **required and signed, with no minimum or maximum**, and
  implements it as a *step* (`date -u -s "@$(( $(cat marker) + offset_ms ))"`),
  not a rate. A positive offset is a forward jump. `compensation.py:2100-2143`
- `net.ingress_block` — `net.packet_loss` already has
  `direction: str = "egress"`, and `_direction()` implements the full ingress
  path with an ifb/mirred redirect
  (`ip link add ifb0 … tc filter … action mirred egress redirect dev ifb0`).
  `compensation.py:733-786`

There is also a **live bug** this exercise surfaced, which wave 1 fixes:
`db.query_error` declares `error: str = "deadlock"` but its compensation
(`_db_query_error_undo`, `compensation.py:1744-1770`) reads only `probability`
and `port`. The param is inert — three requested ids
(`db.lock_contention`, `db.deadlock`, `db.transaction_abort`) are asking for a
knob that already exists and is never read.

## What the repository can and cannot perturb

Dependency set is `pydantic, typer, click, pyyaml, structlog, kubernetes`
(`pyproject.toml`). There is **no fault-injection library, no proxy library, no
message-queue client, and no consensus client.** Grep for `envoy`,
`toxiproxy`, `chaos-mesh`, `setrlimit`, `losetup`, `dmsetup`, `umount`,
`mitmproxy` returns zero hits in `src/`.

The entire in-container perturbation vocabulary is: `tc`, `iptables`, `date`,
`mount`, `chmod`, `sh`, `python`, `kill`, plus the engine binary
(`docker`/`podman`/`kubectl`) and `nsenter` on the node lane. `impact._PROBE_BINS`
(`impact.py:171-180`) is exactly that list, and nothing else.

This is why `mq.*`, `obs.*`, and `cluster.*` are the hard part of the request:
they are broker, telemetry, and consensus-protocol level. There is no
mechanism in this codebase that reaches them, and inventing one is a
substrate project, not a catalog addition.

## Plan structure

The work is ordered so that each wave is independently shippable and each wave
makes the next one cheaper.

| Wave | Document | Fault ids added | Registry churn |
| --- | --- | --- | --- |
| 0 | [wave-0-collisions.md](wave-0-collisions.md) | 0 | decisions only — resolve the naming and dead-param questions |
| 1 | [wave-1-params.md](wave-1-params.md) | 0 (31 ids retired) | `params_schema` + compensation builders only |
| 2 | [wave-2-new-container.md](wave-2-new-container.md) | **~14** | catalog + executor + compensation + `REQUIREMENTS` |
| 3 | [wave-3-no-primitive.md](wave-3-no-primitive.md) | 0 (9 ids as `catalog_only`) | catalog only |
| 4 | [wave-4-new-domains.md](wave-4-new-domains.md) | 0-2 (21 ids remapped or refused) | new substrate, or `catalog_only` |

Wave 1 before wave 2 is deliberate: several wave-2 ids are only worth adding
*because* wave 1 removes the overlap that would otherwise make them ambiguous
(`net.tcp_half_open` vs `net.partition`, `fs.corrupt` vs `fs.read_only`).

## Definition of done, per fault

Adding a fault id is not additive — **five registries must agree** or the test
suite fails. The full checklist with file references is in
[contract-checklist.md](contract-checklist.md). In short:

1. `CATALOG` entry in `src/mayhem/domain/catalog.py` — validated at **import
   time** by `validate_catalog()` (`catalog.py:1792`), so one non-conforming
   entry breaks `import mayhem` entirely.
2. Executor routing in `src/mayhem/agents/executors.py` — by prefix
   (`FaultExecutor.supports`, `executors.py:81`) or an explicit
   `_register_fault_executor` override (`executors.py:3863`).
3. A compensation template in `src/mayhem/controller/compensation.py` —
   `template_for()` (`compensation.py:2313`). Without one, `compensated()`
   raises `InvariantViolationError("plan_uncompensated_fault")` and the planner
   refuses the drill.
4. An entry in `impact.REQUIREMENTS` (`impact.py:65`) or `_ENGINE_FAULTS`
   (`impact.py:136`), or the fault is treated as inert and silently bypassed.
5. Param seeding where a required param cannot be satisfied by the generic test
   seed (`tests/unit/test_container_fault_matrix.py:69-84`).

## Known blocker unrelated to this plan

The `examples/testCase` drill in this repo is currently refused before it runs:

```
blocked:
  - [safety.refused] blast radius: max_concurrent_faults exceeded
    [blast_radius.max_concurrent_faults]
```

`max_concurrent_faults` defaults to `3`
(`BlastRadiusBudget.max_concurrent_faults`, `domain/experiments.py:60`) and is
checked as `len(fault_ids_so_far) + 1` per plan step
(`safety.py:205-217`) — a **prefix count of fault steps**, not real
concurrency. That drill plans 42 fault steps, so it trips on step 4.

Two separate issues, both worth fixing before any new fault is exercised
against it:

- `config.max_faults: 1` in `examples/testCase/mayhem.yaml` is **not
  enforced anywhere in `src/`**. `docs/drill-spec.md:359-360` describes it as
  gating concurrent faults, but only `blast_radius.max_concurrent_faults` is
  executable. The doc and the code disagree.
- `Preflight.blast_radius` (`preflight.py:52-73`) is a looser re-derivation
  than the real gate: it omits `dependents_closure` and never surfaces
  `max_concurrent_faults` or `max_duration_per_fault_s`. The displayed
  `blast_radius: {...}` line is indicative only; `safety.py:166-251` is
  authoritative.
