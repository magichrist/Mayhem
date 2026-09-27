# Implementation outcome

What actually shipped, wave by wave, against what the plan predicted. Written
after the fact so the deltas are visible rather than quietly edited away.

## Scorecard

| Wave | Plan said | Shipped | Delta |
| --- | --- | --- | --- |
| 1 | retire 31 ids by widening params, 0 new ids | 0 new ids, 6 param sets, **2 live defects fixed** | as planned |
| 2 | 14 new container-lane faults | **12** new faults | 2 fewer |
| 3 | 9 `catalog_only` refusals | **9** | as planned |
| 4 | remap or refuse 21 invalid-prefix ids | 0 ids, `obs.*` deferred to an ADR | as planned |
| — | — | **+21 catalog entries total** (120 → 141) | |

Catalog went 120 → 141: 12 executable faults and 9 refusals. The 31 retired ids
cost zero catalog entries.

## The two defects wave 1 found

Neither was asked for. Both were live.

**`db.query_error.error` was inert.** The catalog declared
`error: str = "deadlock"`; the compensation read only `probability` and `port`.
Every value produced the same TCP RST. The param was visible in
`mayhem discover faults` and did nothing. It now selects the mechanism —
`deadlock` (RST), `lock_timeout` (blackhole, so the client deadline fires),
`serialization_failure` (latency on the DB flow only) — and the regression guard
asserts three distinct argv so it cannot go inert again.

**`db.slow_query` contradicted its own name.** It advertised latency while
shipping an `iptables DROP`, which is a blackhole — the exact wire behaviour of
the `db.query_timeout` it was contrasted against. `mode` now makes the default
honest and keeps the old behaviour reachable.

`db.slow_query`'s new default is a **breaking change**. Existing drills that
relied on the blackhole need `mode: timeout`.

## Corrections to this plan

**`http.stream_stall` was never blocked.** `wave-2-new-container.md` called it
high-difficulty because the relay was "one-shot". It was already a chunked,
bidirectional, two-thread pump. See the correction in that file for the measured
before/after. The `catalog_only` fallback it recommended was not needed.

**`net.mtu_mismatch` scope.** `_tc_qdisc_undo` shapes a whole interface. For a
DB-scoped fault that degrades unrelated egress, so wave 1 added
`_tc_port_netem_undo` — a `prio` root with netem on one band and a u32 filter
steering only the target dport into it. Stricter than the plan specified, in the
direction of not breaking traffic nobody asked us to break.

**`fs.corrupt` is not a payload fault.** The plan leaned on the payload
lifecycle, but `PayloadExecutor.undo` only SIGKILLs the burner process, which is
useless for a fault that mutates data the target owns. It runs as a
`ToolExecutor` that copies the original aside and restores it, so it is
genuinely reversible rather than "reconciled".

**`fs.read_only` has a latent shell-injection surface.** `_fs_read_only_undo`
interpolates its `path` param into an `sh -c` command line unquoted. `fs.corrupt`
uses `shlex.quote` and the plan's other new builders validate their inputs. The
pre-existing one is **not** fixed here — it is a separate change and it is
recorded as such rather than fixed silently inside a fault-addition commit.

## What a fault actually costs

Adding one is not additive. Five registries must agree, and the first two run at
**import time** — one non-conforming entry breaks `import mayhem` for the whole
package, not one command.

Roughly, per executable fault: one `_define` entry, one compensation builder, one
`_tool_template` or `_PAYLOAD_FAULTS` registration, one `REQUIREMENTS` entry,
sometimes an executor override, and the seed maps in the three matrices that
generate params.

Two traps that cost real time and are worth remembering:

- **A requirement bin missing from `_PROBE_BINS` can never be reported present.**
  `ip` was not in it, so `net.interface_down` and `net.mtu_mismatch` would have
  been marked permanently inert on every container, with the fault looking
  registered and the gate quietly saying "cannot prove impact possible".
- **Executor routing is by id prefix, and the prefix is often already claimed.**
  `process.*` belongs to `ProcPauseExecutor`, `net.*` to `ToolExecutor`, `fs.*` to
  `PayloadExecutor`. Prefix matching alone would have run all four wave-2 payload
  faults on the wrong lifecycle. Each needed an explicit override.

## Verification that mattered

Structure checks are necessary and not sufficient. The two highest-value tests
in this work are the ones that *execute* something:

- `tests/unit/test_http_proxy_wire.py` runs the generated proxy program against
  real sockets and asserts the wire bytes. It caught `relay()` being called with
  three arguments by a two-argument function — a `TypeError` that would only
  have surfaced inside a container, at fault-injection time, in production.
- `tests/unit/test_fault_params_wave1.py` asserts three `db.query_error` values
  produce three distinct argv. That is the regression guard for the inert param.

Both properties that had already fooled us once — a script that parsed but
completed nothing, and a param that existed but did nothing — were the same
shape: **green tests, broken behaviour.** Anything asserting on generated source
text should have a sibling that runs it.

## Deferred

- **`obs.*` (4 ids).** The literal ask cannot work, but "does the drill still
  reach a correct verdict when its evidence is missing?" is testable today and
  is a product decision about what a verdict means. It belongs in an ADR, not a
  fault entry. See `wave-4-new-domains.md`.
- **`mq.*` (7 ids) and the 5 invalid namespaces.** Substrate work, not catalog
  work. `src/mayhem/toolkit/manifests/toxiproxy.yaml` already exists and no
  executor references it — wiring it is the plausible path.
- **`fs.read_only` path quoting.** Noted above.
- **`config.max_faults` is still unenforced.** Wave 1 corrected the docs to match
  the code. The code is the thing that is arguably wrong, and making it enforced
  would change what existing drills do.
