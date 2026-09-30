# Plan 3 — dry run, preview, and a damage quota

**Problem:** `mayhem run` requires `-e/--execute`, and the preflight
`blast_radius: {...}` line is a **looser re-derivation** than the gate that
actually refuses. Neither CNCF project has a simulate field in any CRD.

## The lie on screen

`controller/preflight.py::_blast_radius_for` (`preflight.py:52-73`) is **not**
`safety.check_blast_radius` (`safety.py:166-251`). The differences:

- preflight **omits `dependents_closure`** — it counts direct targets only, so
  it understates the radius
- its numerator is `len(affected)` over *all* node kinds with a
  `NodeKind.SERVICE` denominator — kind-mismatched
- it **never surfaces** `max_concurrent_faults` or `max_duration_per_fault_s`,
  which are the two limits most likely to refuse the run
- it is wrapped in `except Exception: return {}`, so a failure prints
  `blast_radius: unknown` and the run proceeds

So the operator sees one set of numbers, the gate enforces another, and the
refusal message names a limit that was not on screen. The `examples/testCase`
drill demonstrates the shape: the preview said nothing about
`max_concurrent_faults`, and the run refused on it.

## Part A — a preview that is the gate

> ### STATUS — A1 SHIPPED (uncommitted): preflight now computes the *real* gate
>
> The drift that made the lie possible is **closed**. `preflight.py` no longer
> re-derives a looser version of the blast-radius maths — it calls the real
> `safety.check_blast_radius`, twice per step:
>
> - once against a **lifted budget** to harvest `stats` for *every* step,
>   including steps the gate refuses (the gate short-circuits, so a refused
>   step never returns its numbers); the gate's `stats` are independent of the
>   budget, so a probe through a lifted budget returns exactly what the
>   enforcing call would have;
> - once against the **real budget** for the authoritative verdict, caught as
>   `SafetyRefusedError` whose `.decision` supplies `rule_id`, `reason` and
>   `remediation` verbatim.
>
> Both use a `dataclasses.replace` clone with fresh `decisions`/`warnings`, so
> probing never pollutes the safety record the run is judged by.
>
> Measured proof of the old bug: on a 3-service `web → api → db` chain faulting
> `db`, preflight said **33.3%** while the gate said **100.0%** — it omitted
> `dependents_closure` entirely and divided a mixed-kind node count by a
> `NodeKind.SERVICE` denominator.
>
> All **five** limits now render (previously only 2 of 5 were ever shown, and
> the two most likely to refuse — `max_concurrent_faults`,
> `max_duration_per_fault_s` — were the missing ones). Failure-to-compute is
> now an explicit `status: "unknown"` with a reason; the old
> `except Exception: return {}` made a failure indistinguishable from a tool
> with no opinion.
>
> Tests: `tests/unit/test_preflight_blast_radius.py`, 15 tests, 14 of which
> fail against the pre-fix tree (the drift guard is
> `test_preflight_services_pct_equals_the_real_gate`).

> ### STILL OPEN in Part A
>
> A1 fixed the *numbers*. The two deeper proposals below — showing the actual
> mutation, and Part B's damage quota — are **not started**. Note that fixing
> A1 surfaced a gate bug this plan did not anticipate: `safety.py:231` builds a
> `frozenset` of *all* faults so far rather than the pair, so
> `forbidden_fault_pairs` is silently inert for plans longer than two faults.
> See `06-debt-and-quality.md` §7a.


### Proposal

`mayhem run --preview` (or `mayhem plan run`, alongside the existing
`mayhem prepare plan`) that runs the **real** `validate_plan` and prints the
**real** computed radius, with no execution.

Two options:

| | effort | honesty |
| --- | --- | --- |
| **A1.** Make preflight call `safety.check_blast_radius` for real, and surface every field the gate uses | small | high — same code path, cannot drift |
| **A2.** Add a distinct `--preview` that executes the planner + gate and dumps the full decision trace | medium | highest — shows the decision, not just the numbers |

**Recommendation: A1 first, A2 as `mayhem run --explain`.** A1 removes the lie
with a small change. A2 is the genuinely differentiating surface and should
exist, but it is a feature, not a bug fix.

The preview must print, per the actual gate:

```
blast radius   services 3/7 (42.9%, cap 50%)  hosts 1 (cap 2)
               concurrent faults 4 (cap 3)  <-- the one that will refuse
               duration/fault 10.0s (cap 300s)
verdict        REFUSED: blast_radius.max_concurrent_faults
               raise blast_radius.max_concurrent_faults, or split the drill
```

Naming the failing limit **before** it fails, with the remediation, is the
whole point.

### The deeper version: show the mutation

A1 fixes the numbers. The unclaimed feature is showing the operator **what will
actually be executed, per target, before it happens**:

```
plan r-testcase-1cfd841c  hash cbfbdfaa5ebe   4 steps

  1  proc.pause        testcase-api
       inject  @engine kill --signal SIGSTOP testcase-api
       undo    @engine kill --signal SIGCONT testcase-api
       verify  exec: ps -p <pid>
  2  net.latency       testcase-lb
       inject  tc qdisc add dev eth0 root netem delay 5000ms
       undo    tc qdisc del dev eth0 root
       ...

probes      12 runtime checks, 0 unresolvable
gates       impact gate: 1 fault proven inert (clock.skew, rootless SYS_TIME) -> will be bypassed
            capability: iproute2 missing in testcase-lb -> mayhem prepare dependencies install
undo        every step has a write-ahead undo; residue risk: none
```

That argv already exists — it is exactly what `_tool_op` stores and what
`test_argv_pairs_decode_to_string_lists` asserts. It is simply never shown to a
human. `mayhem inspect` can already reach into a plan; the missing piece is
rendering it as an approval artefact.

## Part B — a damage quota

**Nobody bounds cumulative damage.** Chaos Mesh bounds one experiment. Litmus
bounds one experiment. Even AWS FIS, the most safety-forward of the three,
enforces a quota — *"no single table may be subject to more than 5,040 minutes
of impairment in a 7-day rolling window."* Mayhem has nothing.

This matters because mayhem's own `campaign` and `maniac` run faults repeatedly
and synthetically. `maniac` draws faults from the topology with no cumulative
limit. A user running `mayhem campaign` against a staging environment all week
has no idea how much cumulative impairment they caused.

### Proposal

```yaml
blast_radius:
  damage_quota:
    budget: 4h            # cumulative injected-seconds per target
    window: 168h          # rolling 7 days
    per_fault_ceiling: 300s
```

Enforced at plan time by the same `check_blast_radius` that enforces the
existing five limits, and reported by `mayhem prepare plan` like everything
else. The accounting key is `(node_id, fault_id)`; the value is
`duration × 1` per injection, summed over the rolling window from the store.

Why this is cheap: mayhem already persists runs, leases, and a
`steady_state_evaluations` table. It needs one aggregate query and one more
`SafetyDecision` rule. The hard part is not the accounting, it is choosing
defaults that do not surprise.

Defaults must be **generous enough never to fire on normal use** and tight
enough to catch a runaway. Proposal: 4h per target per 7 days, which is
roughly 50 `net.latency` faults at the default 300s cap. Any user who hits it
has either deliberately run a long campaign or has something wrong — both worth
telling.

## Sequencing

| Step | Deliverable | Risk |
| --- | --- | --- |
| A1 | preflight uses the real gate; every limit surfaced; the `except: return {}` becomes a visible "unknown" | **low — pure fix, do first** |
| A2 | `mayhem run --explain` renders the plan as an approval artefact | medium |
| B1 | damage quota accounting + config | medium |
| B2 | quota reported by `mayhem prepare plan` and in the verdict | low |

A1 is a bug fix disguised as a feature and should not wait for the rest. The
`except Exception: return {}` swallowing in preflight is the kind of thing that
should never have shipped: a failure to compute a number produced the same
output as "the number is zero", and an operator reading `blast_radius: unknown`
cannot tell it apart from a tool that has no opinion.

---

## STATUS — Part A and Part B both SHIPPED.

**A1 — the preview is the gate.** `preflight.py` calls the real
`safety.check_blast_radius`, twice per step: once through a lifted budget to
harvest stats for steps the gate short-circuits on, once against the real
budget for the authoritative verdict. All five limits render. Measured proof of
the old bug: on a `web → api → db` chain faulting `db`, preflight said
**33.3%** where the gate said **100.0%**.

**Part B — the cumulative damage quota is live and wired.** `domain/quota.py`
prices a fault from its **real** `FaultDefinition` (`risk` × `reversibility` ×
duration), charging every node in the `dependents_closure` the per-step
`max_services_pct` already computes. It is carried on
`BlastRadiusBudget.damage_quota` and enforced in `check_blast_radius` after the
five per-step checks, which run unchanged. **Stricter wins**; the cumulative
budget can only refuse more, never less. It fires **before** the step runs.

Example: 10 × `net.latency`@30s on one node passes all five per-step checks
(33.3% services vs a 100% cap, 0 hosts, 30s each) and is refused at step 8 on
the cumulative total — 270 > 250 damage-seconds.

Defaults: 14400 s budget, 3600 s per-fault ceiling, 7-day window. Active by
default rather than opt-in, because a quota nobody configures is a quota
nobody gets.

## A safety rule that used to be decorative

`forbidden_fault_pairs` compared `frozenset((*fault_ids_so_far, new_fault_id))`
— **every** fault so far — against two-element pairs. On a 3-fault plan it
tested `{'a','b','c'}`, which matches nothing. **The rule was silently inert
for any plan longer than two faults.** A user who configured a forbidden pair
and wrote a 3-step drill believed they were protected and were not.

Now evaluated against each `{earlier, new}` pair, which is complete. **This is
the most important behaviour change in 1.0**: plans that ran under 0.9.x with a
3+ step forbidden pair will now be refused. Recorded in the changelog.
