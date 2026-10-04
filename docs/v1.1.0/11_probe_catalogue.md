# Probe catalogue, tolerance reference and condition authoring guide

Companion to `docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md`. Everything
here is generated from the code that enforces it, and the surface that prints it is
`mayhem probe`:

```
mayhem probe catalogue      # every family, its locator, and whether mayhem can read it
mayhem probe connectors     # the shipped read paths, their bounds, and the rollout order
mayhem probe tolerances     # the tolerance-type reference, including the absent one
mayhem probe build ...      # author a probe definition; prints the pin a plan must carry
mayhem probe condition ...  # author a stop condition against a probe
mayhem probe uncover ...    # what would this run NOT be able to see?
```

If a number here disagrees with the command, the command is right and this file is
stale.

---

## 1. The one rule everything else serves

**A probe that cannot be run reports `UNAVAILABLE`, and `UNAVAILABLE` never reads as
healthy.**

This is not a convention. It is the same rule
`controller/preflight_gate.py` states for its five ports — an unbound port, a port
that raises, a port that answers `None`, and a port that answers in the wrong shape
are **one finding, not four** — and it is enforced by the same three-part structure:

| Layer | What it owns |
| --- | --- |
| `domain/probes.py` | what a probe *is*: locator, unit, cadence, lifecycle stages, version pin |
| `domain/stop_conditions.py` | how a bound is compared, and what a firing must cite |
| `controller/probe_service.py` | asking one port once, and reducing every way of failing to `UNAVAILABLE` |
| `controller/probe_collector.py` | walking the lifecycle, and saying what the run may conclude |
| `controller/probe_integrations.py` | the read paths, and the timeout / size / redaction contract |
| `domain/probe_evidence.py` | turning readings into rows, verifying citations, sealing conditions |

`refuses_probe(availability)` is written `is not AVAILABLE`, not as a membership test,
so an unrecognised availability arriving from a port **refuses rather than passes by
omission**. The rule "no witness means no certificate" cannot be widened by adding a
third enum member nobody thought about.

### `UNAVAILABLE` and `unhealthy` are different findings, and are kept apart

- `UNAVAILABLE` says *mayhem has no witness*. It is a wiring problem. A `redis`
  family with no bound port says nothing whatsoever about whether Redis is fine; it
  says mayhem declined to look.
- A failing reading says *mayhem looked and the answer was no*. That is an
  operational fact about the system.

`ProbeReading` carries the two apart (`availability` versus `observation`), so a
report cannot render "the Redis probe found nothing wrong" from a port that was
never bound.

### Three states of coverage

`ProbeCoverage.of(readings)` reduces a sweep to what it establishes:

| State | Meaning |
| --- | --- |
| `complete` | every graded probe produced an available, non-settling reading |
| `partial` | some did — the run **may** report what it saw and **must** name what it did not |
| `blind` | no graded probe produced one. The run watched nothing, and nothing here is a finding about the system |

`blind` is the state in which every answer mayhem could give is a statement about
mayhem rather than about the system, and it may never be reported as a pass. The
`verdict_bearing` property is `False` in that state, and there is no code path in the
engine that turns a blind coverage into a verdict.

A probe whose only readings came from a settling window counts as **unobserved**, not
as observed: it ran, it was recorded, and it is not allowed to say anything yet.

---

## 2. Probe catalogue

Nineteen families. The plan's prose sentence named sixteen comma-separated items;
the three compound ones split here for the reasons on each member (HTTP/HTTPS is one
family because the scheme is part of the endpoint; TCP/UDP are two because a UDP
"connect" has no handshake; Kafka/RabbitMQ/NATS are three because they are three
brokers with three failure modes). The discrepancy is recorded in the plan's ledger.

| Family | Located by | Shipped read path | Rollout tier |
| --- | --- | --- | --- |
| `http` | `endpoint` (absolute `http(s)://`) | — | declared only |
| `tcp` | `endpoint` | — | declared only |
| `udp` | `endpoint` | — | declared only |
| `dns` | `query` | — | declared only |
| `grpc` | `endpoint` | — | declared only |
| `sql` | `query` | — | declared only |
| `redis` | `query` | — | declared only |
| `kafka` | `query` | — | declared only |
| `rabbitmq` | `query` | — | declared only |
| `nats` | `query` | — | declared only |
| `process` | `target` | — | declared only |
| `file` | `path` | — | declared only |
| `command` | `command` (argv tuple) | — | declared only |
| `prometheus` | `query` (PromQL) | `prometheus`, `grafana`, `datadog`, `new-relic`, `cloudwatch`, `azure-monitor`, `gcp-monitoring` | 1 (prometheus, grafana) / 3 (the rest) |
| `opentelemetry` | `query` | `opentelemetry` | 1 |
| `logs` | `query` (LogQL) | `loki`, `elastic`, `opensearch` | 1 (loki) / 3 (the rest) |
| `traces` | `query` | `tempo`, `jaeger` | 2 |
| `kubernetes` | `target` **or** `query` | — | declared only |
| `synthetic` | `steps` | `pagerduty`, `opsgenie` (on-call signals) | 3 |

**"declared only" is not "supported".** It means the family exists as a definition
and is refused nothing — and mayhem ships no read path for it, so a probe of that
family is `UNAVAILABLE` until somebody binds a port. `mayhem probe catalogue` prints
those names under `declared only`, and `mayhem probe uncover` prints the
consequence. The catalogue never implies coverage it does not have.

Where two connectors serve one family, `ConnectorCatalog.ambiguous_families()` names
the collision rather than choosing by iteration order, and
`ConnectorProbePorts.ports()` binds the **first bound** connector in catalogue order.
Which one a deployment uses is a deployment decision, so it is visible.

### What a definition must carry

`mayhem probe build` will not produce a definition that fails these, and the rule is
the same one a run applies:

- a **locator** for the family (`probes.probe_without_locator`) — a probe that
  resolves to nothing reports calm, which is the failure this vocabulary exists to
  remove;
- an **absolute `https://`/`http://` URL** for `http`
  (`probes.http_endpoint_not_absolute`);
- a **unit**, non-blank (`probes.probe_unit_blank`), and every reading must be in it
  (`probes.probe_reading_unit_mismatch`) — refused, **never converted**;
- **at least one lifecycle stage** (`probes.probe_without_stage`) — a probe not
  scheduled anywhere runs whenever the collector happens to reach it, and a baseline
  captured mid-fault is a baseline of the perturbation;
- a **noise budget** for each settling stage it claims: `warm-up` requires `warmup`,
  `after-recovery` requires `cooldown` (`probes.probe_noise_budget_missing`). A
  budget with no stage, or a stage with no budget, is refused — either alone is a
  setting that either does nothing or discovers its noise mid-verdict.

### Pinning

A version is not a pin. `ProbePin` carries `id`, `version` **and** a content
`fingerprint`, because a definition edited in place keeps its version, and a
version-only pin would happily verify a plan against a probe that now asks a
different question. `ProbePlan.bind` refuses three ways:

| Rule | When |
| --- | --- |
| `probes.unpinned_probe` | the plan pins an id the catalogue does not hold |
| `probes.probe_version_drift` | the version moved |
| `probes.probe_definition_drift` | the definition changed while still claiming its version |

Construction **is** the check: `ProbeService.__post_init__` binds, so a drifted plan
never reaches a port.

### Lifecycle

Six stages, each anchored to the `Phase` the verdict core already grades in, so a
stage cannot introduce a fourth spelling:

| Stage | Phase | Readings may support a verdict |
| --- | --- | --- |
| `pre-baseline` | `pre` | yes — they are the baseline |
| `warm-up` | `pre` | **no** — the budgeted settling window |
| `during-fault` | `during` | yes |
| `continuous` | `during` | yes, and spans pre and post too |
| `after-recovery` | `post` | **no** — the budgeted settling window |
| `final-verification` | `post` | yes — the proof the fault is gone |

Settling stages are excluded from **grading a verdict** and from **coverage**, not
from the **stop signal**. An available reading taken during `warm-up` still becomes a
sample, so a latency breach during warm-up is qualified immediately — hiding it until
the settling window closed would be exactly the "noise discovered mid-verdict" failure
the budget exists to prevent. Both halves are asserted in
`tests/unit/test_probe_collector.py`.

---

## 3. Tolerance reference

Four mechanisms, each defining its comparison function once, shared by the evaluator
and the stop-condition engine. `mayhem probe tolerances` prints this table from
`TOLERANCE_REFERENCE`.

| Kind | Carries | Compares | Baseline | Note |
| --- | --- | --- | --- | --- |
| `absolute` | `AbsoluteExpect` (`eq`/`lte`/`gte`) | the reading against a fixed bound, in the declared unit | no | a bound on both ends has no single governing bound, so hysteresis is refused rather than approximated |
| `ratio` | `Tolerance` against a captured baseline | relative **deviation**, never magnitude | **required** | a fully inverted signal cannot pass; with no baseline the bound is *unmeasurable*, which reads as not-met and never as healthy |
| `percentage` | `percent` | `\|delta_pct\|` from a baseline, reusing the steady-state change maths | **required** | reuses the verdict core's comparison rather than restating it |
| `operator` | a whole `SloCriterion` | the criterion's own operator table | no | the bucket percentile bounds and time-to-recovery land in, rather than a fifth mechanism |

### `categorical` is absent, and that is a decision

There is no `categorical` tolerance, because
`domain/observations.ObservationResult` carries `value: float | None` and **no label,
enum or string field**. There is nothing for a categorical comparison to compare.

Rather than leave that as a comment, `ProbeValueKind.CATEGORICAL` exists so an author
can *declare* a categorical probe and be **refused** with
`probes.categorical_unsupported`, naming the missing field. The refusal is lifted in
the same commit that adds the field, and
`tests/unit/test_probes.py::TestCategoricalIsRefusedDeliberately::test_the_refusals_precondition_still_holds`
fails the moment a label-like field appears — so the refusal cannot rot into a claim
that something cannot exist.

---

## 4. Authoring a stop condition

```bash
mayhem probe condition --metric http.api --op lte --value 250 \
    --for-samples 2 --debounce 1.5 --cooldown 60 --max-duration 30
```

| Flag | Meaning | Fail-closed note |
| --- | --- | --- |
| `--metric` | a probe id, as printed by `probe build` | a metric no bound probe produces is refused at sweep construction — a typo that can never fire is a defect in the plan, not a fact about coverage |
| `--op` | `eq`, `lte`, `gte` | `lt`/`gt` are refused: they have no `AbsoluteExpect` field. Percentile and time-to-recovery belong in an `SloCriterion` |
| `--value` | the bound | — |
| `--fires-when` | `broken` (default) or `met` | — |
| `--for-samples` | consecutive breaching samples required | a floor, not a cap: the run cites **every** sample that built the firing |
| `--debounce` | seconds the breach must persist | — |
| `--cooldown` | seconds after a firing before this can fire again | threaded across sweeps via `last_fired_epoch_s` |
| `--max-duration` | the observation window | on expiry the domain reports `EXPIRED` — **not** a firing and **not** a clear bill of health |
| `--hysteresis` | dead band as a fraction of the bound | kept separate from `--hysteresis-absolute` because the two are different *sizes* and the surface must not pick one |

### AND / OR

`Condition.all(...)` and `Condition.any(...)` carry `cooldown` and `max_duration` —
controls that mean something on a composite. `for_samples`, `debounce` and `hysteresis`
only mean something against a stream, so setting them on a composite is **refused by
name** rather than accepted and ignored, which is how a debounce becomes a comment.
An empty conjunction or disjunction is refused: both are vacuous, and neither is a
stop.

### A firing must cite its samples

`Firing` cannot be constructed without at least one cited sample, and each cited
sample must itself be available — citing a `missing` observation as proof of a breach
is the same defect one layer down. A stop that stopped "on a condition" with nothing
behind it is refused at three layers: the domain (`ConditionResult`), the type
(`Firing`), and plan 10's stop trigger, whose `observed_values` name each reading as
`<metric>@<recorded-at>`.

### A timeout is not an answer

A window that ran out reports `EXPIRED` from the domain and is surfaced verbatim.
**A timeout means "we did not look", and it is never reported as "we looked and saw
nothing."** The sweep never reads a clock — `stage_times` is a required input, and a
sweep with no stages or a missing stage time is refused, because a firing whose
timestamp mayhem invented cannot be replayed.

---

## 5. Evidence and the seal

A reading becomes an envelope row through `domain/probe_evidence.py`, which is the
only place that conversion happens. Three properties:

1. **Every attempt produces a row**, available or not. An `UNAVAILABLE` attempt
   produces `availability: "unavailable"`, `value: null`, and its reason — because
   "the run watched this and it was fine" and "the run could not watch this" are
   different facts, and a filter that keeps only the rows with numbers erases the
   first.
2. **Redaction happens before a byte of it becomes a document.** The reading's note is
   redacted, the finished row is walked by `domain.redaction.redact`, and the durable
   write is additionally gated by
   `infra/secret_resolver.require_persistable_document`. The connector path redacts
   the response body before the `ProbeObservation` is even constructed, and
   `SignalConnector` refuses at construction an endpoint that carries a credential —
   a redacted credential in a catalogue is still a credential in whatever version
   control holds it.
3. **Citations must be findable.** `assert_citations_verified` is the Phase 4
   acceptance criterion as a function: a firing whose cited samples cannot be matched
   to recorded evidence **fails verification** with
   `probes.verdict_cites_unrecorded_observation`, naming every unmatched citation.

The match is by `fingerprint_for(sample)` — a digest computed from the *sample* side
and from the *record* side out of **one** shared payload function, so a replay holding
only the recorded stream can re-derive it. The stage is deliberately **not** part of a
reading's identity: a sample carries no stage, so hashing it would make every citation
unmatched against evidence recorded by a sweep that walked a different stage list —
a false positive that reads exactly like tampering. Both halves are asserted as tests.

Conditions and probe pins are sealed together into `SealedConditionSet`, whose digest
covers both, because a condition tree that never changed while the probe definition
it reads was edited in place is exactly the drift this boundary should catch. Drift is
`probes.sealed_conditions_drifted`; an unsealed set is
`probes.sealed_conditions_unsealed`.

`infra/probe_seal_store.py` persists the seal in one table with one writer, and
verifies on **read** as well as on write — a seal written correctly and then altered in
the database is the case a reviewer needs caught.

### Synthetic transactions judge business correctness

A synthetic probe that checked "every step returned HTTP 200" would certify the
absence of transport errors and call it business correctness. Each step is judged on
one of four assertions, and the status code is one of them:

| Assertion | What it checks |
| --- | --- |
| `status-ok` | the transport succeeded — necessary, never sufficient |
| `field-equals` | a named business field holds its expected value |
| `order-respected` | the step ran after the one before it |
| `no-error-signal` | the body carries no error marker |

Three outcomes, and the third is the point:

- `correct` — every assertion held; `asserts_correctness` is `True`.
- `incorrect` — at least one assertion failed; `supports_verdict` is `True`, because
  the negative verdict is established too.
- `undetermined` — at least one assertion could not be observed.
  `supports_verdict` is **False**. A transaction where mayhem watched three of four
  steps is **not** a correct transaction, and `synthetic_outcome` will not let it be
  reported as one. Undetermined outranks observed failures, because "we also saw a
  failure" is not a reason to assert we saw everything.

Zero steps is refused (`probes.synthetic_transaction_vacuous`) — a check that
evaluated nothing is refused rather than passed, the same rule the preflight gate
applies to a vacuous gate.

---

## 6. Rollout order

The plan's order is encoded in `ROLLOUT_TIER_ORDER`, so the CLI and this document read
the same table:

1. **Metric and log families first** — `prometheus`, `opentelemetry`, `grafana`,
   `loki`. No vendor account, no contract, and they are what a first install can
   actually honour.
2. **Trace and synthetic second** — `tempo`, `jaeger`. Trace storage has a retention
   and a cost story that should be settled before a probe depends on it.
3. **Third-party integrations last** — `datadog`, `new-relic`, `elastic`,
   `opensearch`, `cloudwatch`, `azure-monitor`, `gcp-monitoring`, `pagerduty`,
   `opsgenie`. Each needs a credential, a contract and a renewal date.

PAGERDUTY and OPSGENIE are `oncall` signal kinds and are tier 3 regardless: an
incident count is a statement about humans, not about the system under test, and
grading a run on it before the metric families are trustworthy would invert the
confidence order.

---

## 7. What this documentation does **not** claim

Stated plainly, because the plan's Phase 6 acceptance criterion is "no doc claims an
integration proves more than its provenance states":

- **No live-cell behaviour is claimed.** The Phase 2 acceptance criterion reads "a
  breached condition stops a run before nominal fault duration in live-cell tests".
  This repository cannot inject a fault into a live Kubernetes cluster from a unit
  test. What is tested is the *decision*: with readings recorded at `t=0..3` and a
  breach qualified at `t=3`, the engine fires, cites the breaching samples, and hands
  plan 10 a stop command naming them. The live path is asserted to be
  **`UNAVAILABLE`** — a `kubernetes`-family probe with no bound port — because that
  is the honest state, and `refuses_probe` says so out loud.
- **No signature verification is claimed anywhere.** `mayhem.providers.pack.
  SIGNATURE_VERIFICATION_IMPLEMENTED` stays `False`. A probe reading is evidence that
  mayhem asked and got a number back; it is not evidence that the number is
  authentic. `ConnectorId` has no member whose name contains `verified` or
  `signature`, and a test asserts that, so adding one fails the suite rather than
  silently raising `verified-live`.
- **`verified-live` is 0 and stays 0.**
- **The shipped connectors are declarations, not clients.** They say *what may be
  asked, of where, and under which bounds*; a bound client answers them. Fifteen
  copies of `observability/base.fetch_json` would be fifteen places to get the cap
  wrong, and no test in this repository has spoken to Prometheus, Datadog or
  PagerDuty.
- **The endpoint templates are placeholders.** They are vendor documentation shapes
  with a `{base}` a deployment substitutes, and none of them is anybody's
  production address — asserted, so shipping one fails a test.
- **Migration 36 is registered but not applied.** `PROBE_SEAL_MIGRATION` is defined in
  `infra/probe_seal_store.py` and is **not** in
  `infra.migrations.ALL_MIGRATIONS`, because this work item does not own that file.
  Until it is, the seal table exists only where a caller splices the migration in —
  which is what `tests/unit/test_probe_evidence.py` does, against a real migrated
  in-memory database. The claim under test is *this module's* schema, not production's.
- **`mayhem probe` is not registered.** It is absent from
  `cli/command_registry.py`, so the one-line registration it owes is recorded in the
  plan's ledger and asserted absent by a test, rather than being quietly added.