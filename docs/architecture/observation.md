# Observation & Evidence

Tgondi's credibility rests on honest observation: every claim in a run summary must be backed by
recorded evidence. This document defines the event model, the journal, storage of history, and the
seams for future sinks.

---

## 1. Event model

Everything observable flows through one typed `Event` union (defined in domain):

| Kind | Producer | Payload highlights |
|---|---|---|
| `run.started / completed / failed / aborted` | controller | status, timings, seed, config snapshot ref |
| `step.started / finished / skipped` | engine | step id, action type, outcome |
| `fault.injected / recovered / failed` | recovery manager | lease id, fault, targets, backend/tool |
| `tool.executed` | toolkit executor | argv digest, exit code, duration, artifact ref |
| `check.evaluated` | evaluation runner | check id, phase, passed, measured value |
| `observation.window` | observer hub | steady-state window results (`pre/during/post`) |
| `agent.state_changed` | agent supervisor | agent id, state transition |
| `lease.state_changed` | janitor/watchdog | lease id, from → to state |
| `drift.reported` | topology service | drift items |
| `safety.refused` | safety engine | gate that refused, reason |
| `maniac.decision` | maniac | candidate scores summary, chosen plan |

Events are append-only; they are written to SQLite (source of truth) and mirrored into the
journal. Agents emit events over their channel ([agent-architecture](agent-architecture.md) §1) —
they never write storage directly.

## 2. The Journal

Per-run, human-readable Markdown narrative written continuously during execution:

```markdown
# Run r-20260823-141201 — net.partition between api and db

## Hypothesis
DB connection pool exhaustion should surface as 5xx within 30s.

## Timeline
14:12:01  discovered 12 nodes (2 drift warnings)
14:12:02  steady-state PRE window: 3/3 checks passed
14:12:05  injected net.partition (iptables DROP, lease l-a1f3)
14:12:35  DURING window: check "api health" FAILED — p99 8.4s, error rate 41%
...
## Recovery
14:13:10  released lease l-a1f3; verification probe passed (chain absent)
## Evaluation
POST window: 5/5 checks passed · time-to-recover: 9.2s
## Verdict
Hypothesis CONFIRMED with evidence refs [art-017, art-018]
```

The journal lives at `.tgondi/journals/<run-id>.md`, is streamed to stdout in watch mode, and its
final block is persisted as the run row's summary.

## 3. Artifacts

Raw evidence that doesn't fit a row — tool stdout/stderr full captures, probe bodies, k6 result
files, discovery snapshots — is stored under `.tgondi/artifacts/<run-id>/…` and referenced by
`artifact_ref`. Rows never inline large payloads; truncation is always explicit
([toolkit.md](toolkit.md) §4).

## 4. Steady-state windows

Checks are evaluated in three phases per [experiment-engine](experiment-engine.md):
`pre` (baseline gate), `during` (violation policy), `post` (recovery proof). Each evaluation row
records measured value + expectation expression, so summaries can quote numbers rather than
adjectives.

## 5. Storage split

| Concern | Home |
|---|---|
| Structured history (runs, steps, leases, tool runs, checks, decisions) | SQLite — [reference/sqlite-schema.md](../reference/sqlite-schema.md) |
| Human narrative | Journal markdown files |
| Raw payloads | Artifact store |
| Live streaming | stdout + future sink interface |

## 6. Future sinks (v1.x)

An `ObserverSink` protocol (`async def emit(event) -> None`) exists from day one as an internal
seam ([ADR-0011](../adr/0011-toolkit-as-extension-point-no-plugin-system.md)); planned sinks:

- **Prometheus** — metrics endpoint on controller (opt-in): fault counts, MTTR histograms,
  check pass rates.
- **OpenTelemetry** — spans per step/fault for correlation with app traces.
- **Slack/webhook** — notify channel on completion/abortion via existing `Notify` step action.

No sink may become load-bearing for correctness: recovery and audit read only from SQLite +
journal, so a dead sink degrades nothing.

## 7. Redaction

Environment captures and tool env digests are redacted by pattern list from config
(`observation.redact_patterns`, default covers common secret var names). Redaction happens at
capture time — raw secrets are never written anywhere.
