# Observability

Mayhem can *read* from observability backends and it can emit local
OpenTelemetry spans. It never writes to a remote backend.

## Connectors

| Connector | Direction | Purpose |
| --- | --- | --- |
| `mayhem.observability.prometheus.PrometheusConnector` | read-only | Instant queries against `/api/v1/query` |
| `mayhem.observability.loki.LokiConnector` | read-only | Range queries against `/loki/api/v1/query_range` |
| `mayhem.observability.otel.InMemorySpanSink` | local write | Records run-lifecycle spans in this process |

Remote connectors are opt-in: nothing in the default run path dials Prometheus or
Loki. A connector is constructed explicitly and handed an `ObservationProvider`
slot (see `mayhem.providers.observation`).

## Bounds every connector inherits

`mayhem.observability.base.fetch_json` enforces, for all of them:

- a **timeout** (default 5s) passed to the transport;
- a **response-size cap** (default 256 KiB) — an over-large response is refused,
  not truncated into a lie;
- a **JSON shape check** — non-JSON and unexpected shapes are refused;
- **redaction** of every error detail and every log line before it can reach
  evidence. `Authorization: Bearer …` and bare `bearer …` tokens are covered by
  the shared policy in `mayhem.domain.redaction`.

## Failure is degraded, never silent

A connector error becomes an `ObservationResult` with
`status=ERROR`, `value=None`. The SLO criterion that depends on it then *fails*
with `observation unavailable (error)` — a broken metrics endpoint can never be
mistaken for a healthy system.

## Lifecycle spans

A run emits, in order: `mayhem.plan`, `mayhem.approval`, `mayhem.lease`,
`mayhem.mutation`, `mayhem.verification`, `mayhem.compensation`,
`mayhem.evidence`. Only the span **names** are persisted to the evidence
envelope (`emitted_spans`); span attributes are redacted at the sink and are not
written to evidence. `missing_spans()` reports which required spans a run failed
to emit.
