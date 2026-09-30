# Plan 05 — Application and Dependency Faults

**Priority:** P1. Gap item 5.

## Objective
Expand beyond infrastructure faults into realistic production dependency failures — without duplicating the faults that already exist.

## Builds on
The catalog already ships `http.*` (error injection, upstream timeout, header inject, response truncate, stream stall), `dependency.*`, `db.*` (`db.query_error`, `db.slow_query` with real modes after wave 1), four DNS fault kinds, and two TLS kinds, plus the hand-rolled in-container passthrough proxy that backs the proxy-mode faults. The wave-1 lesson stands: the parameter, not the id, carries the mechanism.

## Fault groups (candidates — Phase 1 decides new vs. param)
HTTP (abort, delay, timeout, reset, status/header/body mutation,
replace/patch); gRPC (status injection, metadata mutation, delay,
timeout, message fault); DNS (NXDOMAIN, SERVFAIL, timeout, wrong IP,
delay); TLS (expired cert simulation, handshake failure, protocol
mismatch, trust-chain failure); TCP (refuse, reset, timeout,
blackhole); messaging (publish/consume failure, ack delay/failure,
partition simulation, rebalance pressure — substrate decision required:
no broker client ships today); database (connection failure, query
latency, pool pressure, transaction failure, replication delay,
failover simulation).

## Phase 1 — Domain model: collision audit first
Map every candidate against `definition_for()` and the reliability-matrix parameter table. Output is a wave-0-style decision table: already-exists (retire the ask), param-extension (add one axis), genuinely-new (new id). The messaging group additionally needs the wave-4 substrate ruling (no broker client in domain; toxiproxy manifest exists but no executor references it). Acceptance: the audit table is checked in and every subsequent phase cites it; a test fails if a proposed id duplicates an existing mechanism.

## Phase 2 — Engine: proxy and tool mechanisms
Genuinely-new faults build on the existing proxy pump (chunked, bidirectional, two-thread — stall/abort/delay fall out of it) or `ToolExecutor` argv pairs (`fs.corrupt` precedent: data the target owns routes through tool undo, never marker-kill). Acceptance: each mechanism runs against real sockets in tests, in the style of the proxy wire test that caught the `relay()` arity bug.

## Phase 3 — Surface: params, targeting, probes
Parameter grammar per fault (direction, status, headers, bytes, stall_ms axes before new ids), explicit dependency targeting (`target.dependency` selectors), and matching probe definitions so business-level probes can validate real customer workflows. Acceptance: `discover faults -e` explains each new axis; three-distinct-argv regression guards per parameter set.

## Phase 4 — Safety and evidence integration
Compensation templates for every new id (planner refuses without one); impact REQUIREMENTS rows; dependency-fan-out accounting so a fault aimed at one dependency cannot silently take its neighbors (feeds 14 prediction). Acceptance: recovery semantics proven per fault; blast accounting covers the dependency closure.

## Phase 5 — Tests, regression guards, negative controls
Wire tests executing generated proxy programs; param-inertness guards; refusal tests for unresolvable dependencies. Negative control: a dependency fault aimed at a non-existent upstream refuses at plan time, never injects nowhere and reports success. Acceptance: new ids swept into the six deriving test files automatically.

## Phase 6 — Docs, honesty gates, rollout
Reliability-matrix entries (parameter-first, with the "id someone reaches for first does not exist" notes where applicable); drill-spec parameter catalogue additions. Rollout: HTTP/gRPC first, messaging only after the substrate ruling lands. Acceptance: no doc presents a retired id as available.

## Dependencies
01 (certification), 03 (proxy-bearing agents), 14 (dependency fan-out).

## Phase 1 outcome — collision audit (DONE)

Every candidate in the fault-group list above was mapped against
`definition_for()` and the parameter table each existing definition actually
declares. The verdict vocabulary is the wave-0 one: **ALREADY-EXISTS** (retire
the ask), **PARAM-EXTENSION** (add one axis to an existing id, no new id),
**GENUINELY-NEW** (a new id whose mechanism no shipped fault has).

| candidate | verdict | covering / target fault id | mechanism note |
| --- | --- | --- | --- |
| HTTP abort | ALREADY-EXISTS | `net.connection_reset` | An abort and a reset are the same observable: the exchange dies mid-stream. `net.connection_reset` already carries `port`/`protocol`; a second id would be a synonym with its own compensation to keep honest. |
| HTTP delay | ALREADY-EXISTS | `http.latency` | `delay_ms` + `probability` + `port` on the existing proxy pump. |
| HTTP timeout | ALREADY-EXISTS | `http.upstream_timeout` | `timeout_ms`, plus an `upstream` selector. |
| HTTP reset | ALREADY-EXISTS | `net.connection_reset` | Same mechanism as the abort ask. One mechanism, one id. |
| HTTP status mutation | ALREADY-EXISTS | `http.error_injection` | The `status` axis. |
| HTTP header mutation | ALREADY-EXISTS | `http.header_inject` | The `headers` axis, already validated at plan time by `_http_headers` (no CR, ASCII only, every line must parse as `Name: value`). |
| HTTP body mutation / replace | ALREADY-EXISTS | `dependency.malformed_response` | `body` + `content_type` already substitute a whole response body. "Mutation" and "replace" are the same ask, so they are one row. |
| HTTP body patch (field-level) | PARAM-EXTENSION | `http.response_truncate` | A `patch` axis beside `bytes`: interpolate spec values into the body at named offsets. No new id — but see open question 2, this axis is the one that needs its own byte-safety validator. |
| gRPC status injection | GENUINELY-NEW | `grpc.status_injection` | gRPC status travels in a `grpc-status` **trailer**; the proxy pump writes headers only, so no shipped id can produce one. Maps to `FaultCategory.HTTP_API` (open question 3). |
| gRPC metadata mutation | PARAM-EXTENSION | `http.header_inject` | gRPC metadata *is* HTTP/2 headers, and the `headers` axis already takes arbitrary names. |
| gRPC delay | ALREADY-EXISTS | `http.latency` | Same pump, same `delay_ms` axis. |
| gRPC timeout | ALREADY-EXISTS | `http.upstream_timeout` | Same pump, same `timeout_ms` axis. |
| gRPC message fault (per-message) | GENUINELY-NEW | `grpc.message_fault` | Needs length-prefix-aware framing. `http.response_truncate` truncates a byte stream; it cannot corrupt one framed message while leaving the rest of the stream well-formed. |
| DNS NXDOMAIN | ALREADY-EXISTS | `dns.nxdomain` | The `domain` axis. |
| DNS SERVFAIL | ALREADY-EXISTS | `dns.servfail` | — |
| DNS timeout | ALREADY-EXISTS | `dns.timeout` | — |
| DNS wrong IP | GENUINELY-NEW | `dns.wrong_answer` | Every shipped DNS fault *fails* the lookup. None returns a well-formed answer pointing at the wrong address, which is the only way to exercise a client's stale-cache or split-horizon assumption. |
| DNS delay | ALREADY-EXISTS | `dns.resolve_delay` | The `seconds` axis. |
| TLS expired cert simulation | ALREADY-EXISTS | `tls.certificate_expired` | Reached today by a `_tool_template` that truncates the CA bundle at `/etc/ssl/certs/ca-certificates.crt`. No new axis needed. |
| TLS handshake failure | ALREADY-EXISTS | `tls.handshake_failure` | The `port` axis. |
| TLS protocol mismatch | GENUINELY-NEW | `tls.protocol_mismatch` | Requires the proxy to terminate TLS. It does not — there is no TLS handling anywhere in `src/`. Blocked on open question 1. |
| TLS trust-chain failure | GENUINELY-NEW | `tls.trust_chain_failure` | A client surfaces `unknown CA`, not the generic handshake failure `tls.handshake_failure` produces, and the two lead to different remediations. Also blocked on open question 1. |
| TCP refuse | ALREADY-EXISTS | `net.connection_refuse` | `port`/`protocol`. |
| TCP reset | ALREADY-EXISTS | `net.connection_reset` | `port`/`protocol`. |
| TCP timeout (connect never completes) | ALREADY-EXISTS | `net.tcp_half_open` | `port` axis; a half-open connection is exactly a connect that never finishes. A read timeout *after* the handshake is `dependency.timeout{delay_ms}`. |
| TCP blackhole (silent drop) | ALREADY-EXISTS | `net.partition` | Silent drop with no RST is what `net.partition` already does — the toxiproxy manifest even lists it as that tool's `primary` fallback, with no `net.latency` compensation depending on it. |
| messaging publish failure | GENUINELY-NEW | `mq.publish_failure` | Needs a broker-protocol client. See the substrate ruling below. |
| messaging consume failure | GENUINELY-NEW | `mq.consume_failure` | Same. |
| messaging ack delay | GENUINELY-NEW | `mq.ack_delay` | Broker-internal state — unreachable even with toxiproxy wired. |
| messaging ack failure | GENUINELY-NEW | `mq.ack_failure` | Same. |
| messaging partition simulation | GENUINELY-NEW | `mq.partition` | Broker-internal ownership state, not a wire fault. Distinct from `net.partition`, which is about the wire. |
| messaging rebalance pressure | GENUINELY-NEW | `mq.rebalance_pressure` | Broker-internal consumer-group state. The nearest shipped ask is `k8s.hpa_oscillation`-style orchestration churn, which is a different mechanism with a different undo. |
| database connection failure | ALREADY-EXISTS | `dependency.connection_refuse` | `port`/`protocol`. A refused connect is the same observable whether the database is down or the target port is wrong. |
| database query latency | ALREADY-EXISTS | `db.slow_query` | `seconds` + `mode`, with real modes since wave 1. |
| database pool pressure | ALREADY-EXISTS | `db.connection_exhaust` | `connections` + `host` + `port`. |
| database transaction failure | ALREADY-EXISTS | `db.query_error` | Wave 0 already retired `db.transaction_abort` and `db.deadlock` into this id, and wave 1 wired the `error` axis: `_DB_QUERY_ERROR_MODES` now maps `deadlock`→reject, `lock_timeout`→drop, `serialization_failure`→latency. A transaction abort is a value of that axis, not a new id. |
| database replication delay | GENUINELY-NEW | `db.replication_delay` | No shipped id models replica lag, and no parameter distinguishes hitting a primary from hitting a replica — so "the read went to a stale node" cannot be aimed today. |
| database failover simulation | ALREADY-EXISTS | `k8s.service_endpoint_flap` | The observable of a failover is endpoint churn while roles change, and endpoint withdrawal/flip already ships. Caveat: that cover's `engine_lanes` is `kubernetes` only, so on a non-Kubernetes target the ask is not actually covered — see the incident defect below. |

**Counts.** 24 ALREADY-EXISTS, 2 PARAM-EXTENSION, 12 GENUINELY-NEW. If the
verdicts stand as written, Phase 2+ adds **12 new catalog ids**:
`grpc.status_injection`, `grpc.message_fault`, `dns.wrong_answer`,
`tls.protocol_mismatch`, `tls.trust_chain_failure`, `mq.publish_failure`,
`mq.consume_failure`, `mq.ack_delay`, `mq.ack_failure`, `mq.partition`,
`mq.rebalance_pressure`, `db.replication_delay`. **26 of the 38 asks retire as
ids** (24 already-exists + 2 param-extensions), which leaves **14 asks** as the
actual build list: those 2 parameter axes plus the 12 new ids. A further 2 of
the 12 (`tls.protocol_mismatch`, `tls.trust_chain_failure`) are blocked on
open question 1, and all 6 `mq.*` are blocked on the substrate ruling.

## Phase 1 outcome — messaging substrate ruling

The messaging group is **not schedulable** until an ADR rules on a
broker-protocol proxy substrate and a domain dependency-policy exception. The
evidence:

- **No broker client in dependencies.** `pyproject.toml` declares exactly
  `pydantic`, `typer`, `click`, `pyyaml`, `structlog`, `kubernetes`. A `grep` for
  `grpc` or `protobuf` across `src/` returns **zero** hits.
- **`toolkit/manifests/toxiproxy.yaml` is referenced by no executor.** Outside
  the manifest's own `probe.cmd` there is no `toxiproxy-cli` invocation in
  `src/`; `_PREFIX_TO_CATEGORY` has no toxiproxy/toxic prefix entry; and no
  compensation template exists for it. `ResourceType.TOXIPROXY_TOXIC` is
  reserved in `domain/resources.py` and given a recovery sort key in
  `controller/resource_manager.py`, but **no code path ever creates one** — the
  manifest is capability negotiation, nothing more.
- **The import-linter contract forbids a broker client in the domain layer.**
  The `Domain layer has zero IO and no upward imports` contract forbids `socket`
  (along with `asyncio`, `subprocess`, `sqlite3`, `pathlib`, `os`,
  `mayhem.toolkit`, `mayhem.agents`, `mayhem.controller`, `mayhem.infra`) in
  `mayhem.domain`, and any broker client needs `socket`. A proxy substrate
  therefore has to live outside the domain, which is a dependency-policy
  decision, not an implementation detail.
- **Even with toxiproxy wired, three of the six are unreachable.** ack-delay,
  ack-failure and rebalance-pressure are broker-internal state: they are
  properties of the broker's consumer-group bookkeeping, not of the bytes on the
  wire, so a byte-level toxic cannot produce them. Scheduling them would produce
  ids that cannot be honoured by any mechanism the substrate can build.

## Phase 1 outcome — open questions

1. **Does the proxy terminate TLS?** To make `tls.protocol_mismatch` (and
   `tls.trust_chain_failure`) reachable the proxy would have to terminate the
   client's TLS session and re-originate its own, because a pass-through proxy
   never sees the negotiated protocol. Mayhem has no TLS handling in `src/` today,
   so whether it *should* is **UNKNOWN and is a product decision** — it decides
   the fault's blast radius, the key custody story (plan 19), and whether
   Mayhem claims a fault it cannot honour. It is not a question Phase 2 may
   answer by picking a default.
2. **A body-patch axis needs its own byte-safety validator.** The natural
   implementation of the `http.response_truncate` patch axis interpolates spec
   values into generated source. `http.header_inject` gets away with validating
   at plan time in `_http_headers` because its value is assembled into a header
   block. **Do not assume that validator transfers**: a body patch writes bytes
   into a stream, where a length-prefix, a content-length, or a JSON boundary
   can be broken by a value the header path would have accepted. This axis needs
   a byte-safety check of its own, written and tested on the same model as
   `_http_headers` but not reusing its rules.
3. **gRPC can reuse `FaultCategory.HTTP_API`; `mq` cannot.** gRPC ids should map
   to the existing `FaultCategory.HTTP_API` — gRPC is HTTP/2, and the substrate
   is the same proxy. `mq.*` needs a new `FaultCategory`, and a bare new category
   is not enough: `domain/catalog.py` keeps three exhaustive per-category total
   maps — `_FAILURE_DOMAIN_BY_CATEGORY`, `_VERIFICATION_BY_CATEGORY` and
   `_EFFECT_BY_CATEGORY` — and `_define` indexes all three while the module is
   being imported. A category missing an entry in any one of them raises
   `KeyError` **at import time, for the whole package**, not at the point the new
   id is used. `domain/faults.py::_PREFIX_TO_CATEGORY` needs the `mq` prefix too.

## Phase 1 outcome — incident defect found

`db.slow_query` **has no `port` parameter** — it declares only `seconds` and
`mode` — and `controller/compensation.py` **hardcodes `3306` in three places**:
line 2448 (the `netem delay` undo), line 2450 (`_netfilter_undo("3306")`) and
line 2461 (`_netfilter_verify("3306")`). The family therefore cannot be aimed at
a Postgres (5432) or SQL Server (1433) target at all: the operator sets a
`seconds` and the fault lands on MySQL's port whatever the target is. The
neighbouring `db.query_error` *does* have a `port` param and reads it via
`_iparam(fault, "port", 3306)`, which is what makes the omission on
`db.slow_query` a defect rather than a house style.

This is the **same defect class wave 1 found in `db.query_error.error`** — a
parameter the surface promises that the mechanism does not honour. It is a live
lie: a fault that reports injecting against a Postgres is not injecting against a
Postgres. It is **to be fixed by Phase 3 explicit dependency targeting, not
routed around** — the fix is a `port` param on `db.slow_query` plus three
replacements of the literal, and the `db.replication_delay` id above is
unbuildable until it lands, because a lag fault aimed at a replica needs to name
a port at all.

## STATUS
- Phase 1 (domain model): DONE — the 38-candidate collision audit is checked in above (24 already-exists, 2 param-extensions, 12 genuinely-new), the messaging substrate ruling is recorded, three open questions are logged, and one live defect (`db.slow_query`'s hardcoded 3306) is found and assigned to Phase 3.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.

Known limitation: Phase 2 is gated on the messaging ADR **for the messaging group
only**. The HTTP, gRPC, DNS, TCP and database rows of the audit table are not
blocked by it and can proceed on the normal dependency order; only the six `mq.*`
ids wait.
