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
| DNS NXDOMAIN | ALREADY-EXISTS | `dns.nxdomain` | The `domain` axis. Note the id overstates the mechanism — it writes a hosts-file answer, not `RCODE 3`. Recorded in the Phase 2/3 outcome below. |
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
Postgres. It is **fixed in Phase 3 explicit dependency targeting, not routed
around** — the fix is a `port` param on `db.slow_query` plus three replacements
of the literal, and the `db.replication_delay` id above is unbuildable until it
lands, because a lag fault aimed at a replica needs to name a port at all. See
"Phase 2/3 outcome" below for what shipped.

## Phase 2/3 outcome — param extensions and the incident defect

This lane builds the **only** two PARAM-EXTENSION verdicts from the table above
plus the live defect the audit surfaced. It adds **no new fault ids**: the 12
GENUINELY-NEW rows stay unbuilt, and the messaging and gRPC groups were not
touched (substrate ADR). Every change is a `params_schema` entry plus the
compensation builder that honours it, which is the wave-1 shape.

| item | fault id | axis | default | what it does |
| --- | --- | --- | --- | --- |
| param extension | `http.response_truncate` | `body: str` | *(absent = inert)* | the operator's bytes become the response body instead of the `b'x' * send_bytes` filler |
| param extension | `dns.nxdomain` | `address: str` | `127.0.0.1` | the address the hosts-file answer points the domain at |
| **defect fix** | `db.slow_query` | `port: int [1, 65535]` | `3306` | the family can finally be aimed at a non-MySQL target |

### `http.response_truncate{body}` — a byte-safety validator of its own

Open question 2 asked for one and warned against reusing `_http_headers`' rules.
They do not transfer, and the reason is structural rather than a matter of taste:

- **The header rules are too strict here.** `_http_headers` refuses CR because a
  CR terminates a *header line*. A CR inside a body is written after the head,
  where it cannot terminate anything, and a body with a stray CRLF is a
  legitimate production corruption. Refusing it would neuter the fault.
- **The header rules are silent about the real hazard.** `_http_headers` writes
  no body, so it never has to keep a `Content-Length` honest. A body does, and a
  drill spec gives us a `str` — where `len()` counts characters and the wire
  counts bytes. That mismatch does not truncate, it *hangs*, while the catalog
  still describes the fault as `http.response_truncate`.

So `_http_body` is a separate validator with four rules, and none of them is
"parse it as `Name: value`":

1. **Content-Length coherence.** The declared length is derived from the same
   `bytes` object that is embedded in the generated program, so the two cannot
   drift. The program also carries `assert len(body) == <n>` as a tripwire for a
   future edit that re-encodes or truncates the value.
2. **ASCII only.** This is what makes characters and bytes the same number, and
   it is the one rule the header validator also has — for a different reason
   (`.encode('ascii')` raising `UnicodeEncodeError`, an exception the proxy's
   `except OSError` does not catch). Widening the body to a declared encoding is
   a product decision about what a body byte *is*, and it was not made here.
3. **A 4 KiB bound.** The header path has no equivalent cap. The body value rides
   through the JSON-encoded argv, the container exec command line, the
   `<<'MAYHEM_PY_EOF'` heredoc *and* the wire, and `ParamSpec` has `min_length`
   but no `max_length`.
4. **Source and heredoc safety.** The value is embedded as `repr` of a `bytes`
   object, which escapes quotes, backslashes, newlines and non-printables, so no
   byte of it can terminate the python string literal or start a line. That is
   asserted, not assumed: the hostile cases are in the test file, and the
   assertion is that the shell *around* the heredoc is byte-identical to the
   benign case.

What it deliberately does **not** police is the body's *semantics*. A body that
breaks a JSON document, a length-prefixed frame or a client's own parse is the
fault, not a bug; refusing that would leave only well-formed responses, which is
not a fault at all.

The emitted program keeps the repo's kwarg-defaults-to-inert discipline: without
a `body`, all four pre-existing proxy modes render a **byte-identical** program
and a byte-identical response, and the body branch does not exist in the source
at all. Three distinct bodies are asserted to produce three distinct argv *and*
three distinct generated programs, and the axis is additionally executed against
real sockets in `tests/unit/test_http_proxy_wire.py`, because a Content-Length
bug does not show up in a source assertion — it shows up as a client that hangs.

**Scope note.** `dependency.response_truncate` shares the builder and therefore
inherits the code path, but its `params_schema` does not declare the axis, so
`validate_params` refuses `body` there. One axis, one id; the asymmetry is
asserted by a test so it stays a decision rather than an accident.

### `dns.nxdomain{address}` — and the id/behaviour mismatch

**Rename honesty, recorded because the id overstates the mechanism.** The
mechanism appends `<address> <domain>` to `/etc/hosts` and restores the file on
undo. That is a **hosts-file answer**, not DNS `RCODE 3`: a client asking a real
nameserver still gets a normal answer, and a client whose resolver skips the
hosts file — or that is serving from cache — sees no fault at all. What it
reliably reproduces is the common production shape *"the name resolves, to the
wrong place"*, with loopback standing in for a dependency that is genuinely
down. `dns.servfail` and `dns.timeout` are the ids that fail a lookup on the
wire; a true NXDOMAIN answer is not among the shipped ids, and the audit's
`dns.wrong_answer` id is the honest forward path. The id is not renamed here
because it is public surface in drill specs; the mismatch is stated instead, in
the catalog comment, in the builder docstring, and by a test that fails if the
mechanism ever changes.

`address` defaults to the value that was hardcoded, so every existing drill emits
byte-identical argv. It is validated with `ipaddress.ip_address` — a *different*
discipline from the `domain`, which is free-form text and gets `shlex.quote`.
Quoting is enough for the shell but not for the file: a newline inside a
single-quoted word survives as data to `echo`, which then writes **two** hosts
lines, the second one attacker-chosen. `ip_address` accepts an IPv4 or IPv6
literal and nothing else, so that surface does not exist.

### `db.slow_query{port}` — the incident defect, fixed

`port` now exists on the schema, with the same bounds and the same 3306 default
as `db.query_error`, and all three literals are gone: the `netem` delay, the
`iptables DROP` and the verify probe now read `_iparam(fault, "port", 3306)`. The
`timeout` mode moved to the `_param_netfilter` / `_param_netfilter_verify` pair —
the exact pattern `db.query_error` already used — which is what made the omission
a defect rather than a house style. Defaulting to 3306 keeps every existing drill
byte-identical.

`db.slow_query` was the last caller of the literal-dport `_netfilter_undo` /
`_netfilter_verify` pair, so that pair is deleted. Every netfilter builder now
goes through the param-reading variant, which means **a builder can no longer pin
a port its own schema does not expose** — the defect class is structurally gone
from this file, not just from this fault. `db.replication_delay` (a GENUINELY-NEW
row, still unbuilt) is no longer blocked on a port that could not be named.

### Regression guards added

- Three-distinct-argv guards for all three axes, plus three-distinct-*source* for
  the body axis, plus execution against real sockets for the body axis. All three
  were verified to fail under a deliberate mutation of the implementation (the
  axis ignored; the port re-hardcoded; the address ignored).
- A source-level guard that greps the `db.slow_query` builders for a port
  literal, because an argv-only test still passes if a fourth code path
  reintroduces `3306`.
- Hostile-body cases asserting the shell around the heredoc is byte-identical to
  the benign case.
- A test that fails if `docs/05` stops stating the `dns.nxdomain` mismatch.

## Phase 4 outcome — dependency fan-out accounting

Blast-radius gating was already correct: `check_blast_radius` walked
`_affected_node_ids`, which unions each target with
`TopologyGraph.dependents_closure`, and the caps counted what came out. What was
missing was that nobody could *read* the widening. A targeted service and a
service reached because something it depends on was targeted both arrived as
strings in one `frozenset`, so a plan whose fan-out tripled after someone widened
a selector read identically to the plan it replaced.

`mayhem.domain.dependency_fanout` makes it explicit, and it is deliberately
**accounting rather than a second blast-radius rule**:

* `DependencyFanout.aimed` is what the plan named; `.collateral` is only what it
  reached. The two being separate fields is the whole point — the flattened set
  cannot tell them apart.
* `.reached` carries each node's `depth` and `via`, so a first hop (`depth == 1`)
  is distinguishable from a compounded one. In the reference graph in
  `tests/unit/test_dependency_fanout.py`, aiming at `x-pg` reaches `n-api`,
  `n-worker` and `n-cron` at depth 1, and `n-web` at depth 2 through `n-api`.
* `.unreached_dependencies` names the dependency nodes the graph *does* contain
  that this fan-out does **not** touch. That is the half a hits-only list would
  hide, and it is what makes an empty value meaningful: it means "nothing was
  missed", which is interpretable only because the same field is non-empty one
  target earlier in the same graph.
* `.widened` answers the one question a reviewer asks — did this fault reach
  anything it did not aim at? — as a property of the record, so it can be asked
  without knowing what the planner believed.
* `FanoutLedger` aggregates a plan's steps and its aggregate is the **union**:
  three faults each reaching one service is not three services.
* `.record` and `.to_dict()` carry a `sealed_digest` over every other key, so a
  projection edited after the fact is detectable.

The refusal is `dependency.unresolved`: a fault aimed at a dependency the
topology snapshot does not contain resolves to no node, affects nothing, and
historically passed every cap. `fanout_ledger` refuses **before** computing any
projection, so a plan cannot be reported as having a clean zero-width fan-out when
the truth is that one of its steps aims at nothing. Disabling it is a named
opt-in (`require_resolved=False`) for diagnostics, not the default.

### What this does not claim

* **It does not change any decision.** The projection walks the same
  `DEPENDS_ON` and `CONNECTS_VIA` edges as `dependents_closure`, and
  `test_the_gate_gives_the_same_answer_from_targets_and_from_the_record` asserts
  the gate returns the identical verdict across three budgets whether handed the
  raw target set or the record's `affected` set. Minting no limit and refusing
  nothing new is what makes this Phase 4 rather than a rewrite of the gate.
* **It does not see dependencies the graph does not declare.** Fan-out is
  computed from declared edges. A service calling a third-party API with no edge
  in the topology is not in the closure;
  `test_an_undeclared_dependency_is_absent_and_that_is_reported` declares the
  missing edge and shows the same call then sees it — the limit was the input,
  not the walk.
* **It does not claim a fault *did* reach anything.** It reports what the graph
  says *would* be reached, at plan time, from the topology snapshot in hand. Live
  reach is evidence; this is a projection.
* **It is not wired into the executor.** Nothing in `executor.execute` calls it
  yet, and no sealed fan-out record reaches the evidence store. The ledger is
  produced on request, and the existing blast caps remain the enforcement path.
* **It does not re-derive the per-service caps.** `services_hit` and `hosts_hit`
  still count what the flattened set contains, and this module adds no cumulative
  limit of its own.
* **It does not implement the 12 genuinely-new fault ids.** The audit table
  above still stands; this phase made their targeting measurable, not their
  behaviour real.

## Phase 5 outcome — the sweep criterion, made checkable

The acceptance line for this phase is one sentence: *"new ids swept into the six
deriving test files automatically."* `tests/unit/test_fault_sweep_coverage.py`
turns it into two properties of the repository:

1. **A full sweep exists, redundantly.** Some module derives its parametrization
   from `CATALOG` itself, so a new id is collected the moment it lands. The
   minimum is two *independent* modules, not a file count.
2. **A hardcoded list is never the only coverage.** Every id a literal list
   names must also be swept by a deriving module.

### What the survey found

Measuring before asserting changed the shape of the work:

* **The plan says six; four is the real number.** `test_certification_badge_honesty.py`,
  `test_failure_modes.py`, `test_fault_catalog_all.py` and
  `test_fault_catalog_exhaustive.py` each perform an unfiltered sweep over all
  145 ids. The minimum is therefore asserted as *two independent sweepers* rather
  than as a file count, because the property worth keeping is redundancy and a
  count would break when someone usefully splits a file in two.
* **Sixteen module-level id lists in `tests/unit/` are literals.** That is
  legitimate — a family-specific suite should name its family — and it is also the
  exact shape that silently stops covering a new id. The guard's job is to prove
  each one is a narrowing rather than a sole owner.
* **There are no `dep.*` ids.** The catalog's dependency family is
  `dependency.` (eight ids). The Phase 4 suite had been labelling a nonexistent
  `dep.latency`, which is corrected.

### Three defects the negative controls found

* **The guard was counting itself.** It imports `CATALOG` and holds the full id
  set, so it satisfied its own `MINIMUM_FULL_SWEEPS`. With three of the four real
  sweepers collapsed to literals the suite still passed — the redundancy it exists
  to enforce was unenforced. It is now excluded by path identity, and
  `test_the_guard_never_counts_itself` names the bug.
* **Two assertions could not fail.** `ids <= CATALOG_IDS` and
  `ids - CATALOG_IDS` are both true by construction once `_id_sets` has filtered,
  and deleting either left the suite green. Both were removed rather than kept as
  decoration. The real limit they papered over is now written down: **a literal
  naming an id the catalog has since retired is invisible to this file**, because
  the stale member disqualifies the whole set. That belongs to the module that
  owns the list, which is the only place that knows what the id meant.
* **Nine mutations, all behaving as designed.** Seven are caught. The eighth is
  survived on purpose — collapsing one of four sweepers must be absorbed by the
  other three — and the ninth, collapsing three, is caught.

### What this does not claim

* **It does not make hardcoded lists obsolete.** Sixteen remain, and they are
  allowed to. The claim is only that none of them is the sole owner of an id.
* **It does not catch stale ids.** See above.
* **It does not cover non-catalog ids.** A test module that parameterizes over
  engine names, node kinds or providers is outside its view entirely.
* **It does not assert the sweep *tests* pass.** It inspects which ids a module
  parametrizes over; running them is pytest's job. A sweep whose assertions are
  wrong is still a sweep as far as this file is concerned.
* **It does not count towards certification.** No rung of
  `tests/unit/test_certification_badge_honesty.py` moves because of this.

## Phase 6 outcome — the matrix, the gate, and the rollout order

Phase 6's acceptance criterion is one sentence: *"no doc presents a retired id as
available."* `docs/fault-catalog/reliability-matrix.md` is the document where
that matters most — it is what an operator opens to decide which fault to reach
for — and it had **no gate on it at all**. `tests/unit/test_reliability_matrix_honesty.py`
is that criterion, plus two further claims the matrix makes by construction:

* **Every fault id named resolves.** One deliberate carve-out: an id named on a
  line that says it is absent. That carve-out *is* the phase's own "id someone
  reaches for first does not exist" deliverable, and a synthetic two-sided case
  pins that it discriminates rather than excusing any line containing a
  negation.
* **No family row offers a catalog-only id without saying so in that row.** The
  refusal is attached to the id, not to the row, because a row-level check would
  let a marked id excuse the next unmarked one.
* **Every parameter named in a row exists in that definition's schema.**

### What the gate found

* **Three family rows routed readers to refusable ids.** `fs.permission_failure`
  (Storage), `process.startup_delay` (Process lifecycle) and
  `dependency.malformed_response` (Application dependencies) are all
  catalog-only: complete metadata, no executor, deterministic refusal at
  admission. The paragraph below the table explained that, and the row is where a
  reader stops. Each is now marked where it is named, with the missing mechanism
  named and **no executable stand-in offered** — pointing at another catalog-only
  id would have repeated the mistake, which is exactly what a first draft of the
  `fs.permission_failure` annotation did.
* **Two parameters in the new table did not exist.** `dependency.timeout` takes
  `delay_ms`; `duration` and `timeout_ms` are not among its parameters. Caught by
  the parameter check, not by reading.
* **There is no `dependency.slow`**, so the reachable-first table names the gap
  rather than pretending an id exists.

### Rollout order

The plan's ordering holds, and the reason is unchanged: **HTTP and gRPC first;
messaging only after the substrate ruling lands.** The `mq.*` group is the only
part of the audit table gated on the messaging ADR. Everything else — HTTP,
gRPC, DNS, TCP, database — proceeds on the normal dependency order, and the
parameter extensions from Phase 2 and the `db.slow_query` defect from Phase 1
ship on that order.

### What this does not claim

* **No new fault was built.** This phase documents and gates the id surface that
  exists. The 12 genuinely-new ids remain unbuilt, and the eight unblocked ones
  among them are ready to build but are not built.
* **Value claims are not checked.** `ParamSpec` carries a name, a type, bounds
  and a default, and **no enum**. So `mode: timeout` is verified only in the sense
  that `mode` exists; whether `timeout` is accepted is a claim about the executor.
  `test_value_claims_are_not_schema_guarantees_and_this_file_says_so` fails if a
  future `ParamSpec` gains an enum, so the gate widens rather than going stale.
* **The refusal window is 200 characters**, a clause rather than a cell. A cell
  can hold several ids, and a refusal stated after the last of them says nothing
  about the first.
* **The gate reads one document.** `docs/v1.1.0/*.md`, the README and the
  lowlevel report have their own gates; this one covers the matrix only.
* **Drill-spec parameter catalogues were not extended.** The drill specs live
  in plan 13; nothing in this phase added parameters to them, and no drill spec
  gained a dependency-family entry.

## STATUS
- Phase 1 (domain model): DONE — the 38-candidate collision audit is checked in above (24 already-exists, 2 param-extensions, 12 genuinely-new), the messaging substrate ruling is recorded, three open questions are logged, and one live defect (`db.slow_query`'s hardcoded 3306) was found and assigned to Phase 3.
- Phase 2 (proxy and tool mechanisms): DONE for this lane — both param-extension mechanisms landed (the `body` branch on the proxy's canned path, the validated hosts-file line). **The 12 genuinely-new ids are not built**, so this phase is complete only for the two verdicts that were parameter work.
- Phase 3 (params, targeting, probes): DONE for this lane — three param axes ship, `db.slow_query` can be aimed at Postgres or SQL Server, and each axis has a three-distinct-output guard. Explicit `target.dependency` selectors and the matching business-level probe definitions are **not** done.
- Phase 4 (safety and evidence integration): DONE for the dependency half — `mayhem.domain.dependency_fanout` records what a dependency fault was aimed at, what it reached through it and which declared dependencies it did not touch, and refuses a fault aimed at a dependency the topology does not contain. It is accounting layered on the existing blast gate, not a second gate. The dependency-level **fault implementations** the audit identified, and any evidence-store wiring for them, are **not** done.
- Phase 5 (tests, regression guards, negative controls): DONE for the sweep half — `tests/unit/test_fault_sweep_coverage.py` turns the acceptance line into a repository property: a full catalog sweep exists, redundantly, and no hardcoded id list is the only coverage of an id it names. The plan's "six deriving test files" is **wrong**: four modules sweep the catalog unfiltered and sixteen module-level id lists are literals. The proxy-program and param-inertness guards shipped in Phase 3; the unresolvable-dependency refusals shipped in Phase 4 and are re-asserted here so this phase's own negative control is reachable from this file too.
- Phase 6 (docs, honesty gates, rollout): DONE — the reliability matrix now carries the reachable-first dependency table and marks the three catalog-only ids its family rows were offering, `tests/unit/test_reliability_matrix_honesty.py` enforces "no doc presents a retired id as available" along with two further claims the matrix makes, and the rollout order below is recorded. **The 12 genuinely-new ids remain unbuilt**, so this phase describes the id surface that exists, not one that was extended.

Overall: 6 of 6 phases complete, with the scoping below unchanged and
carried forward. The plan's six phases are done; the 12 genuinely-new fault ids
it identified are **not built**, and no phase here was permitted to paper over
that. Phase 4 delivered the accounting that makes their targeting measurable and
Phase 6 delivered the honesty that keeps them from being described as if they
existed.

Known limitation: Phase 2 is gated on the messaging ADR **for the messaging group
only**. The HTTP, gRPC, DNS, TCP and database rows of the audit table are not
blocked by it and can proceed on the normal dependency order; only the six `mq.*`
ids wait.
