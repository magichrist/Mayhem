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

## STATUS — planning only, 0%
