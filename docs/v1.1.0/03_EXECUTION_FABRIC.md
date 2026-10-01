# Plan 03 — Distributed Execution Fabric

**Priority:** P0. Gap items 3, 16, 28.

## Objective
Create one execution protocol for local engines, Kubernetes agents, hosts, clouds, and third-party fault providers — and fold the missing orchestration constructs (gap 16) and transactional execution semantics (gap 28) into it rather than bolting them on later.

## Builds on (existing code — extend, do not bypass)
- `agents/protocol.py` ndjson JSON-RPC (`mayhem/1`, `run_id`/`agent_id` enforced at frame level) is the wire starting point.
- `agents/transports.py` controller-initiated sessions (agents never listen) stays the topology; mTLS and identity arrive via 19.
- `domain/leases.py` (`FaultLease`, `LeaseState`, `assert_all_recovered`) stays the recovery guarantee; fencing tokens extend it.
- `controller/executor.py` `RunEngine.execute` ordering (intent → gate → open run → grouped steps → recover → verdict → close) stays the run shape; the fabric distributes it.
- `agents/executors.py` `can_apply` (capability revalidation at the mutation boundary) and the never-raise undo contract stay mandatory for every provider.

## Core concepts
- Agent, Provider, Capability, Target, Action, Compensation, Verification
- Lease, fencing token, run/step ID, idempotency key

## Protocol
```text
prepare -> reserve -> validate -> inject -> observe -> compensate -> verify -> close
```

## Agent responsibilities
- capability discovery
- secure command execution
- local rollback
- heartbeat
- resource inspection
- local evidence buffering

## Controller responsibilities
- planning, policy, scheduling, approvals
- orchestration, evidence aggregation, verdict

## Providers
Docker, Podman, Kubernetes, Linux host, Chaos Mesh, Litmus, AWS FIS,
Pumba, Toxiproxy, custom provider SDK (see 17 for the SDK surface).

## Phase 1 — Domain model: protocol vocabulary and step semantics
Add `domain/fabric.py`: `FabricCommand` (signed-command envelope: plan digest, nonce, idempotency key, fencing token), `StepSemantics` (`serial | parallel | conditional | loop | retry | timeout | branch | join | wait | approval | compensate` — gap 16 constructs as planner-level types, not provider behavior), `Reservation` (resource locks feeding gap 86 via 07). Pure types with transition tests. Acceptance: an unsigned or replayed command is unrepresentable at the type level.

## Phase 2 — Engine: distributed RunEngine with fencing
Split run ownership: the controller owns planning/verdict, agents own injection/undo under leases; exactly one owner per step via fencing tokens monotonic across controller failover; idempotent retries keyed on idempotency keys; provider errors normalized to the existing `StepOutcome` taxonomy (`TARGET_DRIFT | FAILED_TO_APPLY | RESOURCE_CONFLICT`). Acceptance: controller failover cannot produce two owners executing the same step (chaos-tested with a killed controller).

## Phase 3 — Surface: agent enrollment and provider registration
Agent enrollment (identity bootstrapping per 19), provider registration through the existing `providers/registry.py` permission model (default posture stays nothing). Acceptance: a third-party provider installs without core changes and its permissions are visible pre-execution.

## Phase 4 — Safety and evidence integration
Every fabric command bound to the frozen plan digest; approval invalidation on plan change (09) enforced at dispatch; agent-side watchdog compensation stays the last resort (existing `agents/watchdog.py` semantics). Evidence buffered locally, sealed centrally per 12. Acceptance: a command against a superseded plan digest is refused by the agent, with the refusal in evidence.

## Phase 5 — Tests, regression guards, negative controls
Protocol conformance suite (malformed/replayed/forged commands), failover drills, provider-error normalization matrix, orchestration-semantics tests (a `loop` that exceeds budget stops; a `branch` taken wrongly is detectable in evidence). Negative control: an agent that accepts an unsigned command fails the suite loudly. Acceptance: all green plus live cells in 01 for the local providers.

## Phase 6 — Docs, honesty gates, rollout
Document the protocol version (`mayhem/1` successor rules), provider integration guide, and the explicit non-guarantee: at-most-once vs exactly-once semantics per action class. Rollout: local agents first, then K8s DaemonSet agents (02), then third-party providers.

## Dependencies
07 (policy at dispatch), 09 (approvals), 12 (sealed evidence), 19 (mTLS, identities).

## STATUS
- Phase 1 (domain model): DONE — `domain/fabric.py` landed the `FabricCommand` envelope (no defaulted field anywhere, so an unsigned command is unrepresentable), `NonceLedger`, `FencingToken`, `StepSemantics` with its well-formedness table, `StepSpec`, `Reservation`, and the refusal vocabulary; 111 tests.
- Phase 2 (engine): DONE — `controller/fabric_engine.py` landed the dispatch layer: a stateless engine (every decision is a projection over the durable journal plus the lease sink, so a new instance over the same durable objects *is* a controller failover) with fence checks, one effect per `(step, epoch)` (`fabric_duplicate_dispatch`), idempotent retries keyed on `idempotency_key` that spend a fresh nonce and never re-run the provider, nonce-replay refusal, reservation checks before dispatch, provider errors normalised into the existing `StepOutcome`/`TargetOutcome` taxonomy (a target that moved is `TARGET_DRIFT`, never a pass), and claim/settlement crash reconciliation; 52 tests including a killed-controller drill.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.

Known limitations:
- Signature **verification is not implemented** and is not in scope for this phase. `FabricCommand.signing_payload` states *what* was signed; checking it needs the identities, keys and trust roots of plan 19. A `signature` string on the envelope is a claim, not proof, until then.
- `FABRIC_UNDERSIGNED` is currently **raised nowhere**, by design. The envelope makes an unsigned command unrepresentable at the type level, so the decision function that would raise it has no reachable input; it stays named so the refusal vocabulary is complete and the code that eventually needs it does not have to invent a spelling. The engine calls that decision function on every dispatch (`FabricEngine._require_signed`) so the future wire receiver has a seam to decode into.
- The dispatch journal ships as a **protocol, not a table**: `FabricJournal` has no SQLite implementation in this phase (no migration lands here), so the crash-resume drill proves the *engine* resumes from durable objects it did not hold, using the real `InMemoryLeaseSink` and the real `LeaseClient`/`FaultLease` state machine — not that the production binding exists. A durable `FabricJournal` in the controller's store is Phase 4 work.
- Drift-by-mismatch is only decidable when the caller states `DispatchRequest.expected_target`; a step dispatched with `None` falls back to provider error codes and cannot notice an `ok` about the wrong object. That is a declared limitation of the call site, not a silent pass.
