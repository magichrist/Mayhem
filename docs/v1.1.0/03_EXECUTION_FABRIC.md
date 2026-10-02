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
- Phase 4 (safety and evidence integration): DONE — the three Phase 2 open items are closed, and one of them is closed by *not* inventing anything:
  - **A durable `FabricJournal`.** `infra/fabric_journal.py` owns the table (`MIGRATION_SQL`/`DOWN_SQL`, `fabric_journal`, version 33) and a row model that re-derives its digest, its index columns, and its stamp from the payload it stores; `controller/fabric_evidence.SqliteFabricJournal` maps `DispatchClaim`/`DispatchSettlement` onto it (the mapping lives above because the layering contract forbids `infra` importing `controller`). Crash-resume is now a claim about a real migrated SQLite database — closed, dropped, and reopened across the "restart" — with the real `SQLiteLeaseSink` behind it, not an in-memory double.
  - **Verification wired into dispatch.** `FabricEngine` takes a `FabricCommandVerifierPort`, which plan 19's `AgentCommandVerifier` satisfies as-is; no HMAC, key material, nonce table or revocation check is reimplemented here. Verification is the *last* preflight check by design — every check before it can only refuse, never act, so an unauthenticated command cannot burn a nonce on its way to being rejected, and a command refused for a deposed fence can still be re-minted.
  - **Sealing.** `controller/fabric_evidence.FabricEvidenceRecorder` writes dispatch, retry, settlement, drift and refusal into a sealed chain per run (`<run_id>:fabric`) through plan 12's `AttestationRepository`, and `fabric_timeline()` reconstructs who dispatched what under which epoch and what the provider reported, from reloaded bytes re-verified by plan 12's own domain verifier.
  - 69 tests in `tests/unit/test_fabric_evidence.py`.
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.

Phase 4 landed out of order (Phase 3 has not started), so the count is 3 and not 4. Nothing about Phase 4's scope was deferred into Phase 3 to make the arithmetic work.

Known limitations:
- Signature **verification is implemented now**, by reusing plan 19's `AgentCommandVerifier` (HMAC-SHA256 over the canonical envelope, constant-time compared, with key binding, identity usability, revocation, plan binding, fence and nonce freshness). It remains a *symmetric* scheme: it proves a holder of the shared key produced these bytes, not public-key authorship to a third party. CA-backed X.509 mTLS is still plan 19 Phase 3 and still fails closed with `SIGNATURE_PORT_UNAVAILABLE`.
- **`FABRIC_UNDERSIGNED` now has real raise sites**, and there are two of them for two different facts. `FabricEngine._verify` raises it when the signature does not verify under a key the agent's *current* credential names; `decode_wire_command` raises it for a frame whose `signature`/`signing_key_id` fields are missing or blank. A frame that is malformed in some *other* field is refused as `FABRIC_MALFORMED_ENVELOPE` instead — spending the one code that means "the signature did not verify" on a question about a missing fence would be a lie. The in-process `_require_signed` check is retained as the cheap first read of the same claim, and remains unreachable in-process by Phase 1's construction.
- The fabric's migration ships **outside** `infra/migrations.py`, which several concurrent lanes append to. Registering it is one line (`FABRIC_JOURNAL_MIGRATION` in `ALL_MIGRATIONS` after `M0032_HA_DR`); until that happens the table exists only where a caller splices the migration in, which is what every test in `tests/unit/test_fabric_evidence.py` does.
- `FabricJournalTable.append` calls `require_persistable_document` before its transaction opens, so it needs a `BOUNDARY_CALL_SITES` row in `tests/unit/test_evidence_boundary.py`. That file is not this phase's to edit, so `TestTheGateCannotBeDeleted::test_every_module_calling_a_gate_is_registered` fails until the row `("mayhem.infra.fabric_journal", "FabricJournalTable.append") -> {"require_persistable_document"}` is added. The gate was **not** weakened to make that test pass.
- The fabric's dispatch chain is keyed `<run_id>:fabric` rather than being interleaved into the run's own chain: `attestation_events` is keyed `(run_id, sequence)` and `verify_chain` requires every event to link to its predecessor, so a run's whole-chain seal at run close and an unbounded per-dispatch stream cannot share one chain. It is also *not* a run-close chain, so `chain_completeness` would correctly report it incomplete — run-level authorization completeness is `verify_run_completeness` on the run's own chain.
- Manifests the fabric writes are **unsigned**, carrying plan 12's `unsigned_no_signing` state and the reason beside it. Sealing attests integrity, not authorship.
- Drift-by-mismatch is only decidable when the caller states `DispatchRequest.expected_target`; a step dispatched with `None` falls back to provider error codes and cannot notice an `ok` about the wrong object. That is a declared limitation of the call site, not a silent pass.
- A settlement row's `epoch` column is a schema floor (`1`), not a claim: `DispatchSettlement` carries no fence, and inventing one to fill the column would put a number where a reader would expect authority. The settlement's epoch is in the sealed payload, where the dispatch result put it.
- Crash-resume still does not decide whether an effect *happened*. It makes the window visible — an open claim plus an unreconciled lease — and refuses to retry an unknown effect into a second one (`FABRIC_INFLIGHT_UNRESOLVED`). That is a property of the record, not of the storage.
- Approval invalidation on plan change (09) is enforced at dispatch through the plan-digest binding only. The approval *evaluation* itself still happens at admission (`controller/approval_gate.py`); the fabric refuses a command whose digest no longer matches the frozen plan, and does not re-run the approval quorum per command.
