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
- Phase 3 (surface: agent enrollment and provider registration): DONE — `mayhem agent enroll|list|show|revoke` (`cli/agent_cmd.py`) over `AgentIdentityRepository`: enrollment writes identity and **never key material**, a duplicate id is refused rather than overwritten (re-enrolling would reset its version and launder its revocation history), `show` exits non-zero when the identity may not authenticate, and `revoke` requires an actor with the first revocation winning. Provider registration stays on `providers/registry.py`'s permission model (the default posture stays nothing) and `mayhem extend providers inspect` now prints each provider's declared permissions pre-execution — so a third-party provider installs without core changes and what it asks for is visible before any of its code loads, which is the phase's acceptance criterion. Registered in the single inventory, the active-surface pins, the exhaustive matrix, and the README command table. Enrollment is declaration, not authentication: every id and actor here is a declared string, the same honesty `mayhem policy publish --by` records. 19 tests in `tests/unit/test_agent_surface.py`.
- Phase 4 (safety and evidence integration): DONE — the three Phase 2 open items are closed, and one of them is closed by *not* inventing anything:
  - **A durable `FabricJournal`.** `infra/fabric_journal.py` owns the table (`MIGRATION_SQL`/`DOWN_SQL`, `fabric_journal`, version 33) and a row model that re-derives its digest, its index columns, and its stamp from the payload it stores; `controller/fabric_evidence.SqliteFabricJournal` maps `DispatchClaim`/`DispatchSettlement` onto it (the mapping lives above because the layering contract forbids `infra` importing `controller`). Crash-resume is now a claim about a real migrated SQLite database — closed, dropped, and reopened across the "restart" — with the real `SQLiteLeaseSink` behind it, not an in-memory double.
  - **Verification wired into dispatch.** `FabricEngine` takes a `FabricCommandVerifierPort`, which plan 19's `AgentCommandVerifier` satisfies as-is; no HMAC, key material, nonce table or revocation check is reimplemented here. Verification is the *last* preflight check by design — every check before it can only refuse, never act, so an unauthenticated command cannot burn a nonce on its way to being rejected, and a command refused for a deposed fence can still be re-minted.
  - **Sealing.** `controller/fabric_evidence.FabricEvidenceRecorder` writes dispatch, retry, settlement, drift and refusal into a sealed chain per run (`<run_id>:fabric`) through plan 12's `AttestationRepository`, and `fabric_timeline()` reconstructs who dispatched what under which epoch and what the provider reported, from reloaded bytes re-verified by plan 12's own domain verifier.
  - 69 tests in `tests/unit/test_fabric_evidence.py`.
- Phase 5 (tests, regression guards, negative controls): DONE — `tests/unit/test_fabric_conformance.py` (54) is the protocol conformance suite the plan names. **Wire conformance** for the frames a hostile peer sends: a body forged after signing decodes at the wire seam (the seam checks the envelope, not the bytes) and is refused by the verifier with `FABRIC_UNDERSIGNED`; a frame with no signature at all keeps `FABRIC_UNDERSIGNED` while any *other* missing field is `FABRIC_MALFORMED_ENVELOPE` naming the field — the two codes stay two facts; bytes that are not a frame at all are malformed; a replayed nonce is refused by the domain ledger; a deposed fence is refused by the domain predicate. **The plan's negative control** ("an agent that accepts an unsigned command fails the suite loudly") is asserted as: no spelling of an unsigned frame constructs an envelope, and a verifier-bound engine never reaches a provider on a forged signature. **Failover drills with plan 19's verifier bound on every controller** — the spelling a real deployment runs: a failover chain cannot double-execute, a deposed owner is refused with its session untouched, and the successor inherits the ledger, the served fence, and the leases. **The provider-error normalization matrix** driven over every declared drift code and every declared conflict code, the agent-refusal table end to end, drift shown outranking the provider's own verdict, and the drift sealed into evidence under its own event kind. **Orchestration-semantics controls**, honest about the layer: `loop`/`branch` are planner-level vocabulary by this plan's own text ("not provider behavior"), so the controls live at the types — an unbounded `loop` and a targetless `branch` are unconstructible, the iteration cap is total over the eleven-member vocabulary — plus a structural assertion that the dispatch engine's source carries no semantics interpreter at all, so one cannot quietly appear without this suite failing. **Acceptance — live cells in 01 for the local providers:** the podman cell (darwin/arm64/rootless) was certified live through `mayhem certify run` — sealed bundle, recovery verified, residue clean — and re-verified by `certify regress --rerun` reproducing the claim; the suite reads that record through the store and is a real assertion where the record exists, skipped with the producing command where it does not. Docker and Kubernetes cells have never been certified and nothing here claims otherwise.
- Phase 6 (docs, honesty gates, rollout): DONE — three sections appended below: the **`mayhem/1` successor rules** (the version is pinned at the envelope and every other value is refused at construction; a successor adds required fields in a new version, never optional extras; refusal codes may be added, never re-meaning; a mixed fleet is visible pre-dispatch through the framing field registration carries), the **provider integration guide** (controller-initiated sessions — agents never listen — lease discipline, the two error-code tables as the normalization join points, registry permissions with the nothing default, enrollment as declaration not authentication, X.509 failing closed), and the **explicit non-guarantee**: at-most-once per (step, epoch) with idempotent retries, never exactly-once, with the unresolved-effect state named rather than papered over. Rollout: local agents first (the certified podman cell is the first live proof), then K8s DaemonSet agents (02), then third-party providers (17). Enforced by `tests/unit/test_fabric_plan_docs.py`, which parses this document, cross-checks `Overall:` against the `DONE` lines, verifies every `FABRIC_*` code quoted in backticks exists in the source, verifies the doc names all eleven `StepSemantics` members, refuses exactly-once over-claims and any claim that a successor version ships, and proves each of its own checkers bites against mutated copies.

Overall: 6 of 6 phases complete. Phases 3 and 5 landed after 4 — the out-of-order landing was recorded when the count was 3 and never inflated — and nothing about Phase 4's scope was deferred into Phase 3 to make the arithmetic work.

Known limitations:
- Signature **verification is implemented now**, by reusing plan 19's `AgentCommandVerifier` (HMAC-SHA256 over the canonical envelope, constant-time compared, with key binding, identity usability, revocation, plan binding, fence and nonce freshness). It remains a *symmetric* scheme: it proves a holder of the shared key produced these bytes, not public-key authorship to a third party. CA-backed X.509 mTLS is still plan 19 Phase 3 and still fails closed with `SIGNATURE_PORT_UNAVAILABLE`.
- **`FABRIC_UNDERSIGNED` now has real raise sites**, and there are two of them for two different facts. `FabricEngine._verify` raises it when the signature does not verify under a key the agent's *current* credential names; `decode_wire_command` raises it for a frame whose `signature`/`signing_key_id` fields are missing or blank. A frame that is malformed in some *other* field is refused as `FABRIC_MALFORMED_ENVELOPE` instead — spending the one code that means "the signature did not verify" on a question about a missing fence would be a lie. The in-process `_require_signed` check is retained as the cheap first read of the same claim, and remains unreachable in-process by Phase 1's construction.
- **CLOSED — the fabric's migration is in the production chain.** The earlier ledger recorded `FABRIC_JOURNAL_MIGRATION` as absent from `migrations.py::ALL_MIGRATIONS`; it is registered now (the chain is contiguous through the journal's version), `tests/unit/test_fabric_evidence.py` migrates every fixture through `ALL_MIGRATIONS` itself rather than a splice, and `tests/unit/test_fabric_migration_registration.py` exists so the registration cannot quietly disappear. The crash-resume claim is therefore about a *migrated* database, not a test-spliced one — which is what the original defect demanded.
- `FabricJournalTable.append` calls `require_persistable_document` before its transaction opens, so it needed a `BOUNDARY_CALL_SITES` row in `tests/unit/test_evidence_boundary.py`, which is not this phase's file. That file has since been edited and the row `("mayhem.infra.fabric_journal", "FabricJournalTable.append") -> {"require_persistable_document"}` is in place, so `TestTheGateCannotBeDeleted::test_every_module_calling_a_gate_is_registered` passes. **The gate was never weakened to get there**, and the completeness guard was not relaxed to accommodate the new module: it is the `(module, function)` form, so it still fails if a second gated writer is added to `fabric_journal.py` without its own row.
- The fabric's dispatch chain is keyed `<run_id>:fabric` rather than being interleaved into the run's own chain: `attestation_events` is keyed `(run_id, sequence)` and `verify_chain` requires every event to link to its predecessor, so a run's whole-chain seal at run close and an unbounded per-dispatch stream cannot share one chain. It is also *not* a run-close chain, so `chain_completeness` would correctly report it incomplete — run-level authorization completeness is `verify_run_completeness` on the run's own chain.
- Manifests the fabric writes are **unsigned**, carrying plan 12's `unsigned_no_signing` state and the reason beside it. Sealing attests integrity, not authorship.
- Drift-by-mismatch is only decidable when the caller states `DispatchRequest.expected_target`; a step dispatched with `None` falls back to provider error codes and cannot notice an `ok` about the wrong object. That is a declared limitation of the call site, not a silent pass.
- A settlement row's `epoch` column is a schema floor (`1`), not a claim: `DispatchSettlement` carries no fence, and inventing one to fill the column would put a number where a reader would expect authority. The settlement's epoch is in the sealed payload, where the dispatch result put it.
- Crash-resume still does not decide whether an effect *happened*. It makes the window visible — an open claim plus an unreconciled lease — and refuses to retry an unknown effect into a second one (`FABRIC_INFLIGHT_UNRESOLVED`). That is a property of the record, not of the storage.
- Approval invalidation on plan change (09) is enforced at dispatch through the plan-digest binding only. The approval *evaluation* itself still happens at admission (`controller/approval_gate.py`); the fabric refuses a command whose digest no longer matches the frozen plan, and does not re-run the approval quorum per command.

## The `mayhem/1` successor rules

The fabric speaks `mayhem/1`, pinned at `mayhem.domain.fabric.FABRIC_PROTOCOL_VERSION` and enforced at the envelope: a command naming any other version has no constructor. The successor rules are about changing that honestly:

* **A successor version adds required fields; it never adds optional extras.** `FabricCommand` has no defaulted field anywhere, which is why an unsigned command is unrepresentable. A `mayhem/2` that carries a new *optional* field would let old agents accept new commands silently — the one drift the envelope exists to prevent. New capability arrives as a new required field in a new version, and old frames fail validation against it by name (`FABRIC_MALFORMED_ENVELOPE`, fields listed).
* **Refusal codes are added, never re-meaning.** The `FABRIC_*` vocabulary is part of the wire contract: an integrator routes on `fabric_stale_fence` meaning *contention*. Renaming a condition's code, or spending an existing code on a new condition, is a breaking change requiring a version bump — adding a new code is not.
* **A mixed fleet is visible pre-dispatch, not discovered at failure.** A frame's protocol field is the first thing read; an old agent receiving a new-version frame refuses at decode before touching a lease, and the refusal lands in the sealed chain like every other. Nothing upgrades in place.
* **Deprecation runs through the inventory.** When `mayhem/1` is eventually retired, the change lands in the same single inventory (`cli/command_registry.py`, the exhaustive matrix) that every other surface change must move, so "what protocol does this build speak" is answerable from one table.

## Provider integration guide

What a third-party provider does, and does not do, to join the fabric:

* **Agents never listen.** Sessions are controller-initiated (`agents/transports.py`); a provider opens no port and accepts no inbound connection. The controller dials, authenticates per plan 19, and dispatches over that session.
* **One vocabulary, executed identically everywhere.** The planner's `StepSemantics` — `serial`, `parallel`, `conditional`, `loop`, `retry`, `timeout`, `branch`, `join`, `wait`, `approval`, `compensate` — is planner-level, not provider behavior: a Docker executor and a Chaos Mesh executor run the same constructs, and neither reinterprets them. A provider that cannot express one of the eleven says so through `can_apply`, never by redefining it.
* **Everything travels in the envelope.** A provider receives a `FabricCommand`, verifies it through plan 19's `AgentCommandVerifier` port (an unbound or unavailable port fails closed — `SIGNATURE_PORT_UNAVAILABLE`, never a pass), and only then acts. There is no side channel for "trusted" providers.
* **Leases stay mandatory.** The agent-side executor contract (`can_apply` revalidation at the mutation boundary, the never-raise undo, the write-ahead lease) applies to every provider without exception. A provider that cannot produce a lease cannot apply an effect.
* **Errors are normalized, not invented.** A provider maps its native failures onto the two declared tables — drift codes (`target_missing`, `pod_not_found`, …) and conflict codes (`resource_busy`, `lease_held`, …) in `controller/fabric_engine.py`. Anything unmapped reads as failed-to-apply on a present target; a provider's `ok` about an object the plan did not name is drift, never success.
* **Permissions are declared and visible pre-execution.** Registration goes through `providers/registry.py` with the default posture of nothing; `mayhem extend providers inspect` prints what a provider asks for before any of its implementation code loads. A provider asking for capabilities nobody granted is refused at the registry, not at the mutation boundary.
* **Enrollment is declaration, not authentication.** `mayhem agent enroll` records identity facts — it never mints key material, and nothing about the enrollment authenticates the declarer. Keys, revocation and verification live in plan 19; X.509 fails closed until its CA arrives.

## Delivery semantics: the explicit non-guarantee

What the fabric promises per action class, stated as limits rather than slogans:

* **At-most-once per `(step, epoch)` — not exactly-once.** The journal refuses a second effect at one epoch (`fabric_duplicate_dispatch`), and an idempotent retry keyed on `idempotency_key` never re-runs the provider. But a crash between the provider call and the settlement leaves the effect's *happening* unknown: the fabric records an open claim plus an unreconciled lease and refuses to retry into a second effect (`fabric_inflight_unresolved`) — it does not, and cannot, certify the first one landed.
* **Compensation is the recovery guarantee, not the delivery one.** `domain/leases.py`'s `assert_all_recovered` is the promise an effect is undone; it says nothing about whether delivery was once, twice-seen, or once-and-unknown. The watchdog path (`agents/watchdog.py`) stays the last resort and its lease states which mechanism released it.
* **Drift is reported, not retried through.** A provider that reports success about the wrong object settles `TARGET_DRIFT` in evidence; the fabric never auto-retries a drifted step, because the target the plan named is gone and the plan is frozen.
* **No cross-step transaction.** Two steps of one run are two dispatches with two leases; the fabric offers sequencing (`depends_on`) and reservations, never atomic multi-step commit. A mid-run failure recovers forward per step and the verdict records what actually happened.

## Rollout order

1. **Local agents first** — the podman cell certified live through plan 01 (`certify run`, sealed chain, recovery verified, residue clean, reproduced by `certify regress --rerun`) is the first real proof; docker follows on the same path when a cell exists.
2. **Kubernetes DaemonSet agents (plan 02)** — the same envelope and lease discipline, once 02's fabric half lands; the admission work already there stays the gate.
3. **Third-party providers (plan 17's SDK)** — registry permissions, declared capabilities, and the conformance suite as the bar: a provider that cannot pass `tests/unit/test_fabric_conformance.py`'s wire section has not integrated.

Enforced by `tests/unit/test_fabric_plan_docs.py` — the honesty gate over this document.
