# Milestone 6 — Core Chaos Arsenal (equipped by M2/M3 infra)

> **Verdict basis:** `docs/answer2.md` rework items for arsenal + review §10-seed: process (kill/stop), resource pressure (cpu/mem/disk), container lifecycle, network (latency/loss via M3 NetworkPath), dependency/database (block/timeout).
> **Decision locks (grill Q12, Q16, Q18):** **core chaos set** here; network fault *archetypes* land now on the M3 `NetworkPath` model + fingerprints; DNS/TLS/application + load/fuzz/deadline generators deferred to M8; tool-specific cancellation wiring (from M2's framework ladder) implemented here per tool; acceptance = unit + e2e-where-live.

## 1. Goal

Populate the arsenal with the reliability-critical, well-understood fault families that the M2/M3 backbone (owned-resource lifecycle, mutation journal, cancellation ladder, capability verdicts, RuntimeAdapter, NetworkPath) now supports **correctly** — each as a fingerprintable, journaled, recoverable, cancellable operation. This is where "we can inject into containers" becomes "we can intentionally break the right thing and clean it up."

**Out of scope (now):** DNS/TLS/application faults, load/stress/fuzz *generators* (→ M8); kubernetes execution (→ M7 interface only).

## 2. ADR lock (freeze before code)

- **ADR-M6-1 — Every fault is an owned, fingerprintable resource operation.** Each archetype uses the M2 `OwnedResource` lifecycle + M3 fingerprint + M2 journal. A fault that cannot be attributed/cleaned up does not ship.
- **ADR-M6-2 — Process faults.** `process.kill` / `process.stop` / `process.pause` verified by `ProcessRuntimeIdentity` + PID-reuse starttime evidence (M2). `kill` = escalation-ladder last rung; `stop` = SIGTERM->graceful; idle pause = SIGSTOP/SIGCONT with resume in recovery.
- **ADR-M6-3 — Resource-pressure faults.** `resource.cpu` (stress-ng), `resource.memory` (bounded), `resource.disk` (fill a bounded temp path) — all bounded by duration/deadline and cancellable via the M2 ladder; never an unbounded/leaked allocation.
- **ADR-M6-4 — Container lifecycle faults.** `container.restart` / `container.pause` / `container.kill` use the RuntimeAdapter; TARGET_DRIFT detection re-resolves identity before and after (a restarted container is re-verified, not assumed).
- **ADR-M6-5 — Network faults target NetworkPath.** `network.latency` / `network.loss` apply via `tc`/netem on the M3 `NetworkPath` (source/dest/interface/namespace/protocol/ports) and carry the M3 ownership fingerprint; rules are removed (journaled) on recovery — never left behind.
- **ADR-M6-6 — Dependency/database faults.** `dependency.block` / `dependency.timeout` disrupt a named dependency path (port/connection) with a clear fingerprint; recovery restores connectivity; a timeout is cancellable.

## 3. Phases

### Phase 6.1 — Process fault archetypes

**Tasks**
- Implement `process.kill/stop/pause` on the M2 identity + cancellation + journal backbone; wire tool-specific cancellation (the M2 ladder finally drives process sends).
- PID-reuse guard active (starttime match before signalling).

**Acceptance criteria**
- Unit `test_faults.py`/`test_executor.py` (mocked): kill/stop/pause journal, attribute to `OwnedResource`, respect the ladder; starttime mismatch → no signal (drift-safe).
- e2e: kill a real container process; stop resumes by recovery.

### Phase 6.2 — Resource-pressure archetypes

**Tasks**
- Implement `resource.cpu` (stress-ng bounded), `resource.memory` (bounded), `resource.disk` (bounded temp fill) with duration/deadline bounds + cancellation + cleanup.

**Acceptance criteria**
- Unit: each pressure fault is bounded and cancellable; a cancelled pressure run leaves no leaked process/allocation (journal cleanup asserts).
- e2e: bounded cpu pressure on a real container; recovery removes it.

### Phase 6.3 — Container lifecycle archetypes

**Tasks**
- Implement `container.restart/pause/kill` via the RuntimeAdapter; re-resolve identity after restart (TARGET_DRIFT-safe).

**Acceptance criteria**
- Unit: identity re-resolved before/after; post-restart identity mismatch handled.
- e2e: restart a real compose service; pause→resume restores state.

### Phase 6.4 — Network fault archetypes (on NetworkPath)

**Tasks**
- Implement `network.latency` / `network.loss` via `tc`/netem targeting the M3 `NetworkPath` (need a container to use netns/interface via the M3 adapter).
- Fingerprint + journal each `tc` rule; recovery removes the exact rule (never a broad `tc qdisc del` that could touch unrelated paths).

**Acceptance criteria**
- Unit `test_fingerprint.py`/`test_resources.py`: rules are fingerprintable; recovery removes only the owned rule.
- e2e (docker): inject latency on a path; verify the rule applied then removed cleanly by recovery.

### Phase 6.5 — Dependency/database archetypes

**Tasks**
- Implement `dependency.block`/`dependency.timeout` on a named dependency path (port/connection), fingerprintable + cancellable; recovery restores.

**Acceptance criteria**
- Unit: block/timeout journal + restore; cancellable mid-block.
- e2e: block a real dependency port; recovery restores connectivity.

### Phase 6.6 — Arsenal regression + e2e + no-leftover sweep

**Tasks**
- Full unit/integration suite + an e2e sweep of every archetype against a real compose target; after the sweep, assert the environment is clean (no phantom processes, rules, or fullness).
- No Mypy/ruff regressions.

**Acceptance criteria**
- All archetypes e2e-green; post-drill environment assertions clean (the janitor/watchdog + journal black-box the "no leftovers" guarantee).
- Each archetype maps to a fingerprint + OwnedResource + journal entry in the report.

## 4. Testing / DONE stance (Q18)

**Unit + e2e-where-live.** This milestone is all live mutation, so each archetype requires both unit (mocked) and e2e (real docker) coverage. The "no leftovers" post-drill sweep is a hard DONE gate.

## 5. Risks / open items

- **tc/netem specificity:** removing "the exact owned rule" (ADR-M6-5) is critical — a broad delete is dangerous. Build the fingerprint->rule mapping rigorously.
- **Resource pressure runaway:** every pressure fault must be bound + cancellable; assert no leaked allocation after cancellation.
- **Container restart invalidates pid-based state:** re-resolution + drift handling is mandatory (ADR-M6-4).
- **Scope discipline:** do not let "while we're here" pull DNS/TLS/load/fuzz into this milestone — those are M8 and carry different ownership/cleanup semantics.
