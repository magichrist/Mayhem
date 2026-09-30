# Plan 04 — Low-Level Fault Engine Expansion

**Priority:** P1. Gap item 4.

## Objective
Close the major functional gap versus deep Kubernetes chaos injectors while keeping Mayhem's safety and evidence model above the engines.

## Builds on
- The five-registry contract from the new-faults contract-checklist (catalog → executor routing → compensation template → impact REQUIREMENTS → deriving tests).Zero slack today: every new fault must extend all five or import breaks.
- `agents/impact.py` REQUIREMENTS table, `_PROBE_BINS`, `_CAP_BITS`, `_PM_PACKAGES`: new bins/caps/packages rows are mandatory per primitive.
- Existing `catalog_only` refusals stay authoritative: `clock.freeze`, `fs.read_error`, `fs.permission_failure`, `mem.oom_kill`-class entries are not "unimplemented" — promoting one requires the missing mechanism to actually exist, never a weaker substitute.

## Fault families
### eBPF / kernel
- syscall failure, syscall latency, syscall return mutation, selected kernel fault simulation

### IO / storage
- read delay, write delay, IO error, filesystem full, block-device delay/error, inode exhaustion, permission faults

### JVM
- method delay, return-value mutation, exception injection, GC pressure, allocation pressure, thread pressure

### Clock
- realtime skew, monotonic skew where technically safe, clock offset, per-clock targeting. (`clock.freeze` stays catalog-only until a `libfaketime`-class mechanism exists with a real undo.)

## Safety requirements
Every low-level fault declares: required capabilities, scope,
reversibility, compensation, residue checks, maximum safe duration,
incompatible fault pairs.

## Architecture
Keep mechanisms in providers/backends; keep admission and verdict logic in Mayhem core.

## Phase 1 — Domain model: primitive descriptors
Add `domain/lowlevel.py`: `KernelPrimitive` (syscall target, errno/latency mode, attachment scope), `IOPrimitive`, `JVMPrimitive`, each carrying capability demands, reversibility, and residue-check definitions as pure data. New `FaultCategory` values only with entries in all three category-keyed maps (the wave-0 lesson: a bare category is an import-time `KeyError`). Acceptance: category-map completeness test extended; descriptor tests pin every required field.

## Phase 2 — Engine: provider-side mechanisms
Implement mechanisms behind the 17 provider SDK (eBPF loader, device-mapper/FUSE shims, JVM agent attach), each paired with its compensation template in `controller/compensation.py` — the planner refuses any fault without one. Acceptance: each primitive demonstrates inject → observe → undo → verify on a dev cell before catalog entry.

## Phase 3 — Surface: catalog entries and explanations
Add catalog definitions with full metadata (failure domain, target kinds, engine lanes, risk, reversibility, observable effect, verification method, maturity and date policy) plus `discover faults -e` explanations naming the mechanism and its limits. Acceptance: contract-checklist walk passes; the six deriving test files sweep the new ids automatically.

## Phase 4 — Safety and evidence integration
Impact-gate REQUIREMENTS rows (bins must exist in `_PROBE_BINS` or the fault gates inert forever — trap documented, test pinned); maximum-safe-duration enforcement in admission; incompatible-pair declarations feeding the 07 collision graph. Acceptance: an unsupported kernel/engine combination refuses loudly — silent fallback to a weaker mechanism fails the suite.

## Phase 5 — Tests, regression guards, negative controls
Wire-execution tests in the style of `test_http_proxy_wire.py` (run the mechanism, not just its source text); low-level residue auto-scan after recovery; regression guard asserting distinct argv per parameter value so params cannot go inert. Acceptance: all new primitives enter the 01 certification pipeline; none ships as `verified-live` without a live cell.

## Phase 6 — Docs, honesty gates, rollout
Per-fault parameter catalogue entries in drill-spec style, substrate-ceiling notes (what still cannot be injected and why), rollout one family at a time behind capability detection. Acceptance: README substrate section updated only with what cells prove.

## Dependencies
01 (certification pipeline), 03 (fabric distribution), 07 (collision graph), 17 (provider SDK).

## STATUS — planning only, 0%
