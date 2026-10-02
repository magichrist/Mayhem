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

> **Outcome (see STATUS).** No mechanism was implemented. 18 of the 22 Phase 1
> primitives have no substrate to run on, so this phase closed with four
> `catalog_only` refusals that name the missing mechanism rather than with
> provider SDK work, and the acceptance bar above ("demonstrates inject → observe
> → undo → verify on a dev cell") is unmet for all 22. The remaining mechanism
> work is what would let `process.syscall_error`, `process.syscall_return_mutation`,
> `fs.read_delay` and `fs.block_device_delay` be promoted out of `catalog_only`.

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

## STATUS
- Phase 1 (domain model): DONE — `domain/lowlevel.py` landed `KernelPrimitive`, `IOPrimitive`, `JVMPrimitive` and `ClockPrimitive` on a shared `LowLevelPrimitive` base, each carrying required capabilities, an impact-gate-checkable demand set, a `ReversibilityStatement` (rung + undo + verification + Phase-2 compensation template + reconciliation), a maximum safe duration, non-empty residue checks, an incompatibility set, and a `MissingMechanism` where one applies; 22 descriptors declared, 341 tests in `tests/unit/test_lowlevel.py`.
- Phase 2 (engine: provider-side mechanisms): DONE **as refusals, not as mechanisms** — 18 of the 22 primitives cannot be injected by mayhem's current substrate, so this phase landed four `catalog_only` catalog entries whose `refusal_reason` names the missing mechanism, plus a written rule for each of the fourteen that stay descriptor-only. 106 tests in `tests/unit/test_lowlevel_refusals.py`. **No provider-side mechanism was built**: the eBPF loader, the FUSE and device-mapper shims, the JVM attach agent and the clock-interception preload are all still absent, so Phase 4's REQUIREMENTS rows and Phase 5's wire-execution tests have nothing to gate yet. The plan's own Phase 3 line — "each primitive demonstrates inject → observe → undo → verify on a dev cell before catalog entry" — is not met for any of them, which is precisely why they are refusals and not catalog entries with mechanisms.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.

**Still no new `FaultCategory`, and no new fault mechanism.** Phase 2 added
four fault *ids*, all of them `catalog_only` refusals. The category rule from
Phase 1 is unchanged: `_FAILURE_DOMAIN_BY_CATEGORY`, `_VERIFICATION_BY_CATEGORY`
and `_EFFECT_BY_CATEGORY` in `domain/catalog.py` are three TOTAL maps indexed by
`_define` at import time, so a category missing from any of them raises
`KeyError` and breaks `import mayhem` for the entire package. Phase 2's four
entries reuse `PROCESS` (kernel) and `STORAGE` (io) and live under the `process.`
and `fs.` prefixes that already map to those categories.

### Phase 2: the honest catalog outcome

Four `catalog_only` refusals, one per **missing mechanism** rather than one per
primitive:

| catalog id | descriptor(s) it answers for | missing mechanism named in the refusal |
| --- | --- | --- |
| `process.syscall_error` | `kernel.syscall_errno`, `kernel.syscall_latency` | `ebpf_kprobe_loader` |
| `process.syscall_return_mutation` | `kernel.syscall_return_mutation` | `ebpf_return_value_rewrite` |
| `fs.read_delay` | `io.read_delay`, `io.write_delay` | `fuse_delay_shim` |
| `fs.block_device_delay` | `io.block_device_delay` | `device_mapper_delay_target` |

Each refusal names the mechanism, names why the substrate cannot satisfy it
today (`bpftool` has no `_PROBE_BINS` row, `SYS_ADMIN` has no `_CAP_BITS` row,
no `/dev/fuse` passthrough, no loop device or `/dev/mapper/control`), and points
at what exists instead — naming the *difference* between that fault and the one
pointed at, never presenting it as equivalent.

All four are recorded in `agents/impact.py`'s `_CATALOG_ONLY_FAULTS`. That is
load-bearing, not bookkeeping: an id absent from that set makes `gate_fault` fall
through to "no in-image tooling required" and report `impact_possible=True` about
a fault that cannot physically take effect.
`tests/unit/test_lowlevel_refusals.py` contains the negative control that
*observes* the contradiction by removing an id from the set at runtime.

### The selection rule, and the fourteen that stay descriptor-only

A blocked primitive gets an id iff **all four** hold:

- **R1 — the name is one a user would type.** The catalog is the discovery
  surface (`mayhem discover faults`), so a refusal only earns a row if the id is
  reachable from plan 04's family list or the catalog's own vocabulary. A refusal
  under a name nothing produces is unreachable.
- **R2 — no existing refusal already owns it.** When a descriptor's
  `MissingMechanism.anchor_fault_id` is set, the authoritative refusal is already
  a `catalog_only` row. Two refusals for one failure drift.
- **R3 — the mechanism is buildable.** A `catalog_only` entry is a *promotion
  ticket*: it says "keep this until the mechanism exists". A `NOT_STEPPABLE`
  descriptor can never be promoted, so publishing one would put a permanent
  "keep until built" row in the catalog for something unbuildable.
- **R4 — the id is expressible.** No new `FaultCategory` and no new prefix.

Two further descriptor-only shapes, both structural:

- **R5a** — the id a user would type is occupied by an *active* entry with a
  different mechanism.
- **R5b** — the descriptor's risk rung has no catalog row for its scope.

What that leaves, with the reason for each:

| primitive(s) | rule | why no id |
| --- | --- | --- |
| `io.read_error`, `io.permission_error`, `jvm.exception_injection`, `clock.realtime_freeze` | R2 | `fs.read_error`, `fs.permission_failure`, `app.exception` and `clock.freeze` are already the authoritative `catalog_only` refusals; each is the descriptor's `anchor_fault_id` and is left untouched |
| `clock.monotonic_offset`, `clock.monotonic_freeze` | R3 | `NOT_STEPPABLE` on Linux: `adjtimex` steps `CLOCK_REALTIME` only and monotonic time can merely be slewed a few hundred ppm. A refusal here would be a promise of promotion that can never be kept |
| `jvm.method_delay`, `jvm.return_value_mutation`, `jvm.allocation_pressure`, `jvm.gc_pressure`, `jvm.thread_pressure` | R4 | `jvm` is absent from `_PREFIX_TO_CATEGORY`, and adding it means a new `FaultCategory` or a category redefinition in `domain/faults.py` — a file this lane does not own and a decision Phase 3 owns. Reusing `app.*` would invent `app.jvm_*` names that nothing in the taxonomy produces; the one JVM failure a user plausibly reaches for, exception injection, is already refused by `app.exception` |
| `io.write_delay` | R5a | the id `fs.write_delay` is already **active**, and its mechanism is a burner process writing its own marker file — it perturbs contention, not any target's write latency. A second id would need a name the catalog's vocabulary does not produce; the honest correction of that entry is a re-scope decision, not a refusal |
| `io.torn_write` | R5b | the descriptor is `CRITICAL` and container-scoped, while the catalog reserves the `CRITICAL` rung for pod/node faults (`test_critical_faults_are_pods_or_nodes`). Publishing the id would mean either understating the risk or misfiling the scope |

`kernel.syscall_latency` and `io.write_delay` are covered by an existing
refusal rather than an absent one — one refusal per mechanism, so there is one
text to keep in step. That is why `process.syscall_error`'s refusal also answers
the syscall-latency primitive and `fs.read_delay`'s also answers
`io.write_delay`'s.

**Fourteen of the eighteen blocked primitives are descriptor-only.** That is the
honest count, not a shortfall: the plan says "the refusal_reason is the
deliverable", and a refusal is only worth publishing where it is the one a user
will actually meet.

### Where the refusals live in the five-registry contract

Four of the five registries are touched; the fifth is a deliberate absence.

| registry | what Phase 2 did |
| --- | --- |
| catalog definition | four `_define(..., catalog_only=True, refusal_reason=...)` entries with full metadata: failure domain, target kinds, engine lanes, risk, reversibility, observable effect, verification method, maturity and date policy (stays `EXPERIMENTAL`, `verification_date` stays `None` — the catalog-only maturity contract) |
| executor routing | **none**, deliberately. No `_register_fault_executor` override. `execution_status()` reports `catalog-only` and `_executor_name()` reports `catalog.unsupported` on all three engines |
| compensation template | **none**, deliberately. `template_for()` returns `None` and `compensated()` refuses with `plan_uncompensated_fault` |
| impact `REQUIREMENTS` | **none**, deliberately — a requirements row would gate a fault that has no tooling to probe. Instead each id is in `_CATALOG_ONLY_FAULTS`, which is the only row that can honestly describe it |
| deriving tests | swept automatically: `test_fault_catalog_exhaustive`, `test_fault_catalog_all`, `test_catalog_only_refusals`, `test_impact_gate`, `test_runtime_execution_matrix` and `test_container_fault_matrix` all derive from `CATALOG` |

### Known limitations of Phase 2

- **Four refusals, eighteen blocked primitives.** The rule above explains each of
  the fourteen omissions, and the test suite asserts both directions: a nineteenth
  blocked primitive fails until someone decides, and every rule id is re-checked
  against the fact that justifies it.
- **The six `jvm.*` descriptors have no catalog surface at all.** They are
  reachable only through `domain/lowlevel.py`. A user asking "how do I delay a
  Java method?" is told about `app.exception` and nothing else. Publishing
  `app.jvm_*` ids is a real option and a naming decision this lane deliberately
  did not take unilaterally.
- **`process.syscall_error` and `process.syscall_return_mutation` sit under a
  prefix `ProcPauseExecutor` owns.** It is safe today only because every routing
  contract derives from the active set and excludes `catalog_only` ids. If a
  future change routes on `executor_for` presence rather than on
  `catalog_only`, these two ids become the first things to move.
- **`required_caps` on a refusal names a capability nothing reads.** Each entry
  declares `SYS_ADMIN` to record *why* the gate cannot evaluate the demand; no
  code consumes it, so it can go stale without failing anything.
- **Refusal prose is not machine-checked against the domain.** The test suite
  binds each refusal to its descriptor's `MissingMechanism.mechanism` string, but
  `validate_catalog` itself only requires a non-blank refusal — it has no
  mechanism vocabulary, because `FaultDefinition` has no field for one.


## Phase 1 detail — unchanged by Phase 2

Everything below describes Phase 1's substrate analysis and is still true. Phase 2
did not edit a descriptor, promote a primitive, or make any of these mechanisms
appear; it only decided which of them a user would meet in the catalog. Where the
table below names a mechanism, the Phase 2 table above says whether it now has a
refusal (`ebpf_kprobe_loader`, `ebpf_return_value_rewrite`, `fuse_delay_shim`,
`device_mapper_delay_target`), whether an existing refusal already answers for it
(`device_mapper_error_target`, `permission_preserving_executor`,
`clock_interception_preload`, one `jvm.*` row), or whether it stays
descriptor-only (`device_mapper_partial_write_target`, the `jvm.*` rows,
`clock_interception_preload`'s monotonic pair).

### What today's substrate can and cannot inject

`LowLevelPrimitive.substrate_verdict(surface)` is a pure predicate, and the
answer is *no* for 18 of the 22 descriptors. The injectable four are not new
capabilities — they are the existing `fs.fill`, `fs.inode_exhaust`, `fs.read_only`
and `clock.skew` mechanisms described from below, and each names the catalog id
that already carries it.

Blocked, by named missing mechanism:

| mechanism | descriptors | why |
| --- | --- | --- |
| `ebpf_kprobe_loader` | `kernel.syscall_errno`, `kernel.syscall_latency` | no eBPF support of any kind; `bpftool` is in no `_PROBE_BINS` row and `SYS_ADMIN` in no `_CAP_BITS` row, so the gate could not evaluate the demand even if the loader existed |
| `ebpf_return_value_rewrite` | `kernel.syscall_return_mutation` | a kprobe loader alone does not rewrite a traced return register |
| `fuse_delay_shim` | `io.read_delay`, `io.write_delay` | no FUSE daemon, no `/dev/fuse` passthrough, no `mount`/`fusermount3` in the probe set |
| `device_mapper_error_target` | `io.read_error` | no loop device, no `/dev/mapper/control`; anchored to `fs.read_error` |
| `device_mapper_delay_target` | `io.block_device_delay` | same, plus a snapshot of the device to reactivate |
| `device_mapper_partial_write_target` | `io.torn_write` | same, and no original on disk to restore — hence the one `IRREVERSIBLE` descriptor |
| `permission_preserving_executor` | `io.permission_error` | `chmod` restores the mode but cannot express a per-call denial; anchored to `fs.permission_failure` |
| `jvm_attach_agent`, `jvm_bytecode_instrumentation` | all six `jvm.*` | mayhem ships no JVM support; `jcmd` is in no probe set and `jvm.attach` in no manifest |
| `clock_interception_preload` | `clock.realtime_freeze` | no preload lane; anchored to `clock.freeze` |

`clock.monotonic_offset` and `clock.monotonic_freeze` are a **third** category:
`MissingCode.NOT_STEPPABLE` with `unachievable_substrate=True`. CLOCK_MONOTONIC
is not steppable on Linux — `adjtimex` steps CLOCK_REALTIME only and monotonic
time can merely be slewed by a few hundred ppm — so no amount of mechanism work
makes them injectable. That is deliberately distinguishable from "not built yet",
because a roadmap item that can never close is worse than no roadmap item.

### How checkable the capability demands are

`CURRENT_SUBSTRATE` is a domain-side restatement of `agents/impact.py`'s
`_PROBE_BINS`, `_CAP_BITS` and `_PM_PACKAGES`, plus the toolkit's manifest
vocabulary. `mayhem.domain` sits below `mayhem.agents` in the layered
import-linter contract, so the domain cannot ask the real gate anything — the
copy is the only way to make the question answerable, and four tests re-check it
against the real tables on every run. The predicate classifies each demand into
one of the three documented traps (`BIN_NOT_PROBED`, `CAP_BIT_UNDEFINED`,
`BIN_NOT_INSTALLABLE`) or `HOST_TOOL_ABSENT` / `TOOL_NOT_MANIFESTED`, and
`validate_substrate_claims` refuses a descriptor whose declared
`covers_reasons` is not **exactly** the set the surface produced — in both
directions, so neither a silent over-claim nor an "unimplemented" excuse on top
of a working mechanism survives.

Two known gaps in the checkable set, recorded rather than papered over: a cap-bit
name with no `Capability` mapping is unrepresentable in a descriptor (it would
ask the domain to reason about a vocabulary it cannot map), and `SYS_TIME` maps
to `Capability.NET_ADMIN` because that is what `clock.skew` declares today
rather than inventing a ninth `Capability`.

### Known limitations of Phase 1

- `CURRENT_SUBSTRATE` is a second literal that must change with
  `agents/impact.py`. The import-linter contract forbids the dependency, so the
  four restatement tests are load-bearing, not hygiene.
- `registry_problems()` is a pure function and is deliberately **not** run at
  import. `domain/catalog.py` validates at import and a non-conforming entry
  there breaks the whole package; a registry nothing else imports should not be
  able to do the same. A test asserts it is empty instead.
- Descriptors carry no `params_schema`. Mapping a descriptor onto a catalog entry
  is Phase 3 work and the param grammar is part of that decision.
- `fs.write_delay` is an active catalog entry whose mechanism is a burner process
  writing to its own marker file, so it perturbs contention and not any target's
  write latency. The `io.write_delay` descriptor records that as a near-miss
  rather than presenting it as this primitive. Renaming or re-scoping that id is
  a Phase 3 decision and is not made here.

