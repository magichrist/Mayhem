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

## STATUS
- Phase 1 (domain model): DONE — `domain/lowlevel.py` landed `KernelPrimitive`, `IOPrimitive`, `JVMPrimitive` and `ClockPrimitive` on a shared `LowLevelPrimitive` base, each carrying required capabilities, an impact-gate-checkable demand set, a `ReversibilityStatement` (rung + undo + verification + Phase-2 compensation template + reconciliation), a maximum safe duration, non-empty residue checks, an incompatibility set, and a `MissingMechanism` where one applies; 22 descriptors declared, 341 tests in `tests/unit/test_lowlevel.py`.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.

**No new `FaultCategory` and no new fault id was added in this phase, on purpose.**

*No category.* Every descriptor reuses an existing category through
`REUSED_CATEGORY_BY_FAMILY` (kernel→`PROCESS`, io→`STORAGE`, jvm→`PROCESS`,
clock→`CLOCK`), and a model validator refuses any other value. A `FaultCategory`
is not one line: `_FAILURE_DOMAIN_BY_CATEGORY`, `_VERIFICATION_BY_CATEGORY` and
`_EFFECT_BY_CATEGORY` in `domain/catalog.py` are three TOTAL maps indexed by
`_define` at import time, so a category missing from any of them raises
`KeyError` and breaks `import mayhem` for the entire package, not one command.
`tests/unit/test_fault_catalog_exhaustive.py` also asserts category-set equality.
A test here re-checks every reused category against all three maps, so Phase 1
cannot become the commit that adds the fourth.

*No fault id.* The five-registry contract (catalog entry → executor routing →
compensation template → impact REQUIREMENTS → deriving tests) is untouched: this
lane adds no `CATALOG` entry, no `_register_fault_executor` override, no
compensation builder, no `REQUIREMENTS` row and no executor routing. A test
asserts every descriptor id is absent from `CATALOG`, and that the four ids the
descriptors *reference* (`fs.fill`, `fs.inode_exhaust`, `fs.read_only`,
`clock.skew`) resolve through `catalog.definition_for` and are **not**
`catalog_only`.

The existing `catalog_only` refusals stay authoritative. `clock.freeze`,
`fs.read_error` and `fs.permission_failure` each have a descriptor whose
`MissingMechanism.anchor_fault_id` points at that refusal, and a test asserts the
anchor is still a `catalog_only` entry whose reason starts `catalog.unsupported`.
`MissingMechanism` has **no substitute field**; `near_misses` records the ids a
reader is likely to reach for together with why each is not equivalent, so "here
is a weaker thing you could use instead" is not expressible.

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

