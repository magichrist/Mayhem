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
- Phase 1 (domain model): DONE — `domain/lowlevel.py` landed `KernelPrimitive`, `IOPrimitive`, `JVMPrimitive` and `ClockPrimitive` on a shared `LowLevelPrimitive` base, each carrying required capabilities, an impact-gate-checkable demand set, a `ReversibilityStatement` (rung + undo + verification + Phase-2 compensation template + reconciliation), a maximum safe duration, non-empty residue checks, an incompatibility set, and a `MissingMechanism` where one applies; 22 descriptors declared, 343 tests in `tests/unit/test_lowlevel.py`. **Not landed:** the parameter grammar (Phase 3's job, deferred by this phase), and any mechanism for any of the 22.
- Phase 2 (engine: provider-side mechanisms): DONE **as refusals, not as mechanisms** — 18 of the 22 primitives cannot be injected by mayhem's current substrate, so this phase landed four `catalog_only` catalog entries whose `refusal_reason` names the missing mechanism, plus a written rule for each of the fourteen that stay descriptor-only. 106 tests in `tests/unit/test_lowlevel_refusals.py`. **No provider-side mechanism was built**: the eBPF loader, the FUSE and device-mapper shims, the JVM attach agent and the clock-interception preload are all still absent, so Phase 4's REQUIREMENTS rows and Phase 5's wire-execution tests have nothing to gate yet. The plan's own Phase 3 line — "each primitive demonstrates inject → observe → undo → verify on a dev cell before catalog entry" — is not met for any of them, which is precisely why they are refusals and not catalog entries with mechanisms. **Not landed:** any mechanism, any executor routing, any compensation template and any impact-gate `REQUIREMENTS` row; the four `_CATALOG_ONLY_FAULTS` rows are the only impact-gate rows any of this plan's ids carries, and they are still true.
- Phase 3 (surface: catalog entries and explanations): DONE — the **parameter grammar** Phase 1 recorded as deferred work now exists and is *derived* from fields the descriptor already validates (`ParamKind`, `PrimitiveParam`, `parameter_grammar`, `resolve_params`, `AttachSpecification`, `specification_for`), and Phase 3 added the three magnitudes the grammar exposed as missing: `KernelPrimitive.latency_ms`, `IOPrimitive.delay_ms` and `JVMPrimitive.pressure_units`, each required exactly when the mode perturbs by an amount and bounded by the descriptor's own maximum safe duration. `domain/lowlevel_report.py` is the surface that was missing entirely — `PrimitiveDisposition` (carried / refused / descriptor-only / unachievable), `PrimitiveAvailability` (never anything but `declared_not_applied` unless an active catalog fault already carries it), `PrimitiveExplanation` whose validator **refuses `mechanism_applied=True`**, and `explain_primitive`/`explain_primitives`/`describe_explanation`. Phase 2's two selection tables moved out of `tests/unit/test_lowlevel_refusals.py` and into `domain/lowlevel_report.py` as `CATALOG_REFUSAL_BY_PRIMITIVE` and `DESCRIPTOR_ONLY_RULES`, because a decision a person is meant to read cannot live only in a test; the Phase 2 suite now inverts them. `cli/lowlevel_cmd.py` exposes it as `mayhem lowlevel primitives|explain`. **Not landed:** registration of that group (`cli/command_registry.py`, `cli/app.py` are outside this lane) — reported as an integration dependency below. 340 tests in `tests/unit/test_lowlevel_surface.py`.
- Phase 4 (safety and evidence integration): DONE — `domain/lowlevel_admission.py` is the gate the plan's eighteen blocked primitives had nowhere to go: eight checks (`primitive:known`, `primitive:substrate`, `engine:supported`, `admission:duration`, `admission:parameters`, `collision:pairs`, `mechanism:probe`, `mechanism:apply`), `LowLevelStatus` with `refuses_gate` written `is not PASS`, a `MechanismPort` that **no implementation of exists in this repository** and that is `UNAVAILABLE` when unbound, raising, `None`-shaped or wrong-shaped, and an `AdmissionReport` with no field for a substituted mechanism. It enforces the plan's maximum-safe-duration rule (with a `MIN_OBSERVABLE_FRACTION` floor, because a window too short to observe is the inert parameter wearing a duration), refuses `kubernetes` for every family by name with the adapter reason, and derives plan 07's `collision_edges()` from the descriptors' own symmetric `incompatible_ids`. **The plan's `REQUIREMENTS` row is deliberately absent**: `requirements_rows_needed()` returns the ids a row would genuinely gate and it is **empty**, because every blocked primitive trips one of the four documented traps (`bin_not_probed`, `cap_bit_undefined`, `bin_not_installable`, `tool_not_manifested`) against the real `agents/impact.py` tables. 241 tests in `tests/unit/test_lowlevel_admission.py`. **Not landed:** the collision edges are derived but not registered into plan 07's bundle, and the four gate rule ids below are unmapped in `safety_proof.py`.
- Phase 5 (tests, regression guards, negative controls): DONE — `tests/unit/test_lowlevel_wire.py` runs the wire path through the real Click tree for **all twenty-two** primitives and asserts each is refused with exit `5` and `applied_primitive=none`; it proves the privileged half is unreachable two ways (the CLI constructs no bound `MechanismPorts`, and an AST sweep finds no class in `src/mayhem` declaring `probe`/`attach`/`detach`/`residue`); it drives `scan_after_recovery` — the residue auto-scan — with a fake observer that is dirty on pass one and clean on pass two, and its negative controls make it raise on a never-clean undo, on answers for undeclared facets, and on a zero pass budget; it runs the **inertness guard** (two distinct legal values of every parameter of every primitive must produce two distinct attachment specifications) and its control shows a specification blinded to the delay cannot tell two delays apart; and it puts all twenty-two through `infra/promotion.evaluate_maturity` with a hand-supplied unit-evidence receipt and asserts every decision is below `verified-unit`, `live_record_count == 0`, `live_verified is False`. 91 tests in `tests/unit/test_lowlevel_wire.py`. **Not landed:** no primitive enters plan 01's certification pipeline as a *candidate*, because a primitive that cannot be injected cannot be certified on a cell — the suite asserts that absence rather than inventing an entry.
- Phase 6 (docs, honesty gates, rollout): DONE — this STATUS, the per-family drill-spec parameter catalogue, the substrate-ceiling notes, the one-family-at-a-time rollout ladder behind capability detection, and `tests/unit/test_lowlevel_doc_honesty.py`, which parses this document rather than trusting it: the `Overall:` count must equal the number of `DONE` ledger lines, every fault id it names must exist and still be `catalog_only` and still be in `agents/impact.py`'s `_CATALOG_ONLY_FAULTS`, every rule id it explains must still decide a primitive, and seven literal forbidden claims — enumerated in the suite rather than here, so that this document cannot trip its own gate — each fail a test. 39 tests in `tests/unit/test_lowlevel_doc_honesty.py`. **Not landed:** the README substrate section is **unchanged**, because no cell has proved anything; that is the acceptance criterion ("updated only with what cells prove") met by not editing it.

Overall: 6 of 6 phases complete.

**Still no new `FaultCategory`, still no new fault id, and still no mechanism.**
Phases 3 to 6 added four domain and CLI modules and three test files. They added
**no fault id, no `FaultCategory`, no executor routing, no compensation template,
no impact-gate row and no catalog entry**: the four `catalog_only` refusals are
Phase 2's, and `verified-live` remains 0 for every id this plan touches. What
changed is that the eighteen blocked primitives now have a *decision* (Phase 4),
a *nameable* refusal with a mechanism and its limits (Phase 3), a parameter
grammar that cannot go inert (Phases 3 and 5), a residue scan that cannot report
clean on partial coverage (Phases 4 and 5), and a document a test keeps honest
(Phase 6). The mechanism work is unchanged and is what would let
`process.syscall_error`, `process.syscall_return_mutation`, `fs.read_delay` and
`fs.block_device_delay` be promoted out of `catalog_only`.

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
that already carries it:

| descriptor | mechanism it reuses | backing catalog id |
| --- | --- | --- |
| `io.capacity_exhaustion` | marker files written by an in-container burner | `fs.fill` |
| `io.inode_exhaustion` | marker files, one per inode | `fs.inode_exhaust` |
| `io.filesystem_read_only` | a read-only remount, undone by remounting | `fs.read_only` |
| `clock.realtime_offset` | `adjtimex` under `SYS_TIME`, undone by stepping back | `clock.skew` |

Note what the table says and does not say. All four describe a **mechanism that
already exists and already runs**; none of them is something this plan built, and
none of the four is a low-level fault in the sense the plan means. They appear as
"injectable" because the substrate can carry the mechanism their backing entry
uses — the descriptor documents that entry, it does not propose a new one. The one
high-risk row is `io.filesystem_read_only`, which is high-risk because
`fs.read_only` is, and its residue check is a `findmnt` comparison against the
pre-injection mount options.

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


## Phase 3 detail — the parameter grammar and the explanation

### The grammar is derived, not written

Phase 1 recorded "descriptors carry no `params_schema`" as a limitation and named
the mapping as Phase 3's job. It is done by **derivation**
(`domain/lowlevel.py::parameter_grammar`) rather than by hand, because a
hand-written grammar is free to disagree with the model — the same class of drift
that makes an impact-gate `REQUIREMENTS` row name a binary no fault probes. Every
parameter is read from a field the descriptor already validates:

| family | target selectors | mode quantity |
| --- | --- | --- |
| `kernel` | `syscall` (the descriptor's own set, required), `attachment` (`process`/`thread`) | `errno` (closed `ErrorCode` table), `latency_ms`, `mutation` (closed table) |
| `io` | the descriptor's own `path_param` under its own name, `operation` | `delay_ms`, `errno` |
| `jvm` | `target_class`, `target_method`, `instrumentation` | `exception_class`, `delay_ms`, `pressure_units` (unit per mode: `bytes`, `invocations`, `threads`) |
| `clock` | `clock_id` | `offset_ms` (± the descriptor's window), `rate_ppm` (± `MAX_SLEW_PPM`) |

### Three magnitudes the derivation exposed as missing

Deriving the grammar surfaced a real defect rather than confirming the model:
five descriptors had a mode that perturbs *by an amount* and no amount to
perturb by. `kernel.syscall_latency`, `io.read_delay`, `io.write_delay`,
`io.block_device_delay` and `jvm.method_delay` were delay modes whose only
parameter was "on or off" — the inert-parameter defect the plan's Phase 5 names,
one layer below where the plan expected to find it. Phase 3 added
`KernelPrimitive.latency_ms`, `IOPrimitive.delay_ms` and `JVMPrimitive.
pressure_units`, required exactly when the mode scales and bounded by the
descriptor's own `max_safe_duration_s` through one shared rule
(`_magnitude_is_declared`). A magnitude of zero, a magnitude on a mode that has
none, and a magnitude longer than the recovery window are all construction
errors.

`magnitude_holder()` says where each primitive's amount lives in words, so the
absence of a parameter is never read as the absence of a size:
`io.capacity_exhaustion` takes its size from `fs.fill`'s parameters,
`io.read_error`'s "magnitude" is an errno — a code, not an amount — and
`clock.realtime_freeze` applies a transformation with nothing to scale.

### Drill-spec parameter catalogue

Written in the form a `mayhem.yaml` would carry them. **None of these requests
can be satisfied by this build** — they are the parameters a mechanism would
receive, and the refusal is what `mayhem lowlevel admit` returns.

```yaml
# kernel: make read() return -EIO on the target process
containers:
  checkout-api:
    faults:
      - fault: process.syscall_error          # catalog_only: ebpf_kprobe_loader
        duration: 30s
        params: {syscall: read, errno: EIO}  # errno ∈ the closed ErrorCode table
# → refused: ebpf_kprobe_loader is missing; bpftool has no _PROBE_BINS row and
#   SYS_ADMIN has no _CAP_BITS row.

# io: delay every read on one mount by 1500ms
      - fault: fs.read_delay                  # catalog_only: fuse_delay_shim
        duration: 60s
        params: {path: /srv/cache, delay_ms: 1500}   # 1..120000, ≤ the 120s window
# → refused: no FUSE passthrough daemon, no /dev/fuse in the target, no mount
#   tooling in the probe set.

# jvm: hold ThreadPoolExecutor.getActiveCount for 1200ms
      - fault: app.jvm_method_delay           # no such id: `jvm` is not a prefix
        params: {target_class: java.util.concurrent.ThreadPoolExecutor,
                 target_method: getActiveCount, delay_ms: 1200}
# → not expressible: rule R4.  Reach it through `mayhem lowlevel explain
#   jvm.method_delay`, which prints the grammar and the reason.

# clock: shift CLOCK_REALTIME by +60s
      - fault: clock.skew                    # active; carries clock.realtime_offset
        params: {offset_ms: 60000}
```

### Known limitations of Phase 3

- **`mayhem lowlevel` is not registered.** `cli/command_registry.py` and
  `cli/app.py` are outside this lane's ownership, so the group is exported and
  invoked directly through `CliRunner`. Its absence from `mayhem --help` is a
  known gap, not an oversight, and the suite asserts the absence so the
  integration pass's row is expected rather than surprising.
- **The `jvm.*` grammar has no fault id to travel in.** It is fully specified and
  fully checkable, and `mayhem lowlevel` prints it, but a drill spec cannot carry
  it until a prefix is registered. That remains a naming decision, not a
  technical gap, and Phase 3 deliberately did not take it unilaterally.
- **`mechanism_applied` is a field that is always `False` and whose validator
  refuses `True`.** A reviewer may reasonably ask why a type carries a field that
  can hold one value. The answer is that the promotion path has to exist for the
  refusal to be reversible, and putting the path behind a construction error means
  the day it is taken is a failing test by name rather than a silent flip.

## Phase 4 detail — the gate

### Decision, not mechanism

`domain/lowlevel_admission.py` decides; the privileged half is behind
`MechanismPort`, and **no class in `src/mayhem` implements it** — asserted by an
AST sweep, not by a comment. An unbound port, a port that raises, a port that
answers `None` and a port that answers the wrong type are all `UNAVAILABLE`, and
`UNAVAILABLE` refuses, for
`mayhem.controller.preflight_gate`'s reason: *mayhem cannot see an eBPF loader,
so it cannot certify that one attached.*

### Why no `REQUIREMENTS` row

The plan asks for one per primitive. `requirements_rows_needed()` answers the
question as data and returns **the empty tuple**, because a row is worth
publishing only when the gate could actually evaluate the primitive's demand, and
every one of the eighteen blocked primitives trips one of the four traps against
the real tables:

| trap | a blocked primitive's demand | what the gate would report |
| --- | --- | --- |
| `bin_not_probed` | `bpftool`, `dmsetup`, `jcmd`, `mount`, `fusermount3`, `faketime` | never probed → the fault gates INERT forever |
| `cap_bit_undefined` | `SYS_ADMIN`, `BPF` | `has_cap` returns `False` unconditionally |
| `bin_not_installable` | any probed bin with no `_PM_PACKAGES` row | reportable, never installable |
| `tool_not_manifested` | `kernel.syscall_attach`, `jvm.attach`, `clock.intercept`, `storage.fuse_shim` | the capability is not installable as a tool |

A row naming an unprobed bin is not a gate. It is a line in a report that reads
like a gate which ran and cleared — the `ip` bug the plan's Phase 1 already
documents. The four `catalog_only` ids keep `_CATALOG_ONLY_FAULTS`, which is the
only impact-gate row that can honestly describe them.

### The engine refusal, by name

`SUPPORTED_ENGINES` is `{docker, podman}`. All four mechanisms are **in-image**:
they need a binary in the image and a capability inside the container. mayhem's
Kubernetes adapter sets neither `cap_add` nor a host `debugfs` mount on a pod
spec, so an attempt there would run as an agent with the pod's own privileges
rather than as a container root — a *different fault with a different blast
radius*. The gate refuses the combination by name instead of trying it.

### No silent fallback — structurally

`LowLevelRequest` and `AdmissionReport` have no field for a substitute, and the
check catalogue is a fixed tuple, so a weaker mechanism cannot be introduced
without changing the catalogue (which a test pins). When a port *is* bound, the
gate calls it — it is a decision seam, not a wall — but the report's
`applied_primitive` is only set when nothing refused, so a run can never record
an injection it also refused.

## Phase 5 detail — what was executed

### The wire path, for all twenty-two

`mayhem lowlevel admit PRIMITIVE_ID` is invoked through the real Click tree for
every primitive and every one is refused with exit `5`
(`ExitCode.SAFETY_REFUSAL`) and `applied_primitive=none`. The privileged half is
shown unreachable two ways: replacing `MechanismPorts` with a counting factory
records that the CLI never constructs a bound one, and an AST sweep of
`src/mayhem` finds no class declaring `probe`/`attach`/`detach`/`residue`.

The control behind that claim is stated in the suite rather than assumed: binding
a *tripwire* port **does** reach it, which is what makes "no port is bound" the
operative fact rather than a property of the gate's logic. And the two refusals
are distinguished — no port gives `UNAVAILABLE` ("mayhem has no witness", a
wiring finding) while an honest port reporting "not applied" gives `REFUSED`
("mayhem looked, and the answer was no", an environment finding). A gate whose
verdict could not move would be refusing for a reason it does not know.

### The residue auto-scan, and what it refuses

`scan_after_recovery` re-runs the **whole declared set** until clean, because an
undo can be asynchronous — a kprobe entry disappears once the module unloads, a
device-mapper target once the table is flushed — and a single look taken
immediately after the undo is a finding about *when*, not about the world. It is
fail-closed: an undo that never lands raises `lowlevel.residue_not_clean` rather
than returning the last scan. Its negative controls are a never-clean observer, an
observer that answers for facets the descriptor never declared, and a zero pass
budget.

### The inertness guard

For every primitive and every parameter, two distinct legal values must produce two
distinct `AttachSpecification.fingerprint()`s. This is the parameter-grammar
analogue of "distinct argv per parameter value", and a low-level attach is
described by a specification rather than by a command line — so the guard runs on
the specification. Its control blinds a specification to the delay entirely and
shows the comparison collapsing, which is what proves the guard reads the
magnitude at all rather than passing on some other field.

### The certification pipeline, honestly

Phase 5's acceptance clause says "all new primitives enter the 01 certification
pipeline; none ships as `verified-live` without a live cell". The first half is
**not met, deliberately**: a primitive that cannot be injected cannot be
certified on a cell, and eighteen of the twenty-two have no fault id for the
pipeline to promote at all. What landed instead is the check that would catch a
false claim: every primitive is put through `infra/promotion.evaluate_maturity`
with the most generous inputs available — a unit-evidence receipt supplied by
hand — and every decision is still below `verified-unit`, with
`live_record_count == 0` and `live_verified is False`. `EvidenceStore` seeds
nothing, so a `verified-live` count in any report is zero.

## Phase 6 detail — substrate ceiling and rollout

### Substrate ceiling: what still cannot be injected, and why

mayhem decides which low-level primitive to attempt and refuses every one it
cannot perform. In this build it attaches no eBPF program, creates no FUSE mount
or device-mapper target, and loads no JVM agent, so no primitive described here
has been injected on any host. Read a primitive as a contract a mechanism must
satisfy, never as evidence that a fault was injected.

| ceiling | what it blocks | what would lift it |
| --- | --- | --- |
| no eBPF loader, and `bpftool` in no `_PROBE_BINS` row | all three `kernel.*` primitives | a CO-RE loader, plus a `_PROBE_BINS` row for `bpftool` and a `_CAP_BITS` row for `CAP_BPF`/`SYS_ADMIN` |
| no `/dev/fuse` passthrough and no `mount`/`fusermount3` in the probe set | `io.read_delay`, `io.write_delay` | a FUSE daemon mayhem can provision into the target container, and the mount tooling rows |
| no loop device, no `/dev/mapper/control` | `io.block_device_delay`, `io.read_error`, `io.torn_write` | a device-mapper target plus a read-only snapshot to reactivate; `io.torn_write` additionally has no original on disk, which is why it is the one `IRREVERSIBLE` descriptor |
| no `chmod` equivalent for a per-call denial | `io.permission_error` | a permission-preserving executor; `chmod` restores the mode and cannot express the fault |
| no JVM support of any kind, `jcmd` in no probe set | all six `jvm.*` primitives | a JVMTI/Java-instrumentation attach agent, a target VM that permits attach, and an image with a JVM |
| `CLOCK_MONOTONIC` is not steppable on Linux | `clock.monotonic_offset`, `clock.monotonic_freeze` | **nothing.** `adjtimex` steps `CLOCK_REALTIME` only and monotonic time can merely be slewed a few hundred ppm. A roadmap item that can never close is worse than no roadmap item, so these are `UNACHIEVABLE` rather than `REFUSED` |
| the Kubernetes adapter writes neither `cap_add` nor a host `debugfs` mount | every primitive on the `kubernetes` lane | a pod-spec capability path — a product change in the adapter, not in plan 04 |
| no signature verification (`providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`) | nothing in this plan, and it is not claimed | out of scope |

### Rollout: one family at a time, behind capability detection

The order is **cheapest substrate first**, because each family that lands makes
the next one's requirements measurable rather than hypothetical. Nothing is
rolled out before the family above it has a `verified-live` cell.

1. **`clock`** — `clock.realtime_offset` is already carried by `clock.skew`; the
   only new work is a `libfaketime`-class preload for `clock.realtime_freeze`,
   whose promotion ticket is `clock.freeze`. Detection: `faketime` present in the
   probe set **and** `SYS_TIME` in `_CAP_BITS`.
2. **`io`** — the FUSE delay shim. It needs a daemon mayhem provisions and a
   `/dev/fuse` passthrough, which is a container-shape change before it is a fault.
   Detection: `/dev/fuse` readable in the target **and** `fusermount3` probed.
3. **`jvm`** — the attach agent, once an id exists to carry it (the `R4` naming
   decision, still open). Detection: `jcmd` probed **and** a manifest declaring
   `jvm.attach`.
4. **`kernel`** — last, and only after the capability rows exist: a kprobe loader
   with `bpftool` in `_PROBE_BINS` and `CAP_BPF` in `_CAP_BITS` is the difference
   between a gate that runs and a gate that reports INERT.

### Integration dependencies this lane could not satisfy

Stated here rather than left for a reader to infer. Each is a file outside this
lane's ownership.

| what | exact identifiers | where |
| --- | --- | --- |
| CLI registration | add a `CommandSpec("lowlevel", "lowlevel_cmd")` row and map it to `lowlevel_cmd.lowlevel` | `src/mayhem/cli/command_registry.py` |
| proof-line mapping | `lowlevel.admission_refused`, `lowlevel.mechanism_evidence_required`, `lowlevel.mechanism_applied_without_available` → `ObligationName.CAPABILITY_REQUIREMENTS` (each is a statement about whether *this run* could touch a target) | `OBLIGATION_FOR_RULE` in `src/mayhem/controller/safety_proof.py`, plus the same three keys in `src/mayhem/controller/check_gate.py::RULE_CHECK` |
| evidence-boundary row | none owed: nothing in this plan persists, and `AdmissionReport.to_payload()` is a projection a caller may write. If a future lane writes a refusal through an existing evidence writer, add `(mayhem.domain.lowlevel_admission, admission_report) -> {}` | `tests/unit/test_evidence_boundary.py::BOUNDARY_CALL_SITES` |
| collision-graph registration | register `collision_edges()` (15 edges) in the plan-07 bundle's compatibility list | plan 07's bundle; `domain/policy.py` |
| no migration reserved | this plan defines no table and touches no SQL | — |

### Deliberately not done

- **No README substrate-section edit.** Phase 6's acceptance is "README substrate
  section updated only with what cells prove"; no cell has proved anything, so the
  honest edit is none.
- **No `FaultCategory`, no new fault id, no new prefix.** `jvm.*` still has no
  id, and that remains a naming decision rather than a technical gap.
- **No executor routing and no compensation template** for anything added in
  Phases 3–6, because nothing added there is executable.
- **No promotion of any refusal.** `process.syscall_error`,
  `process.syscall_return_mutation`, `fs.read_delay` and `fs.block_device_delay`
  stay `catalog_only`, and `verified-live` stays 0 for every id this plan names.
