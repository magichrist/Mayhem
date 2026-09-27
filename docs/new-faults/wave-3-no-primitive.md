# Wave 3 — 9 ids that have no primitive in this codebase

These requests describe real production failure modes that mayhem **cannot
currently inject**. The correct outcome is a `catalog_only` catalog entry that
documents the gap and refuses deterministically — not a fault that appears to
work.

The repo already has this pattern with 4 entries:
`process.startup_delay`, `fs.permission_failure`, `dependency.malformed_response`,
`k8s.image_pull_slow`. `validate_catalog` enforces the two halves of the
contract (`catalog.py:1826-1833`):

- `catalog_only=True` **requires** a non-blank `refusal_reason`
- `catalog_only=False` **must not** carry one

and `tests/unit/test_fault_catalog_exhaustive.py:706-780` additionally requires
the refusal to start with `catalog.unsupported` (or `k8s.unsupported`), to
exceed 30 characters, and to be enforced at plan time by `plan_drill`.

## 3.1 The 9

| id | why there is no primitive | what would be needed |
| --- | --- | --- |
| `cpu.steal` | CPU steal is hypervisor-enforced. Nothing in `src/` talks to KVM, vCenter, or a cloud host scheduler. The nearest existing fault, `cpu.throttle`, caps the cgroup CPU share — **voluntary CFS throttling**, a fundamentally different mechanism from involuntary steal. | hypervisor/host control plane (libvirt, or a cloud API). Out of scope for a container-scoped tool. |
| `cpu.interrupt_storm` | needs IRQ/softirq control: `/proc/interrupts` manipulation, RPS/RFS tuning, or a device that generates interrupts. Zero hits in `src/`. `load.spike` and `fuzz.protocol_abuse` create *soft* CPU load, not an IRQ storm. | host-level kernel tuning, outside the container. |
| `mem.fragment` | needs buddy-allocator or `MADV_FREE`/hugepage control. `mem.freeze` allocates and holds; `mem.swap_pressure` writes to `/dev/shm`. Neither fragments. | allocator-level control, or a specific runtime's GC/malloc tuning. |
| `fs.read_error` | needs `dm-error`/`dm-flakey` (device-mapper), a FUSE shim, or a bad loop device. Grep for `losetup`, `dmsetup`, `device-mapper`, FUSE ⇒ zero hits. The only mount operation in the tree is `mount -o remount,ro` (`compensation.py:1919-1965`), which does not produce EIO on read. | device-mapper target, which requires `SYS_ADMIN` and a loop device — a host-level substrate. |
| `clock.freeze` | requires libfaketime, a time namespace, or an offsetting clock hook. Nothing in the tree stops the clock; `clock.skew` always *sets* a new time and always has a `date -u -s` restore path. `container.pause` approximates "time stops passing" but also freezes execution, which is a different (and more severe) mechanism. | libfaketime preload or `CLOCK_REALTIME` interception. |
| `process.oom_kill` | see below | cgroup `memory.events` observation + a real allocation over the limit |
| `mem.oom_kill` | same | same |
| `app.exception` | no in-process fault hook exists anywhere: no bytecode injection, no ptrace/gdb, no `/proc/<pid>/mem` patching, no agent-side code loading. | app cooperation (a fault-injection hook in the service) — a per-service change, not a mayhem change. |
| `app.deadlock` | a true lock cycle is not injectable from outside. The cgroup freezer (`container.pause`) is the only implementable approximation and it is a strictly different mechanism. | app cooperation |

### The OOM case deserves its own decision

`k8s.pod_oom` is the **only** real OOM implementation in the repo
(`K8sPodOomExecutor`, `executors.py:610-668`) and it is k8s-only.
`mem.exhaust` deliberately refuses to OOM: its payload caps the goal at
`memory.max * 95 // 100` "so the run can never OOM-kill the whole container"
(`compensation.py:225-234`).

Three options, in order of preference:

1. **Do not add a container-lane OOM id.** Point users at `k8s.pod_oom` and, for
   container lanes, document that `mem.exhaust{mode=exhaust}` gets close but
   stops short on purpose.
2. **Add `mem.oom_kill` as `catalog_only`** with a refusal naming the 95% cap
   and the irreversibility problem: an OOM kill destroys the process, so it is
   `Reversibility.RECONCILED` at best and needs a supervisor to bring the
   service back. The recovery story, not the injection, is the hard part.
3. Lift the 95% cap behind a new `mem.oom_kill` id. **Not recommended without
   option 2's recovery work** — this converts a safe fault into one that takes
   the container down, and `mayhem`'s entire compensation contract
   (`compensated()` refuses an uncompensatable injection,
   `compensation.py:2321-2327`) is built on the assumption that injected faults
   have a working undo.

`process.oom_kill` and `mem.oom_kill` are the same request twice. If the
decision is to add one, add one.

## 3.2 Registry work per entry

Much lighter than wave 2 — no executor, no compensation template, no
`REQUIREMENTS` entry:

- `catalog.py` — `_define(id=..., category=..., risk=..., catalog_only=True,
  refusal_reason="catalog.unsupported: …", applicable_node_kinds=…,
  max_duration_s=…)`. Note `_define` leaves `maturity` at `EXPERIMENTAL` for
  catalog-only entries (`:193-195`) and `verification_date` stays `None` —
  which is exactly what `TestMaturityMetadata` requires
  (`(maturity is EXPERIMENTAL) == catalog_only`, `test_fault_catalog_exhaustive.py:332`).
- `impact.py` — add to `_CATALOG_ONLY_FAULTS` (`impact.py:148-154`) so
  `gate_fault` returns `impact_possible=False, probed=True` with the
  catalog-only note. There is already drift risk here: the catalog has 4
  `catalog_only` ids but this set has 3 (it excludes the `k8s.*` one, which is
  intentional). **Adding a catalog-only entry without updating this set means
  `gate_fault` falls through to the "no in-image tooling required" default and
  reports it as impact-possible** — a silent contradiction.
- `planner.py` needs nothing: `definition.catalog_only` →
  `PlanningError(refusal_reason)` at `planner.py:1117-1118`.
- Tests — the catalog-only blocks in `test_fault_catalog_exhaustive.py:706-780`
  and `test_fault_catalog_all.py:259-272` (which asserts
  `template_for(...) is None` for catalog-only ids) cover these automatically.
  `test_impact_gate.py` needs the `_CATALOG_ONLY_FAULTS` update.

## 3.3 The refusal_reason is the deliverable

For a refused fault, the refusal text is the entire user-facing value. It must
name the missing mechanism **and** point at what to use instead. Examples in
the right voice:

- `process.oom_kill`:
  `"catalog.unsupported: a container-lane OOM kill is irreversible from inside
  the container and mem.exhaust deliberately caps at 95% of the cgroup limit;
  use k8s.pod_oom on Kubernetes"`
- `cpu.steal`:
  `"catalog.unsupported: CPU steal is hypervisor-enforced and outside a
  container's control; cpu.throttle caps cgroup CPU share, which is voluntary
  CFS throttling, not steal"`
- `fs.read_error`:
  `"catalog.unsupported: read EIO requires a device-mapper error target or a
  FUSE shim, neither of which mayhem provisions; fs.read_only covers
  write-side failure"`
