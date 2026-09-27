# Contract checklist — what adding one fault id actually requires

Adding a fault id is not additive. **Five registries must agree** or the test
suite fails, and the first two are enforced at **import time** — a
non-conforming entry breaks `import mayhem` for the entire package, not just
one command.

Ordered by how early they fail.

## 1. Catalog entry — `src/mayhem/domain/catalog.py`

`CATALOG` (`:244`) is a tuple of `_define(...)` calls. `validate_catalog(CATALOG)`
runs at **module import** (`:1836`), so this is the first gate.

### Required explicitly

| field | why |
| --- | --- |
| `id` | must use a registered prefix; `FaultCategory.from_fault_id` raises otherwise (`faults.py:41-51`, validator at `:191-195`) |
| `category` | must equal `FaultCategory.from_fault_id(id)` — a model validator re-derives and compares (`faults.py:197-206`) |
| `risk` | one of `LOW/MEDIUM/HIGH/CRITICAL` (`domain/risks.py:12-18`) |
| `applicable_node_kinds` | must be non-empty **and** at least one member must map to a target kind, or `_target_kind` raises `ValueError(f"fault {id!r} has no target kind")` (`catalog.py:152-156`) |
| `required_caps` | drives `engine_lanes` derivation; must be non-empty for the expansion families (`test_fault_expansion_catalog.py:45`) |
| `max_duration_s` | no inference; `> 0`, and `<= 600.0` if risk is HIGH/CRITICAL |
| `params_schema` | see §1.2 |
| `catalog_only` + `refusal_reason` | mutually exclusive; see §1.3 |

### Inferred by `_define` (`:188-241`) — normally omit

`maturity` and `verification_date` (EXPERIMENTAL → VERIFIED_UNIT + date, unless
`catalog_only`), `reversibility` (from `_RECONCILED_FAULTS` / `reversible`),
`target_kind`, `target_kinds`, `engine_lanes`, `failure_domain`,
`observable_effect`, `verification_method`, `compensation_evidence`,
`deprecation_path`.

### 1.2 Params

`ParamSpec` (`faults.py:147-156`): `name` (must match
`^[a-z][a-z0-9_.-]{1,63}$`), `type` (one of `string/integer/float/boolean/
duration/percent/bytes`), `required`, `default`, `minimum`, `maximum`,
`min_length`.

Enforced by `validate_params` (`faults.py:208-230`): unknown names rejected;
`required` with a non-`None` default is a shape violation; `minimum`/`maximum`
inclusive; `PERCENT` hard-clamped to `[0,100]`; **`bool` is never accepted for a
numeric param** (`_numeric`, `faults.py:259-263`).

### 1.3 catalog-only contract

- `catalog_only=True` **requires** a non-blank `refusal_reason`
  (`catalog.py:1826-1828`), which must exceed 30 characters and start with
  `catalog.unsupported` (or `k8s.unsupported`)
  (`test_fault_catalog_exhaustive.py:725-733`).
- `catalog_only=False` **must not** carry a `refusal_reason`
  (`catalog.py:1830-1833`).
- `(maturity is EXPERIMENTAL) == catalog_only`
  (`test_fault_catalog_exhaustive.py:332`).
- A catalog-only fault must have **no** compensation template
  (`test_fault_catalog_all.py:259-272`).

### 1.4 Cross-family invariants

From `test_fault_catalog_exhaustive.py`:
`observable_effect` must be >8 chars (`:291-294`) · all members of a category
share one `failure_domain` (except `CONTAINER`) (`:787-794`) · at most 2
`verification_method`s per category (`:796-802`) · `K8S` category ⇒
`KUBERNETES_ENGINE` cap and only `{POD, K8S_NODE}` node kinds (`:804-812`) ·
`CRITICAL` risk ⇒ only `{POD, K8S_NODE}` (`:875-878`) · every category must have
≥1 catalog entry (`:784-785`).

## 2. Executor routing — `src/mayhem/agents/executors.py`

`executor_for(fault_id)` (`:3912`) resolves in strict precedence:

1. `runtime == KUBERNETES` → `k8s_executor_for`
2. `_FAULT_EXECUTOR_OVERRIDES[fault_id]` — exact id, set by
   `_register_fault_executor` (`:3863`)
3. first executor in `EXECUTORS` whose `supports(fault_id)` matches
4. `None` — and `None` makes the fault report as **catalog-only** in
   `infra/catalog_report.py:121-127`

`supports()` is an **exact prefix match** on `fault_id.split(".", 1)[0]`
(`:81-82`). Current claims:

| executor | prefixes |
| --- | --- |
| `ProcPauseExecutor` | `proc`, `process` |
| `PayloadExecutor` | `mem`, `cpu`, `fs`, `fd`, `load`, `fuzz` |
| `ToolExecutor` | `net`, `disk`, `container`, `node`, `http`, `app`, `db`, `dns`, `tls`, `clock`, `dependency` |
| `K8sExecutor` | `supports()` hard-overridden to `False` (`:384-389`) so it never wins container dispatch |

**Consequence:** a prefix owned by a *different* executor needs an explicit
override — that is why `cpu.throttle`, `fs.read_only`, and
`process.crash_loop` all have one (`:3875-3882`). A brand-new prefix routes to
`None`.

Test invariant (`test_runtime_execution_matrix.py:392-401`): every fault must be
owned by **either** its prefix **or** an override, never neither.

## 3. Compensation template — `src/mayhem/controller/compensation.py`

`template_for(fault_id)` is a flat dict lookup (`:2313`). No template ⇒
`compensated()` raises `InvariantViolationError("plan_uncompensated_fault")`
(`:2321-2327`) and the planner refuses the drill. The planner additionally
raises `plan_write_ahead_undo` if a template yields zero undo ops
(`planner.py:1183-1185`).

Enforced for every non-k8s active fault by `test_fault_catalog_all.py:257-285`.
There is currently **no slack**: `len(_TEMPLATES) == 55` equals the non-k8s
active catalog set exactly.

A template is two pure callables (`:596-615`):

```
undo:   (PlannedFault, tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]      # ≥1
verify: (PlannedFault, tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]  # ≥1
```

Both must be **total for every legal param set** — a template that raises makes
the fault unplannable. Three shapes:

| shape | `UndoOp` | used by |
| --- | --- | --- |
| payload | `op="payload.undo"`, args `payload` (python program), `marker`, `pid` | 14 ids via `_payload_undo_ops` (`:530-548`) |
| tool | `op=<name>`, args `inject_argv` + `undo_argv` (JSON `list[str]`), `pid` | 38 ids via `_tool_compensation_templates()` (`:2220-2301`) |
| signal | `op="signal.cont"`, args `pid` | `proc.pause` |

`VerifyProbe` (`domain/leases.py:55-62`): `probe` (`exec`/`tcp`/`http`/
`process`/`metric`/`file`), `args` (**values may be list/dict/bool**, unlike
`UndoOp.args` which is strictly `str→str`), `expect_present`.

Reversibility (`domain/faults.py:111-114`) is **metadata only** — it does not
relax this gate. Even `RECONCILED` faults carry a real template
(`process.stop` → `UndoOp(op="noop")` + a `process` probe with
`expect_present=False`, `compensation.py:69-94`).

## 4. Impact gate — `src/mayhem/agents/impact.py`

An id absent from **both** `REQUIREMENTS` (`:65`) and `_ENGINE_FAULTS` (`:136`)
falls through `gate_fault` to the `"no in-image tooling required"` default
(`:389-395`). Enforced by
`test_impact_gate.py:465-480` (`test_every_catalog_fault_is_classified_by_the_gate`).

`FaultRequirement` (`:43-62`): `bins`, `caps`, `need_root`, `host`. The seven
recurring shapes:

| shape | count | example |
| --- | --- | --- |
| `bins={"python"}` | 18 | `mem.exhaust` |
| `bins={"tc"}, caps={"NET_ADMIN"}` | 9 | `net.latency` |
| `bins={"iptables"}, caps={"NET_ADMIN"}` | 12 | `db.query_error` |
| `bins={"python","iptables"}, caps={"NET_ADMIN"}` | 2 | `http.upstream_timeout` |
| `bins={"sh"}, need_root=True` | 4 | `dns.nxdomain` |
| `bins={"kill"}` | 1 | `proc.pause` |
| `bins={"date"}, caps={"SYS_TIME"}` | 1 | `clock.skew` |

Three traps:

- A bin not in `_PROBE_BINS` (`:171-180`) is **never probed present**, so the
  fault is gated inert forever. `_PROBE_BINS` is `kill, tc, iptables, python,
  python3, date, sh` + the 6 package managers. **`ip` is not in it.**
- A cap not in `_CAP_BITS` (`:37-40`, currently only `NET_ADMIN=12` and
  `SYS_TIME=25`) makes `has_cap` return `False` unconditionally.
- A bin with no `_PM_PACKAGES` row (`:533-561`) is classified `manual` by
  `compile_requirements` (`:767-768`) and can never be auto-installed.

Catalog-only ids must be added to `_CATALOG_ONLY_FAULTS` (`:148-154`) or
`gate_fault` reports them as impact-possible — a silent contradiction. This set
currently has 3 entries while the catalog has 4 `catalog_only` ids (the `k8s.*`
one is intentionally excluded).

## 5. Tests that derive from `CATALOG`

These enumerate the catalog at collection time, so a new active non-k8s fault
is swept in automatically and fails until the fault is genuinely complete:

| file | what it enforces |
| --- | --- |
| `test_fault_catalog_exhaustive.py` | ~90 parametrized tests: shape, maturity metadata, param schema/bounds/type, catalog-only refusals, family cross-sections, coverage matrix |
| `test_fault_catalog_all.py` | `executor_for` and `template_for` non-`None` for every non-k8s active fault (`:228-272`); k8s faults route to `K8sExecutor` and have **no** template (`:246-288`) |
| `test_container_fault_matrix.py` | fault × 6 compose containers; undo ops must textually address the container (`:135-158`); `plan_drill` yields exactly one compensatable step (`:185-214`) |
| `test_runtime_execution_matrix.py` | prefix-or-override invariant (`:392-401`); per-family argv assertions; `can_apply` refusal strings |
| `test_impact_gate.py` | exhaustive gate classification (`:465-480`) |
| `test_fault_expansion_catalog.py` / `_container.py` | named ids, exact `target_kinds` sets, executor class, inject+undo both `.ok` |
| `test_capability_dashboard.py` | `summary["total"] == len(dashboard.rows)` |

Also: `test_m7_k8s.py:565-567` asserts `len(CATALOG) >= 33` (a floor, not a
snapshot); `build_coverage()` asserts `total == len(CATALOG)` and
`sum(by_risk.values()) == len(CATALOG)`.

**Param seeding:** any `required` param must be satisfiable by
`seeds_for()` (`test_container_fault_matrix.py:69-84`), which maps
`integer→1`, `duration→"5s"`, else `"test"`, with a small special-case map.
A new required enum or a string needing a specific value needs an entry there
**and** in the equivalent map in `test_runtime_execution_matrix.py`.

## 6. Docs

- `docs/fault-catalog/README.md:11-15` — the container/k8s expansion table
  (20 explicitly listed ids).
- `docs/fault-catalog/reliability-matrix.md:30-39` — family table; `:64` is the
  builder "definition of done" checklist. Note `:37` points at
  `docs/reference/fault-catalog.md`, **which does not exist**.
- `docs/README.md:24,36-37,55` — authority and inventory rows.
- `README.md` — inline ids at `:128,153,171-173,207,349,375,451`.
- `examples/testCase/mayhem.yaml` / `examples/k8s/mayhem.yaml` — every fault
  named there must resolve and every param must be known
  (`test_example_specs_yaml.py:68-81,180-191`).
- `test_documentation_consistency.py:41-51` — every relative markdown link in
  `README.md`, `CHANGELOG.md`, `docs/**`, `examples/**` must resolve on disk.
