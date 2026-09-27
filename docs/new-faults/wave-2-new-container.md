# Wave 2 — the 14 genuinely new container-lane faults

These are the ids from the 72 that no existing fault covers **and** for which
this codebase has a working substrate. Each one still needs all five registries
(see [contract-checklist.md](contract-checklist.md)).

Prerequisite: wave 1. Without it, `net.tcp_half_open` is ambiguous against
`net.partition`, `fs.corrupt` against `fs.read_only`, and `net.conn_exhaust`
against `db.connection_exhaust`.

## 2.1 Substrate recap

Three executor shapes exist, and every new fault picks exactly one:

| shape | executor | contract | how to add |
| --- | --- | --- | --- |
| **payload** | `PayloadExecutor` (`executors.py:269`) | one `UndoOp(op="payload.undo")` carrying a python program, a marker path, and a pid | add a branch to `_payload_source` (`compensation.py:198-499`) |
| **tool** | `ToolExecutor` (`executors.py:3777`) | one `UndoOp` with JSON `inject_argv` + `undo_argv`, tokens `@engine`/`@cont` | add a `_tool_template(...)` entry |
| **signal** | `ProcPauseExecutor` (`executors.py:106`) | `signal.cont` op, pid-addressed | rarely applicable |

All new ids below fall under prefixes **already claimed** by an executor, so
prefix routing works with no `_register_fault_executor` override — except
`process.*`, which is claimed by `ProcPauseExecutor` and would need an override
like `process.crash_loop` already has (`executors.py:3882`).

`REQUIREMENTS` entries: payload ids need `bins={"python"}`; tool ids using `ip`
need `bins={"ip"}, caps={"NET_ADMIN"}` — and note **`ip` is not in
`_PM_PACKAGES`** (`impact.py:533-561`), so it would land in `manual` and could
never be auto-installed. Either add an `_PM_PACKAGES` row for `ip`
(`iproute2` everywhere — it is the same package that provides `tc`) or use
`tc`-only argv. Adding the row is the right call: `tc` and `ip` ship together
in `iproute2`, and `_PM_PACKAGES["tc"]` already says so.

## 2.2 The 14, by substrate

### Payload family — 4 ids

A branch in `_payload_source`, `bins={"python"}`, `PayloadExecutor` (prefix
`process` needs an override; `fs` is already claimed).

| id | mechanism | params | notes |
| --- | --- | --- | --- |
| `process.thread_exhaust` | spawn threads until the target's thread limit | `threads: int = 512 [1, 65536]`, `hold_s: duration = "30s"` | needs an override: `process` prefix belongs to `ProcPauseExecutor` |
| `process.child_exhaust` | fork until the pid cgroup limit | `children: int = 256 [1, 4096]`, `hold_s: duration = "30s"` | bounded by the container's **pid cgroup**, not `RLIMIT_NPROC` — say so in `observable_effect` |
| `fs.corrupt` | write garbage into a file the app reads | `path: str` (required), `bytes: int = 4096 [16, 1048576]`, `seed: int = 1` | needs a **backup-and-restore** undo, not a marker kill: the payload copies the original to `<path>.mayhem-orig` first. This is the only payload fault that mutates pre-existing data, so the marker-lifecycle verify probe (`test ! -e <marker>`, `compensation.py:562-573`) is not sufficient — see below |
| `net.conn_exhaust` | hold ephemeral ports / fill the accept queue | `count: int = 512 [1, 8192]`, `mode: "ephemeral" \| "accept"` | reuses the `db.connection_exhaust` socket loop; differs by targeting local ports rather than a remote peer |

**`fs.corrupt` is the one payload fault that breaks the shared undo contract.**
`PayloadExecutor.undo` reads the pid from the marker and SIGKILLs the payload
process (`executors.py:284-297`). That is correct for a burner, but `fs.corrupt`
modifies a file that survives the process, so the undo must also restore the
backup. Two options:

- (a) add a `restore` field to the payload op that `PayloadExecutor.undo`
  executes after the kill — touches the shared executor, so it affects all 14
  payload faults; or
- (b) make the payload self-restoring on `SIGTERM` and route the undo through
  `ToolExecutor` with a `cp <path>.mayhem-orig <path>` argv pair instead.

Recommendation: **(b)**. Option (a) widens the blast radius of a shared
executor for one fault, and a `fs.*` id already has a `ToolExecutor` precedent
(`fs.read_only` is registered as an override at `executors.py:3881`).

### Tool family — 5 ids

A `_tool_template(...)` entry with an argv pair.

| id | mechanism | requirement | params |
| --- | --- | --- | --- |
| `net.interface_down` | `ip link set <dev> down` / undo `up` | `ip` + `NET_ADMIN` | `device: str = "eth0"` |
| `net.mtu_mismatch` | `ip link set <dev> mtu <n>` / undo restore | `ip` + `NET_ADMIN` | `device: str = "eth0"`, `mtu: int = 1400 [576, 9216]` |
| `net.tcp_half_open` | `iptables -p tcp --tcp-flags SYN,ACK SYN -j DROP` | `iptables` + `NET_ADMIN` | `port: int` (required), `direction: "egress" \| "ingress"` |
| `http.response_truncate` | proxy emits `Content-Length: N` then closes after `bytes` | `python` + `iptables` + `NET_ADMIN` | `port: int = 80`, `bytes: int = 64 [0, 1048576]`, `probability: pct = 100` |
| `http.header_inject` | proxy adds caller-supplied headers | same | `port: int = 80`, `headers: str = ""`, `probability: pct = 100` |

`net.interface_down` and `net.mtu_mismatch` reuse the in-container `ip link`
capability already proven by `_direction()`'s ingress path
(`compensation.py:735-749`), which runs
`ip link add ifb0 type ifb; ip link set ifb0 up; …; ip link del ifb0`
in-container under `NET_ADMIN`. Same tool class, same capability.

`net.tcp_half_open` requires extending the netfilter builder, which today
emits only `REJECT`/`DROP` on `--dport` (`_netfilter_undo`,
`compensation.py:1154-1178`). Adding a `--tcp-flags` match is a small,
well-contained extension and the undo/delete path already exists.

### Proxy modes — 4 ids

All four extend the one application-level mechanism the repo has: the
hand-rolled in-container passthrough proxy `_http_proxy_source`
(`compensation.py:1402-1500`), installed via
`iptables -t nat -A OUTPUT … -j REDIRECT`. It is real and undo-tested, but
`_HttpEffect` supports **exactly three modes**: canned `status`, pre-relay
`delay_ms`, and token-bucket `rate`.

| id | new mode | difficulty |
| --- | --- | --- |
| `http.response_truncate` | `canned()` honours a declared `Content-Length` and closes early | low — `canned()` already writes the header block |
| `http.header_inject` | `canned()` emits caller-supplied headers | low |
| `dependency.circuit_open` | short-circuit: answer without dialling upstream | low — `forward(c)` always dials today; add a mode that skips it |
| `dependency.response_truncate` | same as `http.response_truncate`, `dependency.`-routed | low, once the mode exists |
| `http.stream_stall` | relay stalls **mid-flight** in one direction | ~~**high** — needs a bidirectional relay~~ **CORRECTED: this premise was wrong.** See below. |

#### Correction: `http.stream_stall` was never blocked

The table above originally called this fault **high** difficulty on the stated
ground that "the current one-shot `relay()` pair" could not express a mid-flight
stall. **That premise is false.** `relay()` is a chunked, bidirectional,
two-thread pump:

```python
def relay(a, b):
    while True:
        d = a.recv(65536)  # 64 KiB chunks, not read-whole-response
        if not d:
            break
        b.sendall(d)
```

and `forward()` already spawns one thread per direction. The first chunk of a
normal HTTP response is the status line and headers, so "headers flushed, then
silence" is exactly a one-shot sleep on the **client-bound** thread after its
first `sendall` — about six lines, and the one-sided behaviour falls out of the
existing two-thread design for free. No new concurrency, no new lifecycle, and
the undo story is unchanged (SIGTERM on the proxy reaps the parked thread and
every socket).

**It shipped, and it is verified on the wire.**
`tests/unit/test_http_proxy_wire.py` runs the generated program against real
sockets and measures the gap between the head arriving and the body arriving,
with and without a stall:

```
  no stall  : head+AAA@ 0.01s   BBB@ 1.02s
  stall 8s  : head+AAA@ 0.02s   BBB@ 8.03s
```

Two things this exercise caught that no structural assertion would have:

- `forward()` called `relay()` with three arguments while `relay()` still took
  two. It compiled, passed every shape assertion, and would have raised
  `TypeError` inside a container at injection time. **Executing the generated
  program is the only thing that catches this class of error.**
- The stall gates the *next* chunk, so a chunk already in flight upstream waits
  only the remainder of the window. An earlier assertion expected a flat
  `stall_ms` offset and was simply wrong about the mechanism.

The `catalog_only` fallback below is therefore **not needed** and no
`refusal_reason` was added.

## 2.3 Per-fault registry work

For each id, all five items in [contract-checklist.md](contract-checklist.md):

- `catalog.py` — `_define(...)` with `id`, `category`, `risk`,
  `required_caps`, `applicable_node_kinds`, `max_duration_s`, `params_schema`.
  `_define` infers `failure_domain`, `observable_effect`,
  `verification_method`, `reversibility`, `target_kind(s)`, `engine_lanes`, and
  `compensation_evidence` from the category and `reversible` flag, so those are
  usually omitted.
- `executors.py` — nothing for `fs`/`net`/`http`/`dependency` (prefix already
  claimed). An override for `process.thread_exhaust` and
  `process.child_exhaust`, and for `fs.corrupt` if wave-2.2's option (b) is
  taken.
- `compensation.py` — a payload branch or a `_tool_template` entry.
- `impact.py` — a `REQUIREMENTS` entry. `bins={"python"}` for payload ids;
  `bins={"ip"}, caps={"NET_ADMIN"}` for the `ip link` ids, **after** adding the
  `ip` row to `_PM_PACKAGES`.
- tests — see below.

## 2.4 Risk and duration caps

`tests/unit/test_fault_catalog_exhaustive.py` enforces:

- `risk in {HIGH, CRITICAL}` ⇒ `max_duration_s <= 600.0` (`:870-873`)
- `risk is CRITICAL` ⇒ `applicable_node_kinds <= {POD, K8S_NODE}` (`:875-878`)
  — so **no container-lane fault may be CRITICAL**
- every non-`catalog_only` fault must be `VERIFIED_UNIT` with a
  `verification_date` (`:346`), which `_define` sets automatically

Suggested assignment: `net.interface_down`, `net.tcp_half_open`,
`net.conn_exhaust`, `fs.corrupt` ⇒ `HIGH`. `net.mtu_mismatch`,
`http.response_truncate`, `http.header_inject`, `http.stream_stall`,
`dependency.circuit_open`, `dependency.response_truncate` ⇒ `MEDIUM`.
`process.thread_exhaust`, `process.child_exhaust` ⇒ `HIGH`.

All are `reversible=True` ⇒ `Reversibility.REVERSIBLE` and
`compensation_evidence = ("undo operation", "verification probe")` by default,
which is what the compensation contract requires.

## 2.5 Tests

Because the matrices are **derived from `CATALOG`**, new ids are swept in
automatically and these will fail until the fault is genuinely complete:

- `test_fault_catalog_exhaustive.py` — every `TestCatalogShape` and
  `TestMaturityMetadata` invariant, plus `test_container_faults_and_k8s_faults_partition_the_active_catalog`
  (`:880-885`).
- `test_fault_catalog_all.py` — `executor_for(fid) is not None` and
  `template_for(fid) is not None` for every non-k8s active fault (`:228-272`).
- `test_container_fault_matrix.py` — 6 compose containers × the new fault; undo
  ops must textually address the container (`:135-158`).
- `test_runtime_execution_matrix.py` — the prefix-or-override invariant
  (`:392-401`) and per-family argv assertions.
- `test_example_specs_yaml.py` — only if the ids are added to
  `examples/testCase/mayhem.yaml`.
- `test_impact_gate.py` — `test_every_catalog_fault_is_classified_by_the_gate`
  (`:465-480`) fails for any id missing from `REQUIREMENTS`/`_ENGINE_FAULTS`.

New targeted tests worth writing:

1. `fs.corrupt` restores the original file content byte-for-byte after undo.
2. `net.interface_down` undo re-links the device **and** the verify probe fails
   loudly if the device name does not exist (a typo'd `device` param would
   otherwise pass silently).
3. `net.tcp_half_open` inject and undo argv both carry `--tcp-flags`.
4. Each new proxy mode produces the expected bytes on the wire.
5. `process.thread_exhaust` and `process.child_exhaust` leave no surviving
   threads/children after undo (the marker-kill guarantee).
