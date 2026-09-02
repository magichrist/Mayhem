"""Compensation synthesis — undo ops and verify probes decided at plan time.

The planner refuses any fault it cannot compensate for: a plan without a
write-ahead undo contract never leaves the planner. Templates are keyed by
fault prefix and may inspect resolved nodes.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from mayhem.domain.common import parse_duration
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.topology import NodeKind, ProcessNode

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.domain.experiments import PlannedFault
    from mayhem.domain.topology import TopologyNode

NO_UNDO = InvariantViolationError("undo_template_missing", "no compensation template")


def _first_process(nodes: tuple[TopologyNode, ...]) -> ProcessNode | None:
    for node in nodes:
        if node.kind is NodeKind.PROCESS and isinstance(node, ProcessNode):
            return node
    return None


# PID placeholder resolved to the live value at execution time (ADR-0020). The
# value encodes the node_id so substitution can target the right container.
_LIVE_PID = "@live-pid"


def _pid_arg(node: TopologyNode) -> str:
    """Return the PID arg for an undo/verify op, using the live placeholder."""
    if getattr(node, "container_name", None):
        return f"{node.id}:{_LIVE_PID}"
    return str(getattr(node, "pid", 0))


def _proc_pause_undo(nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    proc = _first_process(nodes)
    if proc is None:
        raise NO_UNDO
    return (UndoOp(op="signal.cont", args={"pid": _pid_arg(proc)}),)


def _proc_pause_verify(nodes: tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]:
    proc = _first_process(nodes)
    if proc is None:
        raise NO_UNDO
    pid = _pid_arg(proc)
    return (
        VerifyProbe(
            probe="exec",
            args={"cmd": ["ps", "-p", pid], "timeout_s": "5"},
            expect_present=True,
        ),
    )


_SENTINEL = object()


def _param(fault: PlannedFault, name: str, default: object) -> object:
    """Resolve a fault parameter (validated at plan time) or a fallback."""
    value = fault.params.get(name, _SENTINEL)
    if value is _SENTINEL or value is None:
        return default
    return value


def _fparam(fault: PlannedFault, name: str, default: float) -> float:
    """Coerce a validated param to float (params deserialize from YAML scalars)."""
    raw = _param(fault, name, default)
    return default if not isinstance(raw, (int, float)) else float(raw)


def _iparam(fault: PlannedFault, name: str, default: int) -> int:
    """Coerce a validated param to int (params deserialize from YAML scalars)."""
    raw = _param(fault, name, default)
    return default if not isinstance(raw, (int, float)) else int(raw)


def _fault_duration_s(fault: PlannedFault, default: float = 30.0) -> float:
    """Fault window in seconds (planned faults may carry a ``10s`` string)."""
    raw = fault.duration
    if isinstance(raw, str):
        try:
            return parse_duration(raw)
        except (TypeError, ValueError):
            return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _payload_marker(fault: PlannedFault, node: TopologyNode) -> str:
    tag = re.sub(r"[^A-Za-z0-9_-]", "-", f"{fault.fault_id}.{node.id}")
    return f"/tmp/mayhem.{tag}.pid"


def _payload_source(fault: PlannedFault, marker: str) -> str:
    """Python payload that produces a *real* effect inside the target container.

    The payload is executed with ``python -c <source>`` from a detached engine
    exec (``podman/docker exec -d``), so it lives inside the container's pid and
    network namespaces and holds the fault in force until the undo op SIGKILLs
    it. Markers let undo and the effect probe detect the payload deterministically.
    """
    fid = fault.fault_id
    header = f"import os, time\nopen({marker!r}, 'w').write(str(os.getpid()))\n"
    # Payloads holding a fault in force until the undo op SIGKILLs the marker
    # pid must keep the interpreter alive once their threads are spawned —
    # otherwise ``python -c`` hits EOF, the daemon threads are killed at
    # interpreter shutdown, and the effect evaporates within milliseconds.
    _HOLD = "while True:\n    time.sleep(3600)\n"
    if fid == "mem.exhaust":
        amount = _fparam(fault, "amount", 0.0)
        percent = min(_fparam(fault, "percent", 60.0), 99.0)
        return header + (
            # Balloon anonymous memory to the explicit ``amount`` bytes (e.g.
            # ``256M``), or to ``percent`` of the container's cgroup memory
            # limit (falling back to the node's available RAM). An explicit
            # amount is capped at 95% of a real cgroup limit so the run can
            # never OOM-kill the whole container. Pages stay resident and the
            # payload stays alive until the undo op SIGKILLs its marker pid.
            f"amount = {amount:.0f}\n"
            f"percent = {percent:g}\n"
            "try:\n"
            "    f = open('/sys/fs/cgroup/memory.max'); lim = int(f.read().strip()); f.close()\n"
            "except Exception:\n"
            "    lim = 0\n"
            "goal = amount if amount > 0 else (\n"
            "    lim * percent / 100 if 0 < lim < 10 ** 14 else (\n"
            "        os.sysconf('SC_AVPHYS_PAGES') * os.sysconf('SC_PAGE_SIZE') * percent / 100))\n"
            "if 0 < lim < 10 ** 14:\n"
            "    goal = min(goal, lim * 95 // 100)\n"
            "chunks = []\n"
            "while sum(map(len, chunks)) < goal:\n"
            "    try:\n"
            "        chunks.append(bytearray(4 * 2 ** 20))\n"
            "    except MemoryError:\n"
            "        break\n"
            "    time.sleep(0.02)\n"
            "while True:\n"
            "    time.sleep(3600)\n"
        )
    if fid == "cpu.saturate":
        percent = min(_fparam(fault, "percent", 80.0), 100.0)
        return header + (
            # Pin ``percent`` of the container's visible cores. A pure-Python
            # arithmetic loop is GIL-bound to a single core no matter how many
            # threads run, so the burner spins the OpenSSL-backed ``hashlib`` in
            # each thread instead — C work that releases the GIL, letting N
            # threads genuinely saturate N cores. Undo stays intact: SIGKILLing
            # the marker pid kills every burner thread with the process.
            "import threading, hashlib\n"
            "def burn():\n"
            "    buf = bytes(64 * 1024)\n"
            "    while True:\n"
            "        hashlib.sha256(buf).digest()\n"
            f"n = max(1, (os.cpu_count() or 1) * {percent:g} // 100)\n"
            "for _ in range(n):\n"
            "    threading.Thread(target=burn, daemon=True).start()\n" + _HOLD
        )
    if fid == "fs.fill":
        percent = min(_fparam(fault, "percent", 45.0), 99.0)
        capped = 1024**3
        return header + (
            # Fill the container's filesystem to ``percent`` of total capacity,
            # but never beyond a 1 GiB absolute cap so an e2e run cannot fill the
            # podman VM's root disk. The damage target is real: the service's own
            # writable layer (and any other process writing to this filesystem)
            # loses exactly the filled space until undo reclaims it.
            "st = os.statvfs('/tmp')\n"
            "total = st.f_blocks * st.f_frsize\n"
            "free0 = st.f_bavail * st.f_frsize\n"
            "def usage():\n"
            "    s = os.statvfs('/tmp')\n"
            "    return 1 - s.f_bavail * s.f_frsize / (s.f_blocks * s.f_frsize)\n"
            f"goal = min({percent} / 100, (free0 + {capped}) / total)\n"
            "i = 0\n"
            "while usage() < goal:\n"
            "    try:\n"
            "        f = open(marker + '.' + str(i), 'ab')\n"
            "        f.write(b'\\0' * (1 << 20))\n"
            "        f.close()\n"
            "    except OSError:\n"
            "        time.sleep(0.3)\n"
            "    i += 1\n" + _HOLD
        )
    if fid == "fd.exhaust":
        limit = max(_iparam(fault, "limit", 64), 1)
        return header + (
            f"opened = 0\n"
            "fds = []\n"
            f"while opened < {limit}:\n"
            "    try:\n"
            "        fds.append(open('/dev/null'))\n"
            "    except OSError:\n"
            "        break\n"
            "    opened += 1\n"
            "try:\n"
            f"    open({marker!r} + '.count', 'w').write(str(opened))\n"
            "except Exception:\n"
            "    pass\n" + _HOLD
        )
    if fid == "load.spike":
        seconds = min(_fparam(fault, "seconds", 8.0), 60.0)
        concurrency = max(_iparam(fault, "rps", 60) // 50, 1)
        return header + (
            # Push real request traffic at the service's listening port so the
            # server's thread pool / event loop actually contends.
            "import socket\n"
            "port = 8000\n"
            "try:\n"
            "    for line in open('/proc/net/tcp').read().splitlines()[1:]:\n"
            "        p = line.split()\n"
            "        if len(p) > 1 and p[3] == '0A' and p[1].split(':')[1] != '0000':\n"
            "            port = int(p[1].split(':')[1], 16)\n"
            "            break\n"
            "except Exception:\n"
            "    pass\n"
            f"end = time.time() + {seconds}\n"
            "def blast():\n"
            "    while time.time() < end:\n"
            "        try:\n"
            "            s = socket.create_connection(('127.0.0.1', port), timeout=1.5)\n"
            "            s.sendall(b'GET / HTTP/1.1\\r\\n\\r\\n')\n"
            "            s.close()\n"
            "        except OSError:\n"
            "            pass\n"
            "import threading\n"
            f"for _ in range({concurrency}):\n"
            "    threading.Thread(target=blast, daemon=True).start()\n" + f"time.sleep({seconds})\n"
        )
    if fid == "fuzz.protocol_abuse":
        seconds = min(_fparam(fault, "seconds", 8.0), 60.0)
        return header + (
            # Send malformed / hostile HTTP candidates at the service port. The
            # server must parse them; the giant header and binary garbage force
            # real parser work and rejected requests.
            "import socket\n"
            "port = 8000\n"
            "try:\n"
            "    for line in open('/proc/net/tcp').read().splitlines()[1:]:\n"
            "        p = line.split()\n"
            "        if len(p) > 1 and p[3] == '0A' and p[1].split(':')[1] != '0000':\n"
            "            port = int(p[1].split(':')[1], 16)\n"
            "            break\n"
            "except Exception:\n"
            "    pass\n"
            "payloads = (\n"
            "    b'\\x00\\xff\\x80\\r\\n',\n"
            "    b'GET / HTTP/1.1\\r\\nX-A: ' + b'a' * 100000 + b'\\r\\n\\r\\n',\n"
            "    b'\\xff' * 65536,\n"
            "    b'POST / HTTP/1.1\\r\\nContent-Length: -1\\r\\n\\r\\n',\n"
            "    b'GET ../../etc/passwd HTTP/1.1\\r\\n\\r\\n',\n"
            ")\n"
            f"end = time.time() + {seconds}\n"
            "def abuse():\n"
            "    i = 0\n"
            "    while time.time() < end:\n"
            "        try:\n"
            "            s = socket.create_connection(('127.0.0.1', port), timeout=1.5)\n"
            "            s.sendall(payloads[i % len(payloads)])\n"
            "            try:\n"
            "                s.recv(1)\n"
            "            except OSError:\n"
            "                pass\n"
            "            s.close()\n"
            "        except OSError:\n"
            "            pass\n"
            "        i += 1\n"
            "import threading\n"
            "for _ in range(4):\n"
            "    threading.Thread(target=abuse, daemon=True).start()\n" + f"time.sleep({seconds})\n"
        )
    raise NO_UNDO  # pragma: no cover - only reachable for unregistered payloads


# ``` needs `import time` for the loops that reference ``time``.
_PAYLOAD_IMPORTS = "import os, time\n"


def _payload_node(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> TopologyNode | None:
    """Pick the engine address for a payload fault: the first node that carries a
    container_name — a live container, its process, or the compose service
    (blueprint-only topology) — since payload inject/undo/verify all run through
    the container engine (ADR-0020)."""
    from mayhem.domain.topology import (  # noqa: PLC0415
        ContainerNode,
        ProcessNode,
        ServiceNode,
    )

    node: TopologyNode | None = next(
        (
            n
            for n in nodes
            if isinstance(n, (ContainerNode, ProcessNode)) and getattr(n, "container_name", None)
        ),
        None,
    )
    if node is None:
        node = next(
            (n for n in nodes if isinstance(n, ServiceNode) and getattr(n, "container_name", None)),
            None,
        )
    return node


def _payload_undo_ops(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Compensation for payload-family faults: SIGKILL the injected process and
    remove its marker files. Reversible by construction (marker-addressed undo)."""
    node = _payload_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _payload_marker(fault, node)
    src = _PAYLOAD_IMPORTS + _payload_source(fault, marker)
    return (
        UndoOp(
            op="payload.undo",
            args={
                "fault": fault.fault_id,
                "payload": src,
                "marker": marker,
                "pid": _pid_arg(node),  # node_id:@live-pid -> cont/engine at exec
            },
        ),
    )


def _payload_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    """Recovery evidence for payload-family faults: the marker file must be gone
    after undo (undo SIGKILLs the marker pid and deletes the marker). Addressed
    through the same container engine path as the undo op (ADR-0020), so the
    probe only passes once the payload's in-container effects were removed."""
    node = _payload_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _payload_marker(fault, node)
    return (
        VerifyProbe(
            probe="exec",
            args={
                "cmd": ["sh", "-c", f"test ! -e {marker}"],
                "incontainer": True,
                "pid": _pid_arg(node),
                "timeout_s": "5",
            },
            expect_present=True,
        ),
    )


_PAYLOAD_FAULTS = frozenset(
    {
        "mem.exhaust",
        "cpu.saturate",
        "fs.fill",
        "fd.exhaust",
        "load.spike",
        "fuzz.protocol_abuse",
    }
)


class CompensationTemplate:
    """Undo/verify factory pair for one fault family.

    ``build(fault, nodes)`` receives the planned fault (params, duration) and
    the compensation node pool (matched targets + connected processes), so
    templates can parameterize the undo contract by fault params.
    """

    def __init__(
        self,
        undo: Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]],
        verify: Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]],
    ) -> None:
        self._undo = undo
        self._verify = verify

    def build(
        self, fault: PlannedFault, nodes: tuple[TopologyNode, ...]
    ) -> tuple[tuple[UndoOp, ...], tuple[VerifyProbe, ...]]:
        return self._undo(fault, nodes), self._verify(fault, nodes)


def _ignores_fault(
    undo: Callable[[tuple[TopologyNode, ...]], tuple[UndoOp, ...]],
    verify: Callable[[tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]],
) -> CompensationTemplate:
    return CompensationTemplate(
        lambda _fault, nodes: undo(nodes), lambda _fault, nodes: verify(nodes)
    )


def _payload_compensation_templates() -> dict[str, CompensationTemplate]:
    return dict.fromkeys(
        sorted(_PAYLOAD_FAULTS),
        CompensationTemplate(_payload_undo_ops, _payload_verify),
    )


# ---------------------------------------------------------------------------
# Tool compensation — argv-pair faults driven by :class:`ToolExecutor`.
#
# Each family emits exactly one undo op whose args carry ``inject_argv`` /
# ``undo_argv`` (JSON list[str]) plus a ``node_id:@live-pid`` placeholder so the
# live substitute appends the container address (``cont``/``engine``). The argv
# pairs embed ``@engine`` / ``@cont`` tokens that :class:`ToolExecutor` rewrites
# to the live engine + container at execution time (ADR-0020). Verify probes are
# the payload style: an in-container command that must exit 0 after undo, or an
# engine-inspect presence check when the fault stops the container.
# ---------------------------------------------------------------------------

_ENGINE_TOKEN = "@engine"
_CONTAINER_TOKEN = "@cont"


def _tool_node(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> TopologyNode | None:
    """Engine address for an argv-pair fault: same as the payload selection."""
    return _payload_node(fault, nodes)


def _tool_marker(fault: PlannedFault, node: TopologyNode, suffix: str) -> str:
    tag = re.sub(r"[^A-Za-z0-9_-]", "-", f"{fault.fault_id}.{node.id}")
    return f"/tmp/mayhem.{tag}.{suffix}"


def _tool_op(
    fault: PlannedFault,
    node: TopologyNode,
    name: str,
    inject_argv: list[str],
    undo_argv: list[str],
) -> UndoOp:
    return UndoOp(
        op=name,
        args={
            "fault": fault.fault_id,
            "inject_argv": json.dumps(inject_argv),
            "undo_argv": json.dumps(undo_argv),
            "pid": _pid_arg(node),  # node_id:@live-pid -> cont/engine at execution
        },
    )


def _exec_verify(
    node: TopologyNode, cmd: list[str], *, incontainer: bool, timeout_s: str = "5"
) -> VerifyProbe:
    args: dict[str, object] = {"cmd": cmd, "pid": _pid_arg(node), "timeout_s": timeout_s}
    if incontainer:
        args["incontainer"] = True
    return VerifyProbe(probe="exec", args=args, expect_present=True)


def _incontainer_argv(cmd: list[str]) -> list[str]:
    return [_ENGINE_TOKEN, "exec", _CONTAINER_TOKEN, *cmd]


def _engine_argv(action: str) -> list[str]:
    return [_ENGINE_TOKEN, action, _CONTAINER_TOKEN]


def _tool_template(
    undo: Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]],
    verify: Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]],
) -> CompensationTemplate:
    return CompensationTemplate(undo, verify)


def _net_latency_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    delay_ms = _iparam(fault, "seconds", 5) * 1000
    jitter_ms = _iparam(fault, "jitter_ms", 0)
    inject = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", f"{delay_ms}ms"]
    if jitter_ms > 0:
        inject += [f"{jitter_ms}ms"]
    undo = ["tc", "qdisc", "del", "dev", "eth0", "root"]
    return (
        _tool_op(fault, node, "tc.del_qdisc", _incontainer_argv(inject), _incontainer_argv(undo)),
    )


def _net_latency_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return (
        _exec_verify(
            node, ["sh", "-c", "! tc qdisc show dev eth0 | grep -q netem"], incontainer=True
        ),
    )


def _net_partition_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    inject = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%"]
    undo = ["tc", "qdisc", "del", "dev", "eth0", "root"]
    return (
        _tool_op(fault, node, "tc.del_qdisc", _incontainer_argv(inject), _incontainer_argv(undo)),
    )


def _net_partition_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return (
        _exec_verify(
            node, ["sh", "-c", "! tc qdisc show dev eth0 | grep -q netem"], incontainer=True
        ),
    )


def _net_load_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Saturate container egress with a deterministic k6 HTTP load generator.

    The k6 script is written under the marker path (so the verify probe can see
    the fault while it is live), then ``k6 run`` is detached inside the
    container's pid namespace. Undo SIGKILLs the recorded k6 pid and removes
    both marker files, so recovery, undo and the impact probe agree.
    """
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    users = max(1, _iparam(fault, "users", 1))
    url = str(_param(fault, "url", "http://localhost/"))
    url = url.replace("\\", "\\\\").replace('"', '\\"')
    duration_s = max(1, int(_fault_duration_s(fault)))
    script = _tool_marker(fault, node, "load.js")
    pidfile = _tool_marker(fault, node, "k6.pid")
    source = (
        f"cat > {script} <<'K6EOF'\n"
        "import http from 'k6/http';\n"
        "export default function () {\n"
        f'  http.get("{url}");\n'
        "}\n"
        "K6EOF\n"
        f"k6 run -u {users} -d {duration_s}s {script} >/dev/null 2>&1 &\n"
        f"echo $! > {pidfile}\n"
        f'[ -s {pidfile} ] && kill -0 "$(cat {pidfile})" 2>/dev/null && exit 0\n'
        "exit 1\n"
    )
    undo = [
        "sh",
        "-c",
        f'p={pidfile}; [ ! -f "$p" ] || kill "$(cat "$p")" 2>/dev/null; rm -f "$p" {script}',
    ]
    return (
        _tool_op(
            fault,
            node,
            "k6.sync",
            _incontainer_argv(["sh", "-c", source]),
            _incontainer_argv(undo),
        ),
    )


def _net_load_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    script = _tool_marker(fault, node, "load.js")
    pidfile = _tool_marker(fault, node, "k6.pid")
    return (
        _exec_verify(
            node,
            ["sh", "-c", f"test ! -e {script} && test ! -e {pidfile}"],
            incontainer=True,
        ),
    )


def _engine_restart_undo(
    inject_action: str, undo_action: str
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        return (
            _tool_op(
                fault,
                node,
                "engine.restart",
                _engine_argv(inject_action),
                _engine_argv(undo_action),
            ),
        )

    return build


def _engine_signal_undo(
    action: str, undo_action: str
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        sig = str(_param(fault, "signal", "SIGKILL"))
        if sig.startswith("SIG"):
            sig = sig[3:]
        inject = [_ENGINE_TOKEN, action, "--signal", sig, _CONTAINER_TOKEN]
        undo = [_ENGINE_TOKEN, undo_action, _CONTAINER_TOKEN]
        return (_tool_op(fault, node, "engine.restart", inject, undo),)

    return build


def _engine_restart_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return (_exec_verify(node, ["true"], incontainer=False),)


def _netfilter_undo(
    dport: str,
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        inject = [
            "iptables",
            "-I",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            dport,
            "-j",
            "DROP",
        ]
        undo = [
            "iptables",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            dport,
            "-j",
            "DROP",
        ]
        return (
            _tool_op(
                fault,
                node,
                "iptables.sync",
                _incontainer_argv(inject),
                _incontainer_argv(undo),
            ),
        )

    return build


def _http_error_inject() -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        inject = [
            "iptables",
            "-I",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
        undo = [
            "iptables",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
        return (
            _tool_op(
                fault,
                node,
                "iptables.sync",
                _incontainer_argv(inject),
                _incontainer_argv(undo),
            ),
        )

    return build


def _netfilter_verify(
    dport: str,
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        return (
            _exec_verify(
                node,
                ["sh", "-c", f"! iptables -S OUTPUT | grep -q -- '--dport {dport}'"],
                incontainer=True,
            ),
        )

    return build


def _http_error_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return (
        _exec_verify(
            node,
            ["sh", "-c", "! iptables -S OUTPUT | grep -q -- '--dport 80'"],
            incontainer=True,
        ),
    )


def _file_revert_undo(
    target: str, *ops: str
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    """Marker-addressed file swap: back up ``target``, then apply ``ops`` (lines
    of shell run in order). Undo restores the backup and removes the marker."""

    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        marker = _tool_marker(fault, node, "orig")
        inject = ["sh", "-c", f"cp {target} {marker}; " + "; ".join(ops)]
        undo = ["sh", "-c", f"mv -f {marker} {target}; rm -f {marker}"]
        return (
            _tool_op(
                fault,
                node,
                "file.revert",
                _incontainer_argv(inject),
                _incontainer_argv(undo),
            ),
        )

    return build


def _file_revert_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _tool_marker(fault, node, "orig")
    return (
        _exec_verify(
            node,
            ["sh", "-c", f"test ! -e {marker}"],
            incontainer=True,
        ),
    )


def _clock_skew_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _tool_marker(fault, node, "clock.orig")
    offset_ms = _iparam(fault, "offset_ms", 0)
    inject = [
        "sh",
        "-c",
        f"date -u '+%s' > {marker}; target=$(( $(cat {marker}) + {offset_ms} )); "
        f"date -u -s '@$target'",
    ]
    undo = [
        "sh",
        "-c",
        f'if [ -f {marker} ]; then date -u -s "@$(cat {marker})"; fi; rm -f {marker}',
    ]
    return (
        _tool_op(
            fault,
            node,
            "clock.restore",
            _incontainer_argv(inject),
            _incontainer_argv(undo),
        ),
    )


def _clock_skew_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _tool_marker(fault, node, "clock.orig")
    return (
        _exec_verify(
            node,
            ["sh", "-c", f"test ! -e {marker}"],
            incontainer=True,
        ),
    )


def _dns_nxdomain_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    target = "/etc/hosts"
    marker = _tool_marker(fault, node, "orig")
    domain = str(_param(fault, "domain", "example.com"))
    inject = ["sh", "-c", f"cp {target} {marker}; echo '127.0.0.1 {domain}' >> {target}"]
    undo = ["sh", "-c", f"mv -f {marker} {target}; rm -f {marker}"]
    return (
        _tool_op(
            fault,
            node,
            "file.revert",
            _incontainer_argv(inject),
            _incontainer_argv(undo),
        ),
    )


def _tool_compensation_templates() -> dict[str, CompensationTemplate]:
    return {
        "net.latency": _tool_template(_net_latency_undo, _net_latency_verify),
        "net.partition": _tool_template(_net_partition_undo, _net_partition_verify),
        "net.load": _tool_template(_net_load_undo, _net_load_verify),
        "container.kill": _tool_template(
            _engine_signal_undo("kill", "start"), _engine_restart_verify
        ),
        "node.service_stop": _tool_template(
            _engine_restart_undo("stop", "start"), _engine_restart_verify
        ),
        "http.error_injection": _tool_template(_http_error_inject(), _http_error_verify),
        "db.slow_query": _tool_template(
            _netfilter_undo("3306"),
            _netfilter_verify("3306"),
        ),
        "dns.resolve_delay": _tool_template(
            _file_revert_undo(
                "/etc/resolv.conf",
                "printf 'nameserver 10.255.255.1\\n' > /etc/resolv.conf",
            ),
            _file_revert_verify,
        ),
        "dns.nxdomain": _tool_template(_dns_nxdomain_undo, _file_revert_verify),
        "tls.certificate_expired": _tool_template(
            _file_revert_undo(
                "/etc/ssl/certs/ca-certificates.crt",
                ": > /etc/ssl/certs/ca-certificates.crt",
            ),
            _file_revert_verify,
        ),
        "clock.skew": _tool_template(_clock_skew_undo, _clock_skew_verify),
    }


_TEMPLATES: dict[str, CompensationTemplate] = {
    "proc.pause": _ignores_fault(_proc_pause_undo, _proc_pause_verify),
    **_payload_compensation_templates(),
    **_tool_compensation_templates(),
}


def template_for(fault_id: str) -> CompensationTemplate | None:
    return _TEMPLATES.get(fault_id)


def compensated(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> PlannedFault:
    """Return ``fault`` with undo/verify filled in; refuse uncompensatable faults."""
    if fault.undo_ops and fault.verify_probes:
        return fault
    tpl = template_for(fault.fault_id)
    if tpl is None:
        msg = (
            f"fault {fault.fault_id!r} has no compensation template; "
            f"planner refuses to emit an uncompensatable injection"
        )
        raise InvariantViolationError("plan_uncompensated_fault", msg)
    undo_ops, verify_probes = tpl.build(fault, nodes)
    return fault.model_copy(update={"undo_ops": undo_ops, "verify_probes": verify_probes})
