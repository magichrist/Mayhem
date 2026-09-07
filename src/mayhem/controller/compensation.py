"""Compensation synthesis — undo ops and verify probes decided at plan time.

The planner refuses any fault it cannot compensate for: a plan without a
write-ahead undo contract never leaves the planner. Templates are keyed by
fault prefix and may inspect resolved nodes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
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


def _process_term_undo(nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """process.stop / process.kill terminate the pid — nothing to undo.

    The single no-op op still carries the ``pid`` so the inject executor can
    resolve the target; undo itself performs no action (the pid is gone).
    """
    proc = _first_process(nodes)
    if proc is None:
        raise NO_UNDO
    return (UndoOp(op="noop", args={"pid": _pid_arg(proc)}),)


def _process_term_verify(nodes: tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]:
    proc = _first_process(nodes)
    if proc is None:
        raise NO_UNDO
    return (
        VerifyProbe(
            probe="process",
            args={"pid": _pid_arg(proc), "timeout_s": "5"},
            # Target must be gone after termination. The process probe treats
            # a zombie (terminated but un-reaped) as gone, so this stays true
            # even when the parent has not yet called wait().
            expect_present=False,
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


def _payload_source(fault: PlannedFault, marker: str) -> str:  # noqa: PLR0911
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
    _hold = "while True:\n    time.sleep(3600)\n"
    if fid == "mem.exhaust":
        amount = _fparam(fault, "amount", 0.0)
        percent = min(_fparam(fault, "percent", 60.0), 99.0)
        mode = str(_param(fault, "mode", "allocate")).strip().lower()
        if mode != "allocate":
            raise InvariantViolationError(
                "fault_mode", f"unsupported memory-exhaust mode {mode!r}; only 'allocate' exists"
            )
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
    if fid == "mem.leak":
        rate_mb = max(_iparam(fault, "rate_mb", 8), 1)
        return header + (
            # Leak a steady ``rate_mb`` MiB/s (one bytearray per second). The
            # list holds each allocation forever, so the payload's RSS climbs
            # lineally until the undo op SIGKILLs it; the loop is the hold, and
            # the marker pid detaches undo from the allocator thread.
            f"_chunk = bytearray({rate_mb} * 1024 * 1024)\n"
            "_grow = []\n"
            "try:\n"
            "    while True:\n"
            "        _grow.append(_chunk)\n"
            "        time.sleep(1)\n"
            "except Exception:\n"
            "    pass\n"
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
            "    threading.Thread(target=burn, daemon=True).start()\n" + _hold
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
            "    i += 1\n" + _hold
        )
    if fid == "fs.inode_exhaust":
        percent = min(_fparam(fault, "percent", 50.0), 99.0)
        return header + (
            # Exhaust free inodes, not capacity: create zero-byte marker files
            # until ``percent`` of the filesystem's free inodes are consumed,
            # never beyond a hard count cap so an e2e run cannot brick the
            # podman VM's root filesystem. The filesystem is restored when undo
            # SIGKILLs the payload and removes the ``marker.*`` siblings, each
            # of which frees one inode.
            "st = os.statvfs('/tmp')\n"
            "free0 = st.f_ffree\n"
            "def used():\n"
            "    s = os.statvfs('/tmp')\n"
            "    return s.f_files - s.f_ffree\n"
            f"goal = min(free0 * {percent} / 100, 200000)\n"
            "i = 0\n"
            "while used() - free0 < goal:\n"
            "    try:\n"
            "        open(marker + '.' + str(i), 'w').close()\n"
            "    except OSError:\n"
            "        time.sleep(0.3)\n"
            "    i += 1\n" + _hold
        )
    if fid == "fs.io_stress":
        workers = max(_iparam(fault, "workers", 1), 1)
        io_bytes = _fparam(fault, "io_bytes", 64.0 * 1024 * 1024)
        read_mb_s = _iparam(fault, "read_mb_s", 0)
        write_mb_s = _iparam(fault, "write_mb_s", 0)
        if read_mb_s or write_mb_s:
            # Spec twin (fs.io_stress): sustained read()/write() throughput on
            # twin marker working files (``marker.rN``/``marker.wN``) paced to
            # ``read_mb_s``/``write_mb_s`` per worker. Files are marker siblings,
            # so undo removes them with the payload pid via the ``marker.*`` glob.
            rd = max(read_mb_s, 0) * 1024 * 1024
            wr = max(write_mb_s, 0) * 1024 * 1024
            return header + (
                "import threading\n"
                f"rd = {rd}\n"
                f"wr = {wr}\n"
                "blk = 65536\n"
                "def pace(r):\n"
                "    return (blk / r) if r > 0 else 0.0\n"
                "def reader(w):\n"
                "    p = marker + '.r' + str(w)\n"
                "    try:\n"
                "        f = open(p, 'wb'); f.truncate(64 * 1024 * 1024); f.close()\n"
                "        with open(p, 'rb') as f:\n"
                "            while True:\n"
                "                if not f.read(blk):\n"
                "                    f.seek(0)\n"
                "                    continue\n"
                "                time.sleep(pace(rd))\n"
                "    except OSError:\n"
                "        pass\n"
                "def writer(w):\n"
                "    p = marker + '.w' + str(w)\n"
                "    try:\n"
                "        with open(p, 'wb') as f:\n"
                "            while True:\n"
                "                f.write(os.urandom(blk))\n"
                "                f.flush()\n"
                "                time.sleep(pace(wr))\n"
                "    except OSError:\n"
                "        pass\n"
                f"if rd > 0:\n"
                f"    for w in range({workers}):\n"
                "        threading.Thread(target=reader, args=(w,), daemon=True).start()\n"
                f"if wr > 0:\n"
                f"    for w in range({workers}):\n"
                "        threading.Thread(target=writer, args=(w,), daemon=True).start()\n" + _hold
            )
        return header + (
            # Bound I/O churn: ``workers`` writers hammer their marker working
            # file (``marker.wN``) with buffered 64 KiB writes, looping once the
            # per-worker ``io_bytes`` budget is spent (truncate + rewind so the
            # write stays bounded). Working files are marker siblings, so undo
            # removes them with the payload pid via the ``marker.*`` glob.
            "import threading\n"
            f"total = min({io_bytes:.0f}, 1024 ** 3)\n"
            "def writer(w):\n"
            "    written = 0\n"
            "    f = open(marker + '.w' + str(w), 'wb')\n"
            "    try:\n"
            "        while True:\n"
            "            f.write(os.urandom(65536))\n"
            "            f.flush()\n"
            "            written += 65536\n"
            "            if written >= total:\n"
            "                f.truncate(0)\n"
            "                f.seek(0)\n"
            "                written = 0\n"
            "    except OSError:\n"
            "        pass\n"
            "    finally:\n"
            "        f.close()\n"
            f"for w in range({workers}):\n"
            "    threading.Thread(target=writer, args=(w,), daemon=True).start()\n" + _hold
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
            "    pass\n" + _hold
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
        "mem.leak",
        "cpu.saturate",
        "fs.fill",
        "fs.inode_exhaust",
        "fs.io_stress",
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
    tail = ["netem", "delay", f"{delay_ms}ms"]
    if jitter_ms > 0:
        tail.append(f"{jitter_ms}ms")
    return _tc_qdisc_undo(fault, node, tail)


def _net_latency_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return _tc_qdisc_verify(fault, node, "netem")


# ── Direction-aware tc qdisc infra (egress / ingress / both) ──────────────
#
# tc cannot shape inbound traffic directly; standard practice is to mirror the
# container's egress into an ``ifb`` device and attach the qdisc there. The
# ``both`` direction composes both paths in one inject. Undo removes exactly
# the devices/qdiscs this fault added (net_admin scope), so a drill never
# leaves a queue discipline behind: egress delete, ifb + ingress teardown.

_EGRESS_DEV = "eth0"
_IFB_DEV = "ifb0"
_DIRECTIONS = frozenset({"egress", "ingress", "both"})

_INGRESS_SETUP = (
    f"ip link add {_IFB_DEV} type ifb 2>/dev/null; "
    f"ip link set {_IFB_DEV} up; "
    f"tc qdisc del dev {_EGRESS_DEV} ingress 2>/dev/null; "
    f"tc qdisc add dev {_EGRESS_DEV} handle ffff: ingress; "
    f"tc filter add dev {_EGRESS_DEV} parent ffff: protocol ip u32 match u32 0 0 "
    f"action mirred egress redirect dev {_IFB_DEV}"
)

_INGRESS_UNDO = (
    f"tc qdisc del dev {_IFB_DEV} root 2>/dev/null; "
    f"tc qdisc del dev {_EGRESS_DEV} ingress 2>/dev/null; "
    f"ip link del {_IFB_DEV} 2>/dev/null"
)


def _direction(fault: PlannedFault, default: str = "egress") -> str:
    value = str(_param(fault, "direction", default)).strip().lower()
    if value not in _DIRECTIONS:
        raise InvariantViolationError(
            "fault_direction",
            f"unsupported net direction {value!r}; expected one of {sorted(_DIRECTIONS)}",
        )
    return value


def _tc_qdisc_undo(
    fault: PlannedFault, node: TopologyNode, qdisc_tail: list[str]
) -> tuple[UndoOp, ...]:
    """Build inject/undo for a root tc qdisc, honoring ``direction``.

    ``qdisc_tail`` is the ``tc qdisc add dev <dev> root <tail>`` argument list
    that follows the root keyword (e.g. ``["netem", "loss", "10%"]``).
    """
    direction = _direction(fault)
    egress_add = ["tc", "qdisc", "add", "dev", _EGRESS_DEV, "root", *qdisc_tail]
    ifb_add = ["tc", "qdisc", "add", "dev", _IFB_DEV, "root", *qdisc_tail]
    if direction == "egress":
        inject = egress_add
        undo = ["tc", "qdisc", "del", "dev", _EGRESS_DEV, "root"]
    elif direction == "ingress":
        inject = ["sh", "-c", f"{_INGRESS_SETUP}; {' '.join(ifb_add)}"]
        undo = ["sh", "-c", _INGRESS_UNDO]
    else:  # both
        inject = [
            "sh",
            "-c",
            f"{' '.join(egress_add)}; {_INGRESS_SETUP}; {' '.join(ifb_add)}",
        ]
        undo = ["sh", "-c", f"tc qdisc del dev {_EGRESS_DEV} root; {_INGRESS_UNDO}"]
    return (
        _tool_op(fault, node, "tc.del_qdisc", _incontainer_argv(inject), _incontainer_argv(undo)),
    )


def _tc_verify_cmd(fault: PlannedFault, qdisc_grep: str) -> str:
    direction = _direction(fault)
    if direction == "egress":
        return f"! tc qdisc show dev {_EGRESS_DEV} | grep -q {qdisc_grep}"
    if direction == "ingress":
        return f"! ip link show {_IFB_DEV} 2>/dev/null | grep -q {_IFB_DEV}"
    return (
        f"! tc qdisc show dev {_EGRESS_DEV} | grep -q {qdisc_grep} "
        f"&& ! ip link show {_IFB_DEV} 2>/dev/null | grep -q {_IFB_DEV}"
    )


def _tc_qdisc_verify(
    fault: PlannedFault, node: TopologyNode, qdisc_grep: str
) -> tuple[VerifyProbe, ...]:
    return (
        _exec_verify(
            node,
            ["sh", "-c", _tc_verify_cmd(fault, qdisc_grep)],
            incontainer=True,
        ),
    )


def _net_packet_loss_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    percent = min(_iparam(fault, "percent", 10), 100)
    return _tc_qdisc_undo(fault, node, ["netem", "loss", f"{percent}%"])


def _net_packet_loss_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return _tc_qdisc_verify(fault, node, "netem")


_RATE_RE = re.compile(r"^[1-9][0-9]*(kbit|mbit|gbit|kbps|mbps|gbps)?$")


def _bandwidth_tokens(fault: PlannedFault) -> tuple[str, str]:
    rate = str(_param(fault, "rate", "")).strip().lower()
    if not _RATE_RE.match(rate):
        raise InvariantViolationError(
            "fault_rate",
            f"invalid net.bandwidth rate {rate!r}; expected e.g. '10mbit' / '2kbps'",
        )
    burst = str(_param(fault, "burst", "10k")).strip().lower()
    if not re.match(r"^[1-9][0-9]*k?$", burst):
        raise InvariantViolationError(
            "fault_burst", f"invalid net.bandwidth burst {burst!r}; expected bytes like '10k'"
        )
    return rate, burst


def _net_bandwidth_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    rate, burst = _bandwidth_tokens(fault)
    return _tc_qdisc_undo(fault, node, ["tbf", "rate", rate, "burst", burst, "latency", "50ms"])


def _net_bandwidth_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return _tc_qdisc_verify(fault, node, "tbf")


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


def _host_op(
    fault: PlannedFault, name: str, inject_argv: list[str], undo_argv: list[str]
) -> UndoOp:
    """A tool op whose argv runs on the drill host (no ``@engine`` tokens).

    Host-addressed faults (``net.load``) get no container address and no
    ``@live-pid``, so pid substitution leaves the command a plain host process.
    """
    return UndoOp(
        op=name,
        args={
            "fault": fault.fault_id,
            "inject_argv": json.dumps(inject_argv),
            "undo_argv": json.dumps(undo_argv),
        },
    )


def _host_exec_verify(cmd: list[str], *, timeout_s: str = "5") -> VerifyProbe:
    """A verify probe that runs on the drill host (no container address)."""
    return VerifyProbe(
        probe="exec",
        args={"cmd": list(cmd), "timeout_s": timeout_s},
        expect_present=True,
    )


def _net_load_target_url(fault: PlannedFault, node: TopologyNode) -> str:
    """Resolve the URL k6 drives from the host.

    An explicit ``params.url`` wins. Otherwise the first TCP port binding
    selects the address: a binding on a loopback host address
    (``127.0.0.1``/``::1``) is reached through the host's ``localhost:<host_port>``
    (host_port can differ from container_port), while any other binding is
    reached directly at the container's own live IP and container-side port —
    so the host load generator can always reach the container. Blueprint-only
    topology (no live ``ip_address``) or portless nodes fall back to the
    documented ``http://localhost/`` default.
    """
    explicit = _param(fault, "url", None)
    if isinstance(explicit, str) and explicit.strip():
        return explicit
    ip = getattr(node, "ip_address", None)
    ports: tuple[object, ...] = tuple(
        getattr(node, "ports", ()) or getattr(node, "exposed_ports", ())
    )
    for binding in ports:
        if getattr(binding, "protocol", "tcp") != "tcp":
            continue
        host_addr = str(getattr(binding, "host_address", "") or "0.0.0.0")
        host_port = int(getattr(binding, "host_port", 0) or 0)
        if host_port and host_addr.strip("[]") in {"127.0.0.1", "::1", "localhost"}:
            return f"http://localhost:{host_port}/"
        container_port = int(getattr(binding, "container_port", 0) or 0)
        if container_port and ip is not None:
            return f"http://{ip}:{container_port}/"
    return "http://localhost/"


def _net_load_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Saturate the target container with a host-driven k6 HTTP load generator.

    When ``params.script_content`` is set (content of a k6 ``script.js``
    embedded by the planner), the file is materialized on the drill host and
    run as ``k6 run -u <users> -d <duration>s``; otherwise a minimal inline
    script against the container's ``ip:serving-port`` is written. Either way
    the script lives under the marker path (so the verify probe can see the
    fault while it is live) and ``k6 run`` is detached on the host, driving
    load at the container over the network — k6 never runs inside the target.
    Undo SIGKILLs the recorded k6 pid and removes both marker files, so
    recovery, undo and the verify probe agree.
    """
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    users = max(1, _iparam(fault, "users", 1))
    duration_s = max(1, int(_fault_duration_s(fault)))
    script = _tool_marker(fault, node, "load.js")
    pidfile = _tool_marker(fault, node, "k6.pid")
    inline = _param(fault, "script_content", None)
    if inline:
        # User-supplied k6 script.js: materialize the embedded content on the
        # host, then run it. The heredoc delimiter is unique per content so a
        # user script containing a literal ``K6EOF`` line still copies intact.
        delim = f"K6EOF_{abs(hash(inline or '') or 1):x}"
        import_sh = f"cat > {script} <<'{delim}'\n{inline}\n{delim}\n"
    else:
        url = _net_load_target_url(fault, node)
        url = url.replace("\\", "\\\\").replace('"', '\\"')
        import_sh = (
            f"cat > {script} <<'K6EOF'\n"
            "import http from 'k6/http';\n"
            "export default function () {\n"
            f'  http.get("{url}");\n'
            "}\n"
            "K6EOF\n"
        )
    source = (
        import_sh
        + f"k6 run -u {users} -d {duration_s}s {script} >/dev/null 2>&1 &\n"
        + f"echo $! > {pidfile}\n"
        + f'[ -s {pidfile} ] && kill -0 "$(cat {pidfile})" 2>/dev/null && exit 0\n'
        + "exit 1\n"
    )
    undo = [
        "sh",
        "-c",
        f'p={pidfile}; [ ! -f "$p" ] || kill "$(cat "$p")" 2>/dev/null; rm -f "$p" {script}',
    ]
    return (_host_op(fault, "k6.host", ["sh", "-c", source], undo),)


def _net_load_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    script = _tool_marker(fault, node, "load.js")
    pidfile = _tool_marker(fault, node, "k6.pid")
    return (_host_exec_verify(["sh", "-c", f"test ! -e {script} && test ! -e {pidfile}"]),)


# ── net.connection_reset / net.connection_refuse ──────────────────────────


def _net_conn_reset_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    """iptables REJECT with tcp-reset on the target port."""
    return _param_netfilter("port", "tcp", "REJECT", ["--reject-with", "tcp-reset"], 80)(
        fault, nodes
    )


def _net_conn_reset_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _param_netfilter_verify("port", 80)(fault, nodes)


def _net_conn_refuse_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    """iptables REJECT with icmp-port-unreachable on the target port."""
    return _param_netfilter(
        "port", "tcp", "REJECT", ["--reject-with", "icmp-port-unreachable"], 80
    )(fault, nodes)


def _net_conn_refuse_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _param_netfilter_verify("port", 80)(fault, nodes)


# ── net.reorder / net.duplicate ───────────────────────────────────────────


def _net_reorder_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """tc netem reorder: reorder <percent>% with delay_ms base delay."""
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    percent = max(1, min(_iparam(fault, "percent", 30), 100))
    delay_ms = max(1, _iparam(fault, "delay_ms", 50))
    tail = ["netem", "delay", f"{delay_ms}ms", "reorder", f"{percent}%"]
    return _tc_qdisc_undo(fault, node, tail)


def _net_reorder_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return _tc_qdisc_verify(fault, node, "netem")


def _net_duplicate_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """tc netem duplicate: duplicate <percent>% of packets."""
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    percent = max(1, min(_iparam(fault, "percent", 10), 100))
    tail = ["netem", "duplicate", f"{percent}%"]
    return _tc_qdisc_undo(fault, node, tail)


def _net_duplicate_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return _tc_qdisc_verify(fault, node, "netem")


# ── dependency.connection_refuse ──────────────────────────────────────────


def _dep_conn_refuse_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    """iptables REJECT on the dependency's port (fast-fail vs DROP in block)."""
    return _param_netfilter(
        "port", "tcp", "REJECT", ["--reject-with", "icmp-port-unreachable"], 80
    )(fault, nodes)


def _dep_conn_refuse_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _param_netfilter_verify("port", 80)(fault, nodes)


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
    *,
    proto: str = "tcp",
    jump: str = "DROP",
    extra: list[str] | None = None,
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        body = ["-p", proto, "--dport", dport]
        inject = ["iptables", "-I", "OUTPUT", *body, "-j", jump, *(extra or [])]
        undo = ["iptables", "-D", "OUTPUT", *body, "-j", jump, *(extra or [])]
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


def _port_rule(
    fault: PlannedFault,
    *,
    port_param: str,
    default_port: int,
    proto: str,
    jump: str,
    extra: list[str],
) -> tuple[list[str], list[str]]:
    port = _iparam(fault, port_param, default_port)
    body = ["-p", proto, "--dport", str(port)]
    return (
        ["iptables", "-I", "OUTPUT", *body, "-j", jump, *extra],
        ["iptables", "-D", "OUTPUT", *body, "-j", jump, *extra],
    )


def _param_netfilter(
    port_param: str,
    proto: str,
    jump: str,
    extra: list[str],
    default_port: int,
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        inject, undo = _port_rule(
            fault,
            port_param=port_param,
            default_port=default_port,
            proto=proto,
            jump=jump,
            extra=extra,
        )
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


def _param_netfilter_verify(
    port_param: str,
    default_port: int,
) -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        port = _iparam(fault, port_param, default_port)
        return (
            _exec_verify(
                node,
                ["sh", "-c", f"! iptables -S OUTPUT | grep -q -- '--dport {port}'"],
                incontainer=True,
            ),
        )

    return build


def _pulse_rule(
    fault: PlannedFault,
    node: TopologyNode,
    *,
    proto: str,
    dport: int,
    jump: str,
    extra: list[str],
    probability: float,
    marker_suffix: str,
    tick_s: float = 5.0,
) -> tuple[str, str, str]:
    """Deterministic ``probability``-% rule, re-asserted by a background loop.

    The loop keeps a single OUTPUT rule present ``probability``% of the time by
    keying the tick on ``date +%s % 100`` — no random source, so two agents on
    the same second agree. Returns ``(inject, undo, verify_cmd)`` shell snippets;
    the undo kills the loop pid and deletes the rule deterministically.
    """
    marker = _tool_marker(fault, node, marker_suffix)
    pidf = f"{marker}.pid"
    prob = max(0, min(int(probability), 99))
    body = " ".join(["-p", proto, "--dport", str(dport), "-j", jump, *extra])
    inject = f"""P={prob}; M={marker}
loop() {{
  if [ $(( $(date +%s) % 100 )) -lt $P ]; then
    iptables -C OUTPUT {body} 2>/dev/null || iptables -A OUTPUT {body}
  else
    iptables -D OUTPUT {body} 2>/dev/null
  fi
  sleep {tick_s}
}}
loop & echo $! > {pidf}
kill -0 "$(cat {pidf})" 2>/dev/null && exit 0
exit 1"""
    undo = f"""p={pidf}
[ ! -f "$p" ] || kill "$(cat "$p")" 2>/dev/null
iptables -D OUTPUT {body} 2>/dev/null
rm -f {pidf}; true"""
    verify = f"test ! -e {pidf} && ! iptables -S OUTPUT | grep -q -- '--dport {dport}'"
    return inject, undo, verify


def _pulse_undo_op(
    fault: PlannedFault,
    nodes: tuple[TopologyNode, ...],
    *,
    proto: str,
    dport: int,
    jump: str,
    extra: list[str],
    probability: float,
    marker_suffix: str,
    tick_s: float = 5.0,
    op_name: str = "iptables.sync",
) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    inject, undo, _ = _pulse_rule(
        fault,
        node,
        proto=proto,
        dport=dport,
        jump=jump,
        extra=extra,
        probability=probability,
        marker_suffix=marker_suffix,
        tick_s=tick_s,
    )
    return (
        _tool_op(
            fault,
            node,
            op_name,
            _incontainer_argv(["sh", "-c", inject]),
            _incontainer_argv(["sh", "-c", undo]),
        ),
    )


def _pulse_verify(
    fault: PlannedFault,
    nodes: tuple[TopologyNode, ...],
    *,
    dport: int,
    marker_suffix: str,
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    pidf = _tool_marker(fault, node, marker_suffix) + ".pid"
    check = f"test ! -e {pidf} && ! iptables -S OUTPUT | grep -q -- '--dport {dport}'"
    return (
        _exec_verify(
            node,
            ["sh", "-c", check],
            incontainer=True,
        ),
    )


def _pulse_netfilter(
    proto: str,
    dport: int,
    *,
    jump: str,
    extra: list[str],
    probability: float,
    marker_suffix: str,
    tick_s: float = 5.0,
) -> tuple[
    Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]],
    Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]],
]:
    def undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        return _pulse_undo_op(
            fault,
            nodes,
            proto=proto,
            dport=dport,
            jump=jump,
            extra=extra,
            probability=probability,
            marker_suffix=marker_suffix,
            tick_s=tick_s,
        )

    def verify(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]:
        return _pulse_verify(fault, nodes, dport=dport, marker_suffix=marker_suffix)

    return undo, verify


def _http_proxy_source(
    *,
    target: int,
    prob: float,
    marker_port: str,
    delay_ms: int | None = None,
    status: int | None = None,
    rate: int | None = None,
    burst: int = 200,
    code: int = 429,
) -> str:
    """In-container python passthrough proxy serving a fault mode.

    Binds an ephemeral port on loopback and reports it under ``marker_port``; the
    wrapping shell inserts an OUTPUT REDIRECT rule to it. Modes:
      * status — responded calls get canned HTTP ``status``
      * delay  — responded calls are held ``delay_ms`` before relaying
      * rate   — responded calls consume a token bucket (``rate``/s, ``burst``
                 tokens, ``code`` when dry)
    Unresponded calls (outside ``prob``) relay through untouched. The accept
    loop blocks, keeping the interpreter alive for the whole lease.
    """
    lines = [
        "import socket, threading, time, random",
        f"TARGET = {target}",
        f"PROB = {min(max(prob, 0.0), 100.0) / 100.0:.3f}",
        "status = 0",
        "rate = 0",
        "delay_s = 0.0",
        "ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        "ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "ls.bind(('127.0.0.1', 0))",
        "ls.listen(128)",
        f"open({marker_port!r}, 'w').write(str(ls.getsockname()[1]))",
    ]
    if status is not None:
        lines.append(f"status = {max(int(status), 100)}")
        lines.append(f"code = {max(int(status), 100)}")
    if rate is not None:
        lines += [
            f"rate = {max(int(rate), 1)}",
            f"burst = {max(int(burst), 1)}",
            f"code = {max(int(code), 100)}",
            "bucket = float(burst)",
            "last = time.monotonic()",
            "def acquire():",
            "    global bucket, last",
            "    now = time.monotonic()",
            "    bucket = min(bucket + (now - last) * rate, float(burst))",
            "    last = now",
            "    if bucket < 1.0:",
            "        return False",
            "    bucket -= 1.0",
            "    return True",
        ]
    if delay_ms is not None and int(delay_ms) > 0:
        lines.append(f"delay_s = {max(int(delay_ms), 1) / 1000.0:.3f}")
    lines += [
        "def relay(a, b):",
        "    try:",
        "        while True:",
        "            d = a.recv(65536)",
        "            if not d:",
        "                break",
        "            b.sendall(d)",
        "    except OSError:",
        "        pass",
        "    finally:",
        "        try:",
        "            b.shutdown(socket.SHUT_WR)",
        "        except OSError:",
        "            pass",
        "def forward(c):",
        "    s = socket.create_connection(('127.0.0.1', TARGET), timeout=30)",
        "    t1 = threading.Thread(target=relay, args=(c, s), daemon=True)",
        "    t2 = threading.Thread(target=relay, args=(s, c), daemon=True)",
        "    t1.start(); t2.start(); t1.join(); t2.join()",
        "    s.close()",
        "def canned(c, n):",
        "    line = f'HTTP/1.1 {n} X\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n'",
        "    c.sendall(line.encode('ascii'))",
        "def handle(c):",
        "    try:",
        "        if random.random() >= PROB:",
        "            forward(c)",
        "            return",
        "        if status:",
        "            canned(c, status)",
        "            return",
        "        if rate and not acquire():",
        "            canned(c, code)",
        "            return",
        "        if delay_s:",
        "            time.sleep(delay_s)",
        "        forward(c)",
        "    except OSError:",
        "        pass",
        "while True:",
        "    try:",
        "        conn, _ = ls.accept()",
        "    except OSError:",
        "        break",
        "    threading.Thread(target=handle, args=(conn,), daemon=True).start()",
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class _HttpEffect:
    delay_ms: int | None = None
    status: int | None = None
    rate: int | None = None
    burst: int = 200
    code: int = 429


def _http_proxy_ops(
    fault: PlannedFault,
    nodes: tuple[TopologyNode, ...],
    *,
    effect: _HttpEffect | None = None,
    op_name: str = "http.proxy",
) -> tuple[UndoOp, ...]:
    """In-container python proxy + OUTPUT REDIRECT, addressed by a marker pid.

    The proxy owns no state of its own: undo kills the marker pid, deletes the
    nat OUTPUT REDIRECT rule, and removes the marker files, so recovery, undo,
    and the verify probe all agree on the same files (ADR-0021 pattern).
    """
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    if effect is None:
        effect = _HttpEffect()
    marker = _tool_marker(fault, node, "http")
    pidf = f"{marker}.pid"
    portf = f"{marker}.port"
    srcf = f"{marker}.src"
    target = _iparam(fault, "port", 80)
    prob = _fparam(fault, "probability", 100.0)
    source = _http_proxy_source(
        target=target,
        prob=prob,
        marker_port=portf,
        delay_ms=effect.delay_ms,
        status=effect.status,
        rate=effect.rate,
        burst=effect.burst,
        code=effect.code,
    )
    inject = (
        f"cat > {srcf} <<'MAYHEM_PY_EOF'\n{source}MAYHEM_PY_EOF\n"
        f"python3 {srcf} >/dev/null 2>&1 &\n"
        f"echo $! > {pidf}\n"
        f"i=0\n"
        f"while [ ! -s {portf} ] && [ $i -lt 60 ]; do sleep 0.1; i=$((i + 1)); done\n"
        f"[ -s {portf} ] || exit 1\n"
        f"PORT=$(cat {portf})\n"
        f"iptables -t nat -A OUTPUT -p tcp --dport {target} -j REDIRECT --to-ports $PORT\n"
        f"exit 0\n"
    )
    undo = (
        f"p={pidf}\n"
        f'[ ! -f "$p" ] || kill "$(cat "$p")" 2>/dev/null\n'
        f"PORT=$(cat {portf} 2>/dev/null)\n"
        f"RULE='-t nat -D OUTPUT -p tcp --dport {target} -j REDIRECT --to-ports $PORT'\n"
        f'[ -z "$PORT" ] || iptables $RULE 2>/dev/null\n'
        f"rm -f {pidf} {portf} {srcf}\n"
        f"true\n"
    )
    return (
        _tool_op(
            fault,
            node,
            op_name,
            _incontainer_argv(["sh", "-c", inject]),
            _incontainer_argv(["sh", "-c", undo]),
        ),
    )


def _http_proxy_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _tool_marker(fault, node, "http")
    target = _iparam(fault, "port", 80)
    return (
        _exec_verify(
            node,
            [
                "sh",
                "-c",
                f"test ! -e {marker}.pid && test ! -e {marker}.port "
                f"&& ! iptables -t nat -S OUTPUT | grep -q -- '--dport {target}'",
            ],
            incontainer=True,
        ),
    )


def _http_error_inject() -> Callable[[PlannedFault, tuple[TopologyNode, ...]], tuple[UndoOp, ...]]:
    def build(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        prob = _fparam(fault, "probability", 0.0)
        if prob < 1.0:
            # Legacy deterministic fault: hard TCP reset on outgoing 80.
            inject = [
                "iptables",
                "-I",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                str(_iparam(fault, "port", 80)),
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
                str(_iparam(fault, "port", 80)),
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
        # Probabilistic / canned-status mode: proxy serves ``status`` to a
        # ``probability``% slice of the traffic (see http.latency).
        return _http_proxy_ops(
            fault,
            nodes,
            effect=_HttpEffect(status=_iparam(fault, "status", 500)),
        )

    return build


def _http_error_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    if _fparam(fault, "probability", 0.0) < 1.0:
        node = _tool_node(fault, nodes)
        if node is None:
            raise NO_UNDO
        return (
            _exec_verify(
                node,
                [
                    "sh",
                    "-c",
                    f"! iptables -S OUTPUT | grep -q -- '--dport {_iparam(fault, 'port', 80)}'",
                ],
                incontainer=True,
            ),
        )
    return _http_proxy_verify(fault, nodes)


def _http_latency_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    return _http_proxy_ops(
        fault, nodes, effect=_HttpEffect(delay_ms=_iparam(fault, "delay_ms", 100))
    )


def _http_latency_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _http_proxy_verify(fault, nodes)


def _dep_rate_limit_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    rate = _iparam(fault, "rate", 0)
    if rate < 1:
        raise InvariantViolationError(
            "fault_rate", "dependency.rate_limit requires a positive rate"
        )
    return _http_proxy_ops(
        fault,
        nodes,
        effect=_HttpEffect(
            rate=rate,
            burst=_iparam(fault, "burst", 200),
            code=_iparam(fault, "code", 429),
        ),
    )


def _dep_rate_limit_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _http_proxy_verify(fault, nodes)


def _dep_flap_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    port = _iparam(fault, "port", 0)
    interval = max(_fparam(fault, "interval", 10.0), 1.0)
    prob = _fparam(fault, "failure_probability", 50.0)
    proto = str(_param(fault, "protocol", "tcp"))
    return _pulse_undo_op(
        fault,
        nodes,
        proto=proto,
        dport=port,
        jump="DROP",
        extra=[],
        probability=prob,
        marker_suffix="flap",
        tick_s=interval,
    )


def _dep_flap_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _pulse_verify(fault, nodes, dport=_iparam(fault, "port", 0), marker_suffix="flap")


def _db_query_error_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    prob = _fparam(fault, "probability", 100.0)
    if prob >= 100.0:
        return _param_netfilter("port", "tcp", "REJECT", ["--reject-with", "tcp-reset"], 3306)(
            fault, nodes
        )
    return _pulse_undo_op(
        fault,
        nodes,
        proto="tcp",
        dport=_iparam(fault, "port", 3306),
        jump="REJECT",
        extra=["--reject-with", "tcp-reset"],
        probability=prob,
        marker_suffix="db",
    )


def _db_query_error_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    if _fparam(fault, "probability", 100.0) >= 100.0:
        return _param_netfilter_verify("port", 3306)(fault, nodes)
    return _pulse_verify(fault, nodes, dport=_iparam(fault, "port", 3306), marker_suffix="db")


def _tls_failure_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    return _param_netfilter("port", "tcp", "REJECT", ["--reject-with", "tcp-reset"], 443)(
        fault, nodes
    )


def _tls_failure_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    return _param_netfilter_verify("port", 443)(fault, nodes)


def _conn_exhaust_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Exhaust the target's connection pool by holding real sockets open from
    inside the container. Marker-addressed, same lifecycle as the http proxy."""
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    connections = max(_iparam(fault, "connections", 32), 1)
    host = str(_param(fault, "host", "localhost"))
    port = _iparam(fault, "port", 3306)
    marker = _tool_marker(fault, node, "conn")
    pidf = f"{marker}.pid"
    srcf = f"{marker}.src"
    source = (
        "import socket, time\n"
        f"host = {host!r}\n"
        f"port = {port}\n"
        f"total = {connections}\n"
        "left = []\n"
        "while len(left) < total:\n"
        "    try:\n"
        "        s = socket.create_connection((host, port), timeout=10)\n"
        "        left.append(s)\n"
        "    except OSError:\n"
        "        pass\n"
        "while True:\n"
        "    time.sleep(3600)\n"
    )
    inject = (
        f"cat > {srcf} <<'MAYHEM_PY_EOF'\n{source}MAYHEM_PY_EOF\n"
        f"python3 {srcf} >/dev/null 2>&1 &\n"
        f"echo $! > {pidf}\n"
        f'[ -s {pidf} ] && kill -0 "$(cat {pidf})" 2>/dev/null && exit 0\n'
        "exit 1\n"
    )
    undo = f'p={pidf}\n[ ! -f "$p" ] || kill "$(cat "$p")" 2>/dev/null\nrm -f {pidf} {srcf}\ntrue\n'
    return (
        _tool_op(
            fault,
            node,
            "http.proxy",
            _incontainer_argv(["sh", "-c", inject]),
            _incontainer_argv(["sh", "-c", undo]),
        ),
    )


def _conn_exhaust_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _tool_marker(fault, node, "conn")
    return (
        _exec_verify(
            node,
            ["sh", "-c", f"test ! -e {marker}.pid && test ! -e {marker}.src"],
            incontainer=True,
        ),
    )


def _cpu_throttle_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Cap the container's CPU share at ``percent``% of one core.

    Routed to the argv-pair ToolExecutor (executor override), so this must be a
    pure argv-pair op — same shape as container.restart. Undo lifts the cap back
    to unlimited (documented deviation: the pre-fault share is not re-read).
    """
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    percent = max(min(_fparam(fault, "percent", 50.0), 100.0), 1.0)
    return (
        _tool_op(
            fault,
            node,
            "engine.update",
            [_ENGINE_TOKEN, "update", "--cpus", f"{percent / 100:.2f}", _CONTAINER_TOKEN],
            [_ENGINE_TOKEN, "update", "--cpus", "0", _CONTAINER_TOKEN],
        ),
    )


def _cpu_throttle_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return (_exec_verify(node, ["true"], incontainer=False),)


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


def _fs_read_only_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Remount the target filesystem read-only; undo restores read-write.

    A write-probe marker confirms the fs accepts writes again, guarding against
    a remount that silently wedged the container.
    """
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    path = str(_param(fault, "path", "/"))
    marker = _tool_marker(fault, node, "rwprobe")
    inject = ["sh", "-c", f"mount -o remount,ro {path}"]
    undo = [
        "sh",
        "-c",
        f"mount -o remount,rw {path} && touch {marker} && rm -f {marker}",
    ]
    return (
        _tool_op(
            fault,
            node,
            "fs.remount",
            _incontainer_argv(inject),
            _incontainer_argv(undo),
        ),
    )


def _fs_read_only_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    marker = _tool_marker(fault, node, "rwprobe")
    return (
        _exec_verify(
            node,
            ["sh", "-c", f"touch {marker} && rm -f {marker}"],
            incontainer=True,
        ),
    )


# ── process.crash_loop ─────────────────────────────────────────────────────


def _process_crash_loop_undo(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[UndoOp, ...]:
    """Drive a restart cadence via engine stop/start argv-pairs.

    Inject runs ``<engine> stop <cont>; <engine> start <cont>`` once; undo
    ``start``s the container so it recovers to a running state.
    """
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    restart_n = max(1, _iparam(fault, "restarts", 10))
    interval_s = str(_param(fault, "interval", "2s"))
    # Shell loop of stop→start ``restart_n`` times at the engine level; undo
    # just starts the container so the service returns to a running baseline.
    step = (
        f"{_ENGINE_TOKEN} stop {_CONTAINER_TOKEN}; "
        f"{_ENGINE_TOKEN} start {_CONTAINER_TOKEN}; sleep {interval_s}"
    )
    loop = " && ".join([step] * restart_n)
    inject = ["sh", "-c", loop]
    undo = _engine_argv("start")
    return (_tool_op(fault, node, "engine.restart", inject, undo),)


def _process_crash_loop_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    # Undo started the container; the engine start action is the recovery.
    return (_exec_verify(node, ["true"], incontainer=False),)


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


def _dep_block_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    port = _iparam(fault, "port", 0)
    proto = str(_param(fault, "protocol", "tcp"))
    inject = ["iptables", "-A", "OUTPUT", "-p", proto, "--dport", str(port), "-j", "DROP"]
    undo = ["iptables", "-D", "OUTPUT", "-p", proto, "--dport", str(port), "-j", "DROP"]
    return (
        _tool_op(fault, node, "iptables.sync", _incontainer_argv(inject), _incontainer_argv(undo)),
    )


def _dep_block_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    port = _iparam(fault, "port", 0)
    return (
        _exec_verify(
            node,
            ["sh", "-c", f"! iptables -S OUTPUT | grep -q -- '--dport {port}'"],
            incontainer=True,
        ),
    )


def _dep_timeout_undo(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    delay_ms = _iparam(fault, "delay_ms", 500)
    inject = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", f"{delay_ms}ms"]
    undo = ["tc", "qdisc", "del", "dev", "eth0", "root"]
    return (
        _tool_op(fault, node, "tc.del_qdisc", _incontainer_argv(inject), _incontainer_argv(undo)),
    )


def _dep_timeout_verify(
    fault: PlannedFault, nodes: tuple[TopologyNode, ...]
) -> tuple[VerifyProbe, ...]:
    node = _tool_node(fault, nodes)
    if node is None:
        raise NO_UNDO
    return (
        _exec_verify(
            node,
            ["sh", "-c", "! tc qdisc show dev eth0 | grep -q netem"],
            incontainer=True,
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
        "container.restart": _tool_template(
            _engine_restart_undo("restart", "start"), _engine_restart_verify
        ),
        "container.pause": _tool_template(
            _engine_restart_undo("pause", "unpause"), _engine_restart_verify
        ),
        "node.service_stop": _tool_template(
            _engine_restart_undo("stop", "start"), _engine_restart_verify
        ),
        "http.error_injection": _tool_template(_http_error_inject(), _http_error_verify),
        "http.latency": _tool_template(_http_latency_undo, _http_latency_verify),
        "net.packet_loss": _tool_template(_net_packet_loss_undo, _net_packet_loss_verify),
        "net.bandwidth": _tool_template(_net_bandwidth_undo, _net_bandwidth_verify),
        "db.connection_exhaust": _tool_template(_conn_exhaust_undo, _conn_exhaust_verify),
        "db.query_error": _tool_template(_db_query_error_undo, _db_query_error_verify),
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
        "dns.timeout": _tool_template(
            *_pulse_netfilter(
                "udp", 53, jump="DROP", extra=[], probability=80, marker_suffix="dns", tick_s=2.0
            )
        ),
        "dns.servfail": _tool_template(
            *_pulse_netfilter(
                "udp",
                53,
                jump="REJECT",
                extra=["--reject-with", "icmp-port-unreachable"],
                probability=80,
                marker_suffix="dns",
                tick_s=2.0,
            )
        ),
        "tls.certificate_expired": _tool_template(
            _file_revert_undo(
                "/etc/ssl/certs/ca-certificates.crt",
                ": > /etc/ssl/certs/ca-certificates.crt",
            ),
            _file_revert_verify,
        ),
        "tls.handshake_failure": _tool_template(_tls_failure_undo, _tls_failure_verify),
        "clock.skew": _tool_template(_clock_skew_undo, _clock_skew_verify),
        "dependency.block": _tool_template(_dep_block_undo, _dep_block_verify),
        "dependency.timeout": _tool_template(_dep_timeout_undo, _dep_timeout_verify),
        "dependency.flap": _tool_template(_dep_flap_undo, _dep_flap_verify),
        "dependency.rate_limit": _tool_template(_dep_rate_limit_undo, _dep_rate_limit_verify),
        "dependency.connection_refuse": _tool_template(
            _dep_conn_refuse_undo, _dep_conn_refuse_verify
        ),
        "net.connection_reset": _tool_template(_net_conn_reset_undo, _net_conn_reset_verify),
        "net.connection_refuse": _tool_template(_net_conn_refuse_undo, _net_conn_refuse_verify),
        "net.reorder": _tool_template(_net_reorder_undo, _net_reorder_verify),
        "net.duplicate": _tool_template(_net_duplicate_undo, _net_duplicate_verify),
        "fs.read_only": _tool_template(_fs_read_only_undo, _fs_read_only_verify),
        "process.crash_loop": _tool_template(_process_crash_loop_undo, _process_crash_loop_verify),
        "cpu.throttle": _tool_template(_cpu_throttle_undo, _cpu_throttle_verify),
    }


_TEMPLATES: dict[str, CompensationTemplate] = {
    "proc.pause": _ignores_fault(_proc_pause_undo, _proc_pause_verify),
    "process.stop": _ignores_fault(_process_term_undo, _process_term_verify),
    "process.kill": _ignores_fault(_process_term_undo, _process_term_verify),
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
