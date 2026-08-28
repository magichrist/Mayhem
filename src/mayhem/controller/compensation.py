"""Compensation synthesis — undo ops and verify probes decided at plan time.

The planner refuses any fault it cannot compensate for: a plan without a
write-ahead undo contract never leaves the planner. Templates are keyed by
fault prefix and may inspect resolved nodes.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

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
    header = f"import os\nopen({marker!r}, 'w').write(str(os.getpid()))\n"
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
        cores = "max(1, int(os.cpu_count() or 1))"
        return header + (
            "import threading\n"
            "def burn():\n"
            "    x = 0\n"
            "    while True:\n"
            "        x = (x + 1) % 7\n"
            f"n = max(1, int(({cores}) * {percent} / 100))\n"
            "for _ in range(n):\n"
            "    threading.Thread(target=burn, daemon=True).start()\n"
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
            "    i += 1\n"
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
            "    pass\n"
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
            "    threading.Thread(target=blast, daemon=True).start()\n"
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
            "    threading.Thread(target=abuse, daemon=True).start()\n"
        )
    raise NO_UNDO  # pragma: no cover - only reachable for unregistered payloads


# ``` needs `import time` for the loops that reference ``time``.
_PAYLOAD_IMPORTS = "import os, time\n"


def _payload_undo_ops(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    """Compensation for payload-family faults: SIGKILL the injected process and
    remove its marker files. Reversible by construction (marker-addressed undo)."""
    from mayhem.domain.topology import ContainerNode, ProcessNode  # noqa: PLC0415

    node = None
    for candidate in nodes:
        if isinstance(candidate, (ContainerNode, ProcessNode)) and getattr(
            candidate, "container_name", None
        ):
            node = candidate
            break
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
        CompensationTemplate(_payload_undo_ops, lambda _fault, _nodes: ()),
    )


_TEMPLATES: dict[str, CompensationTemplate] = {
    "proc.pause": _ignores_fault(_proc_pause_undo, _proc_pause_verify),
    **_payload_compensation_templates(),
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
