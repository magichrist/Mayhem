"""Fault impact gate — can this fault actually perturb this container?

Faults are functional only when the runtime the flavour injects into is real:
`net.latency` needs ``tc`` *and* the ``NET_ADMIN`` capability to add a netem
qdisc inside the container, `http.error_injection` needs ``iptables``, payload
faults need a Python interpreter, `net.load` needs a ``k6`` binary. A fault
whose tooling is absent still *completes* (inject exits 0) but produces zero
perturbation — the run degrades into a survey instead of a drill.

This module probes the live container once (read-only), decides per family
whether the injection can physically take effect, and lets the planner gate
refuse definitively inert faults before they ever execute.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.toolkit.tool_runner import ToolError, run_tool

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.experiments import ExecutionPlan, PlannedFault
    from mayhem.domain.topology import TopologyGraph

_CAP_BITS: dict[str, int] = {
    "NET_ADMIN": 12,
    "SYS_TIME": 25,
}


@dataclass(frozen=True)
class FaultRequirement:
    """Runtime capability a fault family needs inside the target container."""

    bins: frozenset[str] = frozenset()
    caps: frozenset[str] = frozenset()
    need_root: bool = False

    def describe(self) -> str:
        parts = [f"bin({b})" for b in sorted(self.bins)]
        parts += [f"cap({c})" for c in sorted(self.caps)]
        if self.need_root:
            parts.append("uid(0)")
        return ", ".join(parts) if parts else "none"


REQUIREMENTS: dict[str, FaultRequirement] = {
    "proc.pause": FaultRequirement(bins=frozenset({"kill"})),
    "mem.exhaust": FaultRequirement(bins=frozenset({"python"})),
    "mem.leak": FaultRequirement(bins=frozenset({"python"})),
    "cpu.saturate": FaultRequirement(bins=frozenset({"python"})),
    "fs.fill": FaultRequirement(bins=frozenset({"python"})),
    "fs.inode_exhaust": FaultRequirement(bins=frozenset({"python"})),
    "fs.io_stress": FaultRequirement(bins=frozenset({"python"})),
    "fs.read_only": FaultRequirement(bins=frozenset({"sh"}), need_root=True),
    "fd.exhaust": FaultRequirement(bins=frozenset({"python"})),
    "load.spike": FaultRequirement(bins=frozenset({"python"})),
    "fuzz.protocol_abuse": FaultRequirement(bins=frozenset({"python"})),
    "http.latency": FaultRequirement(bins=frozenset({"python"})),
    "db.connection_exhaust": FaultRequirement(bins=frozenset({"python"})),
    "dependency.rate_limit": FaultRequirement(bins=frozenset({"python"})),
    "net.latency": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.packet_loss": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.bandwidth": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.partition": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.reorder": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.duplicate": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "dependency.timeout": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.load": FaultRequirement(bins=frozenset({"k6"})),
    "http.error_injection": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "net.connection_reset": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "net.connection_refuse": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "db.slow_query": FaultRequirement(bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})),
    "db.query_error": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "dns.timeout": FaultRequirement(bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})),
    "dns.servfail": FaultRequirement(bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})),
    "tls.handshake_failure": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "dependency.block": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "dependency.flap": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "dependency.connection_refuse": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "dns.resolve_delay": FaultRequirement(bins=frozenset({"sh"}), need_root=True),
    "dns.nxdomain": FaultRequirement(bins=frozenset({"sh"}), need_root=True),
    "tls.certificate_expired": FaultRequirement(bins=frozenset({"sh"}), need_root=True),
    "clock.skew": FaultRequirement(bins=frozenset({"date"}), caps=frozenset({"SYS_TIME"})),
}

# Engine-addressed faults (kill/stop/start the runtime itself, or drive the
# host engine: ``update --cpus``, restart cadence): no in-image tooling is
# needed, so they are never gated on container binaries — the engine being
# reachable and the container being resolvable is sufficient.
_ENGINE_FAULTS = frozenset(
    {
        "container.kill",
        "container.restart",
        "container.pause",
        "process.crash_loop",
        "cpu.throttle",
        "node.service_stop",
    }
)

#: Faults whose recovery probe cannot see the live perturbation. The generic
#: "recovery probe inverted during the window" observation is therefore
#: inconclusive for these families, and must not be read as "no impact".
#: Terminate faults (process.stop/kill) blind the probe too: the post-kill
#: world (process gone) is indistinguishable from the post-recovery world, so
#: the observation is inconclusive rather than "no impact".
OBSERVATION_BLIND: frozenset[str] = frozenset({"proc.pause", "process.stop", "process.kill"})

_PROBE_BINS = ("kill", "tc", "iptables", "python", "python3", "date", "sh", "k6")


@dataclass(frozen=True)
class ContainerRuntime:
    """Probed, read-only view of one live container."""

    container: str
    engine: str
    bins: dict[str, bool]
    uid: int | None
    cap_eff: int = 0

    def has_bin(self, name: str) -> bool:
        if name == "python":
            return bool(self.bins.get("python") or self.bins.get("python3"))
        return bool(self.bins.get(name))

    def has_cap(self, name: str) -> bool:
        bit = _CAP_BITS.get(name)
        return bit is not None and bool(self.cap_eff & (1 << bit))


_PROBE_SH = (
    "printf 'BINS'"
    + "".join(
        f"; printf ' {b}:%s' \"$(command -v {b} >/dev/null 2>&1 && echo 1 || echo 0)\""
        for b in _PROBE_BINS
    )
    + "; echo; printf 'UID %s\\n' \"$(id -u 2>/dev/null || echo -1)\";"
    + " printf 'CAPEFF %s\\n' \"$(awk '/CapEff/{print $2}' /proc/1/status 2>/dev/null || echo 0)\""
)

_BINS_RE = re.compile(r"BINS((?:\s+[a-z0-9]+:[01])+)")
_UID_RE = re.compile(r"UID (\d+)")
_CAPEFF_RE = re.compile(r"CAPEFF ([0-9a-fA-F]+)")


def probe_container_runtime(
    engine: str, container: str, timeout_s: int = 10
) -> ContainerRuntime | None:
    """One read-only ``engine exec`` returning the container's runtime surface.

    Returns ``None`` when the engine or container is unreachable — the caller
    treats an unreachable runtime as "cannot prove inert", never as a pass.
    """
    try:
        result = run_tool(
            [engine, "exec", container, "sh", "-c", _PROBE_SH],
            timeout_s=timeout_s,
        )
    except ToolError:
        return None
    if not result.succeeded:
        return None
    return parse_runtime_output(engine, container, result.stdout)


def parse_runtime_output(engine: str, container: str, text: str) -> ContainerRuntime | None:
    m = _BINS_RE.search(text)
    if m is None:
        return None
    bins = {pair.split(":")[0]: pair.split(":")[1] == "1" for pair in m.group(1).split()}
    uid_m = _UID_RE.search(text)
    cap_m = _CAPEFF_RE.search(text)
    cap_eff = int(cap_m.group(1), 16) if cap_m else 0
    uid = int(uid_m.group(1)) if uid_m else None
    return ContainerRuntime(container=container, engine=engine, bins=bins, uid=uid, cap_eff=cap_eff)


@dataclass(frozen=True)
class GateVerdict:
    """Per fault/container: can the injection physically take effect?"""

    fault_id: str
    container: str
    impact_possible: bool
    missing: tuple[str, ...] = ()
    probed: bool = True
    note: str = ""


def gate_fault(
    fault_id: str,
    container: str,
    engine: str,
    runtime: ContainerRuntime | None = None,
) -> GateVerdict:
    """Verdict for one fault against one (optionally pre-probed) container."""
    if fault_id in _ENGINE_FAULTS:
        return GateVerdict(fault_id, container, True, note="engine-addressed fault")
    requirement = REQUIREMENTS.get(fault_id)
    if requirement is None:
        return GateVerdict(fault_id, container, True, note="no in-image tooling required")
    run = runtime if runtime is not None else probe_container_runtime(engine, container)
    if run is None:
        return GateVerdict(
            fault_id,
            container,
            False,
            probed=False,
            note="runtime unreachable — cannot prove impact possible",
        )
    missing: list[str] = []
    for req_bin in sorted(requirement.bins):
        if not run.has_bin(req_bin):
            missing.append(f"bin:{req_bin}")
    for req_cap in sorted(requirement.caps):
        if not run.has_cap(req_cap):
            missing.append(f"cap:{req_cap}")
    if requirement.need_root and run.uid not in (0, None):
        missing.append("uid(0)")
    possible = not missing
    note = "" if possible else f"missing {', '.join(missing)}"
    return GateVerdict(fault_id, container, possible, tuple(missing), note=note)


def _container_for(graph: TopologyGraph, fault: PlannedFault) -> str | None:
    """First resolvable container the fault would inject into (for gating)."""
    for target in fault.targets:
        for node_id in target.node_ids:
            node = graph.by_id(node_id)
            if node is None:
                continue
            name = getattr(node, "container_name", None)
            if isinstance(name, str) and name:
                return name
    return None


def scan_plan_faults(
    plan: ExecutionPlan, graph: TopologyGraph, engine: str
) -> tuple[list[GateVerdict], bool]:
    """Gate every fault in ``plan`` against its live container.

    Returns ``(verdicts, engine_probed)``. ``engine_probed`` is False when the
    engine could not be reached at all; callers must not fail the run on that.
    ``verdicts`` holds one entry per (fault, container) pair, with
    ``impact_possible=False`` only when the live container proved the fault's
    tooling is absent.
    """
    seen: dict[tuple[str, str], ContainerRuntime | None] = {}
    verdicts: list[GateVerdict] = []
    engine_probed = False
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        container = _container_for(graph, fault)
        if container is None:
            verdicts.append(
                GateVerdict(
                    fault.fault_id,
                    "?",
                    False,
                    probed=False,
                    note="no container target resolved — nothing to gate on",
                )
            )
            continue
        key = (engine, container)
        if key in seen:
            runtime = seen[key]
        else:
            runtime = probe_container_runtime(engine, container)
            seen[key] = runtime
        if runtime is not None:
            engine_probed = True
        verdicts.append(gate_fault(fault.fault_id, container, engine, runtime))
    return verdicts, engine_probed


def bypass_from_verdicts(
    verdicts: Sequence[GateVerdict],
) -> dict[tuple[str, str], str]:
    """Verified-inert injections → ``{(fault_id, container): reason}``.

    Fail-safe contract: a fault whose tooling is **proven absent** in its
    target container is bypassed at execution time (logged as ``bypass due to
    <reason>``) instead of aborting the whole run. Only ``probed`` verdicts
    count — an unreachable runtime cannot be proven inert, so those faults are
    still attempted.
    """
    return {
        (v.fault_id, v.container): v.note or v.fault_id
        for v in verdicts
        if v.probed and not v.impact_possible
    }
