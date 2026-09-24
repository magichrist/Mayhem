"""Fault impact gate — can this fault actually perturb this container?

Faults are functional only when the runtime the flavour injects into is real:
`net.latency` needs ``tc`` *and* the ``NET_ADMIN`` capability to add a netem
qdisc inside the container, `http.error_injection` needs ``iptables``, payload
faults need a Python interpreter, `net.load` needs a ``k6`` binary **on the
drill host** (the load generator drives the container from outside; it is not
a container package). A fault whose tooling is absent still *completes* (inject
exits 0) but produces zero perturbation — the run degrades into a survey
instead of a drill.

This module probes the live container once (read-only), decides per family
whether the injection can physically take effect, and lets the planner gate
refuse definitively inert faults before they ever execute. Requirements marked
``host=True`` are resolved against the drill host instead of the container —
the container-tooling probe and ``mayhem dependency install`` never see them.
"""

from __future__ import annotations

import functools
import json
import re
import shutil
import subprocess
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
    """Runtime capability a fault family needs inside the target container.

    ``host=True`` moves the ``bins`` check to the drill host (e.g. ``k6`` for
    ``net.load`` — host-side load generator, not container tooling). The
    container probe and ``mayhem dependency install`` ignore host requirements.
    """

    bins: frozenset[str] = frozenset()
    caps: frozenset[str] = frozenset()
    need_root: bool = False
    host: bool = False

    def describe(self) -> str:
        parts = [f"bin({b}{'@host' if self.host else ''})" for b in sorted(self.bins)]
        parts += [f"cap({c})" for c in sorted(self.caps)]
        if self.need_root:
            parts.append("uid(0)")
        return ", ".join(parts) if parts else "none"


REQUIREMENTS: dict[str, FaultRequirement] = {
    "proc.pause": FaultRequirement(bins=frozenset({"kill"})),
    "mem.exhaust": FaultRequirement(bins=frozenset({"python"})),
    "mem.leak": FaultRequirement(bins=frozenset({"python"})),
    "cpu.saturate": FaultRequirement(bins=frozenset({"python"})),
    "cpu.burst": FaultRequirement(bins=frozenset({"python"})),
    "mem.freeze": FaultRequirement(bins=frozenset({"python"})),
    "mem.swap_pressure": FaultRequirement(bins=frozenset({"python"})),
    "fs.fill": FaultRequirement(bins=frozenset({"python"})),
    "fs.inode_exhaust": FaultRequirement(bins=frozenset({"python"})),
    "fs.io_stress": FaultRequirement(bins=frozenset({"python"})),
    "fs.quota": FaultRequirement(bins=frozenset({"python"})),
    "fs.write_delay": FaultRequirement(bins=frozenset({"python"})),
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
    "net.corrupt": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.congestion": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "dependency.timeout": FaultRequirement(bins=frozenset({"tc"}), caps=frozenset({"NET_ADMIN"})),
    "net.load": FaultRequirement(bins=frozenset({"k6"}), host=True),
    "http.error_injection": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "http.upstream_timeout": FaultRequirement(
        bins=frozenset({"python", "iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "app.response_5xx": FaultRequirement(
        bins=frozenset({"python", "iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "net.connection_reset": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "net.connection_refuse": FaultRequirement(
        bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})
    ),
    "db.slow_query": FaultRequirement(bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})),
    "db.query_error": FaultRequirement(bins=frozenset({"iptables"}), caps=frozenset({"NET_ADMIN"})),
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
        "process.restart_delay",
        "cpu.throttle",
        "node.service_stop",
    }
)

_CATALOG_ONLY_FAULTS = frozenset(
    {
        "dependency.malformed_response",
        "fs.permission_failure",
        "process.startup_delay",
    }
)

#: Faults whose recovery probe cannot see the live perturbation. The generic
#: "recovery probe inverted during the window" observation is therefore
#: inconclusive for these families, and must not be read as "no impact".
#: Terminate faults (process.stop/kill) blind the probe too: the post-kill
#: world (process gone) is indistinguishable from the post-recovery world, so
#: the observation is inconclusive rather than "no impact".
OBSERVATION_BLIND: frozenset[str] = frozenset({"proc.pause", "process.stop", "process.kill"})

#: Package-manager binaries probed so the CLI can tell the user — and offer to
#: run — the right ``<pm> install`` command when a fault's tooling is missing.
#: ``package_manager()`` resolves the first present manager (priority order).
_PACKAGE_MANAGERS = ("apt-get", "apk", "dnf", "yum", "microdnf", "zypper")
#: In-container binaries a fault family may need. ``k6`` is deliberately absent:
#: ``net.load`` drives the container from the drill host, so it is gated there
#: (``host=True``) and never shows up in container dependency management.
_PROBE_BINS: tuple[str, ...] = (
    "kill",
    "tc",
    "iptables",
    "python",
    "python3",
    "date",
    "sh",
    *_PACKAGE_MANAGERS,
)

#: Host-side tooling required by some fault family, checked once via
#: ``shutil.which`` (cached). Container ``mayhem dependency`` only reports these,
#: never installs them.
_HOST_TOOL_BINS: tuple[str, ...] = ("k6",)


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

    def package_manager(self) -> str | None:
        """First package-manager binary present, in priority order.

        ``apt-get`` (Debian/Ubuntu), ``apk`` (Alpine), ``dnf`` (Fedora/RHEL9),
        ``yum`` (RHEL7/8), ``microdnf`` (minimal RHEL/UBI), ``zypper`` (SUSE).
        """
        for pm in _PACKAGE_MANAGERS:
            if self.has_bin(pm):
                return pm
        return None


_PROBE_SH = (
    "printf 'BINS'"
    + "".join(
        f"; printf ' {b}:%s' \"$(command -v {b} >/dev/null 2>&1 && echo 1 || echo 0)\""
        for b in _PROBE_BINS
    )
    + "; echo; printf 'UID %s\\n' \"$(id -u 2>/dev/null || echo -1)\";"
    + " printf 'CAPEFF %s\\n' \"$(awk '/CapEff/{print $2}' /proc/1/status 2>/dev/null || echo 0)\""
)

_BINS_RE = re.compile(r"BINS((?:\s+[a-z0-9-]+:[01])+)")
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


@functools.lru_cache(maxsize=32)
def _host_bin_present(name: str) -> bool:
    """Cached host ``which`` check (host tooling, e.g. k6 for net.load)."""
    return shutil.which(name) is not None


def host_tooling_gaps(plan: ExecutionPlan) -> list[str]:
    """Host-side binaries the plan needs but the drill host lacks (e.g. k6).

    Container ``mayhem dependency`` reports these but never installs them —
    the load generator lives on the host, not in a distro package.
    """
    needed: set[str] = set()
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        requirement = REQUIREMENTS.get(fault.fault_id)
        if requirement is not None and requirement.host:
            needed.update(requirement.bins)
    return sorted(b for b in needed if not _host_bin_present(b))


@dataclass(frozen=True)
class GateVerdict:
    """Per fault/container: can the injection physically take effect?"""

    fault_id: str
    container: str
    impact_possible: bool
    missing: tuple[str, ...] = ()
    probed: bool = True
    host: bool = False
    note: str = ""


@functools.lru_cache(maxsize=8)
def _engine_is_rootless(engine: str) -> bool:
    """True when the container engine runs rootless (userns).

    A rootless engine maps container roots onto unprivileged host uids inside a
    user namespace. That makes two fault families *physically* impossible no
    matter what the container reports:

    * ``CAP_SYS_TIME`` in the container's ``CapEff`` is only meaningful inside
      its userns. Setting the host-global ``CLOCK_REALTIME`` (``clock.skew`` →
      ``date -u -s``) needs ``CAP_SYS_TIME`` in the *initial* user namespace,
      which a rootless engine never grants — time namespaces do not virtualize
      the realtime clock. The kernel returns ``EPERM`` (``login: cannot set
      date: Operation not permitted``) even when ``CAP_SYS_TIME`` is set.

      The container has no way to fake a $(date) read; the fault is inert by
      construction. Probing ``CapEff`` is not enough: the bit reads as present.

    Detection reuses the engine's own ``info`` output. Best-effort — any
    failure (engine missing, odd output) returns False (assume rootful), so a
    detection hiccup never *blocks* a fault that could work.
    """
    try:
        result = subprocess.run(
            [engine, "info", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    try:
        info = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    host = info.get("host") or {}
    security = host.get("security") or {}
    if isinstance(security, dict) and "rootless" in security:
        return bool(security["rootless"])
    # docker: rootless mode surfaces as a userns/rootless security option
    # (podman nests it under host.security; docker keeps access at top level).
    options = host.get("securityOptions") or info.get("SecurityOptions") or []
    return "userns" in " ".join(options) or "rootless" in " ".join(options)


def _gate_sys_time_for_rootless(
    fault_id: str, container: str, engine: str, requirement: FaultRequirement
) -> GateVerdict | None:
    """Rootless engines cannot set CLOCK_REALTIME: reject SYS_TIME faults.

    The container reports ``CAP_SYS_TIME`` (its userns grants the bit) but the
    realtime clock is host-global — setting it demands host-root privilege a
    rootless engine never provides. Treat such a fault as inert (probed) so the
    execution layer bypasses it fail-safe instead of running a doomed inject.
    Returns ``None`` when the fault is unaffected by rootlessness.
    """
    if "SYS_TIME" not in requirement.caps or not _engine_is_rootless(engine):
        return None
    return GateVerdict(
        fault_id,
        container,
        False,
        probed=True,
        note=(
            "rootless engine: container CAP_SYS_TIME is namespaced; "
            "setting the host CLOCK_REALTIME is denied (EPERM)"
        ),
    )


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
        note = (
            "catalog-only: no supported executor; planner refuses before execution"
            if fault_id in _CATALOG_ONLY_FAULTS
            else "no in-image tooling required"
        )
        return GateVerdict(
            fault_id,
            container,
            fault_id not in _CATALOG_ONLY_FAULTS,
            probed=fault_id in _CATALOG_ONLY_FAULTS,
            note=note,
        )
    if requirement.host:
        return _gate_host_requirement(fault_id, container, requirement)
    rootless_gate = _gate_sys_time_for_rootless(fault_id, container, engine, requirement)
    if rootless_gate is not None:
        return rootless_gate
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


def _gate_host_requirement(
    fault_id: str, container: str, requirement: FaultRequirement
) -> GateVerdict:
    """Host-addressed requirements (e.g. net.load → k6 on the drill host).

    The container is irrelevant here: whether the fault perturbs depends on
    host-side attack tooling. No container probe runs, so nothing about this
    verdict can leak into container dependency planning.
    """
    missing = [f"bin:{b}" for b in sorted(requirement.bins) if not _host_bin_present(b)]
    possible = not missing
    note = "" if possible else f"missing host tooling: {', '.join(missing)}"
    return GateVerdict(fault_id, container, possible, tuple(missing), host=True, note=note)


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
        if fault.fault_id in _CATALOG_ONLY_FAULTS:
            verdicts.append(gate_fault(fault.fault_id, "catalog-only", engine))
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
        requirement = REQUIREMENTS.get(fault.fault_id)
        if requirement is not None and requirement.host:
            # Host-addressed fault (net.load → k6): the container runtime is
            # irrelevant, so we never probe it and never count it as engine
            # reachability.
            verdicts.append(gate_fault(fault.fault_id, container, engine))
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


# ── Missing-tooling remediation ─────────────────────────────────────────────
# The gate marks a fault inert when its in-image tooling is absent. The bins a
# fault family needs map onto distro packages; the right <pm> is detected from
# the live container (package_manager()). Bare-metal knowledge:
#   python  → python3  (the probe treats python|python3 as one requirement)
#   tc      → iproute2  (Debian/Alpine/SUSE) / iproute (RHEL-family)
#   kill    → procps(-ng)  (kill(1) lives in the process-utils package)
#   date    → coreutils
#   sh      → dash / busybox / bash depending on the family
# ``k6`` ships in no distro repo (net.load needs the Grafana k6 binary), so it
# is reported as a manual step, never auto-installed.
_PM_PACKAGES: dict[str, dict[str, str]] = {
    "python": dict.fromkeys(_PACKAGE_MANAGERS, "python3"),
    "tc": {
        "apt-get": "iproute2",
        "apk": "iproute2",
        "dnf": "iproute",
        "yum": "iproute",
        "microdnf": "iproute",
        "zypper": "iproute2",
    },
    "iptables": dict.fromkeys(_PACKAGE_MANAGERS, "iptables"),
    "kill": {
        "apt-get": "procps",
        "apk": "procps",
        "dnf": "procps-ng",
        "yum": "procps-ng",
        "microdnf": "procps-ng",
        "zypper": "procps",
    },
    "date": dict.fromkeys(_PACKAGE_MANAGERS, "coreutils"),
    "sh": {
        "apt-get": "dash",
        "apk": "busybox",
        "dnf": "bash",
        "yum": "bash",
        "microdnf": "bash",
        "zypper": "bash",
    },
}
#: Bins whose package cannot be installed from a distro repo. Reported as a
#: manual step with guidance instead of being auto-installed. (Host-side tools
#: like k6 are not listed here — they are covered by ``host=True`` gating and
#: reported via ``host_tooling_gaps()``, never as container packages.)
_MANUAL_BINS: dict[str, str] = {}

#: Engine-manager → ``<pm> install`` sub-command shape. ``apt-get`` also needs
#: an ``update`` pass first (best-effort; a missing index fails loudly).
#: ``microdnf`` only exists in minimal RHEL-family images and is its own binary
#: (not a dnf flag).


def _install_argv(
    engine: str, container: str, pm: str, packages: Sequence[str], *, as_root: bool
) -> list[list[str]]:
    """Exec argv list that installs ``packages`` inside ``container``.

    Each inner list is one standalone ``engine exec`` invocation so the CLI can
    report per-command results. ``as_root`` prefixes ``--user 0`` when the probe
    showed the container's default user is non-root (package managers need
    write access to system dirs).
    """
    prefix = [engine, "exec", container]
    if as_root:
        prefix += ["--user", "0"]
    if pm == "apt-get":
        return [
            [*prefix, "apt-get", "update"],
            [*prefix, "apt-get", "install", "-y", *packages],
        ]
    if pm == "apk":
        return [[*prefix, "apk", "add", "--no-cache", *packages]]
    if pm in ("dnf", "yum", "microdnf"):
        return [[*prefix, pm, "install", "-y", *packages]]
    if pm == "zypper":
        return [[*prefix, "zypper", "-n", "install", *packages]]
    return []


@dataclass(frozen=True)
class ContainerDependencyPlan:
    """Everything the CLI needs to restore a container's fault tooling."""

    container: str
    engine: str
    pm: str | None
    #: Installable package names, deduplicated and sorted ('' when pm is None).
    packages: tuple[str, ...] = ()
    #: The missing bin names those packages provide (verification probe targets).
    bins: tuple[str, ...] = ()
    #: Bins with no auto-installable package — printed as guidance
    #: (e.g. a container with no package manager at all).
    manual: tuple[str, ...] = ()
    #: cap:* requirements the gate flagged — must be granted at runtime, e.g.
    #: ``podman run --cap-add=NET_ADMIN``; never installable in-image.
    caps_missing: tuple[str, ...] = ()
    #: A gated fault also needs uid(0); package installs are attempted as root.
    need_root: bool = False

    @property
    def installable(self) -> bool:
        return bool(self.packages)

    @property
    def gaps_remain(self) -> bool:
        return not (self.installable or self.manual or self.caps_missing or self.need_root)

    def install_argv(self) -> list[list[str]]:
        if self.pm is None or not self.packages:
            return []
        return _install_argv(
            self.engine, self.container, self.pm, self.packages, as_root=self.need_root
        )


def dependency_plan(
    plan: ExecutionPlan, graph: TopologyGraph, engine: str
) -> list[ContainerDependencyPlan]:
    """Union the missing tooling over every planned fault, per container.

    One plan per container that hosts at least one gated-out fault. The plan
    carries the detected package manager, the installable package list, and the
    non-installable gaps (caps need a runtime flag, a container without a
    package manager can only be re-provisioned at image build time, uid(0)
    faults need a root exec). Host-addressed faults (``net.load`` → k6 on the
    drill host) are outside container dependency management — see
    ``host_tooling_gaps()``. Containers that are healthy for every planned
    fault — or unreachable — produce no entry.
    """
    runtimes: dict[str, ContainerRuntime | None] = {}
    missing_by: dict[str, set[str]] = {}
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        requirement = REQUIREMENTS.get(fault.fault_id)
        if requirement is not None and requirement.host:
            continue  # host-addressed tooling (k6) — not a container dependency
        container = _container_for(graph, fault)
        if container is None:
            continue
        if container not in runtimes:
            runtimes[container] = probe_container_runtime(engine, container)
        run = runtimes[container]
        if run is None:
            continue  # unreachable — cannot plan tooling for it
        verdict = gate_fault(fault.fault_id, container, engine, run)
        if verdict.impact_possible:
            continue
        missing_by.setdefault(container, set()).update(verdict.missing)
    plans: list[ContainerDependencyPlan] = []
    for container in sorted(missing_by):
        run = runtimes[container]
        missing = sorted(missing_by[container])
        pm = run.package_manager() if run else None
        packages: set[str] = set()
        bin_map: dict[str, str] = {}
        manual: list[str] = []
        caps_missing = [m for m in missing if m.startswith("cap:")]
        need_root = "uid(0)" in missing
        for item in missing:
            if not item.startswith("bin:"):
                continue
            bin_name = item.split(":", 1)[1]
            mapping = _PM_PACKAGES.get(bin_name, {})
            pkg = mapping.get(pm) if pm else None
            if pkg is not None:
                packages.add(pkg)
                bin_map[bin_name] = pkg
                continue
            manual.append(bin_name)
        plans.append(
            ContainerDependencyPlan(
                container=container,
                engine=engine,
                pm=pm,
                packages=tuple(sorted(packages)),
                bins=tuple(sorted(bin_map)),
                manual=tuple(sorted(set(manual))),
                caps_missing=tuple(caps_missing),
                need_root=need_root,
            )
        )
    return plans


@dataclass(frozen=True)
class ContainerCompilePlan:
    """Offline (no runtime probe) tooling a compose service must carry.

    Produced by ``compile_requirements``: the union of every fault family's
    requirements for the container across the whole drill plan. Unlike
    ``ContainerDependencyPlan`` this is state-independent — it is the join of
    the plan, not a diff against a live container. Host-addressed tooling
    (``net.load`` → k6) never lands here.
    """

    container: str
    #: Bins the planned faults require *and* that map to distro packages.
    bins: tuple[str, ...] = ()
    #: Capability names the service must be started with (bare, e.g.
    #: ``"NET_ADMIN"`` — maps straight onto compose ``cap_add:``).
    caps: tuple[str, ...] = ()
    #: Bins with no mapped distro package — reported, never compile-able.
    manual: tuple[str, ...] = ()


def compile_requirements(plan: ExecutionPlan, graph: TopologyGraph) -> list[ContainerCompilePlan]:
    """Union the tooling requirements per container over the whole plan.

    The compose compiler needs the *requirement* set, not the diff against a
    possibly-unstarted stack: the generated ``docker-compose.mayhem.yml`` must
    carry the tooling before any container runs. Host-addressed faults are
    skipped — they can never be compiled into a service definition.
    """
    bins_by: dict[str, set[str]] = {}
    caps_by: dict[str, set[str]] = {}
    manual_by: dict[str, set[str]] = {}
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        requirement = REQUIREMENTS.get(fault.fault_id)
        if requirement is None or requirement.host:
            continue
        container = _container_for(graph, fault)
        if container is None:
            continue
        manual = {b for b in requirement.bins if b not in _PM_PACKAGES}
        bins = {b for b in requirement.bins if b in _PM_PACKAGES}
        bins_by.setdefault(container, set()).update(bins)
        manual_by.setdefault(container, set()).update(manual)
        caps_by.setdefault(container, set()).update(requirement.caps)
    plans: list[ContainerCompilePlan] = []
    for container in sorted(set(bins_by) | set(caps_by) | set(manual_by)):
        plans.append(
            ContainerCompilePlan(
                container=container,
                bins=tuple(sorted(bins_by.get(container, ()))),
                caps=tuple(sorted(caps_by.get(container, ()))),
                manual=tuple(sorted(manual_by.get(container, ()))),
            )
        )
    return plans
