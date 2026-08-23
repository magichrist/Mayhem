"""Environment fingerprinting — the 'same environment' predicate (run contract).

A run's ``environment_fingerprint`` must change whenever anything that could
alter fault outcomes changes: OS, arch, python, controller version, or the
version/output of any chaos backend present on the host.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from tgondi.toolkit.hashing import digest
from tgondi.toolkit.tool_runner import ToolResult, run_tool

CONTROLLER_VERSION = "0.1.0"

_PROBED_TOOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("docker", ("docker", "--version")),
    ("kubectl", ("kubectl", "version", "--client=true", "-o", "json")),
    ("tc", ("tc", "-Version")),
    ("iptables", ("iptables", "--version")),
    ("stress-ng", ("stress-ng", "--version")),
)


def build_fingerprint(tool_versions: dict[str, str | None]) -> str:
    """Pure hash over the environment descriptor."""
    descriptor: dict[str, Any] = {
        "controller_version": CONTROLLER_VERSION,
        "os": platform.system(),
        "os_release": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "tools": dict(sorted(tool_versions.items())),
    }
    return digest(descriptor)


def collect_tool_versions(
    probed: tuple[tuple[str, tuple[str, ...]], ...] = _PROBED_TOOLS,
) -> tuple[dict[str, str | None], list[ToolResult]]:
    """Probe known backends; missing tools are recorded as None, never fatal."""
    versions: dict[str, str | None] = {}
    evidence: list[ToolResult] = []
    for name, argv in probed:
        try:
            result = run_tool(argv, timeout_s=10)
        except Exception:  # noqa: BLE001 — a missing tool is an expected outcome
            versions[name] = None
            continue
        if result.succeeded or result.exit_code is not None:
            first_line = result.stdout.strip().splitlines()
            versions[name] = first_line[0][:200] if first_line else result.stderr[:200]
        else:
            versions[name] = None
        evidence.append(result)
    return versions, evidence


def current_fingerprint() -> str:
    versions, _ = collect_tool_versions()
    return build_fingerprint(versions)


def interpreter_marker() -> str:
    """Cheap identity of this python process; used by agent heartbeats."""
    return f"python-{sys.version_info.major}.{sys.version_info.minor}"
