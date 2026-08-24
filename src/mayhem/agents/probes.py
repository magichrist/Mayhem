"""Verify probes — proof the world returned to normal (or that it didn't).

A probe result is evidence, not a judgement; ``satisfied`` is computed from
``expect_present`` so negative probes (chain absent) work identically to
positive ones (service healthy).
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.toolkit.tool_runner import run_tool

if TYPE_CHECKING:
    from mayhem.domain.leases import VerifyProbe


@dataclass(frozen=True)
class ProbeResult:
    probe: str
    satisfied: bool
    detail: str

    def to_row(self, lease_id: str) -> dict[str, object]:
        return {
            "lease_id": lease_id,
            "probe": self.probe,
            "satisfied": int(self.satisfied),
            "detail": self.detail,
        }


def _arg_float(args: dict[str, object], key: str, default: float) -> float:
    raw = args.get(key)
    if not isinstance(raw, (int, float, str)) or isinstance(raw, bool):
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _arg_str_list(args: dict[str, object], key: str) -> list[str] | None:
    value = args.get(key)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


@dataclass(frozen=True)
class VerifyReport:
    results: tuple[ProbeResult, ...]

    @property
    def all_satisfied(self) -> bool:
        return bool(self.results) and all(r.satisfied for r in self.results)


def _run_exec(args: dict[str, object]) -> ProbeResult:
    cmd = _arg_str_list(args, "cmd")
    if cmd is None or not cmd:
        return ProbeResult("exec", False, "exec probe requires cmd: list[str]")
    result = run_tool(cmd, timeout_s=_arg_float(args, "timeout_s", 10.0))
    return ProbeResult(
        "exec",
        result.succeeded,
        f"exit={result.exit_code} stderr={result.stderr[:120]!r}",
    )


def _run_tcp(args: dict[str, object]) -> ProbeResult:
    host = str(args.get("host", "127.0.0.1"))
    raw_port = args.get("port")
    if not isinstance(raw_port, int):
        return ProbeResult("tcp.open", False, "tcp probe requires port:int")
    timeout = _arg_float(args, "timeout_s", 3.0)
    try:
        with socket.create_connection((host, raw_port), timeout=timeout):
            return ProbeResult("tcp.open", True, f"{host}:{raw_port} accepted")
    except OSError as exc:
        return ProbeResult("tcp.open", False, f"{host}:{raw_port} refused ({exc})")


def _run_http(args: dict[str, object]) -> ProbeResult:
    url = str(args.get("url", ""))
    expected_raw = args.get("expect_status", 200)
    if not isinstance(expected_raw, int):
        return ProbeResult("http.status", False, "expect_status must be an int")
    timeout = _arg_float(args, "timeout_s", 5.0)
    if not url.startswith(("http://", "https://")):
        return ProbeResult("http.status", False, f"bad url {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, OSError) as exc:
        return ProbeResult("http.status", False, f"{url} unreachable ({exc})")
    return ProbeResult("http.status", status == expected_raw, f"{url} -> {status}")


_HANDLERS = {
    "exec": _run_exec,
    "tcp": _run_tcp,
    "http": _run_http,
}


def run_probe(probe: VerifyProbe) -> ProbeResult:
    handler = _HANDLERS.get(probe.probe.split(".", 1)[0])
    if handler is None:
        return ProbeResult(probe.probe, False, f"unknown probe kind {probe.probe!r}")
    observed = handler(dict(probe.args))
    # expect_present=True  → want the thing to exist → satisfied iff observed.
    # expect_present=False → want absence (e.g. chain gone) → satisfied iff NOT.
    satisfied = observed.satisfied if probe.expect_present else not observed.satisfied
    return ProbeResult(probe.probe, satisfied, observed.detail)


def verify_all(probes: tuple[VerifyProbe, ...], lease_id: str) -> VerifyReport:
    """Run every probe; never raises — a crashing probe is a failed probe."""
    results = []
    for probe in probes:
        try:
            results.append(run_probe(probe))
        except Exception as exc:  # probe crashes are evidence too
            results.append(ProbeResult(probe.probe, False, f"probe crashed: {exc}"))
    return VerifyReport(tuple(results))
