"""Verify probes — proof the world returned to normal (or that it didn't).

A probe result is evidence, not a judgement; ``satisfied`` is computed from
``expect_present`` so negative probes (chain absent) work identically to
positive ones (service healthy).
"""

from __future__ import annotations

import os
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
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
    engine = args.get("engine")
    cont = args.get("cont")
    if engine and cont:
        # Container-addressed presence check. The resolved pid is a pid inside
        # the runtime VM (podman-machine on macOS), which a host ``ps`` cannot
        # see. ``<engine> inspect`` addresses the container main process across
        # the VM boundary, so a nonzero/inspectable container means "present".
        if args.get("incontainer"):
            argv = [str(engine), "exec", str(cont), *cmd]
            result = run_tool(argv, timeout_s=_arg_float(args, "timeout_s", 10.0))
            detail = f"exec {cont} exit={result.exit_code} stderr={result.stderr[:120]!r}"
            return ProbeResult("exec", result.succeeded, detail)
        argv = [str(engine), "inspect", "--format", "{{.State.Pid}}", str(cont)]
        result = run_tool(argv, timeout_s=_arg_float(args, "timeout_s", 10.0))
        pid = result.stdout.strip()
        present = result.succeeded and pid.isdigit() and int(pid) > 0
        return ProbeResult("exec", present, f"inspect {cont} pid={pid!r}")
    result = run_tool(cmd, timeout_s=_arg_float(args, "timeout_s", 10.0))
    detail = f"exit={result.exit_code} stderr={result.stderr[:120]!r}"
    out = (result.stdout or "").strip()
    if out:
        detail = f"{detail} stdout={out[:120]!r}"
    return ProbeResult("exec", result.succeeded, detail)


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


def _run_process(args: dict[str, object]) -> ProbeResult:
    name = str(args.get("name", ""))
    raw_pid = args.get("pid")
    if raw_pid is not None and not isinstance(raw_pid, bool):
        if isinstance(raw_pid, int):
            pid: int = raw_pid
        elif isinstance(raw_pid, str) and raw_pid.strip().lstrip("-").isdigit():
            pid = int(raw_pid)
        else:
            return ProbeResult("process", False, f"bad pid {raw_pid!r}")
        try:
            os.kill(pid, 0)
            return ProbeResult("process", True, f"pid {pid} alive")
        except OSError:
            return ProbeResult("process", False, f"pid {pid} not running")
    if name:
        result = run_tool(["pgrep", "-f", name], timeout_s=_arg_float(args, "timeout_s", 5.0))
        found = result.succeeded and bool((result.stdout or "").strip())
        return ProbeResult("process", found, f"pgrep {name!r} -> {result.stdout!r}")
    return ProbeResult("process", False, "process probe requires name or pid")


def _run_metric(args: dict[str, object]) -> ProbeResult:  # noqa: PLR0911 (one branch per failure mode)
    endpoint = str(args.get("endpoint", ""))
    query = str(args.get("query", ""))
    if not endpoint:
        return ProbeResult("metric", False, "metric probe requires endpoint")
    try:
        with urllib.request.urlopen(
            endpoint, timeout=_arg_float(args, "timeout_s", 5.0)
        ) as response:
            body = response.read(10_000).decode("utf-8", errors="replace")
    except Exception as exc:
        return ProbeResult("metric", False, f"{endpoint} unreachable ({exc})")
    found = (not query) or (query in body)
    if not found:
        return ProbeResult("metric", False, f"metric {query!r} not present")
    threshold_raw = args.get("threshold")
    threshold_num: float | None = None
    if threshold_raw is not None and not isinstance(threshold_raw, bool) and isinstance(
        threshold_raw, (int, float, str)
    ):
        try:
            threshold_num = float(threshold_raw)
        except ValueError:
            return ProbeResult("metric", False, f"bad threshold {threshold_raw!r}")
    elif threshold_raw is not None and not isinstance(threshold_raw, bool):
        return ProbeResult("metric", False, f"bad threshold {threshold_raw!r}")
    if threshold_num is not None:
        try:
            match = re.search(rf"{re.escape(query)}\s+([-+0-9.eE]+)", body)
            if match is None:
                return ProbeResult("metric", False, f"metric {query!r} lacks a value")
            value = float(match.group(1))
            ok = value >= threshold_num
            return ProbeResult("metric", ok, f"{query}={value} (threshold {threshold_num})")
        except (ValueError, IndexError):
            return ProbeResult("metric", False, f"cannot parse {query!r} value")
    return ProbeResult("metric", True, f"metric {query!r} present")


def _run_file(args: dict[str, object]) -> ProbeResult:
    path = str(args.get("path", ""))
    if not path:
        return ProbeResult("file", False, "file probe requires path")
    p = Path(path)
    if not p.exists():
        return ProbeResult("file", False, f"{path} missing")
    contains = args.get("contains")
    if contains:
        try:
            content = p.read_text(errors="replace")
        except OSError as exc:
            return ProbeResult("file", False, f"{path} unreadable ({exc})")
        if str(contains) not in content:
            return ProbeResult("file", False, f"{path} lacks {contains!r}")
    return ProbeResult("file", True, f"{path} present")


_HANDLERS = {
    "exec": _run_exec,
    "tcp": _run_tcp,
    "http": _run_http,
    "process": _run_process,
    "metric": _run_metric,
    "file": _run_file,
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
