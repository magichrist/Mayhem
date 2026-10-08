"""`kubectl mayhem` — thin client over the 08 control-plane API (plan 02 Phase 3).

Thin by contract: this plugin never plans, never admits, never executes. It
reads a CR file (or a drill YAML) and hands the bytes to the control plane —
``POST /api/v1/plans`` compiles through the CLI's planner,
``GET /api/v1/runs`` lists, ``POST /api/v1/runs/{run_id}/stop`` stops — then
renders the response. Every decision stays server-side, where the 08 gateway's
authenticate → authorize → validate → dispatch order applies.

Usage (as a kubectl plugin, `kubectl-mayhem` on PATH)::

    kubectl mayhem plan -f mayhem-drill.yaml [--server URL] [--token TOKEN]
    kubectl mayhem get runs [--server URL]
    kubectl mayhem stop run <run-id> [--server URL]
    kubectl mayhem health [--server URL]

Server and token come from flags or ``MAYHEM_SERVER`` / ``MAYHEM_TOKEN``.
No live cluster is needed to unit-test this module: request construction is
pure (:func:`build_request`), and the tests assert on it, never on a socket.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

API_PREFIX = "/api/v1"

DEFAULT_SERVER = "http://127.0.0.1:8080"


@dataclass(frozen=True)
class PluginRequest:
    """A rendered HTTP request: method, URL, and optional JSON body."""

    method: str
    url: str
    body: dict[str, object] | None = None
    token: str = ""

    def to_urllib(self) -> urllib.request.Request:
        """The real request object. The only I/O-adjacent code in this module."""
        data = json.dumps(self.body).encode("utf-8") if self.body is not None else None
        request = urllib.request.Request(self.url, data=data, method=self.method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        return request


def _server(value: str | None) -> str:
    return (value or os.environ.get("MAYHEM_SERVER") or DEFAULT_SERVER).rstrip("/")


def _token(value: str | None) -> str:
    return value or os.environ.get("MAYHEM_TOKEN") or ""


def build_plan_request(
    drill_file: str | Path, *, server: str | None = None, token: str | None = None
) -> PluginRequest:
    """``kubectl mayhem plan -f FILE`` → ``POST /api/v1/plans``.

    The file is read, never interpreted: the gateway compiles it through the
    CLI planner, so a client-side parse would be a second validator drifting
    from the first. A missing/unreadable file is a CLI usage error, raised
    before any request exists.
    """
    path = Path(drill_file)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"kubectl mayhem: cannot read {path}: {exc}") from None
    return PluginRequest(
        method="POST",
        url=f"{_server(server)}{API_PREFIX}/plans",
        body={"drill_yaml": text, "source": "kubectl-mayhem"},
        token=_token(token),
    )


def build_list_runs_request(
    *, server: str | None = None, token: str | None = None
) -> PluginRequest:
    """``kubectl mayhem get runs`` → ``GET /api/v1/runs``."""
    return PluginRequest(
        method="GET", url=f"{_server(server)}{API_PREFIX}/runs", token=_token(token)
    )


def build_stop_request(
    run_id: str, *, server: str | None = None, token: str | None = None
) -> PluginRequest:
    """``kubectl mayhem stop run ID`` → ``POST /api/v1/runs/{id}/stop``."""
    if not run_id.strip():
        raise SystemExit("kubectl mayhem: `stop run` needs a run id")
    return PluginRequest(
        method="POST",
        url=f"{_server(server)}{API_PREFIX}/runs/{run_id}/stop",
        body={},
        token=_token(token),
    )


def build_health_request(*, server: str | None = None, token: str | None = None) -> PluginRequest:
    """``kubectl mayhem health`` → ``GET /api/v1/health``."""
    return PluginRequest(
        method="GET", url=f"{_server(server)}{API_PREFIX}/health", token=_token(token)
    )


def send(request: PluginRequest, *, timeout_s: float = 30.0) -> object:
    """Perform the request and return the decoded JSON body (or raw text)."""
    try:
        with urllib.request.urlopen(request.to_urllib(), timeout=timeout_s) as response:
            payload = response.read().decode("utf-8")
    except OSError as exc:
        raise SystemExit(f"kubectl mayhem: request failed: {exc}") from None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload


def build_parser() -> argparse.ArgumentParser:
    """The plugin's CLI surface. Every subcommand maps to one API route."""
    parser = argparse.ArgumentParser(prog="kubectl mayhem", description=__doc__)
    parser.add_argument("--server", default=None, help="Control-plane base URL")
    parser.add_argument("--token", default=None, help="Bearer token (or MAYHEM_TOKEN)")
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="Compile a drill/CR file into a frozen plan")
    plan.add_argument("-f", "--file", required=True, help="Drill YAML or MayhemDrill CR")

    get = sub.add_parser("get", help="Read resources")
    get.add_argument("resource", choices=["runs"], help="Resource to list")

    stop = sub.add_parser("stop", help="Stop a run")
    stop.add_argument("resource", choices=["run"], help="Resource kind")
    stop.add_argument("run_id", help="Run id to stop")

    sub.add_parser("health", help="Control-plane liveness")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `kubectl-mayhem` shim. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "plan":
        request = build_plan_request(args.file, server=args.server, token=args.token)
    elif args.command == "get":
        request = build_list_runs_request(server=args.server, token=args.token)
    elif args.command == "stop":
        request = build_stop_request(args.run_id, server=args.server, token=args.token)
    elif args.command == "health":
        request = build_health_request(server=args.server, token=args.token)
    else:  # pragma: no cover — argparse `required=True` refuses this first
        raise SystemExit(f"kubectl mayhem: unknown command {args.command!r}")
    print(json.dumps(send(request), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover — exercised through main()
    sys.exit(main())


__all__ = (
    "API_PREFIX",
    "PluginRequest",
    "build_health_request",
    "build_list_runs_request",
    "build_parser",
    "build_plan_request",
    "build_stop_request",
    "main",
    "send",
)
