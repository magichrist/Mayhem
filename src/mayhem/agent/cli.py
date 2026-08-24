"""``mayhem-agent serve`` — ndjson JSON-RPC session over stdio (ADR-0003).

The agent never binds sockets. The controller spawns this process, locally or
over ``ssh <host> -- mayhem-agent serve``, and speaks the protocol on stdin.
"""

from __future__ import annotations

import typer

from mayhem.agents.executors import NoopExecutor, ProcPauseExecutor
from mayhem.agents.server import serve_sync

app = typer.Typer(help="mayhem fault-injection agent.")


def _builtin_executors() -> tuple[ProcPauseExecutor, NoopExecutor]:
    return (ProcPauseExecutor(), NoopExecutor())


@app.callback()
def _root() -> None:
    """mayhem-agent: controller-spawned fault agent."""


@app.command()
def serve(
    roles: str = typer.Option("proc,fs", "--roles", help="Comma-separated role names."),
) -> None:
    """Serve one JSON-RPC session on stdin/stdout until EOF."""
    role_tuple = tuple(r.strip() for r in roles.split(",") if r.strip())
    serve_sync(roles=role_tuple, executors=_builtin_executors())


if __name__ == "__main__":
    app()
