"""Controller-side transports for agent sessions (ADR-0003).

Both transports spawn the same wire protocol; only the launcher differs.
- ``LocalStdioTransport`` spawns ``mayhem-agent serve`` as a child process.
- ``SSHTransport`` runs a persistent ``ssh … -- mayhem-agent serve`` exec channel
  using the system OpenSSH client (no asyncssh dependency).
Agents never listen on sockets — every session is controller-initiated.

Reconnect policy: exponential backoff with jitter. Channel loss does NOT cancel
in-flight faults; leases survive independently (ADR-0005) and the controller
re-synchronizes via capabilities.query + task.status after reconnecting.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any

RECONNECT_BASE_DELAY_S = 0.5
RECONNECT_MAX_DELAY_S = 30.0


@dataclass(frozen=True)
class SessionSpec:
    """Everything needed to (re)spawn one agent session."""

    roles: tuple[str, ...] = ("proc", "fs")
    agent_command: str = "mayhem-agent"  # overridable for tests / non-PATH installs


class Transport:
    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


class LocalStdioTransport(Transport):
    def __init__(self, spec: SessionSpec | None = None) -> None:
        self._spec = spec or SessionSpec()
        self._process: asyncio.subprocess.Process | None = None

    def _argv(self) -> list[str]:
        return [
            self._spec.agent_command,
            "serve",
            "--roles",
            ",".join(self._spec.roles),
        ]

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        self._process = await asyncio.create_subprocess_exec(
            *self._argv(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # agent logs flow to our stderr for local debugging
        )
        assert self._process.stdin is not None and self._process.stdout is not None
        return self._process.stdout, self._process.stdin

    def describe(self) -> str:
        return f"local:{self._spec.agent_command}"


class SSHTransport(Transport):
    """Persistent ``ssh -o ControlMaster=auto -o ControlPersist=600 host -- <agent> serve``."""

    def __init__(self, target: str, spec: SessionSpec | None = None) -> None:
        self._target = target  # user@host or host
        self._spec = spec or SessionSpec()
        self._process: asyncio.subprocess.Process | None = None

    def argv(self) -> list[str]:
        remote = f"{self._spec.agent_command} serve --roles {','.join(self._spec.roles)}"
        return [
            "ssh",
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPersist=600",
            self._target,
            "--",
            remote,
        ]

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        self._process = await asyncio.create_subprocess_exec(
            *self.argv(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
        )
        assert self._process.stdin is not None and self._process.stdout is not None
        return self._process.stdout, self._process.stdin

    def describe(self) -> str:
        return f"ssh:{self._target}"


@dataclass
class ReconnectingSession:
    """Connect with exponential backoff + jitter until success or max attempts."""

    transport: Transport
    attempts: int = 8
    base_delay_s: float = RECONNECT_BASE_DELAY_S
    max_delay_s: float = RECONNECT_MAX_DELAY_S
    _rng: random.Random = field(default_factory=random.Random)

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int]:
        delay = self.base_delay_s
        last_error: Exception | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                reader, writer = await self.transport.connect()
                return reader, writer, attempt
            except (OSError, ProcessLookupError) as exc:
                last_error = exc
                jittered = delay * self._rng.uniform(0.5, 1.5)
                await asyncio.sleep(jittered)
                delay = min(delay * 2, self.max_delay_s)
        msg = f"could not reach {self.transport.describe()} after {self.attempts} attempts"
        raise ConnectionError(msg) from last_error


def session_for(target: str | None, roles: tuple[str, ...], **kwargs: Any) -> Transport:
    """Factory: ``None`` → local child process; ``user@host`` → SSH exec channel."""
    spec = SessionSpec(roles=roles, **kwargs)
    if target is None:
        return LocalStdioTransport(spec)
    return SSHTransport(target, spec)
