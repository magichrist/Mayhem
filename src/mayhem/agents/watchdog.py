"""Agent-side watchdog (ADR-0005 §3).

Each agent expires its own leases past TTL and compensates locally, so safety
does not depend on the controller ever coming back. Runs inside the agent
process's event loop; every compensation is reported on stderr and queryable
via ``task.status`` — never written to stdout (protocol frames only).
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.agents.executors import FaultExecutor

DEFAULT_SWEEP_INTERVAL_S = 1.0


class ActiveLease:
    """A fault this agent has injected and still owns."""

    def __init__(
        self,
        *,
        lease: Any,
        executor: FaultExecutor,
        deadline_epoch_s: float,
        task_id: str | None = None,
    ) -> None:
        self.lease = lease
        self.executor = executor
        self.deadline_epoch_s = deadline_epoch_s
        self.task_id = task_id
        self.state = "active"  # active -> compensating -> expired | dirty


class AgentWatchdog:
    """Expires owned leases past TTL and undoes them locally."""

    def __init__(self, *, interval_s: float = DEFAULT_SWEEP_INTERVAL_S) -> None:
        self.interval_s = interval_s
        self._active: dict[str, ActiveLease] = {}
        self._final_states: dict[str, str] = {}
        self._runner: asyncio.Task[None] | None = None
        self.clock: Callable[[], float] = time.time

    def register(
        self,
        *,
        lease_id: str,
        lease: Any,
        executor: FaultExecutor,
        ttl_seconds: float,
        now_epoch_s: float | None = None,
        task_id: str | None = None,
    ) -> float:
        """Track an injected fault; returns its absolute expiry deadline."""
        now = time.time() if now_epoch_s is None else now_epoch_s
        entry = ActiveLease(
            lease=lease,
            executor=executor,
            deadline_epoch_s=now + max(ttl_seconds, 0.0),
            task_id=task_id,
        )
        self._active[lease_id] = entry
        return entry.deadline_epoch_s

    def active_count(self) -> int:
        return len(self._active)

    async def sweep(self, *, now_epoch_s: float | None = None) -> list[str]:
        """Undo every lease past its TTL; returns ids compensated this sweep."""
        now = time.time() if now_epoch_s is None else now_epoch_s
        expired = [lid for lid, e in self._active.items() if e.deadline_epoch_s <= now]
        for lease_id in expired:
            entry = self._active.pop(lease_id)
            entry.state = "compensating"
            try:
                outcome = await asyncio.to_thread(entry.executor.undo, entry.lease)
            except Exception as exc:
                entry.state = "dirty"
                print(
                    f"[watchdog] undo raised for {lease_id}: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                self._final_states[lease_id] = entry.state
                continue
            entry.state = "expired" if outcome.ok else "dirty"
            self._final_states[lease_id] = entry.state
            print(
                f"[watchdog] {entry.state} {lease_id}: {outcome.detail}",
                file=sys.stderr,
            )
        return expired

    def final_state(self, lease_id: str) -> str | None:
        """Terminal watchdog state for a compensated lease: expired or dirty."""
        return self._final_states.get(lease_id)

    def history(self) -> list[dict[str, Any]]:
        """Leases this agent already self-compensated (expired|dirty)."""
        return [{"lease_id": lid, "state": state} for lid, state in self._final_states.items()]

    async def run_forever(self) -> None:
        while True:
            await asyncio.sleep(self.interval_s)
            try:
                await self.sweep()
            except Exception as exc:  # a broken sweep must not kill the session
                print(f"[watchdog] sweep error: {exc}", file=sys.stderr)

    def start(self) -> asyncio.Task[None]:
        if self._runner is None or self._runner.done():
            self._runner = asyncio.get_running_loop().create_task(self.run_forever())
        return self._runner

    async def stop(self) -> None:
        if self._runner is not None:
            self._runner.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._runner
            self._runner = None

    def snapshot(self) -> list[dict[str, Any]]:
        now = self.clock()
        return [
            {
                "lease_id": lid,
                "state": e.state,
                "expires_in_s": round(e.deadline_epoch_s - now, 3),
                "task_id": e.task_id,
            }
            for lid, e in self._active.items()
        ]
