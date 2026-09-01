"""Cancellation escalation ladder (ADR-M2 Phase 2.5).

Users can request abort/cancel of a running run and escalate if the current
mechanism fails. The ladder is monotonic:

    grace  ->  term  ->  kill

* ``grace`` — cooperative, safe-abort at the next checkpoint (between steps /
  fault boundaries). In-flight faults are allowed to finish their undo so the
  run never leaves a mutated system behind.
* ``term`` — SIGTERM to live payload toolkit processes; the engine re-asserts
  after a short grace wait.
* ``kill`` — SIGKILL to payload toolkit processes; immediate abort.

A :class:`CancellationToken` is the shared, thread-safe object the signal
handler escalates and the agent loop reads at every safe point. Levels never
decrease: requesting ``term`` after ``kill`` is a no-op.
"""

from __future__ import annotations

from enum import IntEnum
from threading import Lock

_LADDER: tuple["CancellationLevel", ...] = (
    "grace",
    "term",
    "kill",
)


class CancellationLevel(IntEnum):
    """Monotonic cancellation intensity; IntEnum so ``>=`` comparisons order it."""

    NONE = 0
    GRACE = 1
    TERM = 2
    KILL = 3

    @property
    def next(self) -> CancellationLevel | None:
        idx = int(self)
        nxt = _LADDER[idx] if idx < len(_LADDER) else None
        return CancellationLevel[nxt.upper()] if nxt is not None else None

    def __str__(self) -> str:  # paint nicely in logs/events
        return self.name.lower()


class CancellationToken:
    """Thread-safe cancellation signal readable by the agent loop.

    The level only ever rises. Readers observe ``level`` and the convenience
    flags; the signal layer escalates via :meth:`request` / :meth:`escalate`.
    """

    __slots__ = ("_level", "_lock", "_mutations")

    def __init__(self, level: CancellationLevel = CancellationLevel.NONE) -> None:
        self._level: CancellationLevel = CancellationLevel(level)
        self._lock = Lock()
        self._mutations = 0

    # -- escalation ----------------------------------------------------------

    def request(self, level: CancellationLevel) -> bool:
        """Raise the level to *level* (never lower it). Idempotent.

        Returns ``True`` if the level actually changed.
        """
        level = CancellationLevel(level)
        with self._lock:
            if level > self._level:
                self._level = level
                self._mutations += 1
                return True
            return False

    def escalate(self) -> CancellationLevel:
        """Advance one rung up the ladder; ``kill`` is the ceiling.

        Returns the new (effective) level.
        """
        with self._lock:
            nxt = self._level.next
            if nxt is not None:
                self._level = nxt
                self._mutations += 1
            return self._level

    # -- observation ---------------------------------------------------------

    @property
    def level(self) -> CancellationLevel:
        with self._lock:
            return self._level

    @property
    def cancelled(self) -> bool:
        """True at any non-NONE level — agents must stop cooperative work."""
        return self.level != CancellationLevel.NONE

    @property
    def is_kill(self) -> bool:
        return self.level == CancellationLevel.KILL

    def snapshot(self) -> tuple[CancellationLevel, int]:
        """Atomically read ``(level, mutation_count)`` for change detection."""
        with self._lock:
            return self._level, self._mutations