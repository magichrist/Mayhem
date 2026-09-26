"""Persistence for game-day sessions (v0.9.0 expansion task 17).

Deliberately a separate table from ``campaigns``: a game day is a human
activity with its own approvals and freeze window, and mixing the two would let
a campaign status imply a session approval.
"""

from __future__ import annotations

from typing import Any

from mayhem.domain.game_day import GameDaySession
from mayhem.infra.store import Store


class GameDayRepository:
    def __init__(self, store: Store) -> None:
        self._store = store

    def save(self, session: GameDaySession, *, now: str = "") -> GameDaySession:
        stamp = now or session.updated_at or _now()
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO game_day_sessions "
                "(id, name, state, session_json, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (
                    session.id,
                    session.name,
                    session.state.value,
                    session.model_dump_json(),
                    session.created_at or stamp,
                    stamp,
                ),
            )
        return session.model_copy(update={"updated_at": stamp})

    def load(self, session_id: str) -> GameDaySession | None:
        rows = self._store.query(
            "SELECT session_json FROM game_day_sessions WHERE id = ?", (session_id,)
        )
        if not rows:
            return None
        return GameDaySession.model_validate_json(str(dict(rows[0])["session_json"]))

    def list_sessions(self) -> tuple[GameDaySession, ...]:
        rows = self._store.query(
            "SELECT session_json FROM game_day_sessions ORDER BY created_at DESC, id"
        )
        return tuple(
            GameDaySession.model_validate_json(str(dict(row)["session_json"])) for row in rows
        )

    def delete(self, session_id: str) -> bool:
        with self._store.write() as conn:
            cursor = conn.execute("DELETE FROM game_day_sessions WHERE id = ?", (session_id,))
        return bool(cursor.rowcount)


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
