"""ADR-M2 Phase 2.5 — cancellation escalation ladder + CancellationToken."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from mayhem.domain.cancellation import CancellationLevel, CancellationToken

if TYPE_CHECKING:
    from pathlib import Path


class TestCancellationLevel:
    def test_ladder_orders_monotonically(self) -> None:
        assert CancellationLevel.NONE < CancellationLevel.GRACE
        assert CancellationLevel.GRACE < CancellationLevel.TERM
        assert CancellationLevel.TERM < CancellationLevel.KILL

    def test_next_walks_the_ladder(self) -> None:
        assert CancellationLevel.NONE.next == CancellationLevel.GRACE
        assert CancellationLevel.GRACE.next == CancellationLevel.TERM
        assert CancellationLevel.TERM.next == CancellationLevel.KILL
        assert CancellationLevel.KILL.next is None

    def test_str_is_lowercase(self) -> None:
        assert str(CancellationLevel.TERM) == "term"


class TestCancellationToken:
    def test_starts_none(self) -> None:
        token = CancellationToken()
        assert token.level == CancellationLevel.NONE
        assert not token.cancelled
        assert not token.is_kill

    def test_request_raises_level(self) -> None:
        token = CancellationToken()
        assert token.request(CancellationLevel.TERM)
        assert token.level == CancellationLevel.TERM
        assert token.cancelled
        assert not token.is_kill

    def test_request_never_lowers(self) -> None:
        token = CancellationToken(CancellationLevel.KILL)
        assert not token.request(CancellationLevel.GRACE)
        assert token.level == CancellationLevel.KILL

    def test_escalate_steps_up(self) -> None:
        token = CancellationToken()
        assert token.escalate() == CancellationLevel.GRACE
        assert token.escalate() == CancellationLevel.TERM
        assert token.escalate() == CancellationLevel.KILL
        assert token.escalate() == CancellationLevel.KILL  # ceiling
        assert token.is_kill


def _mk_engine(tmp_path: Path):
    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "tg.db")
    sink = SQLiteLeaseSink(store)
    return store, RunEngine(store, sink)


class TestEngineLadder:
    def test_grace_aborts_without_signaling_payloads(self, tmp_path: Path) -> None:
        """A grace-level cancellation stops at the next boundary but does NOT
        SIGTERM live payload processes (cooperative safe-abort)."""
        _store, engine = _mk_engine(tmp_path)
        engine._cancellation.request(CancellationLevel.GRACE)
        signaled: list[tuple[int, int]] = []

        def fake_send(pid, level, cont, engine_):
            del cont, engine_
            signaled.append((pid, level))

        with patch.object(engine, "_send_payload_signal", fake_send):
            assert engine._abort_requested()
        assert signaled == []

    def test_term_signals_payload_pids(self, tmp_path: Path) -> None:
        """TERM sends SIGTERM to every live payload pid carried by active
        leases."""
        from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
        from mayhem.infra.lease_repository import SQLiteLeaseSink

        store, engine = _mk_engine(tmp_path)
        sink = SQLiteLeaseSink(store)
        lease = FaultLease(
            id="l-1",
            fault_id="f1",
            run_id="r1",
            step_id="s1",
            owner_agent="ag-test",
            targets=frozenset({"n-proc"}),
            state=LeaseState.ACTIVE,
            undo_ops=(
                UndoOp(op="signal", args={"pid": "4242", "cont": "c-a", "engine": "podman"}),
            ),
            verify_probes=(VerifyProbe(probe="proc", args={"pid": "4242"}),),
        )
        sink.save(lease)
        engine._cancellation.request(CancellationLevel.TERM)
        sent: list[tuple[int, str]] = []

        def fake_send(pid, level, cont, engine_):
            del level, cont, engine_
            sent.append(pid)

        with patch.object(engine, "_send_payload_signal", fake_send):
            assert engine._abort_requested()
        assert sent == [4242]

    def test_kill_signals_payload_pids(self, tmp_path: Path) -> None:
        from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
        from mayhem.infra.lease_repository import SQLiteLeaseSink

        store, engine = _mk_engine(tmp_path)
        sink = SQLiteLeaseSink(store)
        lease = FaultLease(
            id="l-1",
            fault_id="f1",
            run_id="r1",
            step_id="s1",
            owner_agent="ag-test",
            targets=frozenset({"n-proc"}),
            state=LeaseState.ACTIVE,
            undo_ops=(UndoOp(op="signal", args={"pid": "77"}),),
            verify_probes=(VerifyProbe(probe="proc", args={"pid": "77"}),),
        )
        sink.save(lease)
        engine._cancellation.request(CancellationLevel.KILL)
        sent: list[tuple[int, str]] = []

        def fake_send(pid, level, cont, engine_):
            del level, cont, engine_
            sent.append(pid)

        with patch.object(engine, "_send_payload_signal", fake_send):
            assert engine._abort_requested()
        assert sent == [77]

    def test_send_payload_signal_terminates_on_term(self, tmp_path: Path) -> None:
        """Host-addressed payload gets SIGTERM on TERM, SIGKILL on KILL."""
        import signal

        _store, engine = _mk_engine(tmp_path)
        from mayhem.domain.cancellation import CancellationLevel

        sigs: list[int] = []
        with patch(
            "mayhem.controller.executor.os.kill", side_effect=lambda pid, sig: sigs.append(sig)
        ):
            engine._send_payload_signal(9999, CancellationLevel.TERM, None, None)
            engine._send_payload_signal(10000, CancellationLevel.KILL, None, None)
        assert sigs == [signal.SIGTERM, signal.SIGKILL]

    def test_abort_file_escalates_to_kill(self, tmp_path: Path) -> None:
        """Legacy abort file path still works: presence requests KILL."""
        _store, engine = _mk_engine(tmp_path)
        from mayhem.domain.cancellation import CancellationLevel

        abort = tmp_path / "run.abort"
        abort.write_text("stop")
        engine._abort_file = abort
        assert engine._abort_requested()
        assert engine._cancellation.level == CancellationLevel.KILL
