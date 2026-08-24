"""SQLiteLeaseSink: durable lease protocol half — round trips and sweeps."""
from datetime import timedelta
from pathlib import Path

from mayhem.domain.common import utc_now
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store


def _lease(state: LeaseState = LeaseState.PENDING, **over: object) -> FaultLease:
    payload: dict[str, object] = {
        "id": "l-round",
        "run_id": "r-1",
        "fault_id": "proc.pause",
        "owner_agent": "ag-x",
        "targets": {"n-proc"},
        "undo_ops": (UndoOp(op="signal.cont", args={"pid": "42"}),),
        "verify_probes": (
            VerifyProbe(probe="exec", args={"cmd": ["true"], "timeout_s": 5}, expect_present=True),
        ),
        "ttl_seconds": 30.0,
        "state": state,
    }
    payload.update(over)
    return FaultLease.model_validate(payload)


def _sink(tmp_path: Path) -> SQLiteLeaseSink:
    store = Store.open_migrated(tmp_path / "tg.db")
    return SQLiteLeaseSink(store)


class TestRoundTrip:
    def test_save_then_load_preserves_everything(self, tmp_path: Path) -> None:
        sink = _sink(tmp_path)
        original = _lease()
        sink.save(original)
        loaded = sink.load("l-round")
        assert loaded == original

    def test_active_leases_exclude_terminals(self, tmp_path: Path) -> None:
        sink = _sink(tmp_path)
        sink.save(_lease(LeaseState.RELEASED, id="l-done"))
        sink.save(_lease(LeaseState.EXPIRED, id="l-gone"))
        sink.save(_lease(LeaseState.ACTIVE, id="l-live"))
        active = {lease.id for lease in sink.active_leases()}
        assert active == {"l-live"}

    def test_expired_pending_finds_stale_only(self, tmp_path: Path) -> None:
        sink = _sink(tmp_path)
        fresh = _lease(id="l-fresh")
        stale = _lease(
            id="l-stale", created_at=utc_now() - timedelta(seconds=120), ttl_seconds=10.0
        )
        sink.save(fresh)
        sink.save(stale)
        found = {lease.id for lease in sink.expired_pending(utc_now().timestamp())}
        assert found == {"l-stale"}

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        assert _sink(tmp_path).load("l-nope") is None

    def test_overwrite_same_id(self, tmp_path: Path) -> None:
        sink = _sink(tmp_path)
        sink.save(_lease())
        sink.save(_lease().transition(LeaseState.ACTIVE))
        loaded = sink.load("l-round")
        assert loaded is not None
        assert loaded.state is LeaseState.ACTIVE
