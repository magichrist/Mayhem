"""Janitor: TTL sweeps — expire stale pending, recover orphaned active faults."""

from datetime import timedelta

from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.controller.janitor import Janitor
from mayhem.domain.common import utc_now
from mayhem.domain.leases import FaultLease, LeaseState


def _lease(state: LeaseState, *, age_s: float = 0.0, ttl: float = 60.0) -> FaultLease:
    return FaultLease.model_validate(
        {
            "id": f"l-{state.value}-{int(age_s)}",
            "run_id": "r-j",
            "fault_id": "proc.pause",
            "owner_agent": "ag-j",
            "targets": ["n1"],
            "undo_ops": ({"op": "noop", "args": {}},),
            "verify_probes": (
                {"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": True},
            ),
            "ttl_seconds": ttl,
            "state": state,
            "created_at": utc_now() - timedelta(seconds=age_s),
        }
    )


def _janitor_with(*leases: FaultLease) -> tuple[Janitor, InMemoryLeaseSink]:
    sink = InMemoryLeaseSink()
    for lease in leases:
        sink.save(lease)
    return Janitor(sink), sink


class TestSweep:
    def test_fresh_leases_untouched(self) -> None:
        janitor, sink = _janitor_with(_lease(LeaseState.PENDING), _lease(LeaseState.ACTIVE))
        result = janitor.sweep(now_epoch_s=utc_now().timestamp())
        assert result.quiet
        states = {ls.id: ls.state for ls in sink.active_leases()}
        assert len(states) == 2  # both still non-terminal

    def test_stale_pending_expires_without_undo(self) -> None:
        janitor, sink = _janitor_with(_lease(LeaseState.PENDING, age_s=120.0, ttl=60.0))
        result = janitor.sweep()
        assert result.expired == ("l-pending-120",)
        assert not result.recovered
        loaded = sink.load("l-pending-120")
        assert loaded is not None
        assert loaded.state is LeaseState.EXPIRED

    def test_stale_active_recovered_through_release_path(self) -> None:
        janitor, sink = _janitor_with(_lease(LeaseState.ACTIVE, age_s=300.0, ttl=60.0))
        result = janitor.sweep()
        assert result.recovered == ("l-active-300",)
        released = sink.load("l-active-300")
        assert released is not None
        assert released.state is LeaseState.RELEASED
        assert released.release_mechanism == "janitor"

    def test_sink_failure_reports_dirty_instead_of_silence(self) -> None:
        class ExplodingSink(InMemoryLeaseSink):
            def save(self, lease):
                if lease.state is LeaseState.RELEASING:
                    raise OSError("sink unavailable")
                super().save(lease)

        sink = ExplodingSink()
        sink.save(_lease(LeaseState.ACTIVE, age_s=300.0, ttl=60.0))
        result = Janitor(sink).sweep()
        assert result.recovered == ()
        assert result.dirty == ("l-active-300",)
        # lease honestly recorded as unrecoverable, not silently released
        stranded = sink.load("l-active-300")
        assert stranded is not None
        assert stranded.state is LeaseState.DIRTY
        assert "sink unavailable" in str(stranded.escalation_notes)
