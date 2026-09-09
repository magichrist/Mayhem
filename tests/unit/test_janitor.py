"""Janitor: TTL sweeps — expire stale pending, recover orphaned active faults."""

from datetime import timedelta

from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.controller.janitor import Janitor
from mayhem.domain.common import utc_now
from mayhem.domain.leases import FaultLease, LeaseState


def _lease(state: LeaseState, *, age_s: float = 0.0, ttl: float = 60.0) -> FaultLease:
    payload: dict[str, object] = {
        "id": f"l-{state.value}-{int(age_s)}",
        "run_id": "r-j",
        "fault_id": "proc.pause",
        "owner_agent": "ag-j",
        "targets": ["n1"],
        "undo_ops": ({"op": "noop", "args": {}},),
        "verify_probes": ({"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": True},),
        "ttl_seconds": ttl,
        "state": state,
        "created_at": utc_now() - timedelta(seconds=age_s),
    }
    if state is LeaseState.DIRTY:
        payload["escalation_notes"] = "compensation failed while sweeping"
    return FaultLease.model_validate(payload)


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

    def test_stale_dirty_surrendered_to_expired(self) -> None:
        # A dirty lease (compensation already failed) must not wedge the
        # targets forever: past TTL the janitor surrenders it to EXPIRED.
        # (DIRTY needs escalation notes from the original failure.)
        dirty = _lease(LeaseState.DIRTY, age_s=300.0, ttl=60.0)
        janitor, sink = _janitor_with(dirty)
        result = janitor.sweep()
        assert result.expired == ("l-dirty-300",)
        assert not result.recovered
        loaded = sink.load("l-dirty-300")
        assert loaded is not None
        assert loaded.state is LeaseState.EXPIRED
        assert loaded.release_mechanism == "janitor"

    def test_stale_orphaned_finalized_to_released(self) -> None:
        janitor, sink = _janitor_with(_lease(LeaseState.ORPHANED, age_s=300.0, ttl=60.0))
        result = janitor.sweep()
        assert result.recovered == ("l-orphaned-300",)
        loaded = sink.load("l-orphaned-300")
        assert loaded is not None
        assert loaded.state is LeaseState.RELEASED
        assert loaded.release_mechanism == "janitor"

    def test_stale_releasing_finalized_to_released(self) -> None:
        # A lease stuck in RELEASING (owner died mid-compensation) has the
        # same recovery path: finalize RELEASED so the targets unblock.
        janitor, sink = _janitor_with(_lease(LeaseState.RELEASING, age_s=300.0, ttl=60.0))
        result = janitor.sweep()
        assert result.recovered == ("l-releasing-300",)
        loaded = sink.load("l-releasing-300")
        assert loaded is not None
        assert loaded.state is LeaseState.RELEASED

    def test_dirty_surrender_failure_reports_dirty(self) -> None:
        class ExplodingSink(InMemoryLeaseSink):
            def save(self, lease):
                if lease.state is LeaseState.EXPIRED:
                    raise OSError("sink unavailable")
                super().save(lease)

        sink = ExplodingSink()
        sink.save(_lease(LeaseState.DIRTY, age_s=300.0, ttl=60.0))
        result = Janitor(sink).sweep()
        assert result.expired == ()
        # captive in DIRTY with the original escalation notes preserved
        stranded = sink.load("l-dirty-300")
        assert stranded is not None
        assert stranded.state is LeaseState.DIRTY


class TestSweepWithRunLiveness:
    """A lease whose owner process is provably gone is reclaimed before TTL."""

    def _resolver(self, dead: set[str] = (), alive: set[str] = ()):
        def resolve(run_id: str) -> bool | None:
            if run_id in dead:
                return False
            if run_id in alive:
                return True
            return None  # unknown — TTL stays in charge

        return resolve

    def test_fresh_active_with_dead_owner_is_recovered(self) -> None:
        lease = _lease(LeaseState.ACTIVE, age_s=0.0, ttl=120.0)  # still 2 min of TTL
        janitor, sink = _janitor_with(lease)
        result = janitor.sweep(
            now_epoch_s=utc_now().timestamp(), run_liveness=self._resolver(dead={"r-j"})
        )
        assert result.recovered == (lease.id,)
        released = sink.load(lease.id)
        assert released is not None
        assert released.state is LeaseState.RELEASED
        assert released.release_mechanism == "janitor"
        assert released.escalation_notes and "reclaimed before TTL" in released.escalation_notes

    def test_fresh_pending_with_dead_owner_expires(self) -> None:
        lease = _lease(LeaseState.PENDING, age_s=0.0, ttl=120.0)
        janitor, sink = _janitor_with(lease)
        result = janitor.sweep(
            now_epoch_s=utc_now().timestamp(), run_liveness=self._resolver(dead={"r-j"})
        )
        assert result.expired == (lease.id,)
        assert sink.load(lease.id).state is LeaseState.EXPIRED

    def test_fresh_lease_with_live_owner_is_untouched(self) -> None:
        lease = _lease(LeaseState.ACTIVE, age_s=0.0, ttl=120.0)
        janitor, sink = _janitor_with(lease)
        result = janitor.sweep(
            now_epoch_s=utc_now().timestamp(), run_liveness=self._resolver(alive={"r-j"})
        )
        assert result.quiet
        assert sink.load(lease.id).state is LeaseState.ACTIVE

    def test_fresh_lease_with_unknown_owner_stays_on_ttl(self) -> None:
        lease = _lease(LeaseState.ACTIVE, age_s=0.0, ttl=120.0)
        janitor, sink = _janitor_with(lease)
        result = janitor.sweep(now_epoch_s=utc_now().timestamp(), run_liveness=self._resolver())
        assert result.quiet
        assert sink.load(lease.id).state is LeaseState.ACTIVE

    def test_no_resolver_keeps_old_ttl_behavior(self) -> None:
        lease = _lease(LeaseState.ACTIVE, age_s=0.0, ttl=120.0)
        janitor, _ = _janitor_with(lease)
        result = janitor.sweep(now_epoch_s=utc_now().timestamp())
        assert result.quiet

    def test_resolver_lookup_error_falls_back_to_ttl(self) -> None:
        lease = _lease(LeaseState.ACTIVE, age_s=0.0, ttl=120.0)

        def explode(_run_id: str) -> bool | None:
            raise LookupError("run row missing")

        janitor, _ = _janitor_with(lease)
        result = janitor.sweep(now_epoch_s=utc_now().timestamp(), run_liveness=explode)
        assert result.quiet
