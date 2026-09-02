"""Agent SDK: lease lifecycle, executors, probes — behavior under real processes."""

import json
import socket
import subprocess  # tests spawn their own fixtures
import sys
import time

import pytest

from mayhem.agents.executors import (
    EXECUTORS,
    PayloadExecutor,
    ProcPauseExecutor,
    ToolExecutor,
    executor_for,
)
from mayhem.agents.lease_client import LeaseClient, LeaseConflictError
from mayhem.agents.probes import run_probe, verify_all
from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.domain.errors import InvalidTransitionError
from mayhem.domain.leases import FaultLease, LeaseState, VerifyProbe


def _client(agent_id: str = "ag-test") -> LeaseClient:
    return LeaseClient(InMemoryLeaseSink(), agent_id=agent_id)


def _acquire(client: LeaseClient, targets: tuple[str, ...] = ("n1",)) -> FaultLease:
    return client.acquire(
        run_id="r-1",
        fault_id="proc.pause",
        targets=set(targets),
        undo_ops=({"op": "signal.cont", "args": {"pid": "4242"}, "idempotent": True},),
        verify_probes=({"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": False},),
    )


class TestLeaseLifecycle:
    def test_full_happy_path(self) -> None:
        client = _client()
        lease = _acquire(client)
        assert lease.state is LeaseState.PENDING

        activated = client.activate(lease.id)
        assert activated.state is LeaseState.ACTIVE

        releasing = client.mark_releasing(activated.id)
        assert releasing.state is LeaseState.RELEASING

        released = client.confirm_release(releasing.id, mechanism="normal")
        assert released.state is LeaseState.RELEASED
        assert released.release_mechanism == "normal"
        assert released.is_safe_terminal

    def test_dirty_path_requires_notes(self) -> None:
        client = _client()
        lease = client.activate(_acquire(client).id)
        releasing = client.mark_releasing(lease.id)
        dirty = client.mark_dirty(releasing.id, notes="undo failed: EPERM")
        assert dirty.state is LeaseState.DIRTY
        assert not dirty.is_safe_terminal
        assert dirty.escalation_notes == "undo failed: EPERM"

    def test_target_conflict_between_agents(self) -> None:
        shared = InMemoryLeaseSink()
        first = LeaseClient(shared, agent_id="ag-a")
        second = LeaseClient(shared, agent_id="ag-b")
        first.acquire(run_id="r-1", fault_id="cpu.burn", targets={"svc-1"}, undo_ops=())
        with pytest.raises(LeaseConflictError, match="svc-1"):
            second.acquire(run_id="r-1", fault_id="mem.pressure", targets={"svc-1"}, undo_ops=())

    def test_disjoint_targets_do_not_conflict(self) -> None:
        shared = InMemoryLeaseSink()
        first = LeaseClient(shared, agent_id="ag-a")
        second = LeaseClient(shared, agent_id="ag-b")
        first.acquire(run_id="r-1", fault_id="cpu.burn", targets={"svc-1"}, undo_ops=())
        second.acquire(run_id="r-1", fault_id="mem.pressure", targets={"svc-2"}, undo_ops=())

    def test_stale_lease_past_ttl_is_reaped_not_conflicted(self) -> None:
        """A crashed run's past-TTL lease must not wedge later runs."""
        from datetime import timedelta

        shared = InMemoryLeaseSink()
        first = LeaseClient(shared, agent_id="ag-a")
        stale = first.acquire(run_id="r-1", fault_id="cpu.burn", targets={"svc-1"}, undo_ops=())
        aged = stale.model_copy(update={"created_at": stale.created_at - timedelta(seconds=200)})
        shared.save(aged)
        second = LeaseClient(shared, agent_id="ag-b")
        lease = second.acquire(
            run_id="r-2", fault_id="mem.pressure", targets={"svc-1"}, undo_ops=()
        )
        assert lease.targets == {"svc-1"}
        assert shared.load(stale.id).state is LeaseState.EXPIRED

    def test_live_lease_within_ttl_still_conflicts(self) -> None:
        shared = InMemoryLeaseSink()
        first = LeaseClient(shared, agent_id="ag-a")
        first.acquire(run_id="r-1", fault_id="cpu.burn", targets={"svc-1"}, undo_ops=())
        with pytest.raises(LeaseConflictError, match="svc-1"):
            LeaseClient(shared, agent_id="ag-b").acquire(
                run_id="r-1", fault_id="mem.pressure", targets={"svc-1"}, undo_ops=()
            )

    def test_unknown_lease_raises_key_error(self) -> None:
        with pytest.raises(KeyError):
            _client().activate("l-does-not-exist")

    def test_illegal_transition_propagates_domain_error(self) -> None:
        client = _client()
        lease = _acquire(client)  # PENDING
        # PENDING → RELEASED is not in the transition table.
        with pytest.raises(InvalidTransitionError):
            client.confirm_release(lease.id, mechanism="manual")

    def test_active_leases_filters_terminals(self) -> None:
        client = _client()
        done = client.activate(_acquire(client).id)
        client.mark_releasing(done.id)
        client.confirm_release(done.id, mechanism="normal")
        live = client.activate(_acquire(client).id)
        assert [lease.id for lease in client.active_leases()] == [live.id]

    def test_owner_agent_stamped_on_lease(self) -> None:
        lease = _acquire(_client("ag-special"))
        assert lease.owner_agent == "ag-special"


class TestProcPauseExecutor:
    def test_pause_and_resume_a_real_process(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
        )
        try:
            executor = ProcPauseExecutor()
            lease = FaultLease.model_validate(
                {
                    "id": "l-exec",
                    "run_id": "r-1",
                    "fault_id": "proc.pause",
                    "owner_agent": "ag-t",
                    "targets": ["n1"],
                    "undo_ops": ({"op": "signal.cont", "args": {"pid": str(child.pid)}},),
                    "verify_probes": (),
                }
            )

            injected = executor.inject(lease)
            assert injected.ok
            assert _process_state(child.pid) == "T"

            undone = executor.undo(lease)
            assert undone.ok
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and _process_state(child.pid) == "T":
                time.sleep(0.05)
            assert _process_state(child.pid) != "T"
        finally:
            child.kill()
            child.wait()

    def test_inject_without_pid_fails_cleanly(self) -> None:
        lease = FaultLease.model_validate(
            {
                "id": "l-nopid",
                "run_id": "r-1",
                "fault_id": "proc.pause",
                "owner_agent": "ag-t",
                "targets": ["n1"],
                "verify_probes": (),
            }
        )
        outcome = ProcPauseExecutor().inject(lease)
        assert not outcome.ok
        assert "no usable pid" in outcome.detail

    def test_undo_dead_pid_is_success(self) -> None:
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        pid = str(dead.pid)
        dead.wait()  # now gone
        lease = FaultLease.model_validate(
            {
                "id": "l-dead",
                "run_id": "r-1",
                "fault_id": "proc.pause",
                "owner_agent": "ag-t",
                "targets": ["n1"],
                "undo_ops": ({"op": "signal.cont", "args": {"pid": pid}},),
                "verify_probes": (),
            }
        )
        outcome = ProcPauseExecutor().undo(lease)
        assert outcome.ok


class TestDispatchAndToolExecutors:
    def test_executor_dispatch_table(self) -> None:
        assert isinstance(executor_for("proc.pause"), ProcPauseExecutor)
        assert isinstance(executor_for("fuzz.protocol_abuse"), PayloadExecutor)
        assert isinstance(executor_for("load.spike"), PayloadExecutor)
        assert isinstance(executor_for("mem.exhaust"), PayloadExecutor)
        assert isinstance(executor_for("net.latency"), ToolExecutor)
        assert executor_for("quantum.decohere") is None

    def test_every_registered_prefix_is_claimable(self) -> None:
        claimed: set[str] = set()
        for executor in EXECUTORS:
            claimed |= set(executor.prefixes)
        for prefix in ("net", "cpu", "mem", "disk", "container", "node", "http", "db"):
            assert prefix in claimed

    def test_tool_executor_round_trip_with_real_tools(self) -> None:
        executor = ToolExecutor()
        lease = FaultLease.model_validate(
            {
                "id": "l-tool",
                "run_id": "r-1",
                "fault_id": "net.latency",
                "owner_agent": "ag-t",
                "targets": ["n1"],
                "undo_ops": (
                    {
                        "op": "custom.argv",
                        "args": {
                            "inject_argv": json.dumps([sys.executable, "-c", "print('injecting')"]),
                            "undo_argv": json.dumps([sys.executable, "-c", "pass"]),
                        },
                    },
                ),
                "verify_probes": (),
            }
        )
        injected = executor.inject(lease)
        assert injected.ok and injected.tool_result is not None
        assert "injecting" in injected.tool_result.stdout
        undone = executor.undo(lease)
        assert undone.ok

    def test_tool_executor_missing_argv_is_failure_not_crash(self) -> None:
        lease = FaultLease.model_validate(
            {
                "id": "l-noargv",
                "run_id": "r-1",
                "fault_id": "disk.fill",
                "owner_agent": "ag-t",
                "targets": ["n1"],
                "verify_probes": (),
            }
        )
        assert not ToolExecutor().inject(lease).ok
        assert not ToolExecutor().undo(lease).ok


class TestProbes:
    def test_exec_probe_success_and_failure(self) -> None:
        good = VerifyProbe(
            probe="exec",
            args={"cmd": [sys.executable, "-c", "pass"]},
            expect_present=True,
        )
        bad = VerifyProbe(
            probe="exec",
            args={"cmd": [sys.executable, "-c", "import sys; sys.exit(7)"]},
            expect_present=True,
        )
        assert run_probe(good).satisfied
        assert not run_probe(bad).satisfied

    def test_expect_present_inverts_semantics(self) -> None:
        absent_cmd = VerifyProbe(
            probe="exec",
            args={"cmd": [sys.executable, "-c", "import sys; sys.exit(1)"]},
            expect_present=False,
        )
        # Command fails → the thing we want absent IS absent → satisfied.
        assert run_probe(absent_cmd).satisfied

        present_cmd = VerifyProbe(
            probe="exec",
            args={"cmd": [sys.executable, "-c", "pass"]},
            expect_present=False,
        )
        assert not run_probe(present_cmd).satisfied

    def test_tcp_probe_against_live_and_closed_ports(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port: int = listener.getsockname()[1]
        try:
            open_probe = VerifyProbe(
                probe="tcp.open",
                args={"host": "127.0.0.1", "port": port},
                expect_present=True,
            )
            assert run_probe(open_probe).satisfied
        finally:
            listener.close()
        closed_absent = VerifyProbe(
            probe="tcp.open",
            args={"host": "127.0.0.1", "port": 1},  # nothing listens on 1
        )
        assert run_probe(closed_absent).satisfied  # absence is what we wanted

    def test_unknown_probe_kind_never_satisfies(self) -> None:
        weird = VerifyProbe(probe="teleport.service", args={})
        result = run_probe(weird)
        assert not result.satisfied
        assert "unknown probe kind" in result.detail

    def test_verify_all_tolerates_probe_crashes(self) -> None:
        crashing = VerifyProbe(probe="tcp.open", args={"port": "not-an-int"}, expect_present=True)
        report = verify_all((crashing,), "l-x")
        assert len(report.results) == 1
        assert not report.all_satisfied

    def test_verify_report_all_satisfied(self) -> None:
        good = VerifyProbe(
            probe="exec",
            args={"cmd": [sys.executable, "-c", "pass"]},
            expect_present=True,
        )
        assert verify_all((good,), "l-x").all_satisfied


def _process_state(pid: int) -> str:
    """First letter of `ps` STAT — 'T' when SIGSTOPped ('+' suffix = fg group)."""
    out = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip()[:1]


class TestToolExecutorTokenAddressing:
    def test_dispatch_covers_tool_compensated_families(self) -> None:
        for fid in (
            "dns.resolve_delay",
            "dns.nxdomain",
            "clock.skew",
        ):
            assert isinstance(executor_for(fid), ToolExecutor)

    def test_container_tokens_rewritten_from_live_address(self) -> None:
        executor = ToolExecutor()
        lease = FaultLease.model_validate(
            {
                "id": "l-tok",
                "run_id": "r-1",
                "fault_id": "dns.resolve_delay",
                "owner_agent": "ag-t",
                "targets": ["n1"],
                "undo_ops": (
                    {
                        "op": "file.revert",
                        "args": {
                            "inject_argv": json.dumps(
                                ["@engine", "exec", "@cont", "sh", "-c", "true"]
                            ),
                            "undo_argv": json.dumps(
                                ["@engine", "exec", "@cont", "sh", "-c", "true"]
                            ),
                            "engine": "podman",
                            "cont": "testcase-api",
                        },
                    },
                ),
                "verify_probes": (),
            }
        )
        assert executor._argv_for(lease, "inject_argv") == [
            "podman",
            "exec",
            "testcase-api",
            "sh",
            "-c",
            "true",
        ]

    def test_unaddressed_tokens_survive_verbatim(self) -> None:
        executor = ToolExecutor()
        lease = FaultLease.model_validate(
            {
                "id": "l-bare",
                "run_id": "r-1",
                "fault_id": "net.latency",
                "owner_agent": "ag-t",
                "targets": ["n1"],
                "undo_ops": (
                    {
                        "op": "custom.argv",
                        "args": {
                            "inject_argv": json.dumps([sys.executable, "-c", "print('x')"]),
                            "undo_argv": json.dumps([sys.executable, "-c", "pass"]),
                        },
                    },
                ),
                "verify_probes": (),
            }
        )
        assert executor._argv_for(lease, "inject_argv") == [
            sys.executable,
            "-c",
            "print('x')",
        ]
