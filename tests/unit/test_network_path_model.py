"""NetworkPath fingerprint and DrillFault backward-compat tests (ADR-M3-7)."""

from __future__ import annotations

from mayhem.domain.experiments import DrillFault
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.resources import ResourceType, TrackedResource
from mayhem.domain.topology import (
    NetworkPath,
    compute_network_fingerprint,
)


def test_networkpath_new_fields_roundtrip() -> None:
    p = NetworkPath(
        src_node_id="svc-api",
        dst_node_id="svc-db",
        protocol="tcp",
        ports=(5432,),
        namespace="net-back",
        interface="eth0",
        direction="incoming",
        fingerprint="abc123",
    )
    assert p.namespace == "net-back"
    assert p.interface == "eth0"
    assert p.protocol == "tcp"
    assert p.ports == (5432,)
    assert p.direction == "incoming"
    assert p.fingerprint == "abc123"


def test_networkpath_defaults() -> None:
    p = NetworkPath(src_node_id="a", dst_node_id="b")
    assert p.protocol == "tcp"
    assert p.ports == ()
    assert p.direction == "both"
    assert p.namespace is None
    assert p.interface is None
    assert p.fingerprint == ""


def test_fingerprint_stability() -> None:
    fp1 = compute_network_fingerprint(src="a", dst="b", namespace="ns", protocol="tcp")
    fp2 = compute_network_fingerprint(src="a", dst="b", namespace="ns", protocol="tcp")
    assert fp1 == fp2
    assert len(fp1) == 16
    assert fp1.isalnum()


def test_fingerprint_differs_on_input() -> None:
    assert compute_network_fingerprint(src="a", dst="b") != compute_network_fingerprint(
        src="b", dst="a"
    )


def test_fingerprint_is_hex() -> None:
    fp = compute_network_fingerprint(src="x", dst="y")
    int(fp, 16)  # raises if not hex


def test_resource_type_network_fault_present() -> None:
    assert ResourceType.NETWORK_FAULT == "network_fault"


def test_trackedresource_fingerprint_field() -> None:
    r = TrackedResource(
        id="r-1",
        resource_type=ResourceType.NETWORK_FAULT,
        owner_run_id="run-1",
        owner_step_id="s-1",
        owner_fault_id="f-1",
        target_identity="h-local",
        cleanup_op=UndoOp(op="tc.del_qdisc", args={"device": "eth0"}),
        verify_probe=VerifyProbe(
            probe="exec", args={"cmd": ["tc", "qdisc", "show"]}, expect_present=False
        ),
        fingerprint="deadbeef",
    )
    assert r.fingerprint == "deadbeef"


def test_drillfault_backward_compat() -> None:
    # Without network_path — still valid.
    f = DrillFault(fault="partition")
    assert f.network_path is None

    # With network_path — round-trips.
    f2 = DrillFault(fault="partition", network_path="svc-a:svc-b")
    assert f2.network_path == "svc-a:svc-b"
