"""Payload compensation templates (ADR-0020): undo ops + injected source."""

import json
import re

from mayhem.controller.compensation import _payload_source, _payload_undo_ops, template_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.topology import ProcessNode, ServiceNode


def _mem_fault(amount: float = 0.0, percent: float = 60.0) -> PlannedFault:
    params: dict[str, object] = {"amount": amount} if amount > 0 else {"percent": percent}
    return PlannedFault(fault_id="mem.exhaust", targets=(), params=params, duration=10.0)


def test_mem_exhaust_amount_binding() -> None:
    source = _payload_source(_mem_fault(amount=256 * 1024 * 1024), "/tmp/mayhem.t.pid")
    assert "amount = 268435456" in source
    assert re.search(r"goal = amount if amount > 0", source)
    assert "min(goal, lim * 95 // 100)" in source


def test_mem_exhaust_percent_fallback() -> None:
    source = _payload_source(_mem_fault(percent=40), "/tmp/mayhem.t.pid")
    assert re.search(r"^amount = 0$", source, re.M)
    assert "percent = 40" in source
    assert re.search(r"goal = amount if amount > 0", source)


def test_payload_marks_pid_before_alloc() -> None:
    source = _payload_source(_mem_fault(amount=1024 * 1024), "/tmp/mayhem.t.pid")
    assert "open('/tmp/mayhem.t.pid', 'w').write(str(os.getpid()))" in source
    assert "chunks.append(bytearray(4 * 2 ** 20))" in source


def test_holding_payloads_survive_interpreter_eof() -> None:
    """Faults that hold until undo must not die when ``python -c`` hits EOF."""
    params = {"dur": 0, "duration": 0, "percent": "80", "limit": "64", "amount": "1"}
    for fid in ("cpu.saturate", "fd.exhaust", "fs.fill", "mem.exhaust"):
        fault = PlannedFault(
            fault_id=fid, targets=(), undo_ops=(), verify_probes=(),
            params={k: v for k, v in params.items() if k in ("percent", "amount", "limit")},
            duration=8.0,
        )
        source = _payload_source(fault, "/tmp/mayhem.t.pid")
        assert "time.sleep(3600)" in source, f"{fid} must keep the interpreter alive"


def test_burst_payloads_keep_main_thread_for_window() -> None:
    """load.spike / fuzz.protocol_abuse must sleep through their blast window."""
    for fid in ("load.spike", "fuzz.protocol_abuse"):
        fault = PlannedFault(
            fault_id=fid, targets=(), undo_ops=(), verify_probes=(), params={}, duration=8.0
        )
        source = _payload_source(fault, "/tmp/mayhem.t.pid")
        assert re.search(r"time\.sleep\(8\.0\)", source)


def test_cpu_burner_releases_the_gil() -> None:
    """cpu.saturate must use GIL-releasing C work so N threads pin N cores."""
    fault = PlannedFault(
        fault_id="cpu.saturate", targets=(), undo_ops=(), verify_probes=(),
        params={"percent": "100"}, duration=8.0,
    )
    source = _payload_source(fault, "/tmp/mayhem.t.pid")
    assert "hashlib.sha256" in source
    assert "threading.Thread" in source


def test_payload_undo_addressed_via_service_in_blueprint_only_topology() -> None:
    fault = _mem_fault(percent=60)
    ops = _payload_undo_ops(
        fault,
        (
            ServiceNode(id="svc-api", name="api", container_name="testcase-api"),
            ProcessNode(
                id="p-api", name="api", pid=4242, host_id="h1", container_name=None
            ),
        ),
    )
    assert ops[0].op == "payload.undo"
    assert ops[0].args["pid"] == "svc-api:@live-pid"


def _tool_fault(fault_id: str, **params: object) -> PlannedFault:
    return PlannedFault(fault_id=fault_id, targets=(), params=params or {}, duration=10.0)


def _svc_api() -> tuple[ServiceNode, ProcessNode]:
    return (
        ServiceNode(id="svc-api", name="api", container_name="testcase-api"),
        ProcessNode(id="p-api", name="api", pid=4242, host_id="h1", container_name=None),
    )


def _build(fid: str, **params: object):
    return template_for(fid).build(_tool_fault(fid, **params), _svc_api())


def test_tool_net_latency_binds_delay_and_address() -> None:
    ops, probes = _build("net.latency", seconds=2, jitter_ms=10)
    assert len(ops) == 1 and len(probes) == 1
    op = ops[0]
    assert op.op == "tc.del_qdisc"
    assert op.args["pid"] == "svc-api:@live-pid"
    inject = json.loads(op.args["inject_argv"])
    undo = json.loads(op.args["undo_argv"])
    assert inject[:3] == ["@engine", "exec", "@cont"]
    assert "delay" in inject and "2000ms" in inject and "10ms" in inject
    assert undo[3] == "tc" and "del" in undo


def test_tool_partition_and_slow_query_are_netfilter_reversible() -> None:
    for fid in ("net.partition", "db.slow_query"):
        ops, probes = _build(fid, seconds=5) if fid == "db.slow_query" else _build(fid)
        assert len(ops) == 1 and len(probes) == 1
        inject = json.loads(ops[0].args["inject_argv"])
        undo = json.loads(ops[0].args["undo_argv"])
        assert inject[:3] == ["@engine", "exec", "@cont"]
        assert inject != undo
        assert "iptables" in inject or "tc" in inject


def test_tool_net_load_saturates_with_k6_and_pid_marker() -> None:
    ops, probes = _build("net.load", users=8, url="http://api/health")
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject[:3] == ["@engine", "exec", "@cont"]
    assert "k6 run -u 8 -d 10s" in inject[-1]
    assert "http://api/health" in inject[-1]
    assert "load.js" in inject[-1]
    assert "kill" in undo[-1] and "rm -f" in undo[-1]
    probe = probes[0]
    assert probe.probe == "exec"
    assert "load.js" in probe.args["cmd"][-1] and "k6.pid" in probe.args["cmd"][-1]


def test_tool_engine_restart_families_verify_via_inspect() -> None:
    for fid, inject_verb in (
        ("container.kill", "kill"),
        ("node.service_stop", "stop"),
    ):
        ops, probes = _build(fid, signal="SIGTERM") if fid == "container.kill" else _build(fid)
        assert len(ops) == 1 and len(probes) == 1
        inject = json.loads(ops[0].args["inject_argv"])
        undo = json.loads(ops[0].args["undo_argv"])
        assert inject[:3] == ["@engine", inject_verb, "--signal"] or inject[:3] == [
            "@engine", inject_verb, "@cont",
        ]
        assert undo == ["@engine", "start", "@cont"]
        probe = probes[0]
        assert probe.probe == "exec"
        assert probe.args["pid"] == "svc-api:@live-pid"


def test_tool_http_error_injection_rejects_and_probes_absent() -> None:
    ops, probes = _build("http.error_injection", status=500)
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert "REJECT" in inject and "tcp-reset" in inject
    assert inject != undo
    assert "--dport 80" in probes[0].args["cmd"][-1]


def test_tool_dns_nxdomain_binds_domain_param() -> None:
    ops, probes = _build("dns.nxdomain", domain="internal.example")
    inject = json.loads(ops[0].args["inject_argv"])
    assert "127.0.0.1 internal.example" in inject[-1]
    undo = json.loads(ops[0].args["undo_argv"])
    assert "mv -f" in undo[-1]
    marker = probes[0].args["cmd"][-1].split(" ")[-1]
    assert marker in undo[-1]
    assert marker.startswith("/tmp/mayhem.dns-nxdomain-svc-api.orig")


def test_tool_marker_families_restore_original_file() -> None:
    for fid, params in (
        ("dns.resolve_delay", {"seconds": 5}),
        ("tls.certificate_expired", {}),
        ("clock.skew", {"offset_ms": 60000}),
    ):
        ops, probes = _build(fid, **params)
        assert len(ops) == 1 and len(probes) == 1
        inject = json.loads(ops[0].args["inject_argv"])
        undo = json.loads(ops[0].args["undo_argv"])
        # inject backs up (or snapshots clock epoch); undo restores + deletes marker
        assert "cp " in inject[-1] or "date -u" in inject[-1]
        assert (("mv -f" in undo[-1]) or ("date -u -s" in undo[-1])) and "rm -f" in undo[-1]
        marker = probes[0].args["cmd"][-1].split(" ")[-1]
        assert marker in undo[-1]


def test_tool_clock_skew_applies_offset_from_param() -> None:
    ops, _ = _build("clock.skew", offset_ms=60000)
    inject = json.loads(ops[0].args["inject_argv"])
    assert "+ 60000" in inject[-1]
    assert "@$target" in inject[-1]


def test_tool_template_refuses_without_container_address() -> None:
    fault = _tool_fault("net.latency", seconds=2)
    nodes = (ServiceNode(id="svc-http", name="http", container_name=None),)
    try:
        template_for("net.latency").build(fault, nodes)
    except InvariantViolationError:
        return
    raise AssertionError("expected NO_UNDO for a containerless node pool")
