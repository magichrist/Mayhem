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
            fault_id=fid,
            targets=(),
            undo_ops=(),
            verify_probes=(),
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
        fault_id="cpu.saturate",
        targets=(),
        undo_ops=(),
        verify_probes=(),
        params={"percent": "100"},
        duration=8.0,
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
            ProcessNode(id="p-api", name="api", pid=4242, host_id="h1", container_name=None),
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


def test_tool_net_connection_reset_rejects_with_tcp_reset() -> None:
    ops, probes = _build("net.connection_reset", port=8080)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject[:3] == ["@engine", "exec", "@cont"]
    assert "--dport" in inject and "8080" in inject
    assert "-j" in inject and "REJECT" in inject
    assert "tcp-reset" in inject
    assert "-I" in inject and "-D" in undo


def test_tool_net_connection_refuse_rejects_with_port_unreachable() -> None:
    ops, probes = _build("net.connection_refuse", port=8080)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert "REJECT" in inject and "icmp-port-unreachable" in inject
    assert "-I" in inject and "-D" in undo


def test_tool_net_reorder_uses_tc_netem_reorder_with_delay() -> None:
    ops, probes = _build("net.reorder", percent=30, delay_ms=50)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert "tc" in inject and "qdisc" in inject and "add" in inject
    assert "netem" in inject and "delay" in inject and "50ms" in inject
    assert "reorder" in inject and "30%" in inject
    assert "del" in undo and "root" in undo


def test_tool_net_duplicate_uses_tc_netem_duplicate() -> None:
    ops, probes = _build("net.duplicate", percent=25)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert "netem" in inject and "duplicate" in inject and "25%" in inject
    assert "-I" not in inject and "del" in undo


def test_tool_dependency_connection_refuse_netfilter() -> None:
    ops, probes = _build("dependency.connection_refuse", port=3306)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert "REJECT" in inject and "icmp-port-unreachable" in inject
    assert "--dport" in inject and "3306" in inject
    assert "-I" in inject and "-D" in undo
    probe = probes[0]
    assert probe.probe


def test_tool_fs_read_only_remounts_and_restores_rw() -> None:
    ops, probes = _build("fs.read_only", path="/")
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert "mount -o remount,ro /" in inject
    assert any("remount,rw" in part for part in undo)
    assert any("rwprobe" in part for part in undo)


def test_tool_process_crash_loop_engine_restart_cadence() -> None:
    ops, probes = _build("process.crash_loop", restarts=3, interval="2s")
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert undo[1] == "start" and undo[0] == "@engine" and undo[-1] == "@cont"
    body = inject[-1]
    assert body.startswith("@engine stop @cont; @engine start @cont")
    assert body.count("stop") == 3
    assert body.count("start") == 3
    assert "sleep 2s" in body


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


def test_tool_net_load_with_user_script_embeds_content() -> None:
    source = (
        "import http from 'k6/http';\n"
        "export const options = { vus: __ENV.VU, duration: '120s' };\n"
        "export default function () { http.get('http://10.0.0.5:8080/'); }\n"
    )
    ops, probes = _build("net.load", users=10000, script_content=source)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject[:3] == ["@engine", "exec", "@cont"]
    assert "k6 run -u 10000 -d 10s" in inject[-1]
    assert "http://10.0.0.5:8080/" in inject[-1]
    assert "K6EOF" in inject[-1]
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
            "@engine",
            inject_verb,
            "@cont",
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


# ---------------------------------------------------------------------------
# Phase 6.3 — container.restart / container.pause
# ---------------------------------------------------------------------------


def test_tool_container_restart_uses_engine_restart_and_starts() -> None:
    ops, probes = _build("container.restart")
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject == ["@engine", "restart", "@cont"]
    assert undo == ["@engine", "start", "@cont"]


def test_tool_container_pause_uses_engine_pause_and_unpause() -> None:
    ops, probes = _build("container.pause")
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject == ["@engine", "pause", "@cont"]
    assert undo == ["@engine", "unpause", "@cont"]


# ---------------------------------------------------------------------------
# Phase 6.5 — dependency.block / dependency.timeout
# ---------------------------------------------------------------------------


def test_tool_dep_block_uses_iptables_drop() -> None:
    ops, probes = _build("dependency.block", port=3306, protocol="tcp")
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject[:3] == ["@engine", "exec", "@cont"]
    assert "iptables" in inject
    assert "DROP" in inject
    assert "3306" in inject
    assert "iptables" in undo
    assert "-D" in undo


def test_tool_dep_timeout_uses_tc_netem_delay() -> None:
    ops, probes = _build("dependency.timeout", port=5432, delay_ms=1000)
    assert len(ops) == 1 and len(probes) == 1
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])
    assert inject[:3] == ["@engine", "exec", "@cont"]
    assert "tc" in inject
    assert "delay" in inject
    assert "1000ms" in inject
    assert "tc" in undo
    assert "del" in undo


def test_tool_dep_block_refuses_without_port() -> None:
    from mayhem.domain.catalog import definition_for

    defn = definition_for("dependency.block")
    from mayhem.domain.errors import SchemaValidationError

    try:
        defn.validate_params({})
    except SchemaValidationError:
        return
    raise AssertionError("expected SchemaValidationError for missing required port param")


# ---------------------------------------------------------------------------
# Phase 6.6 — Arsenal regression sweep: every M6 archetype must be
#   * in the catalog,
#   * have a compensation template,
#   * and build valid undo ops for a minimal fault targeting the right node kind.
# ---------------------------------------------------------------------------

# M6 core archetypes and their minimal params + expected node kind.
_M6_ARCHETYPES: dict[str, dict[str, object]] = {
    # Phase 6.1 — Process
    "proc.pause": {"targets": (), "params": {}, "duration": 5.0},
    "process.stop": {"targets": (), "params": {}, "duration": 5.0},
    "process.kill": {"targets": (), "params": {}, "duration": 5.0},
    # Phase 6.2 — Resource pressure
    "cpu.saturate": {"targets": (), "params": {"percent": 50}, "duration": 5.0},
    "mem.exhaust": {"targets": (), "params": {"percent": 30}, "duration": 5.0},
    "fs.fill": {"targets": (), "params": {"percent": 50}, "duration": 5.0},
    # Phase 6.3 — Container lifecycle
    "container.kill": {"targets": (), "params": {}, "duration": 5.0},
    "container.restart": {"targets": (), "params": {}, "duration": 5.0},
    "container.pause": {"targets": (), "params": {}, "duration": 5.0},
    # Phase 6.4 — Network
    "net.latency": {"targets": (), "params": {"seconds": 2}, "duration": 5.0},
    "net.partition": {"targets": (), "params": {}, "duration": 5.0},
    # Phase 6.5 — Dependency / database
    "dependency.block": {"targets": (), "params": {"port": 5432}, "duration": 5.0},
    "dependency.timeout": {
        "targets": (),
        "params": {"port": 5432, "delay_ms": 500},
        "duration": 5.0,
    },
    "db.slow_query": {"targets": (), "params": {"seconds": 3}, "duration": 5.0},
}


def test_arsenal_sweep_every_m6_archetype_has_catalog_entry() -> None:
    from mayhem.domain.catalog import definition_for

    for fault_id in _M6_ARCHETYPES:
        defn = definition_for(fault_id)
        assert defn.id == fault_id


def test_arsenal_sweep_every_m6_archetype_has_compensation_template() -> None:
    for fault_id in _M6_ARCHETYPES:
        tmpl = template_for(fault_id)
        assert tmpl is not None, f"no compensation template for {fault_id}"


def test_arsenal_sweep_every_m6_template_builds_undo_ops() -> None:
    from mayhem.domain.experiments import PlannedFault
    from mayhem.domain.topology import (
        ProcessNode,
        ServiceNode,
    )

    svc = ServiceNode(id="svc-sweep", name="sweep", container_name="test-sweep")
    proc = ProcessNode(
        id="p-sweep", name="sweep", pid=9999, host_id="h1", container_name="test-sweep"
    )
    nodes = (svc, proc)

    # Process faults use PID-based undo ops; payload faults (cpu/mem/fs) use
    # payload.undo ops; tool/container/network/dependency faults use argv pairs.
    pid_based_faults = {"proc.pause", "process.stop", "process.kill"}
    payload_faults = {"cpu.saturate", "mem.exhaust", "fs.fill"}

    for fault_id, kwargs in _M6_ARCHETYPES.items():
        fault = PlannedFault(
            fault_id=fault_id,
            targets=(),
            params=kwargs["params"],  # type: ignore[arg-type]
            duration=kwargs["duration"],  # type: ignore[arg-type]
        )
        tmpl = template_for(fault_id)
        assert tmpl is not None
        ops, _probes = tmpl.build(fault, nodes)
        # Every M6 archetype must produce at least one undo op
        assert len(ops) >= 1, f"{fault_id}: template produced no undo ops"
        for op in ops:
            assert "pid" in op.args, f"{fault_id}: missing pid in op args"
            if fault_id in payload_faults:
                assert op.op == "payload.undo", f"{fault_id}: not a payload undo"
                assert "payload" in op.args, f"{fault_id}: missing payload source"
                continue
            if fault_id in pid_based_faults:
                continue
            assert "inject_argv" in op.args, f"{fault_id}: missing inject_argv"
            assert "undo_argv" in op.args, f"{fault_id}: missing undo_argv"
            inject = json.loads(op.args["inject_argv"])
            undo = json.loads(op.args["undo_argv"])
            assert isinstance(inject, list), f"{fault_id}: inject_argv not a list"
            assert isinstance(undo, list), f"{fault_id}: undo_argv not a list"
            assert inject != undo, f"{fault_id}: inject == undo (no-op fault?)"
