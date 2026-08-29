"""FaultGateway: the pre-run impact gate + runtime probe parsing."""

import json

import pytest

from mayhem.agents import impact
from mayhem.agents.impact import (
    ContainerRuntime,
    GateVerdict,
    bypass_from_verdicts,
    gate_fault,
    parse_runtime_output,
    probe_container_runtime,
    scan_plan_faults,
)
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    NodeKind,
    ProcessNode,
    TargetSelector,
    TopologyGraph,
)


def _runtime(
    bins: dict[str, bool] | None = None,
    uid: int = 0,
    cap_eff: int = 0,
) -> ContainerRuntime:
    return ContainerRuntime(
        container="testcase-api",
        engine="podman",
        bins=bins or {},
        uid=uid,
        cap_eff=cap_eff,
    )


CAP_STRING = (
    "Name:	awk\nUmask:	0022\nState:	S (sleeping)\n"
    "BINS tc:1 python:0 python3:1 sh:1 date:0 k6:1\n"
    "UID 0\n"
    "CAPEFF 400205\n"
)


class TestParse:
    def test_probe_script_is_valid_sh(self) -> None:
        """The probe must not start with a bare ``;`` (it previously did, so
        every runtime probe died with ``sh: syntax error`` and the gate fell
        back to "unreachable" for all faults)."""
        script = impact._PROBE_SH
        assert script.startswith("printf 'BINS'")
        assert "; printf ' tc:" in script
        assert script.count("printf 'BINS'") == 1
        assert "uid 0" not in script

    def test_parses_bins_uid_capeff(self) -> None:
        out = "BINS tc:1 python:0 python3:1 sh:1 date:0 k6:1" + "\nUID 7\n" + CAP_STRING
        run = parse_runtime_output("podman", "testcase-api", out)
        assert run is not None
        assert run.uid == 7
        assert run.bins["tc"] is True and run.bins["python3"] is True
        assert run.cap_eff == 0x400205

    def test_python_alias(self) -> None:
        run = _runtime(bins={"python": False, "python3": True})
        assert run.has_bin("kill") is False
        assert run.has_bin("python") is True

    def test_cap_bit_mapping(self) -> None:
        run = _runtime(cap_eff=1 << 12)
        assert run.has_cap("NET_ADMIN") is True
        assert run.has_cap("SYS_TIME") is False


class TestGate:
    def test_net_latency_needs_tc_and_net_admin(self) -> None:
        run = _runtime(bins={"tc": True}, cap_eff=1 << 12)
        verdict = gate_fault("net.latency", "testcase-api", "podman", run)
        assert verdict.impact_possible is True

    def test_net_load_needs_k6(self) -> None:
        run = _runtime(bins={"k6": False, "python": True})
        verdict = gate_fault("net.load", "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert verdict.missing == ("bin:k6",)

    def test_root_required_family_fails_for_nonroot(self) -> None:
        run = _runtime(bins={"sh": True}, uid=1000)
        verdict = gate_fault("dns.nxdomain", "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert "uid(0)" in verdict.missing

    def test_engine_addressed_family_is_never_gated(self) -> None:
        verdict = gate_fault("container.kill", "testcase-api", "podman", _runtime(bins={}))
        assert verdict.impact_possible is True

    def test_unreachable_runtime_is_inconclusive_not_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(impact, "probe_container_runtime", lambda *a, **k: None)
        verdict = gate_fault("net.latency", "testcase-api", "podman", runtime=None)
        assert verdict.impact_possible is False and verdict.probed is False

    def test_probe_container_runtime_none_on_tool_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.toolkit.tool_runner import ToolError

        def boom(*a, **k):
            raise ToolError("engine unreachable")

        monkeypatch.setattr(impact, "run_tool", boom)
        assert probe_container_runtime("podman", "c") is None


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_id="api",
                container_name="testcase-api",
                state="running",
            ),
            ProcessNode(
                id="proc-api",
                name="api",
                pid=4242,
                host_id="h1",
                container_name="testcase-api",
            ),
        ),
        edges=(Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),),
    )


def _plan(fault_id: str) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.CONTAINER, expr="api")
    fault = PlannedFault(
        fault_id=fault_id,
        targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"ctr-api"})),),
        undo_ops=(
            UndoOp(
                op="sh.sync",
                args={
                    "inject_argv": json.dumps(["tc"]),
                    "undo_argv": json.dumps(["tc"]),
                },
            ),
        ),
        verify_probes=(
            VerifyProbe(
                probe="exec",
                args={"cmd": ["sh", "-c", "true"]},
                expect_present=False,
            ),
        ),
        params={},
        duration=6.0,
    )
    return ExecutionPlan(
        run_id="r-gate",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="s1",
                seq=1,
                fault=fault,
                raw_action=InjectFault(
                    fault=fault_id,
                    selectors=(selector,),
                    params={},
                    duration=6.0,
                ),
            ),
        ),
        config_snapshot_id="c1",
        topology_snapshot_id="t1",
        environment_fingerprint="f",
    )


class TestScan:
    def test_dead_fault_is_flagged_and_engine_is_probed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = _runtime(bins={"k6": False})
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        verdicts, probed = scan_plan_faults(_plan("net.load"), _graph(), "podman")
        assert probed is True
        dead = [v for v in verdicts if not v.impact_possible]
        assert len(dead) == 1
        assert dead[0].fault_id == "net.load" and dead[0].container == "testcase-api"

    def test_healthy_fault_passes_with_no_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = _runtime(bins={"kill": True})
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        verdicts, probed = scan_plan_faults(_plan("proc.pause"), _graph(), "podman")
        assert probed is True and verdicts[0].impact_possible is True

    def test_engine_unreachable_warns_not_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: None)
        verdicts, probed = scan_plan_faults(_plan("net.load"), _graph(), "podman")
        assert probed is False
        assert all(v.probed is False for v in verdicts)


class TestBypass:
    def test_only_probed_inert_verdicts_become_bypasses(self) -> None:
        verdicts = [
            GateVerdict("cpu.saturate", "c-a", True, note="ok"),
            GateVerdict("net.latency", "c-b", False, missing=("bin:tc",), note="missing bin:tc"),
            GateVerdict("clock.skew", "c-c", False, probed=False, note="unreachable"),
            GateVerdict("mem.exhaust", "c-d", False, missing=("uid(0)",), note="missing uid(0)"),
        ]
        bypass = bypass_from_verdicts(verdicts)
        assert bypass == {
            ("net.latency", "c-b"): "missing bin:tc",
            ("mem.exhaust", "c-d"): "missing uid(0)",
        }
        # Unreachable runtimes are not proven inert => attempted, never bypassed.
        assert ("clock.skew", "c-c") not in bypass

    def test_empty_verdicts_produce_empty_bypass(self) -> None:
        assert bypass_from_verdicts([]) == {}


class TestCatalogDose:
    def test_net_load_catalog_entries(self) -> None:
        from mayhem.domain.catalog import definition_for

        d = definition_for("net.load")
        assert d is not None and d.category.value == "network"
        names = {p.name for p in d.params_schema}
        assert {"users", "url"} <= names
        assert d.reversible is True
