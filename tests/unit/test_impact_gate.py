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
from mayhem.domain.identity import RuntimeIdentity
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

    def test_net_load_gates_on_host_k6(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(impact, "_host_bin_present", lambda name: False)
        verdict = gate_fault("net.load", "testcase-api", "podman", _runtime(bins={}))
        assert verdict.impact_possible is False
        assert verdict.host is True
        assert verdict.missing == ("bin:k6",)
        assert "host tooling" in verdict.note

    def test_net_load_passes_when_host_has_k6(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(impact, "_host_bin_present", lambda name: True)
        verdict = gate_fault("net.load", "testcase-api", "podman", _runtime(bins={}))
        assert verdict.impact_possible is True
        assert verdict.host is True

    def test_root_required_family_fails_for_nonroot(self) -> None:
        run = _runtime(bins={"sh": True}, uid=1000)
        verdict = gate_fault("dns.nxdomain", "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert "uid(0)" in verdict.missing

    def test_engine_addressed_family_is_never_gated(self) -> None:
        verdict = gate_fault("container.kill", "testcase-api", "podman", _runtime(bins={}))
        assert verdict.impact_possible is True

    def test_clock_skew_inert_under_rootless_engine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rootless engines cannot set the host CLOCK_REALTIME.

        The container reports CAP_SYS_TIME in its (namespaced) CapEff, so the
        ordinary probe approves the fault — but the realtime clock is
        host-global and the userns bit is meaningless there. The gate must mark
        clock.skew inert (bypassed, not doomed) so the run does not fail with
        ``date: cannot set date: Operation not permitted``.
        """
        monkeypatch.setattr(impact, "_engine_is_rootless", lambda engine: True)
        run = _runtime(bins={"date": True}, cap_eff=1 << 25)
        verdict = gate_fault("clock.skew", "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert verdict.probed is True
        assert "rootless" in verdict.note
        assert (verdict.fault_id, verdict.container) in bypass_from_verdicts([verdict])

    def test_clock_skew_approved_under_rootful_engine(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(impact, "_engine_is_rootless", lambda engine: False)
        run = _runtime(bins={"date": True}, cap_eff=1 << 25)
        verdict = gate_fault("clock.skew", "testcase-api", "podman", run)
        assert verdict.impact_possible is True

    def test_rootless_gate_leaves_non_sys_time_faults_alone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(impact, "_engine_is_rootless", lambda engine: True)
        run = _runtime(bins={"tc": True}, cap_eff=1 << 12)
        verdict = gate_fault("net.latency", "testcase-api", "podman", run)
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
                runtime_identity=RuntimeIdentity(runtime="podman", host_id="h1", runtime_id="api"),
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


class TestRootlessDetection:
    def _clear(self) -> None:
        impact._engine_is_rootless.cache_clear()

    def test_podman_info_rootless_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        self._clear()

        def fake_info(*a, **k):
            return subprocess.CompletedProcess(
                ["podman", "info"],
                0,
                stdout='{"host": {"security": {"rootless": true}}}',
            )

        monkeypatch.setattr(subprocess, "run", fake_info)
        assert impact._engine_is_rootless("podman") is True

    def test_podman_info_rootful_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        self._clear()

        def fake_info(*a, **k):
            return subprocess.CompletedProcess(
                ["podman", "info"],
                0,
                stdout='{"host": {"security": {"rootless": false}}}',
            )

        monkeypatch.setattr(subprocess, "run", fake_info)
        assert impact._engine_is_rootless("podman") is False

    def test_docker_userns_security_option(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        self._clear()

        def fake_info(*a, **k):
            return subprocess.CompletedProcess(
                ["docker", "info"],
                0,
                stdout='{"SecurityOptions": ["name=seccomp,profile=default", "name=userns"]}',
            )

        monkeypatch.setattr(subprocess, "run", fake_info)
        assert impact._engine_is_rootless("docker") is True

    def test_docker_rootful_no_userns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        self._clear()

        def fake_info(*a, **k):
            return subprocess.CompletedProcess(
                ["docker", "info"],
                0,
                stdout='{"SecurityOptions": ["name=seccomp,profile=default"]}',
            )

        monkeypatch.setattr(subprocess, "run", fake_info)
        assert impact._engine_is_rootless("docker") is False

    def test_missing_engine_falls_back_to_rootful(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        self._clear()

        def boom(*a, **k):
            raise FileNotFoundError("podman not installed")

        monkeypatch.setattr(subprocess, "run", boom)
        assert impact._engine_is_rootless("podman") is False

    def test_unparsable_info_falls_back_to_rootful(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        self._clear()

        def junk(*a, **k):
            return subprocess.CompletedProcess(["podman", "info"], 0, stdout="not json{{")

        monkeypatch.setattr(subprocess, "run", junk)
        assert impact._engine_is_rootless("podman") is False


class TestScan:
    def test_dead_fault_is_flagged_and_engine_is_probed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = _runtime(bins={"tc": False}, cap_eff=0)
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        verdicts, probed = scan_plan_faults(_plan("net.latency"), _graph(), "podman")
        assert probed is True
        dead = [v for v in verdicts if not v.impact_possible]
        assert len(dead) == 1
        assert dead[0].fault_id == "net.latency" and dead[0].container == "testcase-api"

    def test_healthy_fault_passes_with_no_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = _runtime(bins={"kill": True})
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        verdicts, probed = scan_plan_faults(_plan("proc.pause"), _graph(), "podman")
        assert probed is True and verdicts[0].impact_possible is True

    def test_engine_unreachable_warns_not_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: None)
        verdicts, probed = scan_plan_faults(_plan("net.latency"), _graph(), "podman")
        assert probed is False
        assert all(v.probed is False for v in verdicts)

    def test_host_fault_needs_no_container_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        probe_calls: list[tuple[str, str]] = []

        def _fake_probe(eng, cont, timeout_s=10):
            probe_calls.append((eng, cont))

        monkeypatch.setattr(impact, "probe_container_runtime", _fake_probe)
        monkeypatch.setattr(impact, "_host_bin_present", lambda name: True)
        verdicts, _ = scan_plan_faults(_plan("net.load"), _graph(), "podman")
        assert probe_calls == []  # net.load is host-addressed — no container probe
        assert verdicts[0].impact_possible is True
        assert verdicts[0].host is True


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


PYTHON_FAMILY = (
    "db.connection_exhaust",
    "http.latency",
    "dependency.rate_limit",
    "mem.leak",
    "fs.inode_exhaust",
    "fs.io_stress",
)
TC_FAMILY = (
    "net.packet_loss",
    "net.bandwidth",
    "net.reorder",
    "net.duplicate",
    "dependency.timeout",
)
NETFILTER_FAMILY = (
    "net.connection_reset",
    "net.connection_refuse",
    "dependency.block",
    "dependency.flap",
    "dependency.connection_refuse",
    "dns.timeout",
    "dns.servfail",
    "tls.handshake_failure",
    "db.query_error",
)


class TestGateCoverage:
    """Every in-container fault family must be gated on its real tooling —
    regressions here are exactly the "inert injection fails at exec time" bug
    class (db.connection_exhaust ran on a python-less image and died in
    inject, because the gate defaulted it to "no tooling required")."""

    @pytest.mark.parametrize("fault_id", PYTHON_FAMILY)
    def test_python_payload_family_requires_python(self, fault_id: str) -> None:
        run = _runtime(bins={"sh": True, "python": False})
        verdict = gate_fault(fault_id, "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert "bin:python" in verdict.missing

    @pytest.mark.parametrize("fault_id", TC_FAMILY)
    def test_tc_family_requires_tc_and_net_admin(self, fault_id: str) -> None:
        run = _runtime(bins={"tc": True})
        verdict = gate_fault(fault_id, "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert verdict.missing == ("cap:NET_ADMIN",)
        rich = _runtime(bins={"tc": True}, cap_eff=1 << 12)
        assert gate_fault(fault_id, "testcase-api", "podman", rich).impact_possible is True

    @pytest.mark.parametrize("fault_id", NETFILTER_FAMILY)
    def test_netfilter_family_requires_iptables_and_net_admin(self, fault_id: str) -> None:
        run = _runtime(bins={"iptables": False})
        verdict = gate_fault(fault_id, "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert "bin:iptables" in verdict.missing
        rich = _runtime(bins={"iptables": True}, cap_eff=1 << 12)
        assert gate_fault(fault_id, "testcase-api", "podman", rich).impact_possible is True

    def test_connection_exhaust_is_not_trusted_without_python(self) -> None:
        run = _runtime(bins={"sh": True, "python": False})
        verdict = gate_fault("db.connection_exhaust", "testcase-api", "podman", run)
        assert verdict.missing == ("bin:python",)

    @pytest.mark.parametrize(
        "fault_id",
        ("container.restart", "container.pause", "process.crash_loop", "cpu.throttle"),
    )
    def test_engine_addressed_family_is_never_gated(self, fault_id: str) -> None:
        assert fault_id in impact._ENGINE_FAULTS
        verdict = gate_fault(fault_id, "testcase-api", "podman", _runtime(bins={}))
        assert verdict.impact_possible is True

    def test_fs_read_only_requires_root(self) -> None:
        run = _runtime(bins={"sh": True}, uid=1000)
        verdict = gate_fault("fs.read_only", "testcase-api", "podman", run)
        assert verdict.impact_possible is False
        assert "uid(0)" in verdict.missing

    def test_every_catalog_fault_is_classified_by_the_gate(self) -> None:
        """No fault may fall through to the "no in-image tooling required"
        default unless it is provably engine/host-side (no container tooling
        exists to gate on)."""
        from mayhem.domain.catalog import all_definitions

        host_side = impact._ENGINE_FAULTS | {"process.stop", "process.kill"}
        uncovered = sorted(
            d.id
            for d in all_definitions()
            if d.id not in host_side
            and not d.id.startswith("k8s.")
            and not d.catalog_only
            and d.id not in impact.REQUIREMENTS
        )
        assert uncovered == []


class TestCatalogDose:
    def test_net_load_catalog_entries(self) -> None:
        from mayhem.domain.catalog import definition_for

        d = definition_for("net.load")
        assert d is not None and d.category.value == "network"
        names = {p.name for p in d.params_schema}
        assert {"users", "url"} <= names
        assert d.reversible is True


class TestPackageManager:
    def test_detects_apt_get(self) -> None:
        run = _runtime(bins={"apt-get": True, "apk": False})
        assert run.package_manager() == "apt-get"

    def test_priority_apt_over_alpine(self) -> None:
        run = _runtime(bins={"apt-get": True, "apk": True})
        assert run.package_manager() == "apt-get"

    def test_none_when_no_manager(self) -> None:
        assert _runtime(bins={}).package_manager() is None

    def test_pm_bins_appear_in_probe_output(self) -> None:
        parsed = impact.parse_runtime_output(
            "podman", "c1", "BINS python:0 apt-get:1 sh:1\nUID 0\nCAPEFF 0\n"
        )
        assert parsed is not None
        assert parsed.has_bin("apt-get") is True
        assert parsed.package_manager() == "apt-get"

    def test_alpine_apk_survives_hyphenated_bins(self) -> None:
        # Regression: the BINS regex must not truncate on the first hyphenated
        # bin (apt-get) and silently drop apk — Alpine reported "pm: none".
        parsed = impact.parse_runtime_output(
            "podman",
            "testcase-lb",
            "BINS kill:1 tc:0 iptables:0 python:0 python3:0 date:1 sh:1 "
            "apt-get:0 apk:1 dnf:0 yum:0 microdnf:0 zypper:0\n"
            "UID 0\nCAPEFF 0\n",
        )
        assert parsed is not None
        assert parsed.has_bin("ash-alias-check") is False  # sanity: unknown name
        assert parsed.has_bin("apk") is True
        assert parsed.package_manager() == "apk"
        assert parsed.has_bin("sh") is True  # Alpine's busybox ash


class TestDependencyPlan:
    def test_apt_get_tc_and_net_admin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = _runtime(
            bins={"apt-get": True, "tc": False, "sh": True},
            cap_eff=0,
        )
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        dp = impact.dependency_plan(_plan("net.latency"), _graph(), "podman")[0]
        assert dp.pm == "apt-get"
        assert dp.packages == ("iproute2",)
        assert dp.bins == ("tc",)
        assert dp.caps_missing == ("cap:NET_ADMIN",)
        assert dp.install_argv() == [
            ["podman", "exec", "testcase-api", "apt-get", "update"],
            ["podman", "exec", "testcase-api", "apt-get", "install", "-y", "iproute2"],
        ]

    def test_alpine_python(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = _runtime(bins={"apk": True, "python3": False, "sh": True})
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        dp = impact.dependency_plan(_plan("mem.exhaust"), _graph(), "podman")[0]
        assert dp.pm == "apk"
        assert dp.packages == ("python3",)
        assert dp.install_argv() == [
            ["podman", "exec", "testcase-api", "apk", "add", "--no-cache", "python3"]
        ]

    def test_host_k6_never_becomes_a_container_dependency(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = _runtime(bins={"k6": False, "apt-get": True}, cap_eff=0)
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        assert impact.dependency_plan(_plan("net.load"), _graph(), "podman") == []
        monkeypatch.setattr(impact, "_host_bin_present", lambda name: False)
        assert impact.host_tooling_gaps(_plan("net.load")) == ["k6"]
        monkeypatch.setattr(impact, "_host_bin_present", lambda name: True)
        assert impact.host_tooling_gaps(_plan("net.load")) == []

    def test_sh_and_root_run_as_user_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = _runtime(bins={"sh": False, "apt-get": True}, uid=1000)
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        dp = impact.dependency_plan(_plan("dns.nxdomain"), _graph(), "podman")[0]
        assert dp.need_root is True
        assert dp.packages == ("dash",)
        for argv in dp.install_argv():
            assert "--user" in argv and "0" in argv

    def test_healthy_container_produces_no_plan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = _runtime(bins={"python": True, "sh": True, "apt-get": False})
        monkeypatch.setattr(impact, "probe_container_runtime", lambda eng, c, timeout_s=10: run)
        assert impact.dependency_plan(_plan("cpu.saturate"), _graph(), "podman") == []


class TestDependencyCli:
    def test_group_has_check_and_install(self) -> None:
        from mayhem.cli.dependency import dependency

        names = {cmd.name for cmd in dependency.commands.values()}
        assert {"check", "install"} <= names

    def test_group_has_compile(self) -> None:
        from mayhem.cli.dependency import dependency

        assert "compile" in {cmd.name for cmd in dependency.commands.values()}


def _plan_many(*fault_ids: str) -> ExecutionPlan:
    """A drill plan holding one step per fault id (all targeting testcase-api)."""
    steps = tuple(_plan(fid).steps[0] for fid in fault_ids)
    return ExecutionPlan(
        run_id="r-union",
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c1",
        topology_snapshot_id="t1",
        environment_fingerprint="f",
    )


class TestCompileRequirements:
    def test_host_fault_adds_nothing(self) -> None:
        # net.load runs k6 on the drill host — never a compose service.
        assert impact.compile_requirements(_plan("net.load"), _graph()) == []

    def test_cap_and_packages_are_baked(self) -> None:
        plans = impact.compile_requirements(_plan("net.latency"), _graph())
        assert len(plans) == 1
        plan = plans[0]
        assert plan.container == "testcase-api"
        assert plan.bins == ("tc",)
        assert plan.caps == ("NET_ADMIN",)
        assert plan.manual == ()

    def test_union_across_faults_single_container(self) -> None:
        plans = impact.compile_requirements(_plan_many("net.latency", "clock.skew"), _graph())
        assert len(plans) == 1
        plan = plans[0]
        assert plan.bins == ("date", "tc")
        assert plan.caps == ("NET_ADMIN", "SYS_TIME")

    def test_root_fault_compiles_packages_but_no_caps(self) -> None:
        # dns.nxdomain needs root at runtime, not a capability; the compose
        # compiler carries the package (sh → dash/…) but never bakes a shell
        # entrypoint prefix or a user field here.
        plans = impact.compile_requirements(_plan("dns.nxdomain"), _graph())
        assert len(plans) == 1
        assert plans[0].bins == ("sh",)
        assert plans[0].caps == ()
        assert plans[0].manual == ()

    def test_package_union_ignores_state(self) -> None:
        # compile_requirements is a static union of the drill plan — it must
        # not probe or depend on the running stack, so a torn-down stack still
        # yields the same requirement.
        plans = impact.compile_requirements(_plan("net.latency"), _graph())
        assert plans[0].bins == ("tc",)
