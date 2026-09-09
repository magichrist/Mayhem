"""Resilience & redundancy end-of-run report (ADR-M6-1)."""

from mayhem.controller.executor import RunResult, StepReport
from mayhem.controller.planner import plan_drill
from mayhem.controller.resilience_report import (
    ResilienceReport,
    build_resilience_report,
    collect_diagnosis,
    score_run,
)
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
)


def _reports(*rows: tuple[str, bool, str, str]) -> tuple[StepReport, ...]:
    return tuple(
        StepReport(step_id=sid, ok=ok, detail=detail, status=status)
        for sid, ok, detail, status in rows
    )


def _replica_graph(alive: set[str]) -> TopologyGraph:
    """lb + api services; lb has two replicas, api one; extra process per container."""
    nodes: list[ContainerNode | ServiceNode | ProcessNode] = []
    edges: list[Edge] = []
    for cid, container_name, service in (
        ("ctr-lb-1", "lb-a", "lb"),
        ("ctr-lb-2", "lb-b", "lb"),
        ("ctr-api-1", "api-a", "api"),
    ):
        nodes.append(
            ContainerNode(
                id=cid,
                name=cid,
                container_name=container_name,
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h-local", runtime_id=container_name
                ),
                state="running" if cid in alive else "exited",
            )
        )
        nodes.append(
            ProcessNode(id=f"proc-{cid}", name=f"sleeper-{cid}", pid=42, host_id="h-local")
        )
        edges.append(Edge(src=cid, dst=f"svc-{service}", kind=EdgeKind.CONTAINED_IN))
        edges.append(Edge(src=cid, dst=f"proc-{cid}", kind=EdgeKind.RUNS_ON))
    nodes.append(ServiceNode(id="svc-lb", name="lb"))
    nodes.append(ServiceNode(id="svc-api", name="api"))
    return TopologyGraph(nodes=tuple(nodes), edges=tuple(edges))


def _group_single() -> dict[str, tuple[str, ...]]:
    return {"ctr-lb-1": ("ctr-lb-1",)}


def _group_replica() -> dict[str, tuple[str, ...]]:
    return {"ctr-lb-1": ("ctr-lb-1", "ctr-lb-2"), "ctr-lb-2": ("ctr-lb-1", "ctr-lb-2")}


class TestScoreRun:
    def test_clean_multi_replica_run_scores_100(self) -> None:
        report = score_run(
            reports=_reports(
                ("lb-fault-1", True, "ok", "ok"),
                ("lb-fault-2", True, "ok", "ok"),
            ),
            targeted=frozenset({"ctr-lb-1"}),
            dirty_leases=(),
            groups=_group_replica(),
            alive=frozenset({"ctr-lb-1", "ctr-lb-2"}),
            step_targets={"lb-fault-1": ("ctr-lb-1",), "lb-fault-2": ("ctr-lb-1",)},
        )
        assert report.score == 100
        assert report.step_performance == 1.0
        assert report.self_healing == 1.0
        assert report.redundancy == 1.0
        assert "targets alive after run: 1/1" in report.breakdown

    def test_killed_single_replica_scores_low(self) -> None:
        """The reported scenario: fault kills the only replica and it stays dead."""
        report = score_run(
            reports=_reports(
                ("lb-fault-1", True, "ok", "ok"),
                ("lb-fault-2", False, "cannot resolve live pid for ctr-lb-1", "failed"),
            ),
            targeted=frozenset({"ctr-lb-1"}),
            dirty_leases=(),
            groups=_group_single(),
            alive=frozenset(),
            step_targets={"lb-fault-1": ("ctr-lb-1",), "lb-fault-2": ("ctr-lb-1",)},
        )
        assert report.score < 50
        assert report.self_healing < 1.0  # target stayed dead → not self-healing
        assert report.redundancy == 0.0  # single member absorbed nothing
        assert "targets alive after run: 0/1" in report.breakdown

    def test_bypassed_steps_are_neutral_but_reported(self) -> None:
        report = score_run(
            reports=_reports(
                ("f1", True, "bypassed", "bypassed"),
                ("f2", True, "bypassed", "bypassed"),
            ),
            targeted=frozenset({"ctr-api-1"}),
            dirty_leases=(),
            groups=_group_single(),
            alive=frozenset({"ctr-api-1"}),
            step_targets={"f1": ("ctr-api-1",), "f2": ("ctr-api-1",)},
        )
        assert report.step_performance == 0.0  # nothing executed, nothing credited
        assert report.redundancy is None  # no executed fault step → no credit
        assert "0/0 ok (2 bypassed)" in " ".join(report.breakdown)

    def test_dirty_lease_halves_self_healing(self) -> None:
        report = score_run(
            reports=_reports(("f1", True, "ok", "ok")),
            targeted=frozenset({"ctr-api-1"}),
            dirty_leases=("lease-1",),
            groups=_group_single(),
            alive=frozenset({"ctr-api-1"}),
            step_targets={"f1": ("ctr-api-1",)},
        )
        assert report.self_healing == 0.5
        assert "dirty leases: 1 (manual remediation required)" in " ".join(report.breakdown)

    def test_redundancy_unmeasured_without_live_graph(self) -> None:
        report = score_run(
            reports=_reports(("f1", True, "ok", "ok")),
            targeted=frozenset({"ctr-lb-1"}),
            dirty_leases=(),
            groups=None,
            alive=None,
            step_targets={"f1": ("ctr-lb-1",)},
        )
        assert report.redundancy is None
        assert any("redundancy: not measured" in line for line in report.breakdown)
        # self-healing still measured from step data alone (no alive info → no penalty)
        assert report.self_healing == 1.0

    def test_twice_faulted_replica_keeps_survivor_credits_redundancy(self) -> None:
        report = score_run(
            reports=_reports(("f1", True, "ok", "ok")),
            targeted=frozenset({"ctr-lb-1"}),
            dirty_leases=(),
            groups=_group_replica(),
            alive=frozenset({"ctr-lb-2"}),  # faulted member down, sibling survived
            step_targets={"f1": ("ctr-lb-1",)},
        )
        assert report.redundancy == 1.0
        assert report.self_healing == 0.5  # targeted member still dead


class TestDiagnosis:
    def test_exited_137_explains_kill_and_missing_self_healing(self) -> None:
        def inspect(ref: str) -> tuple[str, str, str]:
            return ("exited", "137", "0")

        def logs(ref: str) -> str:
            return "epoch=... fatal: connection reset"

        diagnosis = collect_diagnosis(
            "podman",
            (("ctr-lb-1", "lb-a"),),
            inspect_runner=inspect,
            logs_runner=logs,
        )
        joined = "\n".join(diagnosis)
        assert "killed (SIGKILL)" in joined
        assert "did not self-heal" in joined
        assert "ctr-lb-1" in joined

    def test_healthy_containers_collapse_to_count(self) -> None:
        def inspect(ref: str) -> tuple[str, str, str]:
            return ("running", "0", "0")

        diagnosis = collect_diagnosis(
            "podman",
            (("ctr-lb-1", "lb-a"), ("ctr-api-1", "api-a")),
            inspect_runner=inspect,
            logs_runner=lambda ref: "",
        )
        assert len(diagnosis) == 1
        assert "healthy after run: 2/2" in diagnosis[0]

    def test_missing_container_reported_not_found(self) -> None:
        def inspect(ref: str) -> tuple[str, str, str]:
            raise RuntimeError("no such container")

        diagnosis = collect_diagnosis(
            "podman",
            (("ctr-lb-1", "lb-a"),),
            inspect_runner=inspect,
            logs_runner=lambda ref: "",
        )
        assert "not found by podman" in diagnosis[0]
        assert "removed or podman unreachable" in diagnosis[0]

    def test_restarted_but_down_calls_out_instability(self) -> None:
        def inspect(ref: str) -> tuple[str, str, str]:
            return ("exited", "1", "12")

        diagnosis = collect_diagnosis(
            "podman",
            (("ctr-api-1", "api-a"),),
            inspect_runner=inspect,
            logs_runner=lambda ref: "",
        )
        assert "restarted but did not stay up" in diagnosis[0]


class TestBuildResilienceReport:
    def test_wires_graph_and_diagnosis_into_run_result(self) -> None:
        plan = plan_drill(
            "r-res",
            DrillSpec(
                kind="drill",
                name="res",
                containers={
                    "lb-a": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="1s"),))
                },
                execution=(ExecutionStep(parallel=("lb-a",)),),
            ),
            _replica_graph({"ctr-lb-1", "ctr-lb-2"}),
            config_snapshot_id="cfg-1",
            topology_snapshot_id="topo-1",
            environment_fingerprint="fp-test",
        )
        # Fault step against the first replica; the second stayed up.
        report = build_resilience_report(
            plan,
            _reports((plan.steps[0].id, True, "ok", "ok")),
            (),
            _replica_graph({"ctr-lb-2"}),
            "podman",
            inspect_runner=lambda ref: ("running", "0", "0"),
            logs_runner=lambda ref: "",
        )
        assert report.score == 82  # killed replica stayed down (-self-healing), sibling survived
        assert report.redundancy == 1.0
        assert any("healthy after run" in line for line in report.diagnosis)

    def test_wires_diagnosis_without_graph_falls_back_to_plan_identity(self) -> None:
        plan = plan_drill(
            "r-res2",
            DrillSpec(
                kind="drill",
                name="res2",
                containers={
                    "lb-a": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="1s"),))
                },
                execution=(ExecutionStep(parallel=("lb-a",)),),
            ),
            _replica_graph({"ctr-lb-1", "ctr-lb-2"}),
            config_snapshot_id="cfg-1",
            topology_snapshot_id="topo-1",
            environment_fingerprint="fp-test",
        )
        report = build_resilience_report(
            plan,
            _reports((plan.steps[0].id, True, "ok", "ok")),
            (),
            None,
            "podman",
            inspect_runner=lambda ref: ("exited", "137", "0"),
            logs_runner=lambda ref: "boom",
        )
        assert "killed (SIGKILL)" in "\n".join(report.diagnosis)


class TestRunResultSurface:
    def test_summary_md_renders_resilience_and_diagnosis(self) -> None:
        from mayhem.controller.resilience_report import ResilienceReport

        report = ResilienceReport(
            score=35,
            step_performance=0.5,
            self_healing=0.5,
            redundancy=0.0,
            breakdown=(
                "steps: 1/2 ok (0 bypassed)",
                "self-healing: dirty leases 0, targets alive after run: 0/1",
                "redundancy: 0% of faulted replica groups kept a survivor",
            ),
            diagnosis=(
                "ctr-lb-1 (lb-a): state=exited exit_code=137 restarts=0 → "
                "killed and did not self-heal",
            ),
        )
        result = RunResult(
            run_id="r-1",
            status="failed",
            started_at_epoch_s=0.0,
            ended_at_epoch_s=1.0,
            steps=_reports(("f1", False, "cannot resolve live pid for ctr-lb-1", "failed")),
            resilience_report=report,
        )
        md = result.summary_md()
        assert "**resilience**:" in md
        assert "35/100" in md
        assert "**diagnosis**:" in md
        assert "did not self-heal" in md

    def test_grade_bands_are_deterministic(self) -> None:
        for score, letter in ((95, "A"), (90, "A"), (75, "B"), (60, "C"), (45, "D"), (10, "F")):
            report = ResilienceReport(
                score=score, step_performance=1.0, self_healing=1.0, redundancy=1.0
            )
            assert report.grade == letter

    def test_summary_has_single_redundancy_metric(self) -> None:
        report = ResilienceReport(
            score=35,
            step_performance=0.5,
            self_healing=0.5,
            redundancy=0.0,
            breakdown=(
                "steps: 1/2 ok (0 bypassed)",
                "redundancy: 0% of faulted replica groups kept a survivor",
            ),
        )
        md = report.summary_md()
        rows = [line for line in md.splitlines() if line.startswith("| redundancy")]
        assert len(rows) == 1
        assert "redundancy efficacy" in rows[0]
        assert rows[0].count(self._redundancy_cell(report)) == 1

    def test_summary_metrics_table_grounded(self) -> None:
        report = ResilienceReport(score=82, step_performance=1.0, self_healing=0.5, redundancy=1.0)
        md = report.summary_md()
        assert "| metric | result | model |" in md
        assert "Hsueh, Tsai & Iyer" in md
        assert "Hollnagel, Woods & Leveson" in md
        assert "Avizienis, Laprie & Randell" in md
        assert "grade B" in md

    def test_unmeasured_redundancy_reported_once_in_table(self) -> None:
        report = ResilienceReport(score=82, step_performance=1.0, self_healing=1.0, redundancy=None)
        md = report.summary_md()
        rows = [line for line in md.splitlines() if line.startswith("| redundancy")]
        assert len(rows) == 1
        assert "not measured" in rows[0]
        assert not any(line.strip().startswith("redundancy:") for line in md.splitlines())

    def test_summary_omits_weight_clause_for_unused_redundancy(self) -> None:
        report = ResilienceReport(score=82, step_performance=1.0, self_healing=1.0, redundancy=None)
        md = report.summary_md()
        assert "**weighting**: fidelity 35%, recovery 35%, redundancy 30%" in md

    @staticmethod
    def _redundancy_cell(report: ResilienceReport) -> str:
        return f"{report.redundancy:.0%}" if report.redundancy is not None else "not measured"
