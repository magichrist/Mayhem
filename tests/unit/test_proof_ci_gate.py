"""Plan 30 Phase 3, second half: the proof in PR checks and in the API projection.

``mayhem prove`` rendered the artifact, but the phase also names proof views in
PR checks (plan 16) and in a UI (plan 08). Both halves are projections off the
same view-model rather than second implementations, the way plan 14 landed
``risk_preview_payload``:

* **PR checks** — :func:`mayhem.controller.check_gate.proof_view_for_report`
  builds the ``mayhem prove`` view-model from the compilation
  :func:`~mayhem.controller.check_gate.evaluate_pr_checks` already produced.
  No gate runs twice, no planner is added, and an unreachable control plane
  projects to no view at all rather than to a passing one.
* **API/UI** — :func:`mayhem.controller.api_service.proof_payload` builds the
  same view and returns the same payload of it, so the identity
  ``proof_payload(proof) == proof_payload(build_proof_view(proof))`` is
  structural.

Fail-closed throughout: a ``VOID`` proof projects to a ``VOID`` view with its
reason, and the payload never softens a verdict.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from click.testing import CliRunner

from mayhem.cli.ci_cmd import ci
from mayhem.cli.exit_codes import ExitCode
from mayhem.config import PolicyCfg
from mayhem.controller import check_gate as cg
from mayhem.domain.safety_proof import ProofVerdict

if TYPE_CHECKING:
    from pathlib import Path

FP = "f" * 64
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
SHA = "0123456789abcdef0123456789abcdef01234567"
RUN_DIGEST = "0" * 64


def _graph() -> Any:
    from mayhem.domain.topology import (
        Edge,
        EdgeKind,
        HostNode,
        ServiceNode,
        TopologyGraph,
    )

    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _plan() -> Any:
    from mayhem.domain.experiments import (
        ExecutionPlan,
        ExperimentKind,
        InjectFault,
        PlannedFault,
        PlannedStep,
        ResolvedTarget,
    )
    from mayhem.domain.leases import UndoOp, VerifyProbe
    from mayhem.domain.topology import NodeKind, TargetSelector

    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    return ExecutionPlan(
        run_id="r-proof-gate",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(fault="proc.pause", selectors=(selector,), duration=10.0),
                fault=PlannedFault(
                    fault_id="proc.pause",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),),
                    duration=10.0,
                    undo_ops=(UndoOp(op="kill"),),
                    verify_probes=(VerifyProbe(probe="proc.alive"),),
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


def _ctx() -> Any:
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.experiments import BlastRadiusBudget
    from mayhem.domain.quota import DamageQuota

    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=2**31 - 1,
            max_concurrent_faults=2**31 - 1,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        fingerprint=FP,
        damage_quota=DamageQuota(),
    )


def _adapter() -> Any:
    from mayhem.domain.runtime_adapter import (
        AdapterCapabilities,
        CapabilityVerdict,
        RuntimeAdapter,
        VerdictResult,
    )
    from mayhem.topology.providers.base import PartialGraph

    class _FakeAdapter(RuntimeAdapter):
        @property
        def id(self) -> str:
            return "fake-adapter"

        def is_available(self) -> bool:
            return True

        def capabilities(self) -> AdapterCapabilities:
            return AdapterCapabilities(
                engine=self.id,
                supported=frozenset(),
                alternatives=frozenset(),
                version=None,
            )

        def evaluate(self, reqs: Any) -> VerdictResult:
            return VerdictResult(
                engine=self.id,
                requirements=reqs,
                verdicts={"namespace": CapabilityVerdict.SUPPORTED.value},
                blocking=False,
            )

        def ps(self) -> list[dict[str, Any]]:
            return []

        def inspect(self, container_id: str) -> tuple[Any, None]:
            from mayhem.domain.identity import RuntimeIdentity

            return RuntimeIdentity(runtime="fake", host_id="h", runtime_id=container_id), None

        def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
            return ""

        def pid(self, container_id: str) -> int | None:
            return None

        def signal(self, container_id: str, signo: int) -> None:
            return None

        def netns(self, container_id: str) -> str | None:
            return None

        def filter_by_compose(self, project: str, services: Any = None) -> None:
            return None

        def filter_by_names(self, names: list[str]) -> None:
            return None

        def discover(self) -> PartialGraph:
            return PartialGraph(source=self.id)

    return _FakeAdapter()


def _link() -> Any:
    from mayhem.domain.comparison import RunPin
    from mayhem.domain.pipeline import ChangeLink, PipelinePins

    pin = RunPin(
        run_id="run-v25-0001",
        experiment="checkout-resilience",
        release="v2.5",
        environment="staging",
        plan_version="plan-7",
        policy_version="policy-7",
        catalog_version="catalog-2026.09",
        agent_version="agent-2.0.0",
        runtime_version="runtime-2.1.0",
        evidence_digest=RUN_DIGEST,
    )
    return ChangeLink(
        git_sha="a1b2c3d",
        change_ticket="CH-1421",
        pins=PipelinePins.from_run(pin),
        linked_at=NOW,
    )


def _pin() -> Any:
    from mayhem.domain.comparison import RunPin

    return RunPin(
        run_id="run-v25-0001",
        experiment="checkout-resilience",
        release="v2.5",
        environment="staging",
        plan_version="plan-7",
        policy_version="policy-7",
        catalog_version="catalog-2026.09",
        agent_version="agent-2.0.0",
        runtime_version="runtime-2.1.0",
        evidence_digest=RUN_DIGEST,
    )


def _inputs(**overrides: Any) -> cg.CheckInputs:
    fields: dict[str, Any] = {
        "plan": _plan(),
        "graph": _graph(),
        "safety": _ctx(),
        "change": _link(),
        "cited_run": _pin(),
        "adapter": _adapter(),
    }
    fields.update(overrides)
    return cg.CheckInputs(**fields)


def _unreachable_inputs() -> cg.CheckInputs:
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.pipeline import ControlPlaneReach
    from mayhem.domain.topology import TopologyGraph

    return cg.CheckInputs(
        plan=ExecutionPlan.model_construct(),
        graph=TopologyGraph(),
        safety=_ctx(),
        change=_link(),
        control_plane=ControlPlaneReach.UNREACHABLE,
        control_plane_detail="no plan was readable in this test",
    )


# ── the PR-check projection ──────────────────────────────────────────────────


class TestProofViewForReport:
    def test_a_passing_compile_projects_to_a_passing_view(self) -> None:
        report = cg.evaluate_pr_checks(_inputs())
        assert report.compilation is not None
        assert report.compilation.proof.verdict is ProofVerdict.PASS

        view = cg.proof_view_for_report(report)
        assert view is not None
        assert view.verdict == "PASS"
        assert view.plan_digest == report.plan_digest
        assert view.proof_digest == report.compilation.proof.proof_digest
        assert view.void_reason == ""
        assert view.diffs == ()

    def test_every_established_line_cites_a_gate_output(self) -> None:
        from mayhem.cli.proof_cmd import STATUS_ABSENT

        report = cg.evaluate_pr_checks(_inputs())
        view = cg.proof_view_for_report(report)
        assert view is not None
        for line in view.lines:
            if line.status == STATUS_ABSENT:
                assert line.gate_digest == ""
                continue
            assert len(line.gate_digest) == 64, line
            assert line.evidence_ref.startswith("gate-output/"), line

    def test_the_view_is_labelled_by_the_cited_run(self) -> None:
        report = cg.evaluate_pr_checks(_inputs())
        view = cg.proof_view_for_report(report)
        assert view is not None
        assert view.run_id == "run-v25-0001"

        labelled = cg.proof_view_for_report(report, run_id="r-explicit")
        assert labelled is not None
        assert labelled.run_id == "r-explicit"

    def test_no_cited_run_labels_nothing(self) -> None:
        report = cg.evaluate_pr_checks(_inputs(cited_run=None))
        view = cg.proof_view_for_report(report)
        assert view is not None
        assert view.run_id == ""

    def test_an_unreachable_report_projects_to_no_view(self) -> None:
        # Fail-closed: no gate ran, so there is no verdict to project — and in
        # particular no PASS view. The caller reads the UNKNOWN checks.
        report = cg.evaluate_pr_checks(_unreachable_inputs())
        assert report.compilation is None
        assert cg.proof_view_for_report(report) is None
        assert report.proof_verdict == "UNKNOWN"

    def test_a_void_proof_projects_to_a_void_view_with_its_reason(self) -> None:
        # No adapter: the capability line cannot be established, so the proof
        # is VOID — and the view says so rather than softening it.
        report = cg.evaluate_pr_checks(_inputs(adapter=None))
        assert not report.proven
        view = cg.proof_view_for_report(report)
        assert view is not None
        assert view.verdict == "VOID"
        assert "capability_requirements" in view.void_reason
        capability = next(line for line in view.lines if line.name == "capability_requirements")
        assert capability.status == "void"

    def test_proof_verdict_names_the_compiled_verdict(self) -> None:
        assert cg.evaluate_pr_checks(_inputs()).proof_verdict == "PASS"
        assert cg.evaluate_pr_checks(_inputs(adapter=None)).proof_verdict == "VOID"


class TestReportProofPayload:
    def test_to_dict_carries_the_proof_payload(self) -> None:
        from mayhem.domain.safety_proof import ObligationName

        report = cg.evaluate_pr_checks(_inputs())
        payload = report.to_dict()
        assert payload["proof_verdict"] == "PASS"
        proof = payload["proof"]
        assert isinstance(proof, dict)
        assert proof["verdict"] == "PASS"
        assert proof["plan_digest"] == report.plan_digest
        assert [line["name"] for line in proof["obligations"]] == [
            name.value for name in ObligationName
        ]

    def test_unreachable_to_dict_carries_no_proof(self) -> None:
        payload = cg.evaluate_pr_checks(_unreachable_inputs()).to_dict()
        assert payload["proof_verdict"] == "UNKNOWN"
        assert payload["proof"] is None


# ── the API second renderer ──────────────────────────────────────────────────


class TestApiProofPayload:
    def test_the_ui_payload_is_the_cli_payload(self) -> None:
        """Plan 08's half, asserted as landed — the plan-14 identity for proofs.

        :func:`~mayhem.controller.api_service.proof_payload` builds the same
        view the CLI projects off and returns the same payload of it, so a UI
        that dropped a line, or renamed a verdict, would fail here.
        """
        from mayhem.cli.proof_cmd import build_proof_view
        from mayhem.cli.proof_cmd import proof_payload as cli_proof_payload
        from mayhem.controller.api_service import proof_payload as ui_proof_payload

        for proof in (
            cg.evaluate_pr_checks(_inputs()).compilation.proof,  # type: ignore[union-attr]
            cg.evaluate_pr_checks(_inputs(adapter=None)).compilation.proof,  # type: ignore[union-attr]
        ):
            view = build_proof_view(proof, run_id="r-ui")
            assert ui_proof_payload(proof, run_id="r-ui") == cli_proof_payload(view)
            assert ui_proof_payload(proof, run_id="r-ui") == view.to_payload()
            rendered = json.dumps(ui_proof_payload(proof, run_id="r-ui"))
            assert view.verdict in rendered
            for line in view.lines:
                assert line.name in rendered, line.name
                assert line.status in rendered, line.status

    def test_void_stays_void_through_the_projection(self) -> None:
        from mayhem.controller.api_service import proof_payload as ui_proof_payload

        compilation = cg.evaluate_pr_checks(_inputs(adapter=None)).compilation
        assert compilation is not None
        payload = ui_proof_payload(compilation.proof)
        assert payload["verdict"] == "VOID"
        assert "capability_requirements" in payload["void_reason"]

    def test_the_ui_projection_comes_from_the_cli_view_model_not_a_copy(self) -> None:
        """The second renderer is a projection, not a reimplementation.

        If ``api_service`` ever grew its own obligation-building, the two could
        disagree about a verdict while every payload-equality test still passed
        on fixtures that never exercised it. So this asserts the mechanism
        rather than one more output.
        """
        import inspect

        from mayhem.controller import api_service

        source = inspect.getsource(api_service.proof_payload)
        assert "build_proof_view" in source
        assert "proof_payload" in source
        assert "Obligation(" not in source
        assert "ObligationStatus." not in source


# ── mayhem ci check grades the proof ─────────────────────────────────────────


def _write_plan_and_graph(tmp_path: Path) -> tuple[Path, Path]:
    plan_path = tmp_path / "plan.json"
    graph_path = tmp_path / "graph.json"
    plan_path.write_text(_plan().model_dump_json(), encoding="utf-8")
    graph_path.write_text(_graph().model_dump_json(), encoding="utf-8")
    return plan_path, graph_path


class TestCiCheckGradesProofs:
    def test_a_reachable_check_prints_the_proof_artifact(self, tmp_path: Path) -> None:
        # `ci check` binds no adapter, so the proof is VOID and the command
        # refuses — and the artifact it prints is the `mayhem prove` one, with
        # the compiler's own reason, not a summary the surface invented.
        plan_path, graph_path = _write_plan_and_graph(tmp_path)
        result = CliRunner().invoke(
            ci,
            [
                "check",
                "--plan",
                str(plan_path),
                "--graph",
                str(graph_path),
                "--sha",
                SHA,
                "--ticket",
                "MAYHEM-4712",
            ],
            obj=None,
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "SAFETY PROOF: VOID" in result.output
        assert "capability_requirements" in result.output

    def test_an_unreachable_check_prints_no_proof(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            ci,
            ["check", "--sha", SHA, "--ticket", "MAYHEM-4712"],
            obj=None,
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "SAFETY PROOF" not in result.output
