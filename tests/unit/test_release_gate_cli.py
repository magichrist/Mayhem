"""``mayhem ci check --release-gate``: the opt-in gate, driven through the real CLI.

:func:`mayhem.controller.check_gate.release_gate` had **no caller in ``src/``** —
a domain function nobody could reach is not a gate, it is a function. This file
exists because ``mayhem.cli.ci_cmd.check_cmd`` now calls it, and a wiring that
only ever existed on paper deserves the same treatment as the engine it wires.

The harness is the one ``tests/unit/test_ci_surface_cli.py`` uses:
:class:`click.testing.CliRunner` driving the real ``mayhem.cli.ci_cmd.ci`` group
over a real plan and topology on disk. Nothing is monkeypatched, no helper is
called directly, and every refusal asserted below is one an operator sees on a
pipeline log. Where a rule already lives in the domain, the rule id is imported
and asserted rather than restated — re-implementing a refusal here would be a
second copy of a rule that could drift from the first.

## Properties pinned

* **Off is off.** With none of the new flags, the command's stdout and its exit
  code are identical to the explicit ``--no-release-gate`` invocation, and the
  gate prints none of its own lines. (Compared modulo the ``proof digest:``
  line: ``SafetyProof`` carries ``evaluated_at=utc_now()`` with a default
  factory, so that one hex string differs between any two runs of *any*
  ``mayhem ci check`` and has nothing to do with this change.)
* **No ``--suite`` is every required suite missing.** It names the owed suite,
  read from :func:`~mayhem.controller.check_gate.required_suites_for` rather
  than from a literal.
* **The suite's three refusals stay in the suite dataclass.** A ``PASS`` with no
  evidence, a ``PASS`` citing no run, and an ``UNKNOWN`` with no detail arrive
  as ``InvariantViolationError`` carrying *its own* rule ids, through the real
  parser, with the domain's sentence intact.
* **An ``UNKNOWN`` that says why is not an ``UNKNOWN`` that does not.** A suite
  that reached the store and found nothing is a different fact from a suite that
  never reached the store, and parsing must not collapse them.
* **Unparseable evidence is a refusal, not an absence.** A ``--suite`` file
  that is an object rather than an array, and a ``--finding`` file that does not
  read back, both stop the command. A malformed finding must never be read as
  "zero findings", which would be a silent allow.
* **A blank ``--subject`` is refused by the domain's own rule**, with
  :class:`~mayhem.controller.check_gate.ReleaseGateRequest`'s sentence, not by a
  CLI paraphrase.
* **A ``verdict is None`` run says so, and says the gate did not decide it.**
* **Two static guards**, because there is no store boundary here to catch a
  regression the way a store boundary would: that ``release_gate`` really is
  inside ``check_cmd``'s call graph (proven to bite by mutating the source
  string), and that the five new options were appended *after* ``--verdict-out``
  so the generated workflow YAML is byte-for-byte untouched.

## Known limitation — pinned, not papered over

.. warning::

   **From this CLI surface the gate can only ever block; it can never allow.**
   ``check_cmd`` builds :class:`~mayhem.controller.check_gate.CheckInputs`
   without a ``cited_run``, so ``verdict.cited_run`` is ``None`` and
   :func:`~mayhem.domain.pipeline.blocking_reasons` always contains *"no run is
   cited, and a run that cannot be cited cannot back a release-gate decision"*.
   The engine's only path to ``allow`` is an empty reason tuple, so from this
   surface that path is unreachable.

   :meth:`TestTheGateCanOnlyBlockFromThisSurface.test_the_gate_can_only_block_from_this_surface`
   asserts the limitation rather than working around it, and asserts statically
   that this surface still supplies no ``cited_run``. **When a ``--run`` pin is
   added, that test fails on purpose** — the reviewer who adds the pin updates it
   and updates the ``check_cmd`` and module docstrings in
   :mod:`mayhem.cli.ci_cmd` at the same time. Do not make it pass by weakening
   it.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
from typing import TYPE_CHECKING, Any

from click.testing import CliRunner

from mayhem.cli import ci_cmd
from mayhem.cli.ci_cmd import ci
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.check_gate import (
    ChangeKind,
    required_suites_for,
)

if TYPE_CHECKING:
    from pathlib import Path

FP = "f" * 64
SHA = "0123456789abcdef0123456789abcdef01234567"
SUBJECT = "checkout v3"

#: The lines only ``_apply_release_gate`` prints. The summary markdown has its own
#: "### Release gate" section, so the substring ``release-gate`` is present even
#: with the gate off; these prefixes are the surface's, and their absence is what
#: "off changes nothing" means.
_GATE_LINE_PREFIXES = (
    "release gate: ",
    "release-gate ",
    "the checks above had already refused; the gate",
    "the checks above had already refused; the release gate",
)

#: One ``RunPin`` the suite rows below cite, and nothing else reads.
RUN_PIN: dict[str, object] = {
    "run_id": "r-9",
    "experiment": "exp-1",
    "release": "rel-9",
    "environment": "ci",
    "plan_version": "plan-7",
    "policy_version": "policy-7",
    "catalog_version": "catalog-2026.09",
    "agent_version": "agent-2.0.0",
    "runtime_version": "runtime-2.1.0",
    "evidence_digest": "d" * 64,
}

#: The required suite for a ``deployment`` change, read from the domain.
DEPLOY_SUITE = required_suites_for(ChangeKind.DEPLOYMENT)[0]


def _plan_and_graph(tmp_path: Path) -> tuple[Path, Path]:
    """A plan and topology on disk, so ``check`` takes its reachable branch.

    Copied from ``tests/unit/test_ci_surface_cli.py`` rather than imported: the
    point of this file is to exercise the CLI, and a fixture shared across test
    modules is one more thing a reader has to go and read to learn what the
    checks saw.
    """
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


def _reachable(*extra: str, tmp_path: Path) -> Any:
    """``ci check`` over a real plan and topology, with ``extra`` appended."""
    plan_path, graph_path = _plan_and_graph(tmp_path)
    return _run(
        "check",
        "--plan",
        str(plan_path),
        "--graph",
        str(graph_path),
        *_change_flags(),
        *extra,
    )


def _write(tmp_path: Path, name: str, payload: Any) -> Path:
    """Write ``payload`` as JSON (or verbatim, for a string) and return the path."""
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def _gate_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith(_GATE_LINE_PREFIXES)]


def _without_proof_digest(output: str) -> str:
    """Blank the one line that is not a function of the command's arguments."""
    return re.sub(r"^proof digest: \S+$", "proof digest: <varies>", output, flags=re.MULTILINE)


def _module_functions(source: str) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(source)
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def _called_from(entry: str, source: str) -> set[str]:
    """Every name called at any depth from ``entry``, through this module's own functions.

    A graph walk rather than a substring search because ``release_gate(`` also
    occurs inside ``_apply_release_gate``, and a guard that only looked at
    ``check_cmd``'s own body would neither find nor lose the indirection.
    """
    functions = _module_functions(source)
    called: set[str] = set()
    seen: set[str] = set()
    pending = [entry]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        node = functions.get(name)
        if node is None:
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                called.add(sub.func.id)
                pending.append(sub.func.id)
    return called


def _check_cmd_option_names() -> list[str]:
    """``check_cmd``'s ``click.option`` names, in decorator (source) order."""
    functions = _module_functions(inspect.getsource(ci_cmd))
    names: list[str] = []
    for decorator in functions["check_cmd"].decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        func = decorator.func
        if not isinstance(func, ast.Attribute) or func.attr != "option":
            continue
        for arg in decorator.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                names.append(arg.value)
                break
    return names


# ── the gate is opt-in ─────────────────────────────────────────────────────────


class TestReleaseGateIsOptIn:
    def test_release_gate_off_is_the_default_and_changes_nothing(self, tmp_path: Path) -> None:
        """The default invocation is the ``--no-release-gate`` invocation.

        Driven three times: twice with no new flags at all, once with
        ``--no-release-gate`` spelled out. All three must agree on output and exit
        code, and none may print a line ``_apply_release_gate`` owns. Compared
        modulo ``proof digest:``, which varies between any two runs of this
        command because ``SafetyProof`` stamps ``evaluated_at`` from
        ``utc_now()`` — see this module's docstring.
        """
        plan_path, graph_path = _plan_and_graph(tmp_path)
        base = (
            "check",
            "--plan",
            str(plan_path),
            "--graph",
            str(graph_path),
            *_change_flags(),
        )
        implicit_first = _run(*base)
        implicit_second = _run(*base)
        explicit_off = _run(*base, "--no-release-gate")

        assert implicit_first.exit_code == ExitCode.SAFETY_REFUSAL
        assert implicit_first.exit_code == implicit_second.exit_code
        assert implicit_first.exit_code == explicit_off.exit_code
        assert _without_proof_digest(implicit_first.output) == _without_proof_digest(
            implicit_second.output
        )
        assert _without_proof_digest(implicit_first.output) == _without_proof_digest(
            explicit_off.output
        )
        assert _gate_lines(implicit_first.output) == []
        assert _gate_lines(explicit_off.output) == []
        # The summary the pre-gate surface already rendered is still the whole
        # story, so this is a passing assertion about unchanged output and not
        # merely an assertion about silence.
        assert "may this open a release: **no**" in implicit_first.output


# ── what the gate is owed, and what it refuses to read as evidence ─────────────


class TestSuiteEvidence:
    def test_no_suites_blocks_on_every_required_suite(self, tmp_path: Path) -> None:
        """An empty ``--suite`` is *every required suite missing*, not "none owed".

        Parametrised over all three change kinds so the owed suite is read from
        :func:`~mayhem.controller.check_gate.required_suites_for` rather than
        from a literal this file could let drift.
        """
        for kind in ChangeKind:
            result = _reachable(
                "--release-gate",
                "--subject",
                SUBJECT,
                "--change-kind",
                kind.value,
                tmp_path=tmp_path,
            )
            assert result.exit_code == ExitCode.SAFETY_REFUSAL, kind.value
            owed = required_suites_for(kind)
            assert f"release-gate suites owed: {', '.join(owed)}" in result.output
            for name in owed:
                assert f"required resilience suite {name!r} did not report" in result.output

    def test_a_passing_suite_with_no_evidence_ref_is_refused_at_parse(self, tmp_path: Path) -> None:
        """The dataclass's first refusal, through the real parser.

        ``RULE_SUITE_WITHOUT_EVIDENCE`` is imported rather than spelled: the point
        is that the *dataclass* refused, so the test asks the dataclass which
        rule and checks the CLI reported that one.
        """
        from mayhem.controller.check_gate import RULE_SUITE_WITHOUT_EVIDENCE

        suite = _write(
            tmp_path,
            "suite.json",
            [{"name": DEPLOY_SUITE, "outcome": "pass", "run": RUN_PIN}],
        )
        result = _reachable(
            "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
        )
        assert RULE_SUITE_WITHOUT_EVIDENCE == "release_gate.suite_without_evidence"
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert f"rule: {RULE_SUITE_WITHOUT_EVIDENCE}" in result.output
        assert "reports pass with no evidence reference" in result.output
        # Refused before the gate ran, so the gate decided nothing.
        assert _gate_lines(result.output) == []

    def test_a_passing_suite_that_cites_no_run_is_refused(self, tmp_path: Path) -> None:
        """The second refusal: a PASS with evidence but nothing to attribute it to."""
        from mayhem.controller.check_gate import RULE_SUITE_WITHOUT_RUN

        suite = _write(
            tmp_path,
            "suite.json",
            [{"name": DEPLOY_SUITE, "outcome": "pass", "evidence_refs": ["gate-output/x"]}],
        )
        result = _reachable(
            "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
        )
        assert RULE_SUITE_WITHOUT_RUN == "release_gate.suite_without_run"
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert f"rule: {RULE_SUITE_WITHOUT_RUN}" in result.output
        assert "reports pass while citing no run" in result.output
        assert _gate_lines(result.output) == []

    def test_an_unknown_suite_without_a_detail_is_refused(self, tmp_path: Path) -> None:
        """The third refusal: an ``UNKNOWN`` that cannot say what it did not know."""
        from mayhem.controller.check_gate import RULE_SUITE_UNKNOWN_UNEXPLAINED

        suite = _write(tmp_path, "suite.json", [{"name": DEPLOY_SUITE, "outcome": "unknown"}])
        result = _reachable(
            "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
        )
        assert RULE_SUITE_UNKNOWN_UNEXPLAINED == "release_gate.unknown_suite_unexplained"
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert f"rule: {RULE_SUITE_UNKNOWN_UNEXPLAINED}" in result.output
        assert "reported unknown without saying" in result.output
        assert _gate_lines(result.output) == []

    def test_an_unreachable_control_plane_differs_from_a_reachable_one(
        self, tmp_path: Path
    ) -> None:
        """Two ``UNKNOWN`` suites that differ only in *why* stay two facts.

        ``ResilienceSuite``'s docstring is explicit that an ``UNKNOWN`` means the
        evidence store was reached and had nothing — a different fact from a suite
        that never reached the store, and conflating them is how "the runner was
        down" gets recorded as "the service is fine". Both details are accepted by
        the parser, and each must reach the gate's reason sentence verbatim, so
        neither can be read as the other downstream.
        """
        reasons = {}
        for label, detail in (
            ("unreachable", "the runner was unreachable"),
            ("reachable", "the evidence store had nothing to report"),
        ):
            suite = _write(
                tmp_path,
                f"suite-{label}.json",
                [{"name": DEPLOY_SUITE, "outcome": "unknown", "detail": detail}],
            )
            result = _reachable(
                "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
            )
            assert result.exit_code == ExitCode.SAFETY_REFUSAL, label
            reasons[label] = [
                line
                for line in result.output.splitlines()
                if line.startswith("release-gate reason:")
            ]

        for label, detail in (
            ("unreachable", "the runner was unreachable"),
            ("reachable", "the evidence store had nothing to report"),
        ):
            assert any(f"did not conclude: {detail}" in line for line in reasons[label]), label
        assert reasons["unreachable"] != reasons["reachable"]
        # Neither run may quote the other's explanation: that would be the
        # conflation the docstring warns about, arriving through the parser.
        assert all("the evidence store had nothing" not in line for line in reasons["unreachable"])
        assert all("the runner was unreachable" not in line for line in reasons["reachable"])

    def test_a_suite_file_that_is_an_object_rather_than_an_array_is_refused(
        self, tmp_path: Path
    ) -> None:
        """One object cannot say which suites ran, so the file is refused whole.

        This is the edge's own refusal, not the dataclass's — it is about a
        *file*, and the message says so.
        """
        suite = _write(tmp_path, "suite.json", {"name": DEPLOY_SUITE, "outcome": "pass"})
        result = _reachable(
            "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
        )
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "is a JSON dict, not an array" in result.output
        assert "one object cannot say which" in result.output
        assert _gate_lines(result.output) == []


# ── the three fail-closed paths before the gate decides anything ──────────────


class TestGateFailures:
    def test_a_missing_subject_is_refused_with_the_gates_own_rule(self, tmp_path: Path) -> None:
        """The domain's sentence, not a CLI paraphrase of it.

        :class:`~mayhem.controller.check_gate.ReleaseGateRequest` raises
        :data:`~mayhem.controller.check_gate.RULE_BLOCK_WITHOUT_REASON` before
        the CLI gets a say, so the sentence an operator reads is the domain's. The
        assertion is on that exact sentence; a paraphrase would satisfy "the
        command refused" and fail here.
        """
        from mayhem.controller.check_gate import RULE_BLOCK_WITHOUT_REASON

        result = _reachable("--release-gate", tmp_path=tmp_path)
        assert RULE_BLOCK_WITHOUT_REASON == "release_gate.block_without_reason"
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert (
            "a release gate must name the deployment, dependency, or infrastructure "
            "change it is deciding about" in result.output
        )
        assert f"rule: {RULE_BLOCK_WITHOUT_REASON}" in result.output
        # The CLI's own remediation is allowed to be its own sentence; the
        # refusal above is not.
        assert "remediation: pass --subject" in result.output

    def test_a_verdict_of_none_reports_the_pipeline_block(self, tmp_path: Path) -> None:
        """An ungradeable run has no candidate release, and says the gate did not decide it.

        No ``--plan`` means an unreachable control plane, which yields checks
        with no evidence references, which Phase 1 refuses to grade into a
        verdict. The gate therefore has nothing to allow, blocks, and — the part
        asserted here — says the checks had already refused rather than claiming
        the outcome.
        """
        result = _run("check", "--release-gate", "--subject", SUBJECT, *_change_flags())
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "there is no candidate release to gate" in result.output
        assert "the release gate did not decide this outcome" in result.output
        assert not any(
            line.startswith("release gate: allow") for line in _gate_lines(result.output)
        )

    def test_a_malformed_finding_file_blocks_rather_than_reading_as_no_findings(
        self, tmp_path: Path
    ) -> None:
        """Malformed input must never become "zero open findings".

        A finding file mayhem cannot read is an unknown number of open findings,
        and an unknown number is not zero. So it has to stop the command — and it
        has to stop it as a *refusal* (a validation exit and an error line), not
        as a gate that ran and found nothing to object to.

        The second half of the test is the half that matters: a file holding an
        *empty array* is a readable statement of "zero findings", and it gets the
        gate running and printing a decision. Two files that look similar to a
        reader therefore take two different roads, and the malformed one does not
        quietly take the readable one.
        """
        malformed = _write(
            tmp_path, "malformed.json", {"finding_id": "f-1", "summary": "latency moved"}
        )
        refused = _reachable(
            "--release-gate", "--subject", SUBJECT, "--finding", str(malformed), tmp_path=tmp_path
        )
        assert refused.exit_code == ExitCode.VALIDATION_ERROR
        assert "comparison.finding_unreadable" in refused.output
        # The gate never reached a decision, so it printed no decision at all.
        assert _gate_lines(refused.output) == []

        empty = _write(tmp_path, "empty.json", [])
        allowed_to_decide = _reachable(
            "--release-gate", "--subject", SUBJECT, "--finding", str(empty), tmp_path=tmp_path
        )
        assert allowed_to_decide.exit_code == ExitCode.SAFETY_REFUSAL
        assert any(
            line.startswith("release gate: ") for line in _gate_lines(allowed_to_decide.output)
        )


# ── the limitation, pinned ─────────────────────────────────────────────────────


class TestTheGateCanOnlyBlockFromThisSurface:
    def test_the_gate_can_only_block_from_this_surface(self, tmp_path: Path) -> None:
        """Without ``--run``, the gate can still only block — and that stays true.

        Even with a required suite that passed, cited a run, and carried evidence
        — every one of the suite half's conditions satisfied — the gate blocks,
        because no ``cited_run`` was passed and ``blocking_reasons`` therefore
        reports *"no run is cited"*.

        **This used to be an unconditional limitation**, asserted with a note that
        it should be updated rather than weakened once a ``--run`` pin existed.
        That pin now exists, so the honest assertion is the conditional one:
        *without* the flag the gate blocks, *with* it the gate can allow (see
        ``TestTheGateCanAllowWithACitedRun`` below). What must **not** change is
        the reason string — it is ``blocking_reasons``' own sentence, and a run
        that cannot be cited still cannot back a release decision.
        """
        suite = _write(
            tmp_path,
            "suite.json",
            [
                {
                    "name": DEPLOY_SUITE,
                    "outcome": "pass",
                    "run": RUN_PIN,
                    "evidence_refs": ["gate-output/resilience"],
                }
            ],
        )
        result = _reachable(
            "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert not any(
            line.startswith("release gate: allow") for line in _gate_lines(result.output)
        )
        assert any(line.startswith("release gate: block") for line in _gate_lines(result.output))
        # The suite half is satisfied: owed, reported, passed, cited, evidenced.
        assert not any("did not report" in line for line in _gate_lines(result.output))
        assert f"release-gate evidence: run/{RUN_PIN['experiment']}@" in result.output
        # The pipeline half is what closed it, and it is the same sentence
        # ``blocking_reasons`` would produce anywhere else in the codebase.
        assert (
            "no run is cited, and a run that cannot be cited cannot back a "
            "release-gate decision" in result.output
        )

    def test_no_run_flag_means_no_cited_run(self) -> None:
        """The cause is still structural, just opt-in now.

        ``cited_run`` *is* named in ``ci_cmd`` — ``--run`` threads it in. What must
        hold is that it is ``None`` unless the flag was given, so the default
        invocation cannot quietly start citing a run nobody named.
        """
        source = inspect.getsource(ci_cmd)
        assert "_run_pin_from_path(ctx, run_path)" in source
        assert "cited_run=cited_run" in source
        assert 'default=""' in source


class TestTheGateCanAllowWithACitedRun:
    def test_a_cited_run_removes_the_no_run_is_cited_reason(self, tmp_path: Path) -> None:
        """``--run`` removes the structural blocker this surface used to carry.

        Scoped precisely to what is true here. This fixture's plan fails several
        of its own checks (target, blast-radius, damage-budget), so the gate
        still blocks — and asserting otherwise would be a fake test. What ``--run``
        changes is exactly one thing: the *"no run is cited"* reason disappears,
        because ``CheckInputs`` now carries a pin.

        The **allow** branch is proven where it can be proven honestly, at the
        fixture level in ``tests/unit/test_ci_pipeline_gates.py``, where a
        genuinely passing verdict and a passing suite reach
        ``ReleaseGateDecision.opens_release == True``. Driving a full allow
        through this CLI needs a plan and topology that pass every check, which is
        a fixture this module deliberately does not fake.
        """
        suite = _write(
            tmp_path,
            "suite.json",
            [
                {
                    "name": DEPLOY_SUITE,
                    "outcome": "pass",
                    "run": RUN_PIN,
                    "evidence_refs": ["gate-output/resilience"],
                }
            ],
        )
        without = _reachable(
            "--release-gate", "--subject", SUBJECT, "--suite", str(suite), tmp_path=tmp_path
        )
        pin_file = _write(tmp_path, "run.json", dict(RUN_PIN))
        with_run = _reachable(
            "--release-gate",
            "--subject",
            SUBJECT,
            "--suite",
            str(suite),
            "--run",
            str(pin_file),
            tmp_path=tmp_path,
        )
        no_run_cited = "no run is cited, and a run that cannot be cited cannot back a"
        assert no_run_cited in without.output
        assert no_run_cited not in with_run.output, with_run.output
        # The suite half was already satisfied in both, so the difference is the
        # pin and nothing else.
        for result in (without, with_run):
            assert not any("did not report" in line for line in _gate_lines(result.output))
            assert f"release-gate evidence: run/{RUN_PIN['experiment']}@" in result.output

    def test_a_malformed_run_file_refuses_rather_than_reporting_no_run_cited(
        self, tmp_path: Path
    ) -> None:
        """A typo in ``--run`` must not become "no run cited".

        Silently degrading to no pin is the fail-open this option exists to
        close: the operator would see a gate blocked for a reason they are not
        looking at, and would go looking in the wrong place.
        """
        bad = _write(tmp_path, "run.json", {"run_id": "r-1"})
        result = _reachable("--run", str(bad), tmp_path=tmp_path)
        assert result.exit_code == ExitCode.VALIDATION_ERROR, result.output
        assert "no run is cited" not in result.output, result.output
        # It names the offending file rather than reporting a gate decision.
        assert "run.json" in result.output
        assert "is not a run pin mayhem can cite" in result.output, result.output


# ── the two static guards ──────────────────────────────────────────────────────


class TestStaticGuards:
    def test_check_cmd_still_calls_the_release_gate(self) -> None:
        """The wiring itself, because nothing else here would notice it going.

        ``release_gate`` had zero callers in ``src/`` for the whole of this
        module's subject line, and no store boundary exists on this surface to
        raise when it loses one again. So the guard is static: parse
        :mod:`mayhem.cli.ci_cmd`, walk the call graph out of ``check_cmd``, and
        require the engine in it.

        The guard is proven to bite by mutating the source string: drop the call
        in the helper, and drop the helper's call from ``check_cmd``. Both must
        make the guard fail, and each mutation must actually change the source,
        so the assertion cannot pass vacuously on a substitution that missed.
        """
        source = inspect.getsource(ci_cmd)
        assert "release_gate" in _called_from("check_cmd", source), (
            "mayhem ci check no longer reaches release_gate: the gate is dead code again"
        )

        without_the_engine_call = source.replace(
            "release_gate(verdict, request", "_gate_was_never_called(verdict, request"
        )
        assert without_the_engine_call != source, "mutation 1 did not change the source"
        assert "release_gate" not in _called_from("check_cmd", without_the_engine_call)

        without_the_helper_call = source.replace(
            "\n            _apply_release_gate(", "\n            _gate_was_never_wired("
        )
        assert without_the_helper_call != source, "mutation 2 did not change the source"
        assert "release_gate" not in _called_from("check_cmd", without_the_helper_call)

    def test_the_new_options_were_appended_after_verdict_out(self) -> None:
        """Additive, not interleaved — so the generated workflow YAML is untouched.

        ``mayhem ci workflow`` renders a ``run:`` line from a fixed flag order
        (asserted byte-for-byte in ``tests/unit/test_ci_surface_cli.py``). A new
        option spliced *into* the middle of ``check_cmd``'s decorators would move
        nothing on that line, but one inserted above ``--verdict-out`` would put
        the release gate's flags in front of the ones a caller already scripted.
        Appending after ``--verdict-out`` is the cheap, checkable promise that
        this change only ever added to the surface.
        """
        names = _check_cmd_option_names()
        assert names[-7:] == [
            "--verdict-out",
            "--release-gate/--no-release-gate",
            "--subject",
            "--change-kind",
            "--suite",
            "--finding",
            "--run",
        ], names
        for added in (
            "--release-gate/--no-release-gate",
            "--subject",
            "--change-kind",
            "--suite",
            "--finding",
            "--run",
        ):
            assert names.index("--verdict-out") < names.index(added), added
