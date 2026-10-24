"""``mayhem ci`` — the CI/GitOps surface a pipeline actually calls
(docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 3, surface commands).

Four commands, each a *thin* renderer or dispatcher over an engine that already
exists:

``mayhem ci workflow``
    Render a pinned GitHub Actions workflow or GitLab CI component from a
    :class:`~mayhem.controller.ci_surface.WorkflowSpec`. Refuses a floating
    action tag and an unpinned image, and refuses an untrusted value that
    carries shell syntax — the generator puts untrusted values in ``env:`` and
    reads them as quoted ``"$MAYHEM_…"``, so nothing an attacker can type reaches
    a shell.

``mayhem ci check``
    Evaluate a pull request's checks through
    :func:`mayhem.controller.check_gate.evaluate_pr_checks` — the same
    compile → proof → policy path the CLI and the ChatOps path use — render the
    PR-check summary, and **exit non-zero when any check did not pass**. An
    unreadable plan or topology is reported as an unreachable control plane, so
    the checks come back ``UNKNOWN`` and the command still exits non-zero: "mayhem
    could not ask" is not "nothing to report", and a CI step that exits 0 because
    it could not reach its own control plane is a gate that fails open. The
    compiled safety proof is printed as the ``mayhem prove`` artifact — the same
    view-model, projected read-only — and the exit refuses a proof that is not a
    PASS as well as any check that did not pass.

    Two consequences of that design are worth stating plainly, because both look
    like defects and neither is:

    * **No runtime adapter is bound**, so ``validate_plan`` skips the capability
      check and ``capability_requirements`` cannot be established. A plan that
      names a fault therefore always fails ``fault-compatibility``, with the
      compiler's own sentence as the detail. Mayhem will not report a
      compatibility check as passing when it did not ask a runtime anything, and
      this command will not grow a ``--adapter`` flag to make that stop being
      true — an adapter is a live connection, and a CI check should not open one.
    * **The policy is the default one, not the repository's**, because a
      repository-supplied policy file is part of the change under test. See
      :func:`_safety_context`.

``mayhem ci check --release-gate``
    Opt-in, and off by default: the existing invocation's bytes, its exit code,
    and its output are unchanged. With the flag, the check additionally asks
    :func:`mayhem.controller.check_gate.release_gate` whether the change may open
    a release — the same function the ChatOps path and the domain use, now with a
    caller. The gate runs *after* the proof is rendered and *before* the exit,
    and a passing check suite cannot rescue it: the two are separate questions,
    and the release gate can only add a refusal, never lift one.

    The gate is fail-closed at every step. A change with no ``--subject`` is
    refused by :class:`~mayhem.controller.check_gate.ReleaseGateRequest` itself,
    with the rule's own sentence, rather than by a CLI paraphrase of it. No
    ``--suite`` file is **not** "no suites owed" — it is every required suite
    missing, which is precisely what the gate blocks on — so asking for the gate
    and supplying no evidence gets a closed gate that names the missing suite.

``mayhem ci suite``
    Produce the ``--suite`` file the gate above reads, out of evidence this
    repository already stores. Until it existed nothing in ``src/`` produced one,
    so a workflow generated with ``--release-gate`` always blocked — correctly,
    because every owed suite was missing, and uselessly, because no command in
    the tree could fill the gap.

    It grades one stored run against the suites the change owes, and it fails
    closed at every step. A run the store does not hold is a **refusal**, never
    an invented pin. Coverage that is empty is ``UNKNOWN`` carrying a detail,
    never a pass. And ``UNKNOWN`` is **not** a soft pass:
    :func:`mayhem.controller.check_gate.release_gate` blocks on it exactly as it
    blocks on ``FAIL`` — the two are the same answer to the gate, and the only
    difference is what an operator should go and fix.

    Every suite the change owes is reported, including the ones that could not
    conclude, so the gate sees a *complete* report naming what is missing rather
    than a gap it has to infer. A suite this command did not report would leave
    the gate on its "did not report" branch, which says "you owe me a suite file"
    when the truth is "the evidence is not there" — two different problems
    behind one symptom, and only the first of them is the operator's to fix.

    .. warning::

       **On a store this repository builds today, this command cannot emit
       ``pass`` — and will usually refuse before it can try.** It reads two
       writers that nothing in ``src/`` calls:
       :meth:`mayhem.infra.coverage_service.ComparisonService.record_run`
       (no run's measurements are ever sealed, so ``--run`` has nothing to
       find) and
       :meth:`mayhem.infra.coverage_service.CoverageDimensionRepository.record_evidence`
       (no dimension sighting is ever recorded). The ``m5_coverage``
       accounting *is* written by a real path —
       :mod:`mayhem.controller.cell_runner` — but only with a cell state, never
       with a ``RunPin``, so on its own it cannot answer "about which run".

       That gap is upstream of this command and is deliberately not papered over
       here: a rule loosened until ``pass`` became reachable would be a gate that
       opens on nothing, which is the one outcome this whole surface exists to
       prevent. Closing the gap means calling those two writers from the run
       path.

``mayhem ci summary``
    Render the same summary from a verdict document on disk. The commit-status
    step reads it; it is a renderer and it grades nothing.

``mayhem ci status``
    Print the commit status a verdict *would* post, and say plainly that it was
    not posted: this repository ships no forge client, so
    :class:`~mayhem.controller.ci_surface.CommitStatusPort` is unbound and the
    publication is reported as unavailable. The command never pretends otherwise.

Nothing here shells out, and nothing here interpolates a caller-supplied value
into a command line: the values are read into typed objects, validated by the
same constructors the engine validates with, and rendered as data. ``--out`` is
the only file this group writes, it is the path the caller named, and no part of
that path is ever used to build a command.

.. warning::

   **The group is registered, but nothing has ever called it from a pipeline.**
   ``ci`` is in :data:`mayhem.cli.command_registry.COMMAND_SPECS`, so
   ``mayhem ci --help`` resolves and the commands are reachable by a person —
   which is the registration debt this module's earlier revision named. What is
   *not* true is the next step up: this repository ships no forge client, so
   :class:`~mayhem.controller.ci_surface.CommitStatusPort` is unbound and
   ``ci status`` can only report the publication as unavailable. No GitHub
   Actions workflow and no GitLab pipeline in this repository has ever invoked
   mayhem, so nothing here has been exercised by a real CI system. Treat
   ``--help`` as the authority on the surface: the refusals described above are
   the ones this build returns, not ones a future integration may lift.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.proof_cmd import render_proof_lines
from mayhem.cli.resolver import make_group
from mayhem.cli.services import DEFAULT_DB, open_store
from mayhem.config import PolicyCfg
from mayhem.controller.check_gate import (
    CHECK_ORDER,
    ChangeKind,
    CheckInputs,
    ReleaseGateRequest,
    ResilienceSuite,
    evaluate_pr_checks,
    proof_view_for_report,
    release_gate,
    required_suites_for,
)
from mayhem.controller.ci_surface import (
    CHECKOUT_ACTION,
    SETUP_PYTHON_ACTION,
    ImagePin,
    Provider,
    WorkflowSpec,
    publish_commit_status,
    render_check_summary,
    render_github_workflow,
    render_gitlab_component,
    status_for,
)
from mayhem.controller.safety import SafetyContext
from mayhem.domain.comparison import RegressionFinding, RunPin
from mayhem.domain.coverage import CellState
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
from mayhem.domain.pipeline import (
    ChangeLink,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    PipelineOutcome,
    PipelinePins,
    PipelineVerdict,
)
from mayhem.domain.topology import TopologyGraph
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.coverage_service import (
    PLAN_22_SUITES,
    ComparisonService,
    CoverageDimensionRepository,
)

if TYPE_CHECKING:
    from mayhem.infra.store import Store

__all__ = ["ci"]

ci = make_group(
    "ci",
    "Validate a pull request, render a pinned CI workflow, and report the verdict.",
)


def _fail(ctx: click.Context, exc: MayhemCliError) -> None:
    """Emit a refusal in this surface's contract and exit with its code."""
    exc.emit(debug=bool(getattr(ctx.obj, "debug", False)) if ctx.obj else False)
    ctx.exit(int(exc.exit_code))


def _refuse(
    ctx: click.Context,
    exc: MayhemCliError | InvariantViolationError | OSError | ValueError,
    *,
    remediation: str = "",
) -> None:
    """Route *any* refusal this group can produce through :func:`_fail`.

    One funnel, on purpose. Before this existed, a malformed ``--env`` pair and a
    ``--out`` path pointing at a directory were raised where the app-level handler
    could catch them, while a floating action tag was emitted by this group — two
    different error contracts inside one command group, which means the exit code
    a caller sees depends on *which* check happened to reject the input. A caller
    gating on an exit code should not have to know which refusal it triggered.
    """
    if isinstance(exc, MayhemCliError):
        _fail(ctx, exc)
        return
    if isinstance(exc, InvariantViolationError):
        _fail(
            ctx,
            MayhemCliError(
                code="validation_error",
                message=str(exc),
                details={"rule": exc.rule},
                remediation=remediation
                or "pin the action to a 40-character commit SHA and the image to a sha256 digest",
            ),
        )
        return
    _fail(
        ctx,
        MayhemCliError(
            code="validation_error",
            message=str(exc),
            details={},
            remediation=remediation or "check the values this command was given",
        ),
    )


def _write_or_echo(text: str, destination: str) -> None:
    """Write to ``destination`` or print. A directory is refused, not overwritten."""
    if not destination:
        click.echo(text)
        return
    path = Path(destination)
    if path.is_dir():
        raise MayhemCliError(
            code="validation_error",
            message=f"{destination} is a directory; mayhem will not write a file over one",
            details={"path": destination},
            remediation="name a file path",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _parse_env(pairs: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """``NAME=EXPRESSION`` pairs, or a refusal naming the malformed one."""
    parsed: list[tuple[str, str]] = []
    for pair in pairs:
        name, sep, expression = pair.partition("=")
        if not sep or not name.strip() or not expression.strip():
            raise MayhemCliError(
                code="usage_error",
                message=(
                    f"--env {pair!r} is not NAME=EXPRESSION. The name becomes a MAYHEM_ "
                    "environment variable; the expression is the forge's own, and it "
                    "reaches the script only as a quoted expansion"
                ),
                details={"pair": pair},
                remediation="pass --env plan_ref='${{ github.event.pull_request.head.ref }}'",
            )
        parsed.append((name.strip(), expression.strip()))
    return tuple(parsed)


# --------------------------------------------------------------------------- #
# workflow                                                                     #
# --------------------------------------------------------------------------- #


@ci.command("workflow")
@click.option(
    "--provider",
    type=click.Choice([provider.value for provider in Provider]),
    required=True,
    help="Which CI system to generate for.",
)
@click.option("--name", default="mayhem-checks", help="Workflow name (lowercase, [a-z0-9._-]).")
@click.option(
    "--image",
    required=True,
    help="Container image the checks run under, pinned as repository@sha256:<digest>. "
    "A tag is refused: a gate that runs against whatever a tag points at today is "
    "not the gate that ran yesterday.",
)
@click.option(
    "--check",
    "checks",
    type=click.Choice([scope.value for scope in CheckScope]),
    multiple=True,
    help="A check scope to pass to `mayhem ci check`. Repeatable.",
)
@click.option(
    "--release-gate/--no-release-gate",
    default=False,
    help="Whether the generated workflow also asks for the release gate.",
)
@click.option(
    "--env",
    "env_pairs",
    multiple=True,
    metavar="NAME=EXPR",
    help="An untrusted input to bind as MAYHEM_<NAME>. Repeatable.",
)
@click.option("--out", default="", metavar="PATH", help="Write here instead of stdout.")
@click.pass_context
def workflow_cmd(
    ctx: click.Context,
    provider: str,
    name: str,
    image: str,
    checks: tuple[str, ...],
    release_gate: bool,
    env_pairs: tuple[str, ...],
    out: str,
) -> None:
    """Render a pinned CI workflow. Deterministic: same flags, same bytes."""
    try:
        spec = WorkflowSpec(
            name=name,
            provider=Provider(provider),
            image=ImagePin(image=image, purpose="the mayhem build the checks run under"),
            actions=(CHECKOUT_ACTION, SETUP_PYTHON_ACTION),
            checks=tuple(CheckScope(value) for value in checks),
            untrusted_inputs=_parse_env(env_pairs),
            release_gate=release_gate,
        )
        rendered = (
            render_github_workflow(spec)
            if spec.provider is Provider.GITHUB
            else render_gitlab_component(spec)
        )
    except MayhemCliError as exc:
        _fail(ctx, exc)
        return
    except (InvariantViolationError, OSError, ValueError) as exc:
        _refuse(
            ctx,
            exc,
            remediation="pin the action to a 40-character commit SHA and the image to "
            "a sha256 digest",
        )
        return
    try:
        _write_or_echo(rendered, out)
    except (MayhemCliError, OSError) as exc:
        _refuse(ctx, exc, remediation="pass --out a writable file path")
        return


# --------------------------------------------------------------------------- #
# check                                                                        #
# --------------------------------------------------------------------------- #


def _read_json(path: str, subject: str) -> Any:
    candidate = Path(path)
    if not candidate.is_file():
        raise MayhemCliError(
            code="validation_error",
            message=f"{subject} file {path!r} does not exist",
            details={"path": path},
            remediation="pass a path mayhem wrote earlier in this job",
        )
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise MayhemCliError(
            code="validation_error",
            message=f"{subject} file {path!r} is not JSON: {exc}",
            details={"path": path},
            remediation="regenerate it with the command that produced it",
        ) from None


def _load_plan(path: str) -> ExecutionPlan | None:
    try:
        return ExecutionPlan.model_validate(_read_json(path, "plan"))
    except (ValueError, InvariantViolationError):
        return None


def _load_graph(path: str) -> TopologyGraph | None:
    if not path:
        return None
    try:
        return TopologyGraph.model_validate(_read_json(path, "topology"))
    except (ValueError, InvariantViolationError):
        return None


def _parse_pins(pairs: tuple[str, ...]) -> PipelinePins:
    axes: dict[str, str] = {}
    for pair in pairs:
        axis, sep, value = pair.partition("=")
        if not sep or not value.strip():
            raise MayhemCliError(
                code="usage_error",
                message=f"--pin {pair!r} is not axis=value",
                details={"pair": pair},
                remediation="pin plan_version, policy_version, catalog_version, "
                "agent_version, and runtime_version",
            )
        axes[axis.strip()] = value.strip()
    try:
        return PipelinePins(**axes)
    except (TypeError, ValueError) as exc:
        raise MayhemCliError(
            code="usage_error",
            message=f"--pin names an axis mayhem does not have: {exc}",
            details={"axes": sorted(axes)},
            remediation="the axes are plan, policy, catalog, agent, runtime",
        ) from None


def _unreachable_reason(plan: object, graph: object, plan_path: str) -> str:
    """Why the control plane is unreachable, or ``""`` when it is not.

    Two findings, worded differently on purpose: "mayhem was handed no plan" is a
    fact about the invocation, and "mayhem was handed no topology" is a fact about
    the target resolution. Both mean the checks below cannot conclude, and both
    are reported rather than absorbed, because a CI job that ran with a missing
    file should say which file.
    """
    if plan is None:
        return (
            f"the plan at {plan_path!r} could not be read, so mayhem compiled no safety case for it"
            if plan_path
            else "no --plan was supplied"
        )
    if graph is None:
        return (
            "no topology was readable, so mayhem cannot resolve any target and cannot "
            "measure a blast radius"
        )
    return ""


def _safety_context(fingerprint: str) -> SafetyContext:
    """The safety context the checks compile against: default policy, no budget.

    Explicitly *not* the project's policy. A pull-request check runs on whatever
    the CI checkout contains, and a repository-supplied policy file is a thing the
    pull request itself can change — so a PR that loosened the policy would be
    checked against its own loosening. The default is the conservative one, and
    the surface says which it used.
    """
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(),
        fingerprint=fingerprint or "unreadable",
    )


def _evaluate(
    plan: ExecutionPlan | None,
    graph: TopologyGraph | None,
    change: ChangeLink,
    *,
    fingerprint: str,
    plan_path: str = "",
    cited_run: RunPin | None = None,
) -> tuple[Any, str]:
    """Run the real engine, unreachable or not, and return ``(report, reason)``.

    Both branches build the *same* :class:`CheckInputs`; the only difference is
    :attr:`~mayhem.controller.check_gate.CheckInputs.control_plane` and the
    substrate the unreachable branch has to stand in with. That is deliberate: the
    difference between ``UNKNOWN`` and ``PASS`` should have exactly one place it
    can come from, and this function is that place.

    ``cited_run`` is threaded into **both** branches. It is not restricted to the
    reachable one: a cited run is a fact about evidence, and the unreachable
    branch's seven ``UNKNOWN`` checks are already the refusal, so letting the pin
    through changes nothing there except keeping the two branches identical in
    shape.
    """
    reason = _unreachable_reason(plan, graph, plan_path)
    if reason or plan is None or graph is None:
        inputs = CheckInputs(
            plan=_unusable_plan(),
            graph=_empty_graph(),
            safety=_safety_context(fingerprint),
            change=change,
            cited_run=cited_run,
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail=reason or "the plan or topology was not readable",
        )
    else:
        inputs = CheckInputs(
            plan=plan,
            graph=graph,
            safety=_safety_context(fingerprint or plan.environment_fingerprint),
            change=change,
            cited_run=cited_run,
        )
    return evaluate_pr_checks(inputs), reason


def _run_pin_from_path(ctx: click.Context, path: str) -> RunPin | None:
    """The run this change is measured against, or ``None`` when none was named.

    A release-gate decision needs a cited run: ``blocking_reasons`` refuses with
    *"no run is cited, and a run that cannot be cited cannot back a release-gate
    decision"*, which is why ``--release-gate`` could only ever block before this
    option existed.

    Two decisions worth stating:

    * **The pin comes from a file, not the store.** This command's docstring
      claims it is *"Read-only with respect to the store and to any control
      plane"*, and a cited run is a claim about sealed evidence that the
      operator, not this process, vouches for. Reading it from the database
      would make the check depend on the very plane it must not depend on.
    * **A malformed file refuses; it never degrades to "no run cited."** Silently
      falling back would turn a typo in a path into a gate that blocks for a
      reason the operator is not looking at, which is the fail-open this option
      exists to close.
    """
    if not path.strip():
        return None
    try:
        return RunPin.from_dict(_read_json(path, "the cited run's pin"))
    except (InvariantViolationError, TypeError, ValueError) as exc:
        _refuse(
            ctx,
            exc
            if isinstance(exc, InvariantViolationError)
            else MayhemCliError(
                code="validation_error",
                message=f"{path!r} is not a run pin mayhem can cite: {exc}",
                details={"path": path},
                remediation="write it with mayhem's own pin writer; every field is "
                "required and evidence_digest must be sha256 hex",
            ),
            remediation="pass --run a JSON file holding one RunPin",
        )
        return None


def _suites_from_paths(paths: tuple[str, ...]) -> tuple[ResilienceSuite, ...]:
    """The resilience suites a ``--suite`` file — or files — declare, as objects.

    Each file is a JSON **array** of suite rows. An array rather than an object
    because the gate is about a *set* of suites owed, and a file carrying one
    suite is the common case rather than the special one.

    Every row becomes a
    :class:`~mayhem.controller.check_gate.ResilienceSuite` and is validated by
    that dataclass, not here. Its three refusals — a ``PASS`` with no evidence
    reference, a ``PASS`` citing no run, an ``UNKNOWN`` that does not say why —
    stay in one place on purpose; restating them here would be a second copy of
    a rule that could drift from the first. This edge adds only what the
    dataclass cannot know about a *file*: that it exists, that it is an array,
    that an entry is an object, and which entry of which file was rejected.

    An empty ``paths`` is **not** "no suites are owed". It is every required
    suite missing, which is exactly what
    :func:`~mayhem.controller.check_gate.release_gate` blocks on. A caller that
    asks for the gate and supplies no evidence gets a closed gate naming the
    suite it owed, never an open one.
    """
    suites: list[ResilienceSuite] = []
    for path in paths:
        payload = _read_json(path, "resilience suite")
        if not isinstance(payload, list):
            raise MayhemCliError(
                code="validation_error",
                message=(
                    f"resilience suite file {path!r} is a JSON {type(payload).__name__}, "
                    "not an array: a suite file declares the suites that ran, and one "
                    "object cannot say which"
                ),
                details={"path": path},
                remediation='write [{"name": ..., "outcome": ..., "run": ...}]',
            )
        for index, row in enumerate(payload):
            if not isinstance(row, Mapping):
                raise MayhemCliError(
                    code="validation_error",
                    message=(
                        f"resilience suite file {path!r} entry {index} is "
                        f"{row!r}, which is not a suite object"
                    ),
                    details={"path": path, "entry": index},
                    remediation="each entry names the suite it reports and its outcome",
                )
            refs = row.get("evidence_refs") or ()
            run = row.get("run")
            try:
                if isinstance(refs, str) or not isinstance(refs, (list, tuple)):
                    raise ValueError(f"evidence_refs must be an array, not {refs!r}")
                if run is not None and not isinstance(run, Mapping):
                    raise ValueError("run must be an object mayhem can pin, or null")
                raw_outcome = row.get("outcome")
                if not isinstance(raw_outcome, str):
                    raise ValueError(f"outcome must be a string, not {raw_outcome!r}")
                suites.append(
                    ResilienceSuite(
                        name=str(row.get("name") or ""),
                        outcome=CheckOutcome(raw_outcome),
                        evidence_refs=tuple(str(ref) for ref in refs),
                        run=None if run is None else RunPin.from_dict(run),
                        detail=str(row.get("detail") or ""),
                    )
                )
            except (TypeError, ValueError) as exc:
                # Shape and vocabulary only. The suite's own three refusals are
                # InvariantViolationErrors and travel past this handler untouched,
                # so the domain's message is the one a reader sees.
                raise MayhemCliError(
                    code="validation_error",
                    message=(
                        f"resilience suite file {path!r} entry {index} is not a suite "
                        f"mayhem can read: {exc}"
                    ),
                    details={"path": path, "entry": index},
                    remediation="each entry names a suite, an outcome (pass, fail, or "
                    "unknown), its evidence refs, and the run it cites",
                ) from None
    return tuple(suites)


def _apply_release_gate(
    ctx: click.Context,
    *,
    change: ChangeLink,
    verdict: PipelineVerdict | None,
    blocked_already: bool,
    subject: str,
    change_kind: str,
    suite_paths: tuple[str, ...],
    finding_paths: tuple[str, ...],
) -> bool:
    """Ask the release gate about ``change`` and report its answer. ``True`` = blocked.

    Three refusals, and all three fail closed:

    1. **No ``--subject``.** Not pre-empted here. The request object raises
       :data:`~mayhem.controller.check_gate.RULE_BLOCK_WITHOUT_REASON` with its
       own sentence, and that sentence — not a CLI paraphrase of it — is what an
       operator reads.
    2. **No verdict.** ``verdict is None`` means the checks could not be graded
       into a citable one, so no run is cited and there is no candidate release
       for a gate to allow. That is a documented case rather than an error: it is
       reported and it blocks.
    3. **An unreadable suite or finding file.** Routed through the same
       :func:`_refuse` funnel every other refusal in this group uses, so the
       exit code a caller sees does not depend on which check happened to
       reject the input.

    The domain is handed objects, never dicts: ``ResilienceSuite`` and
    ``RegressionFinding`` instances built by their own constructors, so nothing
    downstream of this line can be handed a shape the domain would have refused.
    """
    try:
        request = ReleaseGateRequest(change=change, kind=ChangeKind(change_kind), subject=subject)
    except (InvariantViolationError, ValueError) as exc:
        _refuse(
            ctx,
            exc,
            remediation="pass --subject naming the deployment, dependency, or "
            "infrastructure change this gate is deciding about",
        )
        return True
    if verdict is None:
        click.echo(
            style.info(
                f"release gate: block ({change_kind} {subject!r}) — there is no candidate "
                "release to gate: the checks produced no citable verdict, so no run is "
                "cited and there is nothing here a gate could allow"
            )
        )
        if blocked_already:
            click.echo(
                style.info(
                    "the checks above had already refused; the release gate did not decide "
                    "this outcome"
                )
            )
        return True
    findings: list[RegressionFinding] = []
    try:
        suites = _suites_from_paths(suite_paths)
        for path in finding_paths:
            payload = _read_json(path, "regression finding")
            rows = payload if isinstance(payload, list) else [payload]
            for index, row in enumerate(rows):
                if not isinstance(row, Mapping):
                    raise MayhemCliError(
                        code="validation_error",
                        message=(
                            f"regression finding file {path!r} entry {index} is "
                            f"{row!r}, which is not a finding object"
                        ),
                        details={"path": path, "entry": index},
                        remediation="write it with the command that opened the finding",
                    )
                findings.append(RegressionFinding.from_dict(row))
    except (MayhemCliError, InvariantViolationError, TypeError, ValueError) as exc:
        # ``TypeError`` and ``ValueError`` are caught here on purpose: the suite
        # and finding parsers raise the builtins for a shape they cannot read, and
        # this surface must report that as a refusal with its own remediation
        # rather than as a traceback. ``_refuse`` is typed for the CLI's own
        # exception vocabulary, so the message is rendered here.
        _refuse(
            ctx,
            exc
            if isinstance(exc, (MayhemCliError, InvariantViolationError))
            else MayhemCliError(
                code="validation_error",
                message=f"{path!r} could not be read as {path!r}: {exc}",
                details={"path": path},
                remediation="pass --suite and --finding files mayhem wrote earlier in this job",
            ),
            remediation="pass --suite and --finding files mayhem wrote earlier in this job",
        )
        return True
    decision = release_gate(verdict, request, suites=suites, open_findings=findings)
    allow = "allow" if decision.opens_release else "block"
    click.echo(style.info(f"release gate: {allow} ({decision.kind.value} {decision.subject})"))
    click.echo(style.info(f"release-gate suites owed: {', '.join(decision.required_suites)}"))
    for reason in decision.reasons:
        click.echo(style.info(f"release-gate reason: {reason}"))
    for ref in decision.evidence_refs:
        click.echo(style.info(f"release-gate evidence: {ref}"))
    if blocked_already and not decision.opens_release:
        click.echo(style.info("the checks above had already refused; the gate did not decide this"))
    return not decision.opens_release


@ci.command("check")
@click.option("--plan", "plan_path", default="", metavar="PATH", help="Plan JSON to check.")
@click.option(
    "--graph",
    "graph_path",
    default="",
    metavar="PATH",
    help="Topology JSON the plan's targets resolve in. Omit it and mayhem reports the "
    "control plane unreachable: no graph means no target check, and an unasked "
    "question is not a passed one.",
)
@click.option("--sha", default="", help="Git SHA of the change under check (7-40 hex).")
@click.option("--ticket", default="", help="Change ticket this check belongs to.")
@click.option("--incident", default="", help="Incident this change answers.")
@click.option("--deployment", default="", help="Deployment this change is part of.")
@click.option("--pin", "pin_pairs", multiple=True, metavar="AXIS=VALUE", help="Version pin.")
@click.option("--environment", default="ci", help="Environment scope the checks run in.")
@click.option(
    "--fingerprint",
    default="",
    help="Environment fingerprint the safety case is compiled against. Empty means "
    "the plan's own, which is honest rather than strict: no fingerprint is not a "
    "failed drift check, and this command says which it did.",
)
@click.option(
    "--summary",
    "summary_path",
    default="",
    metavar="PATH",
    help="Write the PR-check markdown here (e.g. $GITHUB_STEP_SUMMARY).",
)
@click.option("--verdict-out", default="", metavar="PATH", help="Write the verdict JSON here.")
@click.option(
    "--release-gate/--no-release-gate",
    default=False,
    help="Also ask the release gate whether this change may open a release. Off by "
    "default: without it the command's output and exit code are exactly what they "
    "were before, and the gate can only add a refusal, never lift one.",
)
@click.option(
    "--subject",
    default="",
    metavar="TEXT",
    help="The deployment, dependency, or infrastructure change the release gate is "
    "deciding about. Required by --release-gate: a gate that blocks without naming "
    "what it blocked is indistinguishable from a gate nobody wired up.",
)
@click.option(
    "--change-kind",
    type=click.Choice([kind.value for kind in ChangeKind]),
    default=ChangeKind.DEPLOYMENT.value,
    help="What changed — and therefore which resilience suites are owed, and which of "
    "them is missing when the gate blocks. Only consulted by --release-gate.",
)
@click.option(
    "--suite",
    "suite_paths",
    multiple=True,
    metavar="PATH",
    help="JSON array of resilience-suite results to feed the release gate. Repeatable. "
    "Omitting it does not mean no suite is owed: it means every required suite is "
    "missing, which blocks.",
)
@click.option(
    "--finding",
    "finding_paths",
    multiple=True,
    metavar="PATH",
    help="JSON regression finding to feed the release gate. Repeatable. Only findings "
    "whose candidate is this verdict's cited run block.",
)
@click.option(
    "--run",
    "run_path",
    default="",
    metavar="PATH",
    help="JSON file holding the RunPin of the run this change is measured against. "
    "A release-gate decision needs a cited run: without one, `blocking_reasons` "
    "refuses with 'no run is cited' and the gate can only ever block. The file is "
    "read, never a store — a cited run is a claim about sealed evidence, and "
    "looking it up locally would make this check depend on a control plane it "
    "deliberately does not depend on.",
)
@click.pass_context
def check_cmd(
    ctx: click.Context,
    plan_path: str,
    graph_path: str,
    sha: str,
    ticket: str,
    incident: str,
    deployment: str,
    pin_pairs: tuple[str, ...],
    environment: str,
    fingerprint: str,
    summary_path: str,
    verdict_out: str,
    release_gate: bool,
    subject: str,
    change_kind: str,
    suite_paths: tuple[str, ...],
    finding_paths: tuple[str, ...],
    run_path: str,
) -> None:
    """Evaluate the pull request's checks and exit non-zero unless they all passed.

    Read-only with respect to the store and to any control plane: it compiles a
    safety case from the plan and topology it was handed and prints the result. It
    never posts a status (that is :func:`mayhem.controller.ci_surface.
    publish_commit_status`, which this repository leaves unbound), and it has no
    ``--force``: a failing check is not something an operator types a flag past.

    With ``--release-gate`` it additionally asks
    :func:`mayhem.controller.check_gate.release_gate` whether the change may open
    a release, and folds that answer into the exit code with ``or`` — the gate can
    only add a refusal, so a passing check suite cannot rescue it.
    """
    change = _change_link_or_fail(
        ctx, sha=sha, ticket=ticket, incident=incident, deployment=deployment, pins=pin_pairs
    )
    if change is None:
        return
    try:
        plan = _load_plan(plan_path) if plan_path else None
        graph = _load_graph(graph_path)
    except MayhemCliError as exc:
        # A file that does not exist, or is not JSON, is a refusal this group
        # reports in its own contract rather than letting bubble to the app-level
        # handler. A plan that is *malformed* takes the other road entirely: it
        # becomes an unreachable control plane, below, because a plan mayhem
        # could not parse is a plan whose safety case was never compiled.
        _fail(ctx, exc)
        return
    cited_run = _run_pin_from_path(ctx, run_path)
    if run_path.strip() and cited_run is None:
        # ``_run_pin_from_path`` already rendered the refusal and it exits; this
        # guard exists so that a future edit which makes it return ``None``
        # instead of refusing cannot quietly reintroduce "no run cited".
        return
    report, reason = _evaluate(
        plan,
        graph,
        change,
        fingerprint=fingerprint,
        plan_path=plan_path,
        cited_run=cited_run,
    )
    # The defect guard, and it is about *count* rather than about who blocked.
    # `report.blocking` is empty exactly when every check passed, so testing it
    # here would refuse the one outcome that is supposed to be reachable — and
    # the message ("evaluated no checks") would name a cause that did not apply.
    # What the surface actually promises is that the engine reported one check
    # per scope in CHECK_ORDER, so that is what is asserted.
    if len(report.checks) < len(CHECK_ORDER):
        _fail(
            ctx,
            MayhemCliError(
                code="safety_refusal",
                message=(
                    f"mayhem reported {len(report.checks)} of {len(CHECK_ORDER)} expected "
                    f"check scopes for {sha[:12]}, so the checks that did report cannot "
                    "stand in for the ones that did not, and a pipeline that checked "
                    "part of what it promised must not pass"
                ),
                details={"sha": sha, "environment": environment},
                remediation="this is a defect in the check surface, not in your change",
            ),
        )
        return
    summary, verdict = _render(report, change, reason)
    try:
        if verdict is not None and verdict_out:
            _write_or_echo(verdict.model_dump_json(indent=2), verdict_out)
        if summary_path:
            _write_or_echo(summary, summary_path)
    except (MayhemCliError, OSError) as exc:
        _refuse(ctx, exc, remediation="pass --summary and --verdict-out writable file paths")
        return
    for line in summary.splitlines():
        click.echo(style.info(line) if line.startswith("|") else line)
    proof_view = proof_view_for_report(report)
    if proof_view is not None:
        # The safety proof as `mayhem prove` renders it, projected off the same
        # view-model rather than re-rendered: the compilation above already ran
        # the gates, so this only reads. Unreachable yields no view and no
        # claim — the UNKNOWN checks above are the whole answer there.
        for line in render_proof_lines(proof_view):
            click.echo(line)
    # Graded on the checks *and* on the proof they were read from. The second
    # half is the belt: every non-PASS line already fails its owning check, so
    # today it never fires alone — but a proof that is not a PASS is the refusal
    # this gate exists to report, and that must not depend on the attribution
    # tables staying complete.
    blocked = bool(report.blocking) or not report.proven
    if release_gate:
        # Asked last and folded in with `or`, so the two halves cannot cancel:
        # a check suite that passed cannot rescue a release gate that blocked,
        # because "the checks passed" and "this change may open a release" are
        # different questions and only the second one is being answered here.
        blocked = (
            _apply_release_gate(
                ctx,
                change=change,
                verdict=verdict,
                blocked_already=blocked,
                subject=subject,
                change_kind=change_kind,
                suite_paths=suite_paths,
                finding_paths=finding_paths,
            )
            or blocked
        )
    if blocked:
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))


def _change_link_or_fail(
    ctx: click.Context,
    *,
    sha: str,
    ticket: str,
    incident: str,
    deployment: str,
    pins: tuple[str, ...],
) -> ChangeLink | None:
    """The change this check is about, or a refusal. ``None`` means it already exited."""
    try:
        parsed_pins = _parse_pins(pins)
    except MayhemCliError as exc:
        _fail(ctx, exc)
        return None
    if not sha.strip() or not any((ticket, incident, deployment)):
        _fail(
            ctx,
            MayhemCliError(
                code="validation_error",
                message=(
                    "a check needs a change to be about: pass --sha and at least one of "
                    "--ticket, --incident, or --deployment. A verdict about a commit "
                    "nobody filed cannot be traced back to the work that justified it"
                ),
                details={"sha": sha},
                remediation='--sha "$GITHUB_SHA" --ticket "$MAYHEM_TICKET"',
            ),
        )
        return None
    try:
        return ChangeLink(
            git_sha=sha,
            change_ticket=ticket,
            incident_id=incident,
            deployment_id=deployment,
            pins=parsed_pins,
        )
    except (InvariantViolationError, ValueError) as exc:
        # `ChangeLink` refuses through both channels: pydantic's own pattern check
        # on `git_sha`, and the invariant on an unattributable change. Both are
        # the same answer to a caller — that flag is wrong — so both land here.
        rule = exc.rule if isinstance(exc, InvariantViolationError) else "change_link.invalid"
        _fail(
            ctx,
            MayhemCliError(
                code="validation_error",
                message=str(exc),
                details={"rule": rule},
                remediation="--sha must be 7-40 lowercase hex characters",
            ),
        )
        return None


def _render(report: Any, change: ChangeLink, reason: str) -> tuple[str, PipelineVerdict | None]:
    """The PR-check markdown, and the verdict when one could honestly be built.

    An unreachable control plane produces checks with **no evidence references** —
    no gate ran, so there is nothing to cite — and Phase 1 refuses to construct a
    verdict without citations. That refusal is the correct behaviour and the
    surface does not route around it: it builds a summary-only verdict whose one
    evidence ref names the *absence* (``plan-digest/unreachable:<sha>``), which is
    true, and whose reasons say why. Inventing a ``gate-output/…`` reference would
    produce a summary that reads as cited and leads nowhere.
    """
    try:
        verdict = report.verdict()
    except InvariantViolationError:
        verdict = None
    if verdict is not None:
        return render_check_summary(verdict), verdict
    fallback = PipelineVerdict(
        outcome=PipelineOutcome.FAIL,
        change=change,
        evidence_refs=(f"plan-digest/unreachable:{change.git_sha[:12]}",),
        checks=report.checks,
        reasons=(reason or "the checks did not conclude, so no verdict could be graded",),
    )
    return render_check_summary(fallback), None


def _unusable_plan() -> ExecutionPlan:
    """A syntactically valid, empty plan — the substrate for an unknown verdict.

    Built with ``model_construct`` rather than validated: there is no plan to
    validate *against*, and inventing a fault step to make the model happy
    would be fabricating the thing the check is supposed to be reporting on. The
    field defaults are exactly the "nothing was authored" values, and nothing
    reads them — :func:`~mayhem.controller.check_gate.evaluate_pr_checks`
    short-circuits to the unreachable report before the plan is touched.

    Only reached when the real plan could not be read. It exists so that the
    unreachable branch constructs the same :class:`CheckInputs` as the reachable
    one and therefore *cannot* accidentally take a different path through the
    engine: the difference between "unknown" and "pass" lives in
    :attr:`~mayhem.controller.check_gate.CheckInputs.control_plane` and nowhere
    else, which is the property worth being unable to break.
    """
    return ExecutionPlan.model_construct()


def _empty_graph() -> TopologyGraph:
    """The empty graph the unreachable branch hands the engine.

    Empty, not fabricated: a graph full of invented nodes would make a blast
    radius measurable against a topology that does not exist, and the whole
    point of the unreachable branch is that nothing was measured.
    """
    return TopologyGraph()


# --------------------------------------------------------------------------- #
# suite                                                                        #
# --------------------------------------------------------------------------- #

#: Which plan-22 fault suites answer each release-gate suite, and it lives here
#: and only here.
#:
#: The two lists are not the wrong list, they are not even the same *question*.
#: ``required_suites_for`` names suites by **trigger** — a deployment, a
#: dependency change, infrastructure drift — because that is what a gate
#: reasons about: what changed, and therefore what resilience is owed.
#: ``PLAN_22_SUITES`` names suites by **fault family** — what was actually
#: exercised — because that is what the coverage store records. Renaming either
#: to match the other would lose the distinction that makes both useful, so the
#: translation is data, and it is kept in exactly one place rather than branched
#: over at the call site.
#:
#: The groupings, and why each one is what it is:
#:
#: * ``post-deploy`` — a deployment owes the question "did the thing we just
#:   shipped come back, and is the platform underneath it still intact".
#:   ``service.availability`` is the first half and ``platform.node`` the
#:   second. ``journey.checkout`` is deliberately excluded: a journey is an
#:   authored customer-flow program, and requiring one for every deployment
#:   would make a suite depend on a piece of collateral that most deployments
#:   do not have.
#: * ``dependency-failure`` — the four ways a dependency is reached: a cache, a
#:   broker, a database, and the network between here and it. All four, because
#:   "the dependency failed" is not a claim mayhem can grade against one of them.
#: * ``infrastructure-drift`` — what the platform changes underneath a healthy
#:   service. ``platform.node`` (drained, lost, partitioned) and ``network.edge``
#:   (latency, loss, resets) are the two drift surfaces; the dependency suites
#:   are excluded because a dependency failing is not the platform moving.
SUITE_FAULT_SUITES: Final[dict[str, tuple[str, ...]]] = {
    "resilience.post-deploy": ("service.availability", "platform.node"),
    "resilience.dependency-failure": (
        "dependency.cache",
        "dependency.broker",
        "dependency.database",
        "network.edge",
    ),
    "resilience.infrastructure-drift": ("platform.node", "network.edge"),
}


def _fault_kinds_for(suite_name: str) -> tuple[str, ...]:
    """The catalog fault kinds a release-gate suite is answered by.

    Read through :attr:`PLAN_22_SUITES` rather than restated here, because that
    registry validates every fault id against the real catalog at import. A
    family renamed or retired upstream therefore surfaces here as a refusal,
    rather than as a silently empty answer that reads exactly like "nothing ran".
    """
    kinds: list[str] = []
    for family in SUITE_FAULT_SUITES.get(suite_name, ()):
        suite = PLAN_22_SUITES.get(family)
        if suite is None:
            raise InvariantViolationError(
                "ci_suite.unknown_fault_suite",
                f"release-gate suite {suite_name!r} maps to plan-22 fault suite "
                f"{family!r}, which is not in PLAN_22_SUITES: the translation names "
                "a suite nothing records, so every fault kind it owes would read as "
                "uncovered forever and no operator would ever learn why",
            )
        kinds.extend(suite.fault_kinds)
    return tuple(dict.fromkeys(kinds))


def _require_every_owed_suite_is_translated() -> None:
    """Refuse, at import, a trigger whose owed suite this file cannot grade.

    Loudly, and for the reason :class:`~mayhem.infra.coverage_service.SuiteRegistry`
    gives for validating itself at construction: a new trigger that owes a suite
    nobody translated would grade as ``UNKNOWN`` — which blocks — and that block
    would read as *"you have no evidence"* when the truth is *"mayhem never
    learned what this change owes"*. Those are different problems with the same
    symptom, and only the first is the operator's to fix. A missing row here is
    this module's bug, so it is raised where a maintainer will see it.
    """
    unmapped = sorted(
        owed
        for kind in ChangeKind
        for owed in required_suites_for(kind)
        if owed not in SUITE_FAULT_SUITES
    )
    if unmapped:
        raise InvariantViolationError(
            "ci_suite.untranslated_suite",
            f"release-gate suites mayhem owes but cannot grade: {unmapped}. Add a row "
            "to SUITE_FAULT_SUITES naming the plan-22 fault suites each one is "
            "answered by",
        )


_require_every_owed_suite_is_translated()


#: Severity order for folding several records of one fault kind into one answer.
#: The **worst** state wins, and only :data:`~mayhem.domain.coverage.CellState.PASSED`
#: may become a ``pass``. That is stricter than
#: :data:`~mayhem.infra.coverage_service.COVERING_STATES`, which counts
#: ``FAILED`` as covered on purpose — "we ran it" is not "it held", and this
#: command answers the second question. One failed attempt therefore cannot be
#: averaged away by a passing one: a suite that partly holds is not a suite that
#: passed.
_SEVERITY: Final[dict[CellState, int]] = {
    CellState.UNKNOWN: 0,
    CellState.PLANNED: 0,
    CellState.BLOCKED: 0,
    CellState.SKIPPED: 0,
    CellState.PASSED: 1,
    CellState.EXECUTED: 2,
    CellState.INCONCLUSIVE: 3,
    CellState.FAILED: 4,
}


@dataclass(frozen=True, slots=True)
class _RecordedFault:
    """What one fault kind has recorded against one run, folded from every cell.

    ``state`` is the worst state any cell for this fault kind recorded, and
    ``refs`` are the citations for all of them, so a ``pass`` can cite every
    piece of evidence behind it rather than the one that happened to be read
    last.
    """

    fault_kind: str
    state: CellState
    refs: tuple[str, ...]


def _coverage_for_run(store: Store, run_id: str) -> dict[str, _RecordedFault]:
    """The fault kinds run ``run_id`` actually recorded coverage for, and how.

    Two repositories, unioned, because neither alone can see a real store:

    * :class:`~mayhem.infra.coverage_service.CoverageDimensionRepository` holds
      *cited* sightings — ``executed:r-1#digest`` — and is the only source that
      records an attempt which did **not** pass. Nothing in ``src/`` writes one.
    * :class:`~mayhem.infra.coverage_repository.SQLiteCoverageRepository` holds
      the ``m5_coverage`` accounting that
      :mod:`~mayhem.controller.cell_runner` writes when a run executes a cell,
      so it is the only source a store built by this repository's own commands
      can actually have.

    Both are filtered to ``run_id``. "This service is covered" is not evidence
    about *this* release, and a gate that accepted it would be reading somebody
    else's run as its own.

    One honest limit: ``m5_coverage`` carries a single ``run_id`` per cell, last
    writer wins, so its ``state`` is the cell's *current* state. The run
    attribution above is the part this command can trust; the state it pairs with
    it is the cell's latest word on the fault.
    """
    accounting = SQLiteCoverageRepository(store)
    dimensions = CoverageDimensionRepository(store)
    observations: list[tuple[str, CellState, str]] = []

    for cell in dimensions.declared_cells():
        sightings = tuple(
            sighting
            for sighting in dimensions.sightings(cell)
            if sighting.run_id == run_id and sighting.counts
        )
        if not sightings:
            continue
        state = accounting.cell_state(cell.coverage_cell) or CellState.UNKNOWN
        observations.extend((cell.fault, state, sighting.citation) for sighting in sightings)

    records = tuple(record for record in accounting.covered_records() if record.run_id == run_id)
    if records:
        states = accounting.states(record.cell for record in records)
        for record in records:
            # ``covered_records`` only returns rows with the legacy ``covered``
            # flag set, and ``record`` sets that flag only for a PASSED state, so
            # PASSED is the correct floor for a row whose state has since been
            # overwritten by a later run.
            observations.append(
                (
                    record.cell.fault_kind,
                    states.get(record.cell.key, CellState.PASSED),
                    f"coverage-cell/{record.cell.target}/{record.cell.fault_kind}",
                )
            )

    recorded: dict[str, _RecordedFault] = {}
    for fault_kind, state, ref in observations:
        entry = recorded.get(fault_kind)
        if entry is None:
            recorded[fault_kind] = _RecordedFault(fault_kind, state, (ref,))
            continue
        worse = state if _SEVERITY.get(state, 0) > _SEVERITY.get(entry.state, 0) else entry.state
        recorded[fault_kind] = _RecordedFault(
            fault_kind, worse, (*entry.refs, ref) if ref not in entry.refs else entry.refs
        )
    return recorded


def _grade_suite(
    suite_name: str,
    fault_kinds: tuple[str, ...],
    recorded: Mapping[str, _RecordedFault],
    pin: RunPin,
) -> ResilienceSuite:
    """Grade one owed suite against what this run recorded. Never guesses a ``pass``.

    Three outcomes, and the middle one is the point:

    * ``fail`` — at least one fault kind this suite is answered by recorded
      ``FAILED`` on this run. The evidence is cited, so the operator can go and
      look at the cell rather than at the sentence.
    * ``pass`` — **every** fault kind recorded ``PASSED``, each with at least one
      citation. Anything short of that — a missing kind, a kind that merely ran,
      a kind that came back inconclusive — is the next branch, not this one.
    * ``unknown`` — the store was reached and could not answer. ``unknown`` is
      not a soft pass: :func:`~mayhem.controller.check_gate.release_gate` blocks
      on it exactly as it blocks on ``fail``, and the only difference is which
      file the operator should go and fix. So the detail says *which* fault kinds
      are missing and whether the run recorded coverage at all, because "no
      coverage for this run" and "some of it" are different faults with the same
      symptom.
    """
    entries = tuple(recorded.get(fault_kind) for fault_kind in fault_kinds)
    failed = tuple(item.fault_kind for item in entries if item and item.state is CellState.FAILED)
    refs = tuple(dict.fromkeys(ref for item in entries if item for ref in item.refs))
    unpassed = tuple(
        fault_kind
        for fault_kind, item in zip(fault_kinds, entries, strict=True)
        if item is None or item.state is not CellState.PASSED
    )

    if failed:
        return ResilienceSuite(
            name=suite_name,
            outcome=CheckOutcome.FAIL,
            evidence_refs=refs,
            run=pin,
            detail=(
                f"{len(failed)} of the {len(fault_kinds)} fault kinds this suite is "
                f"answered by recorded as failed on run {pin.run_id!r}: "
                f"{', '.join(failed)}"
            ),
        )
    if not unpassed:
        return ResilienceSuite(
            name=suite_name,
            outcome=CheckOutcome.PASS,
            evidence_refs=refs,
            run=pin,
            detail=(
                f"all {len(fault_kinds)} fault kinds this suite is answered by recorded "
                f"passed on {pin.label}"
            ),
        )
    if not recorded:
        detail = (
            f"the store was reached and holds no recorded coverage for run "
            f"{pin.run_id!r} at all, so none of the {len(fault_kinds)} fault kinds this "
            "suite is answered by could be confirmed"
        )
    else:
        detail = (
            f"{len(unpassed)} of the {len(fault_kinds)} fault kinds this suite is "
            f"answered by have no passing coverage recorded for run {pin.run_id!r}: "
            f"{', '.join(unpassed)}. A suite that partly holds is not a suite that passed"
        )
    return ResilienceSuite(
        name=suite_name,
        outcome=CheckOutcome.UNKNOWN,
        evidence_refs=refs,
        run=pin,
        detail=detail,
    )


def _suite_row(suite: ResilienceSuite) -> dict[str, Any]:
    """The JSON row ``--suite`` reads, in exactly the shape :func:`_suites_from_paths` wants.

    Deliberately **not** :meth:`~mayhem.controller.check_gate.ResilienceSuite.to_dict`.
    That renders ``run`` as ``pin.label`` — a display string — while the parser
    reads it back through :meth:`~mayhem.domain.comparison.RunPin.from_dict`,
    which wants a pin and refuses a string. Serializing with the dataclass's own
    ``to_dict`` would therefore produce a file this module cannot consume, which
    is the most expensive kind of bug: the producer and the consumer would each
    be right about their own shape and disagree about the file between them.
    """
    return {
        "name": suite.name,
        "outcome": suite.outcome.value,
        "evidence_refs": list(suite.evidence_refs),
        "run": None if suite.run is None else suite.run.to_dict(),
        "detail": suite.detail,
    }


def _store_path(db: str, ctx: click.Context) -> str:
    """``--db``, else the app-wide database, else mayhem's own default."""
    if db:
        return db
    context_db = getattr(getattr(ctx, "obj", None), "db", "")
    return str(context_db) if context_db else DEFAULT_DB


@ci.command("suite")
@click.option(
    "--db",
    default="",
    metavar="PATH",
    help=f"Mayhem store to read. Defaults to the app-wide --db, then {DEFAULT_DB}.",
)
@click.option(
    "--run",
    "run_id",
    required=True,
    metavar="RUN_ID",
    help="The stored run to grade the owed suites against. It must exist in the "
    "store: a run mayhem does not hold has no pin to cite, and citing a pin this "
    "process made up is the one thing a gate must never do.",
)
@click.option(
    "--kind",
    type=click.Choice([kind.value for kind in ChangeKind]),
    default=ChangeKind.DEPLOYMENT.value,
    help="What changed — and therefore which suites are owed. Every suite the "
    "kind owes is reported, whatever its outcome, so the gate never has to "
    "infer a missing suite from silence.",
)
@click.option("--out", default="", metavar="PATH", help="Write here instead of stdout.")
@click.pass_context
def suite_cmd(ctx: click.Context, db: str, run_id: str, kind: str, out: str) -> None:
    """Grade a stored run against the resilience suites a change owes.

    Writes the JSON **array** ``mayhem ci check --suite`` reads, so the two
    commands compose::

        mayhem ci suite --db mayhem.db --run r-checkout-7 --kind deployment \\
          --out suite.json
        mayhem ci check --release-gate --subject "checkout v3" \\
          --suite suite.json --run pin.json

    Read-only with respect to the store, and fail-closed at every step:

    * **A run the store does not hold is a refusal.** Not a synthesised pin, and
      not an empty report. A gate that cites a run mayhem invented is a gate
      that opened on nothing.
    * **No coverage is ``unknown``, never ``pass``.** The store was reached and
      had nothing to say, which is a fact, and the fact is that nobody has shown
      this change anything.
    * ``unknown`` blocks exactly as ``fail`` does. It is not a soft pass; the
      difference between the two is only which file the operator goes and fixes.

    Every owed suite is reported whatever its outcome, because the gate's
    "did not report" branch tells an operator to produce a suite file, and that
    is the wrong instruction when the file exists and the evidence does not.
    """
    path = _store_path(db, ctx)
    if not Path(path).is_file():
        _fail(
            ctx,
            MayhemCliError(
                code="validation_error",
                message=(
                    f"mayhem store {path!r} does not exist, so there is no recorded run "
                    f"{run_id!r} to grade and no evidence to report a suite from. mayhem "
                    "will not create an empty store to report that it knows nothing"
                ),
                details={"db": path, "run_id": run_id},
                remediation="pass --db the store this job wrote, or run mayhem first",
            ),
        )
        return
    try:
        store = open_store(path)
    except (MayhemCliError, OSError, ValueError) as exc:
        _refuse(ctx, exc, remediation="pass --db a mayhem store this job wrote")
        return
    try:
        report = ComparisonService(store).run(run_id)
        if report is None:
            recorded_runs = ComparisonService(store).runs()
            raise MayhemCliError(
                code="validation_error",
                message=(
                    f"the store holds no sealed run report for {run_id!r}. A suite that "
                    "cites a run is what lets the gate compare this release against the "
                    "last one, so mayhem reports nothing rather than citing a pin it "
                    "would have had to invent"
                ),
                details={"run_id": run_id, "stored_runs": list(recorded_runs)},
                remediation=(
                    "pass a run mayhem sealed, or none at all: "
                    + (", ".join(recorded_runs) if recorded_runs else "the store holds none")
                ),
            )
        recorded = _coverage_for_run(store, run_id)
        suites = tuple(
            _grade_suite(name, _fault_kinds_for(name), recorded, report.pin)
            for name in required_suites_for(ChangeKind(kind))
        )
        _write_or_echo(json.dumps([_suite_row(suite) for suite in suites], indent=2), out)
    except (MayhemCliError, InvariantViolationError, OSError, ValueError) as exc:
        _refuse(
            ctx,
            exc,
            remediation="pass --db and --run for a run mayhem sealed, and --out a "
            "writable file path",
        )
        return
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# summary and status                                                           #
# --------------------------------------------------------------------------- #


def _verdict_from(path: str) -> PipelineVerdict:
    payload = _read_json(path, "verdict")
    try:
        return PipelineVerdict.model_validate(payload)
    except (ValueError, InvariantViolationError) as exc:
        raise MayhemCliError(
            code="validation_error",
            message=f"verdict file {path!r} is not a pipeline verdict: {exc}",
            details={"path": path},
            remediation="write it with `mayhem ci check --verdict-out`",
        ) from None


@ci.command("summary")
@click.option("--from", "from_path", required=True, metavar="PATH", help="Verdict JSON.")
@click.option("--out", default="", metavar="PATH", help="Write here instead of stdout.")
@click.pass_context
def summary_cmd(ctx: click.Context, from_path: str, out: str) -> None:
    """Render the PR-check markdown for a verdict document. Grades nothing."""
    try:
        verdict = _verdict_from(from_path)
        rendered = render_check_summary(verdict)
        _write_or_echo(rendered, out)
    except MayhemCliError as exc:
        _fail(ctx, exc)
        return
    except (InvariantViolationError, ValueError) as exc:
        _refuse(ctx, exc, remediation="write the verdict with `mayhem ci check --verdict-out`")
        return
    except OSError as exc:
        _refuse(ctx, exc, remediation="pass --out a writable file path")
        return


@ci.command("status")
@click.option("--from", "from_path", required=True, metavar="PATH", help="Verdict JSON.")
@click.option("--context", default="mayhem/ci", help="Commit-status context key.")
@click.pass_context
def status_cmd(ctx: click.Context, from_path: str, context: str) -> None:
    """Print the commit status a verdict would post — and that it was not posted.

    This repository ships no GitHub client and holds no token, so the status port
    is unbound and the publication is reported as unavailable. The command says
    so rather than exiting quietly, because a CI step that believes it posted a
    status and did not is a check nobody is watching.
    """
    try:
        verdict = _verdict_from(from_path)
        status = status_for(verdict, context=context)
        publication = publish_commit_status(None, git_sha=verdict.change.git_sha, status=status)
    except MayhemCliError as exc:
        _fail(ctx, exc)
        return
    except (InvariantViolationError, ValueError, OSError) as exc:
        _refuse(ctx, exc, remediation="write the verdict with `mayhem ci check --verdict-out`")
        return
    click.echo(f"context:   {status.context}")
    click.echo(f"state:     {status.state}")
    click.echo(f"summary:   {status.description}")
    click.echo(f"posted:    {'yes' if publication.published else 'no'}")
    click.echo(f"detail:    {publication.detail}")
    click.echo(
        style.info(
            "mayhem ships no forge client and holds no token; this repository has never "
            "posted a commit status and this command does not pretend otherwise"
        )
    )
