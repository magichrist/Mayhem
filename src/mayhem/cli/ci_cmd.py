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
    it could not reach its own control plane is a gate that fails open.

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
from pathlib import Path
from typing import Any

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.config import PolicyCfg
from mayhem.controller.check_gate import CHECK_ORDER, CheckInputs, evaluate_pr_checks
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
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
from mayhem.domain.pipeline import (
    ChangeLink,
    CheckScope,
    ControlPlaneReach,
    PipelineOutcome,
    PipelinePins,
    PipelineVerdict,
)
from mayhem.domain.topology import TopologyGraph

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
                or "pin the action to a 40-character commit SHA and the image to a "
                "sha256 digest",
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
            f"the plan at {plan_path!r} could not be read, so mayhem compiled no safety "
            "case for it"
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
) -> tuple[Any, str]:
    """Run the real engine, unreachable or not, and return ``(report, reason)``.

    Both branches build the *same* :class:`CheckInputs`; the only difference is
    :attr:`~mayhem.controller.check_gate.CheckInputs.control_plane` and the
    substrate the unreachable branch has to stand in with. That is deliberate: the
    difference between ``UNKNOWN`` and ``PASS`` should have exactly one place it
    can come from, and this function is that place.
    """
    reason = _unreachable_reason(plan, graph, plan_path)
    if reason or plan is None or graph is None:
        inputs = CheckInputs(
            plan=_unusable_plan(),
            graph=_empty_graph(),
            safety=_safety_context(fingerprint),
            change=change,
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail=reason or "the plan or topology was not readable",
        )
    else:
        inputs = CheckInputs(
            plan=plan,
            graph=graph,
            safety=_safety_context(fingerprint or plan.environment_fingerprint),
            change=change,
        )
    return evaluate_pr_checks(inputs), reason


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
@click.option("--summary", "summary_path", default="", metavar="PATH", help="Write the "
              "PR-check markdown here (e.g. $GITHUB_STEP_SUMMARY).")
@click.option("--verdict-out", default="", metavar="PATH", help="Write the verdict JSON here.")
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
) -> None:
    """Evaluate the pull request's checks and exit non-zero unless they all passed.

    Read-only with respect to the store and to any control plane: it compiles a
    safety case from the plan and topology it was handed and prints the result. It
    never posts a status (that is :func:`mayhem.controller.ci_surface.
    publish_commit_status`, which this repository leaves unbound), and it has no
    ``--force``: a failing check is not something an operator types a flag past.
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
    report, reason = _evaluate(plan, graph, change, fingerprint=fingerprint, plan_path=plan_path)
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
    if report.blocking:
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
        reasons=(
            reason or "the checks did not conclude, so no verdict could be graded",
        ),
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
        publication = publish_commit_status(
            None, git_sha=verdict.change.git_sha, status=status
        )
    except MayhemCliError as exc:
        _fail(ctx, exc)
        return
    except (InvariantViolationError, ValueError, OSError) as exc:
        _refuse(
            ctx, exc, remediation="write the verdict with `mayhem ci check --verdict-out`"
        )
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
