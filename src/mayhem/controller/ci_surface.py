"""The CI surface: pinned workflow generation, the PR-check summary, and the
commit-status seam (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 3, gap 46).

Phase 1 (:mod:`mayhem.domain.pipeline`) named the words a pipeline decision is
made of, and Phase 2 (:mod:`mayhem.controller.check_gate`) produces them. Neither
is reachable by a person: nobody edits a workflow by hand and nobody reads a
verdict off a struct. This module is the surface, and it is the whole of what
Phase 3's action half consists of — a deterministic generator for a GitHub
Actions workflow and a GitLab CI component, one renderer for the PR-check
summary, and one seam (:class:`CommitStatusPort`) for a GitHub App to post
through.

Nothing here runs a check, and nothing here decides. Every check the summary
prints is a :class:`~mayhem.domain.pipeline.PRCheck` that Phase 2 already
graded, and the summary refuses to render a verdict it was not handed — a
renderer that could grade would be a second gate, and two gates is the failure
this whole plan exists to prevent.

Four commitments shape the code, and each is a refusal.

**A generated workflow is pinned, or it is not generated.** Every action is a
:class:`ActionPin` carrying a 40-hex commit SHA and every container image is an
:class:`ImagePin` carrying a ``sha256:`` digest. ``actions/checkout@v4`` is
refused (:data:`RULE_FLOATING_ACTION`) and ``mayhem:2.4`` with no digest is
refused (:data:`RULE_FLOATING_IMAGE`) — because a gate whose definition can
change under you, between the run that passed and the run that failed, is not a
gate. It is a coin flip with a green tick on it. The generator holds no default
tags: :class:`WorkflowSpec` has no field that can carry one.

**No untrusted value is ever interpolated into a script.** This is the
script-injection property, and it is structural rather than advisory. Every
untrusted input (the plan reference, the change ticket, the run id) is passed
*into the environment* under a ``MAYHEM_`` name and read inside the script as a
quoted shell expansion ``"$MAYHEM_PLAN_REF"``. GitHub's ``${{ }}`` expression
syntax appears in exactly one place — the right-hand side of an ``env:``
assignment, where it is a *value* and not code — and :func:`assert_script_containment`
proves it after rendering, scanning every ``run:`` block for a ``${{`` and
refusing the artifact if one is found. The check is deliberately redundant with
the construction rule that refuses an untrusted value containing ``${{``: one of
them can be deleted by accident, and a workflow generator is exactly the place
where a mistake becomes remote code execution on someone else's runner.

**A status that could not be posted is not a passing status.**
:func:`publish_commit_status` takes an *unbound, raising, ``None``-answering or
wrong-shaped* port and treats all four the way
:func:`~mayhem.controller.preflight_gate.port_status` treats them:
:data:`~mayhem.domain.pipeline.ControlPlaneReach.UNREACHABLE`. It never raises,
because a failed HTTP POST is a fact about the network and not a defect in the
caller; and it returns a :class:`StatusPublication` whose
:attr:`~StatusPublication.published` is false, so the caller can tell "the checks
passed and the status was posted" from "the checks passed and nobody was told".
What it never does is turn a refusal into an open gate: the *decision* was made
by Phase 2, fail-closed, before this function is reachable.

**The summary prints the denominator, and prints unknown as unknown.** The
markdown carries every check's outcome verbatim, so a check that reported
:data:`~mayhem.domain.pipeline.CheckOutcome.UNKNOWN` renders as ``UNKNOWN`` and
never as a tick. A coverage line reads ``N of M`` for the reason
:mod:`mayhem.domain.pipeline` states, and the gate line prints
``may this open a release: no`` with the reasons rather than a red emoji.

.. warning::

   **No GitHub Actions workflow has ever run.** These generators are pure string
   functions with unit tests and golden fixtures; nothing in this repository
   opens a socket, holds a token, or posts a status. :class:`CommitStatusPort`
   is an unbound protocol with no implementation here, exactly as
   :class:`~mayhem.controller.preflight_gate.IncidentPort` is in plan 10 — see
   the Phase 3 STATUS line of the plan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol

from mayhem.controller.check_gate import CHECK_NAME
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.pipeline import (
    CONTROL_PLANE_UNREACHABLE,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    PipelineOutcome,
    PipelineVerdict,
    blocking_reasons,
)

if TYPE_CHECKING:
    from mayhem.controller.check_gate import CoverageSurface

__all__ = [
    "CHECKOUT_ACTION",
    "GITHUB_TRIGGER",
    "GITLAB_TRIGGER",
    "PORT_FAILURE_MODES",
    "RULE_FLOATING_ACTION",
    "RULE_FLOATING_IMAGE",
    "RULE_STATUS_UNAVAILABLE",
    "RULE_SUMMARY_WITHOUT_VERDICT",
    "RULE_UNTRUSTED_VALUE",
    "SETUP_PYTHON_ACTION",
    "SUMMARY_SCHEMA_VERSION",
    "WORKFLOW_SCHEMA_VERSION",
    "ActionPin",
    "CommitStatus",
    "CommitStatusPort",
    "ImagePin",
    "Provider",
    "StatusAck",
    "StatusPublication",
    "WorkflowSpec",
    "assert_script_containment",
    "publish_commit_status",
    "render_check_summary",
    "render_github_workflow",
    "render_gitlab_component",
    "status_for",
]

SUMMARY_SCHEMA_VERSION: Final[str] = "1.0"
WORKFLOW_SCHEMA_VERSION: Final[str] = "1.0"

# --- refusal codes -------------------------------------------------------------
# Stable strings: these end up in a workflow file, a commit status, and a chat
# transcript, and somebody greps for them.

RULE_FLOATING_ACTION = "ci_surface.floating_action_ref"
RULE_FLOATING_IMAGE = "ci_surface.floating_image_ref"
RULE_UNTRUSTED_VALUE = "ci_surface.untrusted_value_in_script"
RULE_SUMMARY_WITHOUT_VERDICT = "ci_surface.summary_without_verdict"
RULE_STATUS_UNAVAILABLE = "ci_surface.status_unavailable"

_SHA_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")
_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ACTION_PATH_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")

#: An untrusted value may be *any* of these characters, but never ``$``, ``{``,
#: ``}``, a newline, a NUL, or a backtick. The set is deliberately generous —
#: ``MAYHEM-4712`` and ``PR-1/2`` are ordinary values — and deliberately excludes
#: every character a shell treats as syntax.
_UNTRUSTED_FORBIDDEN: Final[frozenset[str]] = frozenset("`\n\r\0${};&|<>*?!\\'\"()")


def _require_nonblank(value: str, rule: str, subject: str) -> str:
    if not value.strip():
        raise InvariantViolationError(rule, f"{subject} must not be blank")
    return value


class Provider(StrEnum):
    """The two CI systems this generator speaks.

    A closed vocabulary on purpose. Jenkins, Buildkite, Argo Workflows and Tekton
    are named in the plan's integration list and are **not** here: each needs a
    different trust model for "what ran before this step", and emitting a
    plausible-looking YAML for a provider nobody has reasoned about is how a
    pipeline ends up with a gate that is decorative in exactly the environment
    it was supposed to protect. The rollout order in Phase 6 adds them after the
    two that ship, and each addition is a new ``Provider`` member with its own
    pinning and containment rules.
    """

    GITHUB = "github"
    GITLAB = "gitlab"


GITHUB_TRIGGER: Final[str] = "pull_request"
GITLAB_TRIGGER: Final[str] = "merge_request_event"


# =============================================================================
# Pins
# =============================================================================


@dataclass(frozen=True, slots=True)
class ActionPin:
    """One third-party action, pinned to a commit.

    A full 40-hex SHA and nothing else. ``v4``, ``main``, ``v4.1.1``, and a
    short SHA are all refused with :data:`RULE_FLOATING_ACTION`, and the message
    says which one it was: "you asked for ``actions/checkout@v4``" is a question
    an operator can answer, and a gate that changed meaning without anybody
    noticing is a thing you want a *name* for when it happens.
    """

    owner: str
    name: str
    sha: str
    purpose: str = ""

    def __post_init__(self) -> None:
        _require_nonblank(self.owner, RULE_FLOATING_ACTION, "action owner")
        _require_nonblank(self.name, RULE_FLOATING_ACTION, "action name")
        if not _ACTION_PATH_RE.fullmatch(f"{self.owner}/{self.name}"):
            msg = (
                f"{self.owner!r}/{self.name!r} is not a mayhem action path; an action "
                "reference is spelled owner/name"
            )
            raise InvariantViolationError(RULE_FLOATING_ACTION, msg)
        if not _SHA_RE.fullmatch(self.sha):
            msg = (
                f"action {self.owner}/{self.name} is pinned to {self.sha!r}, which is "
                "not a 40-character commit SHA: a tag or a branch can be moved, and a "
                "gate whose definition can move is not a gate"
            )
            raise InvariantViolationError(RULE_FLOATING_ACTION, msg)

    @property
    def ref(self) -> str:
        """``owner/name@sha`` — the only spelling this module will emit."""
        return f"{self.owner}/{self.name}@{self.sha}"

    def describe(self) -> str:
        return self.purpose or self.ref


CHECKOUT_ACTION: Final[ActionPin] = ActionPin(
    owner="actions",
    name="checkout",
    sha="11bd71901bbe5b1630ceea73d27597364c9af683",
    purpose="check the pull request out at the merge ref",
)
SETUP_PYTHON_ACTION: Final[ActionPin] = ActionPin(
    owner="actions",
    name="setup-python",
    sha="0b93645e9fea7318ecaed2b359559ac225c90a2b",
    purpose="pin the interpreter the checks run under",
)


@dataclass(frozen=True, slots=True)
class ImagePin:
    """One container image, pinned to a digest.

    ``mayhem/sre:2.4`` is a label; ``mayhem/sre@sha256:…`` is a thing. The digest
    is what makes a GitOps reference architecture reproducible, and a tag is not
    a promise anybody can check.
    """

    image: str
    purpose: str = ""

    def __post_init__(self) -> None:
        if not _DIGEST_RE.fullmatch(self.image):
            msg = (
                f"container image {self.image!r} is not pinned to a digest: a gate that "
                "runs against whatever a tag points at today is not the gate that ran "
                "yesterday"
            )
            raise InvariantViolationError(RULE_FLOATING_IMAGE, msg)

    @property
    def ref(self) -> str:
        return self.image

    def describe(self) -> str:
        return self.purpose or self.ref


# =============================================================================
# The workflow spec
# =============================================================================


@dataclass(frozen=True, slots=True)
class WorkflowSpec:
    """Everything a generated workflow needs, and nothing it must not have.

    There is no ``permissions`` field, no ``secrets`` field, and no free-form
    ``env`` passthrough, because every one of those is a way for a caller to add
    privilege to a generated file without the generator noticing. The untrusted
    inputs are named (:attr:`untrusted_inputs`) and each one is emitted as an
    ``env:`` assignment read as ``"$MAYHEM_…"`` inside the script.

    :attr:`actions` may not be empty and :attr:`image` has no default: a workflow
    with no pinned base image would run the checks on whatever the runner
    happens to have, which is the same objection as a floating action tag,
    arrived at from the other direction.
    """

    name: str
    provider: Provider
    image: ImagePin
    actions: tuple[ActionPin, ...] = (CHECKOUT_ACTION,)
    checks: tuple[CheckScope, ...] = ()
    untrusted_inputs: tuple[tuple[str, str], ...] = ()
    environment: str = "ci"
    release_gate: bool = False

    def __post_init__(self) -> None:
        if not _NAME_RE.fullmatch(self.name):
            msg = (
                f"workflow name {self.name!r} must be lowercase [a-z0-9._-] so it can "
                "name a file and a required status check"
            )
            raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
        if not self.actions:
            msg = (
                f"workflow {self.name!r} was generated with no pinned actions: a "
                "checkout step that references nothing is a step nobody can audit"
            )
            raise InvariantViolationError(RULE_FLOATING_ACTION, msg)
        seen: set[str] = set()
        for pin in self.actions:
            if pin.ref in seen:
                msg = f"workflow {self.name!r} pins {pin.ref} twice"
                raise InvariantViolationError(RULE_FLOATING_ACTION, msg)
            seen.add(pin.ref)
        for key, value in self.untrusted_inputs:
            _require_untrusted(key, value, workflow=self.name, provider=self.provider)
        seen_keys: set[str] = set()
        for key, _ in self.untrusted_inputs:
            if key in seen_keys:
                msg = f"workflow {self.name!r} binds the environment name {key!r} twice"
                raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
            seen_keys.add(key)

    # -- derivations ---------------------------------------------------------

    def env_name(self, key: str) -> str:
        """The ``MAYHEM_``-prefixed environment name an untrusted input is bound to."""
        _require_nonblank(key, RULE_UNTRUSTED_VALUE, "untrusted input key")
        return f"MAYHEM_{key.upper().replace('-', '_')}"

    def bound_inputs(self) -> tuple[tuple[str, str], ...]:
        """``(MAYHEM_…-name, expression)`` pairs, in declaration order."""
        return tuple(
            (self.env_name(key), expression) for key, expression in self.untrusted_inputs
        )

    def check_names(self) -> tuple[str, ...]:
        """The check scopes this workflow runs, in the engine's own order.

        Read from :data:`~mayhem.controller.check_gate.CHECK_ORDER`-independent
        input order — the spec states which checks it wants, and the surface does
        not reorder or add any, because a workflow that runs a check the engine
        did not grade is a check with no verdict behind it.
        """
        return tuple(CHECK_NAME[scope] for scope in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": WORKFLOW_SCHEMA_VERSION,
            "name": self.name,
            "provider": self.provider.value,
            "image": self.image.ref,
            "actions": [pin.ref for pin in self.actions],
            "checks": list(self.check_names()),
            "untrusted_inputs": [
                {"name": self.env_name(key), "expression": expression}
                for key, expression in self.untrusted_inputs
            ],
            "environment": self.environment,
            "release_gate": self.release_gate,
        }


#: An untrusted *value* never reaches the artifact: it reaches the shell through
#: the environment. What may appear in the artifact is a **forge expression**, and
#: an expression must look like one for the provider it is rendered for. Anything
#: else — a literal with a semicolon, a subshell, a backtick, a newline — is a
#: paste that belongs in a script and is refused here, because the only way to
#: tell the two apart at construction time is to insist the thing be an expression.
_GITHUB_EXPRESSION: Final[re.Pattern[str]] = re.compile(
    r"^\$\{\{\s*[A-Za-z0-9_.*/@<>-]+(?:\s+[A-Za-z0-9_.*/@<>-]+)*\s*\}\}$"
)
_GITLAB_EXPRESSION: Final[re.Pattern[str]] = re.compile(r"^\$\[\[[A-Za-z0-9_.*/@ -]+\]\]$")


def _require_untrusted(key: str, value: str, *, workflow: str, provider: Provider) -> str:
    """One forge expression, or a refusal naming what was wrong with it."""
    _require_nonblank(key, RULE_UNTRUSTED_VALUE, f"workflow {workflow} input name")
    if not _NAME_RE.fullmatch(key):
        msg = (
            f"workflow {workflow} input name {key!r} must be lowercase "
            "[a-z0-9._-] so it becomes a MAYHEM_ environment name"
        )
        raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
    if not value.strip():
        msg = f"workflow {workflow} binds {key!r} to an empty expression"
        raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
    pattern = _GITLAB_EXPRESSION if provider is Provider.GITLAB else _GITHUB_EXPRESSION
    if not pattern.fullmatch(value):
        form = "$[[ inputs.name ]]" if provider is Provider.GITLAB else "${{ github.ref }}"
        offending = sorted({char for char in value if char in _UNTRUSTED_FORBIDDEN})
        msg = (
            f"workflow {workflow} binds {key!r} to {value!r}, which is not a "
            f"{provider.value} expression{(offending and f' and carries {offending}') or ''}. "
            f"An untrusted value reaches the script only as a quoted environment "
            f"expansion, so what may be written here is a forge expression such as "
            f"{form} and nothing that behaves like a shell fragment"
        )
        raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
    return value


# =============================================================================
# Rendering
# =============================================================================

_HEADER: Final[str] = (
    "# Generated by `mayhem ci workflow`. Do not edit by hand.\n"
    "#\n"
    "# Every action is pinned to a commit and the base image to a digest, because a\n"
    "# gate whose definition can move between two runs of the same workflow is not\n"
    "# the same gate. Untrusted inputs arrive through `env:` and are read inside the\n"
    "# script as quoted `\"$MAYHEM_…\"` expansions; no untrusted value is ever\n"
    "# interpolated into the script itself.\n"
)


def _yaml_list(values: tuple[str, ...], indent: str) -> list[str]:
    return [f"{indent}- {value}" for value in values]


def _github_trigger(spec: WorkflowSpec) -> list[str]:
    return [
        "on:",
        f"  {GITHUB_TRIGGER}:",
        "    # A pull request from a fork runs with a read-only token and no secrets,",
        "    # which is why every step below is permitted to do nothing but read.",
        "    types: [opened, synchronize, reopened]",
    ]


def _steps(spec: WorkflowSpec, *, runner: str) -> list[str]:
    """The body of the workflow: pinned checkout, pinned interpreter, one run.

    ``runner`` is the container-launcher prefix *without* any lifecycle flag —
    ``docker run``, not ``docker run --rm``. The flags are added here, in one
    place, so the emitted command line cannot end up carrying the same flag
    twice: a duplicated ``--rm`` is harmless in docker and a duplicated
    ``--privileged`` would not be, and the difference between those two mistakes
    is which line of this function somebody edited.

    Every value a step needs arrives through ``env:``. The only ``${{ }}`` this
    module emits is on the right-hand side of an ``env:`` assignment — GitHub
    substitutes it into a *value*, never into a script — and inside ``run:`` the
    script reads ``"$MAYHEM_…"``, quoted, so a value carrying shell syntax is a
    word rather than a command. :func:`assert_script_containment` proves that
    after rendering.
    """
    lines = [f"  {spec.name}-check:", "    runs-on: ubuntu-latest", "    steps:"]
    for pin in spec.actions:
        lines.append(f"      - name: {pin.describe()}")
        lines.append(f"        uses: {pin.ref}")
        if pin is spec.actions[0]:
            lines.append("        with:")
            lines.append("          persist-credentials: false")
    lines.append("      - name: run the pinned mayhem image")
    container = f'{runner} --rm --network=none -v "$PWD:/work:ro" "$MAYHEM_IMAGE"'
    lines.append(f"        run: {container}")
    lines.append("        env:")
    lines.append(f"          MAYHEM_IMAGE: {spec.image.ref}")
    for name, expression in spec.bound_inputs():
        lines.append(f"          {name}: {expression}")
    arguments = " ".join(f"--check {name}" for name in spec.check_names())
    gate = " --release-gate" if spec.release_gate else ""
    lines.append("      - name: mayhem ci check")
    lines.append(
        f"        run: mayhem ci check --environment {spec.environment}{gate}"
        + (f" {arguments}" if arguments else "")
    )
    lines.append("        env:")
    for name, expression in spec.bound_inputs():
        lines.append(f"          {name}: {expression}")
    return lines


def render_github_workflow(spec: WorkflowSpec) -> str:
    """Render the GitHub Actions workflow for ``spec``. Pure and deterministic.

    Same spec in, byte-identical file out: no clock, no environment, no set
    iteration, no dictionary ordering that a caller controls. The rendered text
    passes through :func:`assert_script_containment` before it is returned, so a
    caller cannot get an un-inspected artifact out of this function.
    """
    if spec.provider is not Provider.GITHUB:
        msg = (
            f"workflow {spec.name!r} targets {spec.provider.value!r}; "
            f"render_github_workflow renders {Provider.GITHUB.value!r}"
        )
        raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
    lines: list[str] = [
        _HEADER.rstrip("\n"),
        f"name: {spec.name}",
        "# Least privilege, stated rather than assumed: this workflow reads a",
        "# pull request and writes a commit status. It has no package write, no",
        "# deployment write, and no id-token.",
        "permissions:",
        "  contents: read",
        "  statuses: write",
        "",
    ]
    lines.extend(_github_trigger(spec))
    lines.append("jobs:")
    lines.extend(_steps(spec, runner="docker run"))
    lines.append("")
    rendered = "\n".join(lines)
    assert_script_containment(rendered)
    return rendered


def render_gitlab_component(spec: WorkflowSpec) -> str:
    """Render the GitLab CI component for ``spec``. Pure and deterministic.

    A GitLab component rather than an included file, because a component is
    addressable and versionable where an ``include:`` line is a path somebody can
    edit. The trigger differs (merge request, not pull request) and the
    permissions differ (GitLab has no equivalent of the token block, so the least
    privilege is expressed as ``GIT_STRATEGY`` plus a documented expectation that
    the project's token scope is read-only) — and both differences are stated in
    the rendered header rather than left for a reader to discover.

    .. note::

       **:attr:`WorkflowSpec.actions` is GitHub-only and this renderer says so.**
       GitLab CI has no ``uses:`` key and no third-party action marketplace, so
       there is nothing here for an :class:`ActionPin` to pin. Silently dropping
       the pins would make a spec that declares three pinned actions look like a
       spec that declares them *and* got them applied; the rendered header names
       the omission instead, so a reader of the file learns it from the file.
       What *is* pinned on the GitLab side is the image, by digest, in the
       component's own ``spec:`` block — and that pin this module does enforce.
    """
    if spec.provider is not Provider.GITLAB:
        msg = (
            f"workflow {spec.name!r} targets {spec.provider.value!r}; "
            f"render_gitlab_component renders {Provider.GITLAB.value!r}"
        )
        raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)
    lines: list[str] = [
        _HEADER.rstrip("\n"),
        "# GitLab CI component. The trigger is a merge request; least privilege is",
        "# the project's own token scope, which this file cannot widen and does not",
        "# pretend to set.",
        "# GitLab CI has no `uses:` key, so the actions pinned in the specification",
        "# are NOT applied here — there is nothing in this CI system for a pin to",
        "# bind to. The image below is pinned by digest, and that pin is enforced.",
        "spec:",
        "  inputs:",
        "    image:",
        f"      default: {spec.image.ref}",
    ]
    for key, _ in spec.untrusted_inputs:
        # Declared with an empty default on purpose: the consuming project
        # supplies it, and a default that shipped a real value would make the
        # component's inputs look configured when they are not.
        lines.append(f"    {key}:")
        lines.append("      default: \"\"")
    lines.extend(
        [
            "---",
            f"mayhem {spec.name}:",
            "  image: $[[ inputs.image ]]",
            "  variables:",
            # A merge-request ref is untrusted input in the same sense a pull
            # request head is: the trigger is bound to a name and read quoted.
            '    MAYHEM_CHANGE_REF: "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"',
        ]
    )
    for name, expression in spec.bound_inputs():
        lines.append(f"    {name}: {expression}")
    arguments = " ".join(f"--check {name}" for name in spec.check_names())
    gate = " --release-gate" if spec.release_gate else ""
    lines.extend(
        [
            f"  {spec.name}-check:",
            "    stage: verify",
            "    rules:",
            f"      - if: '$CI_PIPELINE_SOURCE == \"{GITLAB_TRIGGER}\"'",
            "    script:",
            f"      - mayhem ci check --environment {spec.environment}{gate}"
            + (f" {arguments}" if arguments else ""),
            "    needs:",
            "      - job: mayhem:sast",
            "        optional: true",
            "",
        ]
    )
    rendered = "\n".join(lines)
    assert_script_containment(rendered)
    return rendered


_RUN_LINE_RE: Final[re.Pattern[str]] = re.compile(r"^(\s*)(?:- )?run:")


def assert_script_containment(rendered: str) -> None:
    """Refuse a rendered workflow whose *scripts* contain a GitHub expression.

    The rule this exists for: ``run: echo ${{ github.event.pull_request.title }}``
    is remote code execution on the runner, because GitHub substitutes the
    expression into the script *before* a shell sees it, and a pull-request title
    is attacker-controlled. The safe shape — assign to ``env:``, read as a quoted
    expansion inside ``run:`` — is what the generators emit, and this function is
    the backstop for the day somebody edits the file by hand.

    Only lines inside a ``run:`` block are scanned, and "inside" means *indented
    deeper than the ``run:`` key* — which is what YAML block scalars do and what
    lets the generator put its ``${{ }}`` in the ``env:`` list beside the step
    without tripping its own check. A ``${{ }}`` in a YAML *value* is a
    substitution, not code, and GitLab files legitimately carry none.
    """
    in_run = False
    run_indent = 0
    for line in rendered.splitlines():
        run_match = _RUN_LINE_RE.match(line)
        if run_match:
            in_run = True
            run_indent = len(run_match.group(1))
            # The inline form (``run: echo ${{ … }}``) carries the script on the
            # key's own line, so that half has to be scanned too — that is the
            # exact shape the injection takes.
            if "${{" in line[run_match.end() :]:
                _refuse_expression(line)
            continue
        if not in_run:
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if not stripped or stripped.startswith("#"):
            # A comment inside a script is still script text, so only a blank
            # line or a dedent ends the block.
            continue
        if indent <= run_indent:
            in_run = False
            continue
        if "${{" in line:
            _refuse_expression(line)


def _refuse_expression(line: str) -> None:
    """The one message a script-interpolation refusal ever carries."""
    offenders = sorted({char for char in line if char in "$`" or char in "{}"})
    msg = (
        f"the generated script interpolates an expression: {line.strip()!r}. "
        f"An untrusted value inside a run block reaches a shell before the "
        f"shell can quote it ({offenders}); bind it to env: and read "
        '"$MAYHEM_…" instead'
    )
    raise InvariantViolationError(RULE_UNTRUSTED_VALUE, msg)


# =============================================================================
# The PR-check summary
# =============================================================================

_ICON: Final[dict[CheckOutcome, str]] = {
    CheckOutcome.PASS: "PASS",
    CheckOutcome.FAIL: "FAIL",
    CheckOutcome.UNKNOWN: "UNKNOWN",
}


def _cell_ref(cell: object) -> str:
    """A coverage cell key as a reader sees it.

    :attr:`~mayhem.domain.coverage.CoverageCell.key` joins its four parts with
    the ASCII unit separator, which is correct for a key and unreadable in a
    pull-request comment. Swapped for ``/`` on the way out only: the key inside
    the data is unchanged, and what a reviewer copies out of the summary still
    identifies the cell.
    """
    key = getattr(cell, "key", str(cell))
    return str(key).replace("\x1f", "/")


def render_check_summary(
    verdict: PipelineVerdict,
    *,
    coverage: tuple[CoverageSurface, ...] = (),
) -> str:
    """The PR-check markdown body, exactly as the workflow writes it to the summary.

    Golden-fixtured in ``tests/unit/test_ci_surface.py``: this string is what a
    reviewer reads on the pull request, so its shape is a contract rather than a
    convenience.

    Three properties are load-bearing and each is asserted on the rendered text:

    * every check's outcome is printed verbatim, so ``UNKNOWN`` cannot render as a
      tick and an unreachable control plane cannot read as a pass;
    * every coverage line reads ``N of M``, because a bare fraction is how an
      untested service reports 100%;
    * the release-gate line is delegated to
      :func:`mayhem.domain.pipeline.blocking_reasons`, so this renderer cannot
      disagree with Phase 1 about whether a release opens — it only prints the
      answer.

    Refuses a verdict with no checks at all (:data:`RULE_SUMMARY_WITHOUT_VERDICT`):
    a summary that renders "all checks passed" over zero checks is a green tick
    on an absence, which is the exact artifact this plan refuses everywhere else.
    """
    if not verdict.checks:
        msg = (
            f"refusing to render a check summary for {verdict.change.git_sha}: the "
            "verdict carries no checks, and 'every check passed' over zero checks is "
            "a green tick on an absence"
        )
        raise InvariantViolationError(RULE_SUMMARY_WITHOUT_VERDICT, msg)

    reasons = blocking_reasons(verdict)
    lines: list[str] = [
        f"## mayhem checks — {verdict.change.git_sha}",
        "",
        f"**Pipeline:** {verdict.outcome.value.upper()}",
    ]
    for reference in verdict.change.references:
        lines.append(f"**Change:** {reference}")
    missing = verdict.change.pins.missing
    if missing:
        lines.append(f"**Unpinned axes:** {', '.join(missing)}")
    lines.append("")
    lines.append("| check | scope | outcome | detail |")
    lines.append("| --- | --- | --- | --- |")
    for check in verdict.checks:
        detail = check.detail or (check.finding.message if check.finding else "")
        detail = (detail or "no detail").replace("|", "\\|")
        lines.append(
            f"| `{check.name}` | {check.scope.value} | **{_ICON[check.outcome]}** | {detail} |"
        )
    if coverage:
        lines.extend(["", "### Coverage"])
        for surface in coverage:
            lines.append(f"- {surface.describe()}")
            if surface.gaps:
                lines.append(
                    "  - gaps: "
                    + ", ".join(f"`{_cell_ref(cell)}`" for cell in surface.gaps[:5])
                    + (f" (+{len(surface.gaps) - 5} more)" if len(surface.gaps) > 5 else "")
                )
    lines.extend(["", "### Release gate"])
    if reasons:
        lines.append("may this open a release: **no**")
        lines.extend(f"- {reason}" for reason in reasons)
    else:
        lines.append(
            "may this open a release: **yes** — every check passed and the change "
            "link is pinned"
        )
    if any(check.outcome is CheckOutcome.UNKNOWN for check in verdict.checks):
        lines.extend(
            [
                "",
                f"> {CONTROL_PLANE_UNREACHABLE}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


# =============================================================================
# Commit statuses — the GitHub App seam
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitStatus:
    """The status an app would post: a context, a state, and a description.

    ``state`` is one of ``success`` / ``failure`` / ``pending`` / ``error``, the
    four GitHub accepts. Note there is no ``neutral``: a check that did not
    conclude is posted as ``error`` or ``failure``, never as a shrug. A shrug on
    a required check is a shrug a branch-protection rule will read as a pass.
    """

    context: str
    state: str
    description: str
    target_url: str = ""

    def __post_init__(self) -> None:
        _require_nonblank(self.context, RULE_STATUS_UNAVAILABLE, "commit status context")
        _require_nonblank(self.state, RULE_STATUS_UNAVAILABLE, "commit status state")
        if self.state not in ("success", "failure", "pending", "error"):
            msg = (
                f"commit status state {self.state!r} is not one of success, failure, "
                "pending, error: 'neutral' would be a check that did not conclude "
                "rendering as a check that passed"
            )
            raise InvariantViolationError(RULE_STATUS_UNAVAILABLE, msg)
        if self.description and len(self.description) > 140:
            msg = (
                "commit status description is 141 characters; GitHub truncates at 140, "
                "and a truncated refusal is a refusal nobody can read"
            )
            raise InvariantViolationError(RULE_STATUS_UNAVAILABLE, msg)


class CommitStatusPort(Protocol):
    """What a GitHub App (or any forge adapter) implements. One method.

    Declared structurally and **unimplemented here**: this repository holds no
    token and opens no socket, so the only honest thing to ship is the protocol
    and the tests over fakes. What the tests must prove — that an unbound,
    raising, ``None``-answering and wrong-shaped port are all the same finding —
    is a property of :func:`publish_commit_status`, and a four-line fake proves
    it without a network.

    The acknowledgement is a :class:`StatusAck` and nothing else. Mayhem does
    not read anything inside it; it checks that one *type* came back, because
    "a transport that answers in some shape nobody specified" has to be
    distinguishable from "a transport that answered", or a wrong-shaped reply is
    indistinguishable from a delivered status.
    """

    def post_status(self, *, git_sha: str, status: CommitStatus) -> object | None: ...


@dataclass(frozen=True, slots=True)
class StatusAck:
    """A status the forge acknowledged. Carries nothing mayhem acts on."""

    context: str

    def __post_init__(self) -> None:
        _require_nonblank(self.context, RULE_STATUS_UNAVAILABLE, "status acknowledgement")


@dataclass(frozen=True, slots=True)
class StatusPublication:
    """Whether the status reached the forge, and what to say when it did not."""

    published: bool
    context: str
    detail: str
    reach: ControlPlaneReach

    def to_dict(self) -> dict[str, object]:
        return {
            "published": self.published,
            "context": self.context,
            "detail": self.detail,
            "control_plane": self.reach.value,
        }


def status_for(verdict: PipelineVerdict, *, context: str = "mayhem/ci") -> CommitStatus:
    """The status ``verdict`` should post — read off the verdict, never re-derived.

    :data:`~mayhem.domain.pipeline.CheckOutcome.UNKNOWN` maps to ``error``, not to
    ``pending`` and certainly not to ``success``: the checks did not conclude, and
    ``pending`` on a check that will never resolve is a status that sits on a
    pull request forever while a required check is neither satisfied nor failing.
    """
    if verdict.outcome is PipelineOutcome.PASS:
        state = "success"
        description = f"{len(verdict.checks)} checks passed"
    else:
        state = "failure"
        first = verdict.reasons[0] if verdict.reasons else "the pipeline did not pass"
        description = first[:140]
    unknown = any(check.outcome is CheckOutcome.UNKNOWN for check in verdict.checks)
    if unknown:
        state = "error"
        description = (
            f"{sum(1 for c in verdict.checks if c.outcome is CheckOutcome.UNKNOWN)} "
            f"of {len(verdict.checks)} checks could not conclude: "
            f"{(verdict.reasons[0] if verdict.reasons else CONTROL_PLANE_UNREACHABLE)[:90]}"
        )
    return CommitStatus(context=context, state=state, description=description)


def publish_commit_status(
    port: CommitStatusPort | None,
    *,
    git_sha: str,
    status: CommitStatus,
) -> StatusPublication:
    """Post ``status``, or report the control plane unreachable. Never raises.

    Four ways to have no answer — the port is unbound, the port raised, the port
    returned ``None``, the port returned something that is not ``None`` — and one
    status for all four, exactly as
    :func:`~mayhem.controller.preflight_gate.port_status` collapses them. A DNS
    timeout is a fact about the network, not a fact about the pull request.

    The refusal is *not* a gate decision: the decision was already made,
    fail-closed, by :func:`~mayhem.controller.check_gate.evaluate_pr_checks` and
    :func:`~mayhem.domain.pipeline.blocking_reasons`. This function's job is to
    tell the truth about the *delivery*, so a caller that renders the pipeline as
    green while :attr:`StatusPublication.published` is false is caught by the
    caller's own "nobody was told" state rather than being laundered here.
    """
    _require_nonblank(git_sha, RULE_STATUS_UNAVAILABLE, "commit status git_sha")
    if port is None:
        return StatusPublication(
            published=False,
            context=status.context,
            detail=(
                "no commit-status port is bound: mayhem holds no forge token, so the "
                f"status for {git_sha[:12]} was not posted"
            ),
            reach=ControlPlaneReach.UNREACHABLE,
        )
    try:
        answer = port.post_status(git_sha=git_sha, status=status)
    except Exception as exc:
        return StatusPublication(
            published=False,
            context=status.context,
            detail=f"the status port raised {type(exc).__name__}: {exc}",
            reach=ControlPlaneReach.UNREACHABLE,
        )
    if not isinstance(answer, StatusAck):
        return StatusPublication(
            published=False,
            context=status.context,
            detail=(
                f"the status port for {status.context} answered "
                f"{type(answer).__name__}, which is not a StatusAck: mayhem cannot "
                "confirm a status it cannot recognise, and reports it as unposted"
            ),
            reach=ControlPlaneReach.UNREACHABLE,
        )
    return StatusPublication(
        published=True,
        context=status.context,
        detail=f"posted {status.state} to {status.context} on {git_sha[:12]}",
        reach=ControlPlaneReach.REACHABLE,
    )


#: The four ways a port can fail to answer, named once so the docstring, the
#: tests, and a reader of the report all say the same four words.
PORT_FAILURE_MODES: Final[tuple[str, ...]] = (
    "unbound",
    "raised",
    "answered_none",
    "answered_wrong_shape",
)
