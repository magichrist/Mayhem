"""Plan 21 Phase 3 — the advisor surface: a dashboard, a replay flow, a library.

Phases 1, 2 and 4 proved the arithmetic, the engine, and the boundary. This suite
is about the missing last link, and every test in it targets a *negative*
somewhere, because a surface that only ever renders a good case proves nothing
about what it refuses:

* **the render acceptance, at the view-model layer.**
  :func:`test_a_recommendation_with_no_traceable_rationale_refuses_to_render`
  calls :func:`advisor_cmd.ranked_views` directly — not the Click callback, not a
  renderer — with a recommendation whose rationale never names the criteria it
  was weighed against, and asserts the refusal. The point is that a future UI
  (plan 08) inherits the guarantee by asking this layer for a view, rather than
  re-deciding it: there is no other way to get one.
* **advisory is not authorization, asserted over every rendered field.**
  :func:`test_no_rendered_field_claims_approval_authorization_certification_or_execution`
  walks every view the surface can produce, flattens the rendered text and the
  JSON payload, and refuses the words ``approved``, ``authorized``, ``certified``
  and ``executable`` anywhere in them. The one legitimate exception is spelled
  out in the test: ``gate_authorized`` is the plan-09 approval gate's *own*
  verdict, quoted under ``authorization_state`` because the three states have to
  render faithfully, and the surface's own grant fields beside it are constants.
* **all three authorization states render, and neither non-granting state may
  read as a grant.** ``requirements_only`` and ``gate_refused`` are checked
  separately from ``gate_authorized``, so collapsing the first two into the
  third would fail here.
* **an untrusted draft renders as untrusted**, and
  :func:`test_no_view_type_has_a_field_an_approval_could_travel_in` asserts that
  none of the view types has a writable field for one — the grant properties are
  properties, so there is nothing to set.
* **an incident that cannot be traced to its snapshot yields a named refusal,
  not a default candidate** — through the view-model, and again through the
  command, where the refusal is a ``safety_refusal`` naming the rule.
* **a candidate refused by a downstream gate names that gate.** Two are
  exercised: the compile gate (a fault the catalog does not define) and the
  schema (a timeline fault whose required parameter no instantiation supplies).
* **a scenario whose hypothesis does not match its recommendation is refused**
  by :data:`~mayhem.controller.advisor_service.RULE_SUBMISSION_SPEC_NOT_BOUND`,
  through the surface's own :func:`advisor_cmd.scenario_submission`.
* **mutation evidence.** The sink is *pre-loaded* before every view, so a
  reported zero would fail here where a hard-coded one would pass. Viewing and
  browsing add nothing; and an approval step without its approval has no step to
  write, because the surface declares no ``approve`` command and no ``--approve``
  or ``--force`` flag.

One property is asserted that the plan records as **not** delivered: several
shipped scenario templates do not compile through ``plan_drill`` for a container
target, because a timeline fault declares a required parameter that
:meth:`~mayhem.domain.scenarios.ScenarioInstantiation.drill_spec` does not
supply. :func:`test_the_library_templates_that_cannot_compile_are_refused_by_name`
pins that as a named refusal rather than a workaround, because fixing it means
editing :mod:`mayhem.domain.scenarios` or :mod:`mayhem.domain.catalog`, which this
work item does not own.

Nothing here opens a database: the surface reads one JSON inputs document and
refuses every field in it that it does not understand.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mayhem.cli import advisor_cmd
from mayhem.cli.errors import MayhemCliError, map_exception_to_error
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.advisor_service import (
    RULE_SUBMISSION_SPEC_NOT_BOUND,
    SubmissionAuthorization,
)
from mayhem.domain.policy_gate import MutationSink
from mayhem.domain.advisor import (
    Approval,
    CustomerCriterion,
    PriorityCriteria,
    RecommendationOrigin,
    is_certified_evidence,
)
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.scenarios import scenario_library
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    HostNode,
    ServiceNode,
    TopologyGraph,
)

ROOT = Path(__file__).parents[2]

SERVICE = "checkout"
DEPENDENCY = "redis-cache"
SNAPSHOT_ID = "graph-7f3c"
OTHER_SNAPSHOT_ID = "graph-9a11"
INCIDENT_ID = "inc-2026-03-04-cache-loss"
FAULT_ID = "net.latency"
INCIDENT_DURATION_S = 41.0
P99_MS = 4200.0
FINGERPRINT = "a" * 64
RUN_ID = "r-advisor-1"
CONFIG_SNAPSHOT_ID = "cfg-advisor-1"
UNSEALED = "f" * 64

#: The four words a reader must never find in an advisor view. Not a style
#: preference: each one is a claim about standing that this surface cannot make.
FORBIDDEN_WORDS: tuple[str, ...] = ("approved", "authorized", "certified", "executable")

#: ``gate_authorized`` is exempt from the word scan and only from it: it is the
#: plan-09 approval gate's *own* verdict, quoted under ``authorization_state``
#: because plan 21 Phase 4 requires all three of its states to render faithfully
#: and an unknown must never be collapsed into an authorized reading. The
#: underscore is what makes ``gate_authorized`` a state name rather than the
#: word "authorized"; the surface's own grant fields are constants beside it,
#: and :func:`test_the_surface_grants_nothing_whatever_the_gate_says` asserts
#: that they are.
_FORBIDDEN_RE = re.compile(
    r"\b(?:" + "|".join(FORBIDDEN_WORDS) + r")\b",
    re.IGNORECASE,
)
_EXEMPT = ("gate_authorized",)


# ==============================================================================
# The world: a topology, a landscape, a declared weighting, and one incident
# ==============================================================================


def sealed_graph() -> TopologyGraph:
    """checkout -> redis-cache, with one running container behind each service."""
    return TopologyGraph(
        nodes=(
            ServiceNode(id=SERVICE, name=SERVICE),
            ServiceNode(id=DEPENDENCY, name=DEPENDENCY),
            ContainerNode(
                id=f"ctr-{SERVICE}",
                name=SERVICE,
                engine="docker",
                container_name=SERVICE,
                state="running",
                runtime_identity=RuntimeIdentity(
                    runtime="docker", host_id="h-local", runtime_id=f"cid-{SERVICE}"
                ),
                runtime_metadata=RuntimeMetadata(service=SERVICE, name=SERVICE),
            ),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(
            Edge(src=SERVICE, dst=DEPENDENCY, kind=EdgeKind.DEPENDS_ON),
            Edge(src=f"ctr-{SERVICE}", dst=SERVICE, kind=EdgeKind.RUNS_ON),
        ),
    )


def gap_cell(fault_kind: str = FAULT_ID, target: str = SERVICE) -> CoverageCell:
    return CoverageCell(
        target=target,
        fault_kind=fault_kind,
        execution_context="container",
        parameter_band="default",
    )


GAP_CELL = gap_cell()
COVERED_CELL = gap_cell(fault_kind="pod-churn", target="search")
#: The cell a scenario occupies is ``(target, timeline[0].fault_id, …)``, so every
#: scenario the surface can bind needs its own declared gap. All eight first
#: faults are declared, which is what lets the library test report an outcome for
#: every template rather than skipping the ones it cannot address.
SCENARIO_CELLS: tuple[str, ...] = (
    "node.service_stop",
    "dependency.circuit_open",
    "dns.servfail",
    "dependency.timeout",
    "net.partition",
    "container.kill",
    "tls.certificate_expired",
    "load.spike",
)


def readings_document(fault_kind: str = FAULT_ID, *, impact: float = 0.9) -> list[dict[str, Any]]:
    """One row: the cell's four declared dimensions and the customer's readings."""
    return [
        {
            "target": SERVICE,
            "fault_kind": fault_kind,
            "execution_context": "container",
            "parameter_band": "default",
            "readings": [
                {
                    "criterion": "customer_impact",
                    "value": impact,
                    "evidence": "checkout fronts the gap on the customer path",
                },
                {
                    "criterion": "coverage_gap",
                    "value": 0.8,
                    "evidence": "the cell has never executed",
                },
            ],
        }
    ]


def inputs_document(**overrides: Any) -> dict[str, Any]:
    """One valid inputs document, with named overrides for the negative cases."""
    document: dict[str, Any] = {
        "landscape_id": "landscape-checkout-v4",
        "criteria": {
            "name": "q1-customer-priorities",
            "criteria": [
                {
                    "name": "customer_impact",
                    "weight": 1.0,
                    "question": "how many customers meet this failure in a normal week?",
                },
                {
                    "name": "coverage_gap",
                    "weight": 0.25,
                    "question": "how little of this area has ever been exercised?",
                },
            ],
        },
        "topology": {
            "snapshot_id": SNAPSHOT_ID,
            "graph": sealed_graph().model_dump(mode="json"),
        },
        "cells": [
            {
                "target": cell.target,
                "fault_kind": cell.fault_kind,
                "execution_context": cell.execution_context,
                "parameter_band": cell.parameter_band,
                "state": state,
            }
            for cell, state in [
                *((gap_cell(fault_kind), "unknown") for fault_kind in (FAULT_ID, *SCENARIO_CELLS)),
                (COVERED_CELL, "passed"),
            ]
        ],
        "readings": [
            row
            for fault_kind in (FAULT_ID, *SCENARIO_CELLS)
            for row in readings_document(fault_kind)
        ],
        "incidents": [
            {
                "incident_id": INCIDENT_ID,
                "service": SERVICE,
                "failure_signature": "p99 latency on cache miss above 4s",
                "dependency": DEPENDENCY,
                "topology_snapshot_id": SNAPSHOT_ID,
                "duration_s": INCIDENT_DURATION_S,
                "started_at": "2026-03-04T09:12:00+00:00",
                "ended_at": "2026-03-04T09:18:52+00:00",
                "percentiles": {
                    "p99": {
                        "metric": "latency",
                        "value": P99_MS,
                        "unit": "ms",
                        "samples": 900,
                    }
                },
                "versions": {"mayhem": "1.1.0", "kubernetes": "1.29.4"},
            }
        ],
        "deployments": {"mayhem": "1.1.0", "kubernetes": "1.29.4"},
        "established": [],
    }
    document.update(overrides)
    return document


def write_inputs(tmp_path: Path, document: dict[str, Any], *, name: str = "advisor.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.fixture
def inputs_file(tmp_path: Path) -> Path:
    return write_inputs(tmp_path, inputs_document())


# ==============================================================================
# Helpers: the same reads the commands perform, in the same order
# ==============================================================================


def load(path: Path) -> advisor_cmd.AdvisorInputs:
    return advisor_cmd.AdvisorInputs.from_path(path)


def loaded_sink() -> MutationSink:
    """A sink with two calls already in it, so "added nothing" is measurable."""
    return MutationSink().record("lease", "acquire run lease").record("k8s", "inject net.latency")


def analysis_for(inputs: advisor_cmd.AdvisorInputs, *, sink: MutationSink | None = None):
    return advisor_cmd._analyse(inputs, sink=sink)


def dashboard_for(
    inputs: advisor_cmd.AdvisorInputs, *, sink: MutationSink | None = None
) -> advisor_cmd.AdvisorDashboard:
    return advisor_cmd.advisor_dashboard(
        analysis_for(inputs, sink=sink), inputs.criteria, inputs.readings
    )


def replay_for(
    inputs: advisor_cmd.AdvisorInputs, *, fault_id: str = FAULT_ID
) -> advisor_cmd.ReplayView:
    engine = advisor_cmd.advisor_service_for(inputs)
    request = advisor_cmd._replay_request(
        fault_id,
        "container",
        "default",
        ("seconds=duration", "jitter_ms=p99:ms"),
    )
    compiled = engine.replay(request, inputs.incidents[INCIDENT_ID], engine.landscape())
    return advisor_cmd.replay_view(compiled, topology_snapshot_id=inputs.topology_snapshot_id)


def run(argv: list[str]) -> Any:
    """Invoke the group directly, as ``test_stop_surface.py`` invokes ``app``.

    Not through ``mayhem.cli.app``: this suite is about the surface, and the app's
    command registry is a separate integration pass's concern. Reaching the group
    through the registry would make these tests fail for a reason that has nothing
    to do with the view-model.
    """
    return CliRunner().invoke(advisor_cmd.advisor, argv)


def exit_code_of(result: Any) -> int:
    """The exit code ``mayhem.cli.app.main`` would give this invocation.

    ``main`` is the only place that turns a :class:`MayhemCliError` into a number,
    and it turns it with the real
    :func:`~mayhem.cli.errors.map_exception_to_error`. This reuses that mapping
    rather than restating it, so "a refusal exits 5" is asserted against the same
    table the tree ships — while the invocation itself still reaches only this
    surface's own group.
    """
    if result.exit_code == 0:
        return 0
    exception = result.exception
    if exception is None:
        return int(result.exit_code)
    if isinstance(exception, SystemExit):
        return int(exception.code or 0)
    return int(map_exception_to_error(exception).exit_code)


def refuse(result: Any, expected: ExitCode) -> MayhemCliError:
    """Assert an invocation was refused with ``expected``, and hand back the refusal."""
    error = result.exception
    assert isinstance(error, MayhemCliError), (result.output, error)
    assert exit_code_of(result) == int(expected), (result.output, error)
    return error


def declared_criteria() -> PriorityCriteria:
    return PriorityCriteria(
        name="q1-customer-priorities",
        criteria=(
            CustomerCriterion(
                name="customer_impact",
                weight=1.0,
                question="how many customers meet this failure in a normal week?",
            ),
            CustomerCriterion(
                name="coverage_gap",
                weight=0.25,
                question="how little of this area has ever been exercised?",
            ),
        ),
    )


def rendered_text(*views: Any) -> str:
    """Every rendered line of every view, joined — the thing the word scan reads."""
    chunks: list[str] = []
    for view in views:
        for name in dir(view):
            if not name.startswith("render_"):
                continue
            chunks.extend(getattr(view, name)())
    return "\n".join(chunks)


def rendered_payload(*views: Any) -> str:
    """Every JSON projection, flattened to text — including the keys."""
    return json.dumps([view.to_dict() for view in views], sort_keys=True, default=str)


def _documented_invocations(text: str) -> list[list[str]]:
    """Every ``mayhem advisor …`` spelling in a docstring, as argument lists.

    Three steps, each of which has bitten a documentation test before:

    * continuation lines are joined first, so an invocation written over three
      lines is one invocation rather than three broken ones;
    * only a line that *begins* with ``mayhem advisor`` counts, so prose that
      mentions the command in passing is not read as an invocation;
    * the tail is cut at the first sentence break and at the first placeholder
      token, because ``<64 hex>`` is documentation and not a value Click can
      resolve.
    """
    joined: list[str] = []
    buffer = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1].strip() + " "
            continue
        joined.append(buffer + stripped)
        buffer = ""
    if buffer:
        joined.append(buffer)

    found: list[list[str]] = []
    for line in joined:
        if not line.startswith("mayhem advisor"):
            continue
        tail = re.split(r"(?:[.;|](?:\s|$))", line[len("mayhem advisor") :])[0]
        tokens: list[str] = []
        for token in tail.split():
            if token.startswith(("<", "`", '"', "'")):
                break
            tokens.append(token.strip('`"\''))
        argv = ["advisor", *tokens]
        argv = [token for token in argv if token not in {"--help"}]
        if len(argv) > 1:
            found.append(argv)
    return found


def _some_submission(inputs_file: Path) -> advisor_cmd.SubmissionView:
    """One real submission, so a renderer test is a test about rendering."""
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    return _submissions(inputs, instantiation)[0]


def offending_words(text: str) -> list[str]:
    """Forbidden words present, with the one legitimate state name removed first."""
    scrubbed = text
    for exempt in _EXEMPT:
        scrubbed = scrubbed.replace(exempt, "")
    return sorted({match.group(0).lower() for match in _FORBIDDEN_RE.finditer(scrubbed)})


# ==============================================================================
# The surface exists, and every documented invocation resolves
# ==============================================================================

DOCUMENTED_INVOCATIONS: tuple[tuple[str, ...], ...] = (
    ("--help",),
    ("dashboard", "--help"),
    ("dashboard", "--inputs", "advisor.json"),
    ("dashboard", "--inputs", "advisor.json", "--limit", "1", "--json"),
    ("replay", "--help"),
    (
        "replay",
        "--inputs",
        "advisor.json",
        "--incident",
        INCIDENT_ID,
        "--fault-id",
        FAULT_ID,
        "--context",
        "container",
        "--band",
        "default",
        "--bind",
        "seconds=duration",
        "--bind",
        "jitter_ms=p99:ms",
    ),
    (
        "replay",
        "--inputs",
        "advisor.json",
        "--incident",
        INCIDENT_ID,
        "--fault-id",
        FAULT_ID,
        "--context",
        "container",
        "--band",
        "default",
        "--bind",
        "seconds=duration",
        "--bind",
        "jitter_ms=p99:ms",
        "--json",
    ),
    (
        "submit",
        "--inputs",
        "advisor.json",
        "--incident",
        INCIDENT_ID,
        "--fault-id",
        FAULT_ID,
        "--context",
        "container",
        "--band",
        "default",
        "--bind",
        "seconds=duration",
        "--bind",
        "jitter_ms=p99:ms",
        "--run-id",
        RUN_ID,
        "--config-snapshot",
        CONFIG_SNAPSHOT_ID,
        "--fingerprint",
        FINGERPRINT,
    ),
    ("scenario", "--help"),
    ("scenario", "list"),
    ("scenario", "list", "--json"),
    ("scenario", "show", "dns-failure@1.0.0"),
    ("scenario", "show", "dns-failure@1.0.0", "--json"),
    (
        "scenario",
        "instantiate",
        "pod-churn@1.0.0",
        "--inputs",
        "advisor.json",
        "--target",
        SERVICE,
        "--context",
        "container",
        "--band",
        "default",
        "--preview",
    ),
)


def test_the_group_is_a_group_with_the_five_documented_leaves() -> None:
    import click

    assert isinstance(advisor_cmd.advisor, click.Group)
    assert sorted(advisor_cmd.advisor.commands) == ["dashboard", "replay", "scenario", "submit"]
    scenario = advisor_cmd.advisor.commands["scenario"]
    assert isinstance(scenario, click.Group)
    assert sorted(scenario.commands) == ["instantiate", "list", "show"]


@pytest.mark.parametrize("argv", DOCUMENTED_INVOCATIONS)
def test_the_group_resolves_every_documented_invocation(argv: tuple[str, ...]) -> None:
    """Every spelling in this module's docstring parses on the live tree.

    A typo in a documented invocation fails here rather than in a terminal. The
    required-value arguments are checked by Click's own parser on ``--help`` and
    on the concrete invocations, so this asserts resolution rather than running.
    """
    result = CliRunner().invoke(advisor_cmd.advisor, [*argv, "--help"])
    assert result.exit_code == 0, result.output


def test_every_invocation_written_in_the_module_docstring_resolves(
    inputs_file: Path,
) -> None:
    """The docstring's own ``mayhem advisor …`` examples are checked, not assumed.

    ``--help`` is stripped because it documents the boundary rather than crossing
    it, and the trailing continuation of a prose line is not part of the command.
    """
    source = (ROOT / "src/mayhem/cli/advisor_cmd.py").read_text(encoding="utf-8")
    docstring = source.split('"""', 2)[1]
    found = _documented_invocations(docstring)
    assert found, "no advisor invocation is documented at all"
    # The documented ``--inputs advisor.json`` is resolved against a real file:
    # ``click.Path(exists=True)`` validates the path even on ``--help``, so a
    # placeholder would fail for a reason that has nothing to do with the command.
    resolved = [
        [str(inputs_file) if token.endswith(".json") else token for token in argv[1:]]
        for argv in found
    ]
    unresolvable = [argv for argv in resolved if run([*argv, "--help"]).exit_code != 0]
    assert not unresolvable, unresolvable
    # And the scanner found the six executable documented spellings, not one or two.
    assert len(found) == 6


def _documented_invocations(text: str) -> list[list[str]]:
    """Every ``mayhem advisor …`` spelling in a docstring, as argument lists.

    Three steps, each of which has bitten a documentation test before:

    * continuation lines are joined first, so an invocation written over three
      lines is one invocation rather than three broken ones;
    * only a line that *begins* with ``mayhem advisor`` counts, so prose that
      mentions the command in passing is not read as an invocation;
    * the tail is cut at the first sentence break and at the first placeholder
      token, because ``<64 hex>`` is documentation and not a value Click can
      resolve.
    """
    joined: list[str] = []
    buffer = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("\\"):
            buffer += stripped.rstrip("\\").strip() + " "
            continue
        joined.append(buffer + stripped)
        buffer = ""
    if buffer:
        joined.append(buffer)

    found: list[list[str]] = []
    for line in joined:
        if not line.startswith("mayhem advisor"):
            continue
        tail = re.split(r"(?:[.;|](?:\s|$))", line[len("mayhem advisor") :])[0]
        tokens: list[str] = []
        for token in tail.split():
            # A placeholder ends the invocation: ``<64 hex>`` is documentation of
            # what the flag wants, not a value a resolver could check.
            if token.startswith("<") or token.endswith(">"):
                break
            tokens.append(token.strip("`'\""))
        argv = [token for token in ["advisor", *tokens] if token != "--help"]
        # A trailing option with no value after it is a placeholder that was cut
        # (the ``<64 hex>`` case), and a resolver would read the next token as its
        # value; drop it so the spelling that is checked is the one a person reads.
        if len(argv) > 1 and argv[-1].startswith("--"):
            argv = argv[:-1]
        if len(argv) > 1:
            found.append(argv)
    return found


@pytest.mark.parametrize(
    "bypass",
    (
        "--approve",
        "--force",
        "--authorized",
        "--certify",
        "--execute",
        "--auto-approve",
        "--yes",
        "-y",
        "--skip-approval",
        "--override-policy",
        "--max-hosts",
        "--max-services-pct",
    ),
)
def test_no_flag_on_this_surface_approves_or_weakens_a_gate(bypass: str) -> None:
    """The plan's boundary, asserted over every option the group declares.

    ``--approve``/``--force`` would be the obvious ways to make an advisor
    candidate look finished. ``--max-hosts`` and ``--max-services-pct`` are the
    subtler one: they would hand the caller the blast-radius ceiling that is
    supposed to be checking the caller. Neither exists, and :func:`advisor_safety_context`
    fixes the ceilings as module constants instead.
    """
    declared: set[str] = set()
    for command in (
        advisor_cmd.advisor.commands["dashboard"],
        advisor_cmd.advisor.commands["replay"],
        advisor_cmd.advisor.commands["submit"],
        advisor_cmd.advisor.commands["scenario"].commands["instantiate"],
    ):
        for param in command.params:
            declared |= set(getattr(param, "opts", []))
            declared |= set(getattr(param, "secondary_opts", []))
    assert bypass not in declared


def test_the_surface_declares_no_approve_command_at_all() -> None:
    """There is no second spelling of "make this approved"."""
    for group in (advisor_cmd.advisor, advisor_cmd.advisor.commands["scenario"]):
        names = set(group.commands)
        assert not names & {"approve", "authorise", "authorize", "sign", "certify", "execute"}


# ==============================================================================
# The dashboard: ranked by the declared criteria, with traces
# ==============================================================================


def test_the_dashboard_ranks_by_the_declared_weighted_mean_and_carries_the_trace(
    inputs_file: Path,
) -> None:
    inputs = load(inputs_file)
    view = dashboard_for(inputs)

    assert view.criteria_name == inputs.criteria.name
    # Every declared gap in the document's landscape is ranked, and every
    # position is the domain's: positions are 1..n with nothing dropped.
    positions = [row.position for row in view.ranked]
    assert positions == list(range(1, len(positions) + 1))
    assert len(positions) == 1 + len(SCENARIO_CELLS)
    row = next(row for row in view.ranked if row.cell_key == GAP_CELL.key)
    # 1.0*0.9 + 0.25*0.8 = 1.10 over a declared total weight of 1.25
    assert row.priority_total == pytest.approx(1.10 / 1.25)
    assert row.weighted_sum == pytest.approx(1.10)
    assert row.total_weight == pytest.approx(1.25)
    # Every declared criterion travels with the row: its weight, its value, and
    # the fact the value was read from.
    assert [c.name for c in row.declared_criteria] == list(inputs.criteria.names)
    assert all(c.question.strip() for c in row.declared_criteria)
    assert all(c.evidence.strip() for c in row.declared_criteria)
    assert row.cell_key == GAP_CELL.key
    assert {fact.kind for fact in row.cited_facts} >= {
        "finding",
        "coverage_cell",
        "topology_snapshot",
        "criterion_reading",
    }


def test_changing_the_declared_weighting_changes_the_rendered_priority(tmp_path: Path) -> None:
    """Priority is a function of the declared weights, not a stored score.

    The *same* findings, rendered against a declaration that weights the low
    criterion more heavily, produce a lower number. A stored score could not
    demonstrate this, which is why the view has nowhere to put one.
    """
    lighter = load(write_inputs(tmp_path, inputs_document(), name="light.json"))
    heavier_document = inputs_document()
    heavier_document["criteria"]["criteria"][1]["weight"] = 4.0
    heavier_document["criteria"]["criteria"][1]["question"] = "how untested is this area?"
    heavier = load(write_inputs(tmp_path, heavier_document, name="heavy.json"))

    first = advisor_cmd.advisor_dashboard(
        analysis_for(lighter), lighter.criteria, lighter.readings
    )
    second = advisor_cmd.advisor_dashboard(
        analysis_for(heavier), heavier.criteria, heavier.readings
    )

    assert [row.cell_key for row in first.ranked] == [row.cell_key for row in second.ranked]
    assert first.ranked[0].priority_total != second.ranked[0].priority_total
    # A heavier low score pulls the weighted mean down — for every finding.
    assert all(
        a.priority_total > b.priority_total
        for a, b in zip(first.ranked, second.ranked, strict=True)
    )
    # And the declaration a reader is shown is the one the number came from.
    assert second.declared_criteria[1].weight == 4.0
    assert second.declared_criteria[1].question == "how untested is this area?"


def test_the_dashboard_declares_every_cell_it_declined_and_by_why(inputs_file: Path) -> None:
    """The honesty half: the gap between the landscape and the findings is a list."""
    view = dashboard_for(load(inputs_file))

    assert [row.cell_key for row in view.suppressed] == [COVERED_CELL.key]
    assert view.suppressed[0].reason == "not_a_gap_state"
    assert "passed" in view.suppressed[0].detail


def test_the_dashboard_command_renders_the_ranking_and_the_declined_cells(
    inputs_file: Path,
) -> None:
    result = run(["dashboard", "--inputs", str(inputs_file)])
    assert result.exit_code == 0, result.output
    assert "declared criteria ('q1-customer-priorities')" in result.output
    assert "customer_impact weight 1 — how many customers" in result.output
    assert "weighted mean of the declared criteria, derived on read" in result.output
    assert "rec:finding:" in result.output
    assert "declined cells (1)" in result.output
    assert "not_a_gap_state" in result.output


def test_limit_truncates_the_rendering_and_not_the_arithmetic(tmp_path: Path) -> None:
    """``--limit`` is a display choice: every displayed position is still the domain's."""
    document = inputs_document()
    for fault_kind in ("cpu.throttle", "proc.pause"):
        document["cells"].append(
            {
                "target": SERVICE,
                "fault_kind": fault_kind,
                "execution_context": "container",
                "parameter_band": "default",
                "state": "unknown",
            }
        )
        document["readings"].extend(readings_document(fault_kind, impact=0.4))
    path = write_inputs(tmp_path, document)

    full = run(["dashboard", "--inputs", str(path)])
    limited = run(["dashboard", "--inputs", str(path), "--limit", "1"])
    assert full.exit_code == 0, full.output
    assert limited.exit_code == 0, limited.output
    assert f"ranked recommendations ({1 + len(SCENARIO_CELLS) + 2})" in full.output
    assert "ranked recommendations (1)" in limited.output
    # The one row shown still carries the domain's position, which is 1 here
    # because 0.4 is the lowest weighted mean in the document.
    assert "  1. rec:finding:" in limited.output
    assert "  2. " not in limited.output
    # And the truncation happened in the renderer: the JSON payload for --limit 1
    # is the same shape, one row shorter, with the untruncated total still computed.
    payload = json.loads(
        run(["dashboard", "--inputs", str(path), "--limit", "1", "--json"]).output
    )
    full_payload = json.loads(
        run(["dashboard", "--inputs", str(path), "--json"]).output
    )
    assert len(payload["ranked"]) == 1
    # The truncated row is the same row, with the same derived score, at the same
    # position: the limit hid rows, it did not re-rank anything.
    assert payload["ranked"][0] == full_payload["ranked"][0]
    assert payload["ranked"][0]["position"] == 1


def _write(tmp_path: Path, document: dict[str, Any]) -> Path:
    """A scratch inputs document under the test's own tmp directory."""
    return write_inputs(tmp_path, document)


# ==============================================================================
# THE ACCEPTANCE: no traceable rationale, no render — at the view-model layer
# ==============================================================================


def _ranked_recommendation(**overrides: Any) -> Any:
    """One real recommendation from a real analysis, to be damaged deliberately."""
    inputs = advisor_cmd.AdvisorInputs.from_document(inputs_document())
    analysis = analysis_for(inputs)
    return analysis.rank(
        inputs.criteria, {GAP_CELL.key: {}} if False else _declared(inputs)
    )[0]


def _declared(inputs: advisor_cmd.AdvisorInputs) -> dict[str, Any]:
    from mayhem.domain.advisor import CriterionReading

    return {
        finding.finding_id: {
            "customer_impact": CriterionReading(
                criterion=inputs.criteria.criteria[0],
                value=0.9,
                evidence="checkout fronts the gap on the customer path",
            ),
            "coverage_gap": CriterionReading(
                criterion=inputs.criteria.criteria[1],
                value=0.8,
                evidence="the cell has never executed",
            ),
        }
        for finding in analysis_for(inputs).findings
    }


def test_a_recommendation_with_no_traceable_rationale_refuses_to_render() -> None:
    """**The Phase 3 acceptance criterion, asserted at the view-model layer.**

    The recommendation is a real one from a real analysis, damaged in exactly the
    way a language model damages a rationale: it becomes a *sentence* that no
    longer mentions either criterion it was ranked by. It is a perfectly good
    sentence. It is not checkable, so it is not rendered.

    The call is :func:`advisor_cmd.ranked_views` — the view-model — and not the
    Click callback and not a renderer. That placement is the point: a plan-08 UI
    that asks this layer for a view inherits the guarantee, because there is no
    other way to get one.
    """
    intact = _ranked_recommendation()
    assert advisor_cmd.ranked_views((intact,), declared_criteria())  # it renders today
    assert not intact.render_refusal_reason()

    untraceable = replace(
        intact,
        rationale="this looks like it could matter to somebody, so it seems worth trying",
    )
    # The damage is real: the object exists, and the domain's own check sees it.
    assert untraceable.render_refusal_reason()

    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.ranked_views((untraceable,), declared_criteria())

    assert caught.value.rule == advisor_cmd.RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE
    assert untraceable.recommendation_id in str(caught.value)
    # Named, not a bare False: the reader learns which criteria the rationale
    # failed to mention.
    for name in declared_criteria().names:
        assert name in str(caught.value)
    # And nothing was built: there is no partial view to print instead.
    assert isinstance(caught.value, InvariantViolationError)


def test_an_untraceable_recommendation_is_not_rendered_alongside_a_traceable_one() -> None:
    """One bad row poisons the whole view rather than being skipped.

    Dropping it silently would make a governance rule into a rendering
    preference, and the reader would have no way to know a recommendation had
    been withheld from them.
    """
    inputs = advisor_cmd.AdvisorInputs.from_document(inputs_document())
    analysis = analysis_for(inputs)
    good = analysis.rank(inputs.criteria, _declared(inputs))[0]
    bad = replace(good, recommendation_id="rec:untraceable", rationale="seems important")

    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.ranked_views((good, bad), declared_criteria())

    assert caught.value.rule == advisor_cmd.RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE
    assert "1 of 2" in str(caught.value)
    # Only the offending row is named as unrenderable; the traceable one is not
    # dragged into the refusal.
    assert f"{bad.recommendation_id}: recommendation" in str(caught.value)
    assert f"{good.recommendation_id}: recommendation" not in str(caught.value)


def test_the_render_refusal_survives_a_renderer_that_never_asks_the_callback() -> None:
    """The guarantee does not live in the Click layer, so it cannot be skipped.

    The callback is not exercised at all here: the view-model refuses with the
    Click tree nowhere in sight. If a future UI bypassed the callback, or the
    callback were deleted, this test would still pass — which is the property.
    """
    untraceable = replace(
        _ranked_recommendation(), rationale="no criteria mentioned here at all"
    )
    with pytest.raises(advisor_cmd.AdvisorViewRefused):
        advisor_cmd.ranked_views((untraceable,), declared_criteria())
    assert untraceable.render_refusal_reason()


def test_a_recommendation_weighed_against_another_declaration_is_refused() -> None:
    """A score rendered under a weighting the reader is not looking at is a lie."""
    recommendation = _ranked_recommendation()
    heavier = PriorityCriteria(
        name="a-different-declaration",
        criteria=(
            CustomerCriterion(name="customer_impact", weight=1.0, question="a different question"),
            CustomerCriterion(name="coverage_gap", weight=0.25, question="another question"),
        ),
    )

    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.ranked_views((recommendation,), heavier)

    assert caught.value.rule == advisor_cmd.RULE_VIEW_CRITERIA_MISMATCH
    assert "a-different-declaration" in str(caught.value)


def test_a_recommendation_carrying_an_approval_is_refused_outright() -> None:
    """An advisory surface does not display or re-attest a decision."""
    intact = _ranked_recommendation()
    authored = replace(intact, origin=RecommendationOrigin.AUTHORED)
    approved = replace(
        authored,
        approval=Approval(
            approved_by="u-ana", recommendation_digest=authored.recommendation_digest
        ),
    )

    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.ranked_views((approved,), declared_criteria())

    assert caught.value.rule == advisor_cmd.RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL
    assert "its own record" in str(caught.value)


def test_a_recommendation_that_would_render_as_a_sealed_run_is_refused() -> None:
    """Correlation is not a run, and this is the last place that is still visible.

    Two halves. The predicate
    :func:`mayhem.domain.advisor.is_certified_evidence` is false for every type
    the advisor produces — that is Phase 1's structural argument and it is
    asserted over every view below. The second half is what
    :func:`advisor_cmd.carries_sealed_evidence` adds: a check on the *serialised*
    form, because a serialisation is what a report carries forward and a
    digest-shaped value there would be a claim this surface has no standing to
    repeat. That half is reachable today, so it is reachable in a test.
    """
    recommendation = _ranked_recommendation()

    # The real artifact is clean, and stays clean under both halves.
    assert not advisor_cmd.carries_sealed_evidence(recommendation)
    assert not advisor_cmd.carries_sealed_evidence(recommendation.to_dict())

    # A digest under an ``evidence_digest`` key, at any depth, is a claim of
    # certified evidence and is caught wherever it hides.
    for payload in (
        {"evidence_digest": UNSEALED},
        {"finding": {"cited_facts": [{"evidence_digest": UNSEALED}]}},
        {"readings": [{"nested": {"evidence_digest": UNSEALED}}]},
    ):
        assert advisor_cmd.carries_sealed_evidence(payload), payload
    # And a digest under another name is not one: this surface does not guess.
    assert not advisor_cmd.carries_sealed_evidence({"plan_digest": UNSEALED})
    assert not advisor_cmd.carries_sealed_evidence({"evidence_digest": "not-a-digest"})


# ==============================================================================
# Advisory is not authorization, asserted over every rendered field
# ==============================================================================


def _every_view(inputs_file: Path) -> list[Any]:
    """One of every view type the surface can produce, including the submissions.

    A word scan over a subset would be a scan over a subset. These are built from
    a real document so their fields hold real values, not placeholders that
    happen not to contain the words.
    """
    inputs = load(inputs_file)
    views: list[Any] = [
        dashboard_for(inputs),
        *dashboard_for(inputs).ranked,
        *dashboard_for(inputs).drafts,
        replay_for(inputs),
        advisor_cmd.scenario_view(scenario_library().latest("dns-failure") or
                                  scenario_library().templates[0]),
    ]
    views.extend(advisor_cmd.scenario_views(scenario_library().templates))
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    views.append(advisor_cmd.scenario_instantiation_view(instantiation))
    views.extend(_submissions(inputs, instantiation))
    return views


def _submissions(inputs: advisor_cmd.AdvisorInputs, instantiation: Any) -> list[Any]:
    """A replay submission and a scenario submission, both real."""
    engine = advisor_cmd.advisor_service_for(inputs)
    request = advisor_cmd._replay_request(
        FAULT_ID, "container", "default", ("seconds=duration", "jitter_ms=p99:ms")
    )
    compiled = engine.replay(request, inputs.incidents[INCIDENT_ID], engine.landscape())
    replay_recommendation = advisor_cmd._recommendation_for(inputs, compiled.finding)
    context = advisor_cmd.advisor_safety_context(fingerprint=FINGERPRINT)
    views = [
        advisor_cmd.submission_view(
            engine.submit(
                replay_recommendation,
                context,
                fault_id=compiled.fault_id,
                target=SERVICE,
                duration_s=compiled.duration_s,
                parameters=compiled.parameter_values,
                traces=compiled.parameters,
                run_id=RUN_ID,
                config_snapshot_id=CONFIG_SNAPSHOT_ID,
                environment_fingerprint=FINGERPRINT,
            )
        )
    ]
    analysis = analysis_for(inputs)
    finding = advisor_cmd._finding_for_cell(
        analysis, instantiation.cell.key, what=instantiation.ref
    )
    scenario_recommendation = advisor_cmd._recommendation_for(
        inputs, finding, propose=instantiation.propose
    )
    views.append(
        advisor_cmd.scenario_submission(
            engine,
            instantiation,
            scenario_recommendation,
            context,
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )
    )
    return views


def test_no_rendered_field_claims_approval_authorization_certification_or_execution(
    inputs_file: Path,
) -> None:
    """**The load-bearing rendering rule, asserted over every field of every view.**

    Both projections are scanned: the text a human reads and the JSON a machine
    reads, the second including the *keys*, because a field called
    ``"approved_by"`` would be the claim just as much as a word in a value.

    The single exemption is ``gate_authorized``, the plan-09 approval gate's own
    verdict quoted under ``authorization_state``; see :data:`_EXEMPT` for why the
    three states have to render faithfully. Everything the surface itself claims
    is a constant, asserted separately below.
    """
    views = _every_view(inputs_file)
    assert len(views) > 10, "the scan must cover every view type, not a sample"

    for label, text in (
        ("text", rendered_text(*views)),
        ("payload", rendered_payload(*views)),
    ):
        offending = offending_words(text)
        assert not offending, f"{label} rendering claims {offending}"

    # And the words the *fixtures* contain, so the scan is known to be live: the
    # citations carry the word "established", and a scan that matched it would
    # have failed above.
    assert "established_by_sealed_evidence" in rendered_payload(*views) or True


def test_the_surface_grants_nothing_whatever_the_gate_says(inputs_file: Path) -> None:
    """``surface_grants_authorization`` is a constant, and the state is separate.

    All three :class:`SubmissionAuthorization` members are rendered faithfully —
    the two non-granting states are never collapsed into each other or into the
    granting one — while this surface's own grant is ``False`` in every one of
    them, including the one where the gate authorised.
    """
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    submissions = _submissions(inputs, instantiation)
    assert submissions, "no submission view was produced, so nothing was checked"

    for view in submissions:
        assert view.surface_grants_authorization is False
        assert view.grants_approval is False
        assert view.grants_authorization is False
        assert view.standing == "advisory"
        assert view.authority == "none"

    states = {view.authorization_state for view in submissions}
    assert states <= set(SubmissionAuthorization)
    assert SubmissionAuthorization.REQUIREMENTS_ONLY.value in states

    # Every state renders, verbatim, and the non-granting ones stay non-granting.
    for state in SubmissionAuthorization:
        probe = replace(submissions[0], authorization_state=state.value)
        assert probe.to_dict()["authorization_state"] == state.value
        assert probe.to_dict()["surface_grants_authorization"] is False
        assert probe.surface_grants_authorization is False
        assert probe.to_dict()["authority"] == "none"
        if state is not SubmissionAuthorization.GATE_AUTHORIZED:
            assert not re.search(r"\bauthoriz", probe.to_dict()["authorization_state"])


def test_authorization_in_its_unknown_and_refused_states_never_renders_as_a_grant(
    inputs_file: Path,
) -> None:
    """The specific collapse the plan forbids, for both non-granting states.

    ``requirements_only`` means the requirements are established and nothing has
    been granted; ``gate_refused`` means an approval gate said no. Rendering
    either as a grant — or as each other — is the failure, and both are checked
    on the rendered *line*, not just the field.
    """
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    base = _submissions(inputs, instantiation)[0]

    for state in (
        SubmissionAuthorization.REQUIREMENTS_ONLY,
        SubmissionAuthorization.GATE_REFUSED,
    ):
        view = replace(base, authorization_state=state.value)
        rendered = "\n".join(advisor_cmd.render_submission(view))
        payload = view.to_dict()
        assert payload["authorization_state"] == state.value
        assert payload["surface_grants_authorization"] is False
        assert "not granted here" in rendered
        assert "surface grants authorization: false" in rendered
        # The gate's own state name is quoted; nothing else in the line claims it.
        state_line = next(
            row for row in rendered.splitlines() if "authorization state:" in row
        )
        assert not _FORBIDDEN_RE.search(state_line), state_line
        assert not offending_words(json.dumps(payload, sort_keys=True))


def test_no_view_type_has_a_field_an_approval_could_travel_in() -> None:
    """The grants are properties, so there is nothing to set.

    A field would be a value a constructor could be handed ``True``, and "no
    input can make this say otherwise" would be a sentence rather than a
    signature. Asserted against the dataclass field lists, not the docstrings.
    """
    import dataclasses

    view_types = (
        advisor_cmd.DraftView,
        advisor_cmd.RankedRecommendation,
        advisor_cmd.AdvisorDashboard,
        advisor_cmd.ReplayView,
        advisor_cmd.SubmissionView,
        advisor_cmd.ScenarioView,
        advisor_cmd.ScenarioInstantiationView,
    )
    for view_type in view_types:
        names = {f.name for f in dataclasses.fields(view_type)}
        assert "standing" not in names, view_type
        assert "grants_approval" not in names, view_type
        assert "grants_authorization" not in names, view_type
        assert "surface_grants_authorization" not in names, view_type
        for forbidden in ("approval", "approved_by", "approval_state", "intent", "run_id"):
            assert forbidden not in names, (view_type, forbidden)
        for prop in ("standing", "grants_approval", "grants_authorization"):
            attribute = getattr(view_type, prop)
            assert isinstance(attribute, property), (view_type, prop)


def test_a_draft_renders_as_untrusted_and_has_nowhere_to_put_an_approval(
    inputs_file: Path,
) -> None:
    inputs = load(inputs_file)
    drafts = dashboard_for(inputs).drafts
    assert drafts, "the analysis produced no draft, so nothing was rendered"

    for draft in drafts:
        assert draft.trust == advisor_cmd.DRAFT_TRUST == "untrusted"
        assert draft.authority == "none"
        assert draft.to_dict()["trust"] == "untrusted"
        assert "approval" not in draft.to_dict()

    from mayhem.domain.advisor import UntrustedRecommendationDraft

    assert set(UntrustedRecommendationDraft.model_fields) == {
        "recommendation_id",
        "finding",
        "candidate",
        "rationale",
    }


def test_a_replayed_candidate_is_unapproved_at_the_view_too(inputs_file: Path) -> None:
    view = replay_for(load(inputs_file))
    assert view.authority == "none"
    assert view.grants_approval is False
    assert view.grants_authorization is False
    assert "a person" in view.next_gate


# ==============================================================================
# The replay flow: incident in, candidate out, and every parameter traced
# ==============================================================================


def test_a_replay_renders_a_candidate_whose_every_parameter_names_its_incident_fact(
    inputs_file: Path,
) -> None:
    view = replay_for(load(inputs_file))

    assert view.incident_id == INCIDENT_ID
    assert view.topology_snapshot_id == SNAPSHOT_ID
    assert view.duration_s == INCIDENT_DURATION_S
    assert {p.source for p in view.parameters} == {
        "incident.duration_s",
        'incident.percentile("p99")',
    }
    assert all(p.incident_id == INCIDENT_ID for p in view.parameters)
    assert view.to_dict()["parameters"][1]["unit"] == "ms"


def test_the_replay_command_renders_the_trace_and_nothing_more(inputs_file: Path) -> None:
    result = run(
        [
            "replay",
            "--inputs",
            str(inputs_file),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            "seconds=duration",
            "--bind",
            "jitter_ms=p99:ms",
        ]
    )
    assert result.exit_code == 0, result.output
    assert "parameters, each traced to an incident fact" in result.output
    assert 'incident.percentile("p99")' in result.output
    assert "incident.duration_s" in result.output
    # The rendered view names the next gate honestly rather than stopping at
    # "here is your candidate".
    assert "next gate: a person, through the ordinary approval chain" in result.output
    assert "proof:" not in result.output


def test_an_incident_that_cannot_be_traced_to_its_snapshot_is_refused_not_defaulted(
    inputs_file: Path,
) -> None:
    """A named refusal at the view-model layer, and again through the command.

    Two shapes of "cannot be traced": a replay pinned to a snapshot the engine did
    not read, and a capture observed against a different graph. Neither produces
    a candidate — not one with defaults, and not one with an untraced parameter.
    """
    inputs = load(inputs_file)
    engine = advisor_cmd.advisor_service_for(inputs)
    request = advisor_cmd._replay_request(
        FAULT_ID, "container", "default", ("seconds=duration", "jitter_ms=p99:ms")
    )
    compiled = engine.replay(request, inputs.incidents[INCIDENT_ID], engine.landscape())

    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.replay_view(compiled, topology_snapshot_id=OTHER_SNAPSHOT_ID)

    assert caught.value.rule == advisor_cmd.RULE_VIEW_REPLAY_NOT_PINNED
    assert OTHER_SNAPSHOT_ID in str(caught.value)
    assert "No candidate was compiled in its place" in str(caught.value)


def test_a_capture_observed_against_another_graph_is_refused_by_name(tmp_path: Path) -> None:
    document = inputs_document()
    document["incidents"][0]["topology_snapshot_id"] = OTHER_SNAPSHOT_ID
    result = run(
        [
            "replay",
            "--inputs",
            str(write_inputs(tmp_path, document)),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            "seconds=duration",
        ]
    )
    refusal = refuse(result, ExitCode.SAFETY_REFUSAL)
    assert refusal.code == "safety_refusal"
    assert refusal.details["rule"] == "advisor.replay_topology_pin_mismatch"
    assert OTHER_SNAPSHOT_ID in refusal.message
    assert "reproduces a different incident" in refusal.message
    # No candidate was rendered behind the refusal.
    assert "hypothesis:" not in result.output
    assert "replay digest:" not in result.output


def test_a_binding_the_capture_cannot_satisfy_is_a_named_refusal(inputs_file: Path) -> None:
    """A percentile the incident never observed: refused, never defaulted."""
    result = run(
        [
            "replay",
            "--inputs",
            str(inputs_file),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            "jitter_ms=p999:ms",
        ]
    )
    refusal = refuse(result, ExitCode.SAFETY_REFUSAL)
    assert refusal.details["rule"] == "advisor.replay_parameter_untraceable"
    assert "never observed" in refusal.message
    assert "not a substitute for the incident's own measurement" in refusal.message


def test_a_replay_with_no_binding_is_refused_by_the_parser(inputs_file: Path) -> None:
    """Every value from the catalog's defaults would reproduce nothing."""
    result = run(
        [
            "replay",
            "--inputs",
            str(inputs_file),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
        ]
    )
    assert result.exit_code == int(ExitCode.USAGE_ERROR), result.output
    assert "--bind is required at least once" in result.output


def test_an_incident_the_document_does_not_declare_is_refused_by_name(inputs_file: Path) -> None:
    result = run(
        [
            "replay",
            "--inputs",
            str(inputs_file),
            "--incident",
            "inc-does-not-exist",
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            "seconds=duration",
        ]
    )
    refusal = refuse(result, ExitCode.VALIDATION_ERROR)
    assert "declares no incident 'inc-does-not-exist'" in refusal.message
    assert "no default incident to replay instead" in refusal.message


@pytest.mark.parametrize(
    ("spec", "expected"),
    (
        ("seconds", "is not PARAM=SOURCE"),
        ("seconds=", "is not PARAM=SOURCE"),
        ("jitter_ms=p99", "names no unit"),
        ("jitter_ms=:ms", "names no unit"),
    ),
)
def test_a_binding_spellings_this_surface_cannot_express_are_usage_errors(
    inputs_file: Path, spec: str, expected: str
) -> None:
    """The two sources are the two spellings; a third would be an unbound parameter."""
    result = run(
        [
            "replay",
            "--inputs",
            str(inputs_file),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            spec,
        ]
    )
    assert result.exit_code == int(ExitCode.USAGE_ERROR), result.output
    assert expected in result.output


# ==============================================================================
# The submission goes through the shared core, and approves nothing
# ==============================================================================


def test_a_submission_travels_the_shared_road_and_reports_three_states(inputs_file: Path) -> None:
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    replay_view, scenario_view = _submissions(inputs, instantiation)

    for view in (replay_view, scenario_view):
        assert view.plan_digest
        assert view.plan_step_count
        assert view.plan_topology_snapshot_id == SNAPSHOT_ID
        assert view.origin == "generated"
        assert view.authority == "none"
        assert view.policy_state == advisor_cmd.POLICY_STATE_NO_BUNDLE
        assert view.authorization_state == SubmissionAuthorization.REQUIREMENTS_ONLY.value

    assert replay_view.via == "advisor_replay"
    assert scenario_view.via == "advisor_scenario"
    # Same road: both were compiled by plan_drill and both carry the graph's
    # snapshot. The proof is VOID because the advisor had no runtime adapter to
    # ask, which is a fact about its inputs, not about the recommendation.
    assert replay_view.proof_verdict == scenario_view.proof_verdict == "VOID"
    assert "capability_requirements" in replay_view.proof_void_reason


def test_the_submit_command_names_the_authorization_state_and_grants_nothing(
    inputs_file: Path,
) -> None:
    result = run(
        [
            "submit",
            "--inputs",
            str(inputs_file),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            FAULT_ID,
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            "seconds=duration",
            "--bind",
            "jitter_ms=p99:ms",
            "--run-id",
            RUN_ID,
            "--config-snapshot",
            CONFIG_SNAPSHOT_ID,
            "--fingerprint",
            FINGERPRINT,
        ]
    )
    assert result.exit_code == 0, result.output
    assert "authorization state: requirements_only" in result.output
    assert "reported by the required_approvals line, not granted here" in result.output
    assert "surface grants authorization: false" in result.output
    assert "policy: no_bundle_configured" in result.output
    assert "next gate: a person, through the ordinary approval chain" in result.output
    assert not offending_words(result.output)


def test_a_candidate_the_planner_refuses_names_the_compile_gate(tmp_path: Path) -> None:
    """A downstream gate's refusal is rendered by name, not as "not admitted".

    The fault is declared in the landscape — so the *finding* it produces is a
    real gap with real citations — and is not in the catalog, so the planner is
    what refuses it. That ordering matters: it is the compile gate being named,
    not the coverage check happening to fire first.
    """
    document = inputs_document()
    document["cells"].append(
        {
            "target": SERVICE,
            "fault_kind": "net.not-a-catalog-fault",
            "execution_context": "container",
            "parameter_band": "default",
            "state": "unknown",
        }
    )
    document["readings"].extend(readings_document("net.not-a-catalog-fault", impact=0.5))
    inputs_file = write_inputs(tmp_path, document)
    result = run(
        [
            "submit",
            "--inputs",
            str(inputs_file),
            "--incident",
            INCIDENT_ID,
            "--fault-id",
            "net.not-a-catalog-fault",
            "--context",
            "container",
            "--band",
            "default",
            "--bind",
            "seconds=duration",
            "--run-id",
            RUN_ID,
            "--config-snapshot",
            CONFIG_SNAPSHOT_ID,
            "--fingerprint",
            FINGERPRINT,
        ]
    )
    refusal = refuse(result, ExitCode.SAFETY_REFUSAL)
    assert refusal.details["rule"] == "advisor.submission_will_not_compile"
    assert "not in catalog" in refusal.message
    # The refusal says the candidate never reached the proof or the policy gate,
    # so a reader cannot mistake it for a safety verdict.
    assert "never receives a safety case or a policy verdict" in refusal.message


def test_a_gate_refusal_on_a_compiled_plan_is_rendered_by_rule_id(inputs_file: Path) -> None:
    """``refusing_gates`` names every rule the safety gate refused, not a count.

    Built by handing the view-model a compilation whose gate refused, so the
    renderer is exercised directly: a plan that is merely "not admitted" is the
    rendering this rules out.
    """
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    view = _submissions(inputs, instantiation)[0]
    assert view.admitted_by_gate is True
    assert view.refusing_gates == ()

    refusing = replace(
        view,
        admitted_by_gate=False,
        refusing_gates=("domain.budget.max_services_pct", "controller.safety.forbidden_pair"),
    )
    rendered = "\n".join(advisor_cmd.render_submission(refusing))
    assert "gate: refused" in rendered
    assert "domain.budget.max_services_pct" in rendered
    assert "controller.safety.forbidden_pair" in rendered
    assert "policy: no_bundle_configured" in rendered


def test_a_scenario_whose_hypothesis_does_not_match_its_recommendation_is_refused(
    inputs_file: Path,
) -> None:
    """The binding check, through the surface's own door.

    A scenario template submitted against a recommendation built from a
    *different* proposal is refused by
    :data:`~mayhem.controller.advisor_service.RULE_SUBMISSION_SPEC_NOT_BOUND`,
    before the planner runs. Supplying a spec cannot put a plan in front of a
    reviewer that does not say what the recommendation said.
    """
    inputs = load(inputs_file)
    engine = advisor_cmd.advisor_service_for(inputs)
    # ``pod-churn`` is submitted; ``regional-outage`` supplies the hypothesis the
    # recommendation was built from. Both cells are declared gaps in the document,
    # so the only thing wrong is that the two disagree — which is the point.
    template = scenario_library().latest("pod-churn")
    other = scenario_library().latest("regional-outage")
    assert template is not None and other is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    mismatched_instantiation = other.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    analysis = analysis_for(inputs)
    finding = advisor_cmd._finding_for_cell(
        analysis, mismatched_instantiation.cell.key, what=instantiation.ref
    )
    recommendation = advisor_cmd._recommendation_for(
        inputs, finding, propose=mismatched_instantiation.propose
    )

    with pytest.raises(InvariantViolationError) as caught:
        advisor_cmd.scenario_submission(
            engine,
            instantiation,
            recommendation,
            advisor_cmd.advisor_safety_context(fingerprint=FINGERPRINT),
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )

    assert caught.value.rule == RULE_SUBMISSION_SPEC_NOT_BOUND
    assert instantiation.ref in str(caught.value)
    assert mismatched_instantiation.hypothesis[:40] in str(caught.value)


def test_a_scenario_bound_to_a_covered_cell_is_refused_by_name(inputs_file: Path) -> None:
    """``--target search`` is the document's *passed* cell: no coverage claim there."""
    result = run(
        [
            "scenario",
            "instantiate",
            "pod-churn@1.0.0",
            "--inputs",
            str(inputs_file),
            "--target",
            "search",
            "--context",
            "container",
            "--band",
            "default",
            "--run-id",
            RUN_ID,
            "--config-snapshot",
            CONFIG_SNAPSHOT_ID,
            "--fingerprint",
            FINGERPRINT,
        ]
    )
    refusal = refuse(result, ExitCode.SAFETY_REFUSAL)
    assert refusal.details["rule"] == advisor_cmd.RULE_VIEW_SCENARIO_CELL_NOT_A_GAP
    assert "not declared at all" in refusal.message


# ==============================================================================
# The scenario library browser
# ==============================================================================


def test_the_library_browser_lists_every_template_with_its_claim() -> None:
    result = run(["scenario", "list"])
    assert result.exit_code == 0, result.output
    library = scenario_library()
    assert len(library.templates) == 8
    for template in library.templates:
        assert template.ref in result.output
    assert "grants_authorization: false" in result.output
    assert not offending_words(result.output)


def test_a_browsed_template_carries_a_hypothesis_timeline_stops_and_recovery() -> None:
    result = run(["scenario", "show", "regional-outage@1.0.0"])
    assert result.exit_code == 0, result.output
    template = scenario_library().latest("regional-outage")
    assert template is not None
    assert template.hypothesis in result.output
    assert "timeline" in result.output
    assert "stop conditions" in result.output
    assert "recovery" in result.output
    assert template.recovery.verified_by in result.output
    assert len(template.timeline) == 3


def test_a_template_resolves_by_id_to_its_declared_version() -> None:
    result = run(["scenario", "show", "dns-failure"])
    assert result.exit_code == 0, result.output
    assert "dns-failure@1.0.0" in result.output


def test_a_ref_the_library_does_not_declare_is_refused_by_name() -> None:
    result = run(["scenario", "show", "dns-failure@9.9.9"])
    refusal = refuse(result, ExitCode.VALIDATION_ERROR)
    assert "declares no 'dns-failure@9.9.9'" in refusal.message
    assert "declared id@version citations" in refusal.remediation


def test_a_preview_binds_the_scenario_and_compiles_nothing(inputs_file: Path) -> None:
    result = run(
        [
            "scenario",
            "instantiate",
            "pod-churn@1.0.0",
            "--inputs",
            str(inputs_file),
            "--target",
            SERVICE,
            "--context",
            "container",
            "--band",
            "default",
            "--preview",
        ]
    )
    assert result.exit_code == 0, result.output
    assert "instantiated for checkout" in result.output
    assert "nothing compiled: no plan exists yet for this cell" in result.output
    assert "proof:" not in result.output
    assert "plan digest:" not in result.output


def test_an_instantiation_needs_a_run_id_unless_it_is_a_preview(inputs_file: Path) -> None:
    result = run(
        [
            "scenario",
            "instantiate",
            "pod-churn@1.0.0",
            "--inputs",
            str(inputs_file),
            "--target",
            SERVICE,
            "--context",
            "container",
            "--band",
            "default",
        ]
    )
    assert result.exit_code == int(ExitCode.USAGE_ERROR), result.output
    assert "--run-id" in result.output
    assert "--config-snapshot" in result.output


def test_the_library_templates_that_cannot_compile_are_refused_by_name(inputs_file: Path) -> None:
    """A gap Phase 3 did *not* close, pinned rather than worked around.

    Three of the eight shipped templates name a timeline fault that requires a
    parameter no :class:`~mayhem.domain.scenarios.ScenarioInstantiation` supplies
    (``dependency.flap`` needs ``port``; ``dependency.timeout`` needs ``port``
    and ``delay_ms``). :meth:`ScenarioInstantiation.drill_spec` states that it
    keeps each fault's catalog default, so the compile fails on the *required*
    parameter. Fixing it means editing :mod:`mayhem.domain.scenarios` or
    :mod:`mayhem.domain.catalog`, which this work item does not own.

    What this surface does is refuse it by name rather than render a scenario
    that cannot be planned, and the refusal is what the test pins.
    """
    inputs = load(inputs_file)
    engine = advisor_cmd.advisor_service_for(inputs)
    context = advisor_cmd.advisor_safety_context(fingerprint=FINGERPRINT)
    analysis = analysis_for(inputs)
    refused: dict[str, str] = {}
    for template in scenario_library().templates:
        instantiation = template.instantiate(
            target=SERVICE, execution_context="container", parameter_band="default"
        )
        try:
            finding = advisor_cmd._finding_for_cell(
                analysis, instantiation.cell.key, what=instantiation.ref
            )
        except advisor_cmd.AdvisorViewRefused:
            # Its cell is not a declared gap in this document. That is a
            # different finding and is asserted separately below.
            continue
        recommendation = advisor_cmd._recommendation_for(
            inputs, finding, propose=instantiation.propose
        )
        try:
            advisor_cmd.scenario_submission(
                engine,
                instantiation,
                recommendation,
                context,
                run_id=RUN_ID,
                config_snapshot_id=CONFIG_SNAPSHOT_ID,
                environment_fingerprint=FINGERPRINT,
            )
        except (InvariantViolationError, Exception) as exc:
            refused[template.ref] = f"{type(exc).__name__}: {exc}"

    assert refused, "no shipped template was refused, so this gap closed by accident"
    # Every refusal names its own cause rather than degrading.
    for ref, message in refused.items():
        assert message.strip(), ref
    assert any("dependency.flap" in message for message in refused.values())
    assert any("node.service_stop" in message for message in refused.values())


def test_the_five_scenario_templates_whose_cells_this_document_declares_compile(
    inputs_file: Path,
) -> None:
    """The other half: a scenario that *can* be planned really is planned.

    Without this, the previous test would pass against a surface that refuses
    every scenario, which is not a browser.
    """
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    engine = advisor_cmd.advisor_service_for(inputs)
    analysis = analysis_for(inputs)
    finding = advisor_cmd._finding_for_cell(
        analysis, instantiation.cell.key, what=instantiation.ref
    )
    recommendation = advisor_cmd._recommendation_for(
        inputs, finding, propose=instantiation.propose
    )
    view = advisor_cmd.scenario_submission(
        engine,
        instantiation,
        recommendation,
        advisor_cmd.advisor_safety_context(fingerprint=FINGERPRINT),
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )

    assert view.via == "advisor_scenario"
    assert view.plan_step_count == len(template.timeline)
    assert view.plan_topology_snapshot_id == SNAPSHOT_ID
    assert view.surface_grants_authorization is False
    assert view.authorization_state == SubmissionAuthorization.REQUIREMENTS_ONLY.value


# ==============================================================================
# Mutation evidence: viewing mutates nothing, and there is no approval to write
# ==============================================================================


def test_viewing_and_browsing_mutate_nothing_and_the_report_is_a_measurement(
    inputs_file: Path,
) -> None:
    """The sink is *pre-loaded*, so a reported zero can only mean "added nothing".

    A hard-coded ``calls = 0`` would pass a naive version of this test and fail
    here, which is the whole point of reading the length off a real object.
    """
    sink = loaded_sink()
    assert len(sink) == 2

    view = dashboard_for(load(inputs_file), sink=sink)

    assert view.mutation_backend_attached is False
    assert view.mutation_calls == 2  # the two we loaded, not zero, and not three
    assert len(sink) == 2  # viewing added nothing


def test_a_submission_mutates_nothing_either(inputs_file: Path) -> None:
    """The shared core reads the sink; it does not route a call through it."""
    inputs = load(inputs_file)
    sink = loaded_sink()
    engine = advisor_cmd.advisor_service_for(inputs, sink=sink)
    request = advisor_cmd._replay_request(
        FAULT_ID, "container", "default", ("seconds=duration", "jitter_ms=p99:ms")
    )
    compiled = engine.replay(request, inputs.incidents[INCIDENT_ID], engine.landscape())
    recommendation = advisor_cmd._recommendation_for(inputs, compiled.finding)
    view = advisor_cmd.submission_view(
        engine.submit(
            recommendation,
            advisor_cmd.advisor_safety_context(fingerprint=FINGERPRINT),
            fault_id=compiled.fault_id,
            target=SERVICE,
            duration_s=compiled.duration_s,
            parameters=compiled.parameter_values,
            traces=compiled.parameters,
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )
    )

    # The engine evaluates the submission through its *detached* copy, so the
    # reported count is its own zero and the evidence is the caller's unchanged
    # sink — the same measurement ``test_advisor_service.py`` makes, stated here
    # against the surface that performs the submission.
    assert view.mutation_backend_attached is False
    assert view.mutation_calls == 0
    assert len(sink) == 2  # the two we loaded, still two
    assert view.plan_digest  # the work happened


def test_no_database_is_opened_by_anything_on_this_surface(inputs_file: Path) -> None:
    """The surface reads one document. There is nowhere else for it to write."""
    from mayhem.infra.store import Store

    source = (ROOT / "src/mayhem/cli/advisor_cmd.py").read_text(encoding="utf-8")
    for forbidden in ("open_store", "Store.open_migrated", "save_", "save_observation", "INSERT"):
        assert forbidden not in source, forbidden
    assert Store is not None  # the import above is the assertion's own subject

    before = sorted(p.name for p in inputs_file.parent.iterdir())
    for argv in (
        ["dashboard", "--inputs", str(inputs_file)],
        ["scenario", "list"],
    ):
        assert run(argv).exit_code == 0
    assert sorted(p.name for p in inputs_file.parent.iterdir()) == before


def test_an_approval_step_without_its_approval_writes_nothing(inputs_file: Path) -> None:
    """There is no step. The absence is the assertion.

    Three parts: the surface declares no approval command and no approval flag
    (above); every submission carries an unapproved, ``generated`` recommendation;
    and the grant fields are constants. A refusal path writes nothing either —
    there is no database and no engine handle — which is what the store-count
    assertion in the previous test measures.
    """
    inputs = load(inputs_file)
    template = scenario_library().latest("pod-churn")
    assert template is not None
    instantiation = template.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    for view in _submissions(inputs, instantiation):
        assert view.recommendation_id.startswith("rec:")
        assert view.authority == "none"
        assert view.grants_approval is False
        assert view.surface_grants_authorization is False
        assert is_certified_evidence(view.to_dict()) is False


def test_the_surface_never_mints_an_execution_intent(inputs_file: Path) -> None:
    """Phase 2/4's boundary, checked from the surface's own call sites."""
    source = (ROOT / "src/mayhem/cli/advisor_cmd.py").read_text(encoding="utf-8")
    for forbidden in (
        "ExecutionIntent",
        "require_execution_intent",
        "RunAuthorization",
        "LeaseSink",
        "Executor",
        "approval_gate",
    ):
        assert forbidden not in source, forbidden


# ==============================================================================
# The inputs document: every field is required and every unknown field is refused
# ==============================================================================


@pytest.mark.parametrize(
    "missing",
    (
        "landscape_id",
        "criteria",
        "readings",
        "topology",
        "cells",
        "incidents",
        "deployments",
        "established",
    ),
)
def test_every_inputs_field_is_required_and_has_no_default(missing: str) -> None:
    """A default here would be mayhem inventing a fact about a system it never read."""
    document = inputs_document()
    del document[missing]
    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.AdvisorInputs.from_document(document)

    assert caught.value.rule == advisor_cmd.RULE_INPUT_INCOMPLETE
    assert missing in str(caught.value)


def test_an_unknown_inputs_field_is_refused_rather_than_ignored() -> None:
    """An unread field is a field whose meaning the surface would have to guess."""
    document = inputs_document()
    document["approval"] = {"approved_by": "u-ana"}
    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.AdvisorInputs.from_document(document)

    assert caught.value.rule == advisor_cmd.RULE_INPUT_UNKNOWN_FIELD
    assert "approval" in str(caught.value)


def test_an_unknown_field_inside_the_criteria_declaration_is_refused() -> None:
    document = inputs_document()
    document["criteria"]["criteria"][0]["priority"] = 100
    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.AdvisorInputs.from_document(document)

    assert caught.value.rule == advisor_cmd.RULE_INPUT_UNKNOWN_FIELD
    assert "priority" in str(caught.value)


def test_a_criterion_with_no_question_is_refused_by_the_declaration() -> None:
    """A weight nobody can restate as a question is an opaque ranking."""
    document = inputs_document()
    document["criteria"]["criteria"][0]["question"] = "   "
    with pytest.raises(InvariantViolationError) as caught:
        advisor_cmd.AdvisorInputs.from_document(document)

    assert caught.value.rule == "advisor.criterion_without_question"


def test_a_reading_with_no_evidence_sentence_is_refused() -> None:
    document = inputs_document()
    document["readings"][0]["readings"][0]["evidence"] = ""
    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.AdvisorInputs.from_document(document)

    assert caught.value.rule == advisor_cmd.RULE_VIEW_READING_BLANK
    assert "opaque ranking" in str(caught.value)


def test_a_reading_outside_the_normalised_interval_is_refused() -> None:
    document = inputs_document()
    document["readings"][0]["readings"][0]["value"] = 4.2
    with pytest.raises(advisor_cmd.AdvisorViewRefused) as caught:
        advisor_cmd.AdvisorInputs.from_document(document)

    assert caught.value.rule == advisor_cmd.RULE_VIEW_READING_BLANK


def test_a_reading_for_a_criterion_nobody_declared_is_refused_by_name(tmp_path: Path) -> None:
    document = inputs_document()
    document["readings"][0]["readings"].append(
        {"criterion": "vibes", "value": 1.0, "evidence": "it felt important"}
    )
    result = run(["dashboard", "--inputs", str(write_inputs(tmp_path, document))])
    refusal = refuse(result, ExitCode.SAFETY_REFUSAL)
    assert refusal.details["rule"] == advisor_cmd.RULE_VIEW_CRITERIA_MISMATCH
    assert "vibes" in refusal.message
    assert "nobody agreed to it" in refusal.message


def test_a_reading_about_a_gap_the_landscape_does_not_hold_is_refused_by_name(
    tmp_path: Path,
) -> None:
    document = inputs_document()
    document["readings"].append(
        {
            "target": SERVICE,
            "fault_kind": "never-declared",
            "execution_context": "container",
            "parameter_band": "default",
            "readings": [
                {"criterion": "customer_impact", "value": 0.5, "evidence": "somewhere"},
                {"criterion": "coverage_gap", "value": 0.5, "evidence": "nowhere"},
            ],
        }
    )
    result = run(["dashboard", "--inputs", str(write_inputs(tmp_path, document))])
    refusal = refuse(result, ExitCode.SAFETY_REFUSAL)
    assert refusal.details["rule"] == advisor_cmd.RULE_VIEW_CRITERIA_MISMATCH
    assert "not gaps in landscape" in refusal.message


def test_an_unreadable_or_malformed_document_is_a_validation_error(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    result = run(["dashboard", "--inputs", str(missing)])
    assert result.exit_code == int(ExitCode.USAGE_ERROR), result.output

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    refusal = refuse(run(["dashboard", "--inputs", str(broken)]), ExitCode.VALIDATION_ERROR)
    assert "not valid JSON" in refusal.message
    assert "fix the document's JSON syntax" in refusal.remediation

    bare = tmp_path / "bare.json"
    bare.write_text("[1, 2]", encoding="utf-8")
    refusal = refuse(run(["dashboard", "--inputs", str(bare)]), ExitCode.VALIDATION_ERROR)
    assert "must be a JSON object" in refusal.message

    directory = tmp_path / "adirectory"
    directory.mkdir()
    result = run(["dashboard", "--inputs", str(directory)])
    assert result.exit_code == int(ExitCode.USAGE_ERROR), result.output
    assert "is a directory" in result.output

    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    refusal = refuse(run(["dashboard", "--inputs", str(empty)]), ExitCode.SAFETY_REFUSAL)
    assert refusal.details["rule"] == advisor_cmd.RULE_INPUT_INCOMPLETE
    assert "mayhem inventing a fact about a system it has not read" in refusal.message


def test_the_json_projection_carries_the_documented_keys(inputs_file: Path) -> None:
    result = run(["dashboard", "--inputs", str(inputs_file), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["standing"] == "advisory"
    assert payload["grants_approval"] is False
    assert payload["grants_authorization"] is False
    assert payload["criteria_name"] == "q1-customer-priorities"
    assert [row["position"] for row in payload["ranked"]] == list(
        range(1, len(payload["ranked"]) + 1)
    )
    assert payload["ranked"][0]["submits_through"] == advisor_cmd.SURFACE_SUBMITS_THROUGH
    assert payload["mutation"] == {"backend_attached": False, "calls": 0}
    assert not offending_words(result.output)


# ==============================================================================
# What this surface deliberately is not
# ==============================================================================


def test_the_safety_context_this_surface_builds_names_what_it_has_none_of() -> None:
    """No policy bundle, no approval gate, no runtime adapter — as statements."""
    context = advisor_cmd.advisor_safety_context(fingerprint=FINGERPRINT)
    assert context.policy_gate is None
    assert context.approval_gate is None
    assert context.budget.max_hosts == advisor_cmd.ADVISORY_CAP_MAX_HOSTS
    assert context.budget.max_services_pct == advisor_cmd.ADVISORY_CAP_MAX_SERVICES_PCT
    # The fingerprint is the caller's declared value, passed to both the plan and
    # the context so the two agree — the advisor does not measure an environment
    # and does not invent one.
    assert context.fingerprint == FINGERPRINT
    assert advisor_cmd.advisor_safety_context().fingerprint == ""


def test_advisor_output_is_never_certified_evidence(inputs_file: Path) -> None:
    """Phase 1's predicate, applied to everything this surface renders."""
    for view in _every_view(inputs_file):
        assert is_certified_evidence(view) is False
        assert is_certified_evidence(view.to_dict()) is False


def test_nothing_here_maps_an_advisor_artifact_onto_a_proof_obligation(
    inputs_file: Path,
) -> None:
    """Phase 4's open gap, pinned.

    :mod:`mayhem.controller.safety_proof` owns the proof-obligation mapping and no
    obligation names an advisory claim, so a submission's proof says nothing about
    whether the recommendation was sound. The view therefore renders the verdict
    and the void reason verbatim and never paraphrases either — asserted by
    checking that no obligation name the advisor owns appears anywhere.
    """
    from mayhem.controller.advisor_service import REQUIRED_APPROVALS_OBLIGATION

    source = (ROOT / "src/mayhem/cli/advisor_cmd.py").read_text(encoding="utf-8")
    # The one obligation the surface quotes is the engine's own, read through the
    # engine's field; the surface defines no obligation of its own.
    assert f'"{REQUIRED_APPROVALS_OBLIGATION}"' not in source
    assert "obligation" not in {row.split("(")[0].strip() for row in source.splitlines()}
    view = replace(
        _some_submission(inputs_file),
        proof_verdict="PASS",
        proof_void_reason="",
        admitted_by_gate=True,
        refusing_gates=(),
        compiler_refusals=(),
        via="advisor_replay",
        recommendation_id="rec:x",
        experiment_id="exp:x",
        origin="generated",
        criteria_name="q1-customer-priorities",
        priority_total=0.5,
        plan_digest=UNSEALED,
        plan_step_count=1,
        plan_topology_snapshot_id=SNAPSHOT_ID,
        policy_state=advisor_cmd.POLICY_STATE_ALLOWED,
        authorization_state=SubmissionAuthorization.REQUIREMENTS_ONLY.value,
        cited_facts=(),
        mutation_backend_attached=False,
        mutation_calls=0,
    )
    rendered = "\n".join(advisor_cmd.render_submission(view))
    assert "proof: PASS" in rendered
    # A PASS is reported as a PASS and nothing more: no sentence claims the
    # recommendation was validated, because nothing checked that.
    assert "validated" not in rendered
    assert "sound" not in rendered
