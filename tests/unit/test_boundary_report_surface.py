"""Plan 15 Phase 3 — the ``mayhem boundary`` surface, and the view-model it renders.

Phases 1-2 put the arithmetic and the engine in place, Phase 4 sealed every report
the engine produces and refused a draft that carries its own authority. None of
that is reachable by a person, and this suite is about the last link plus the one
property that is easiest to fake.

The group is invoked **directly** through :class:`~click.testing.CliRunner` as
:data:`risk_preview_cmd.risk_preview` and
:data:`advisor_cmd.advisor` are — not through ``cli.app`` — because this phase's
integration pass owns registration and a suite that resolved through the registry
would be asserting a fact a peer has not landed yet.

What the suite is arranged around:

* **"Indistinguishable downstream of compilation" is asserted structurally.**
  :func:`mayhem.cli.boundary_report_cmd._gate` has no origin parameter, and the
  suite proves the property three ways that a string comparison could not: by
  **instrumenting the three gate functions** and asserting both arms called them
  in the identical order, by asserting the two arms compile to the *same
  ``ExecutionPlan`` type*, and — the strongest form — by asserting the two
  compiled plans are **byte-identical** when the candidate proposes the rung the
  authored drill already encodes. A mutant that gave the generated arm a shortcut,
  stamped the origin onto the plan, or skipped a gate changes one of those three.
* **The negative controls**, each asserting a *named* refusal: a boundary whose
  comparison at its edge was under-sampled, a report whose sections have no
  support, a draft carrying an approval token, a candidate the duration gate
  refuses, an unknown signal, and a blank or unknown ladder value.
* **An untrusted draft never renders as authorized.** The assertion is over the
  whole rendered candidate block and the whole JSON projection: the substrings
  ``approv`` and ``authoriz`` appear in neither, the candidate's ``authority``
  reads ``none``, and no key named after either appears anywhere in the payload.
  The vocabulary choice in the module docstring is what makes that testable.
* **Mutation evidence.** The review surface is asserted to write nothing, measured
  against the safety context it was handed (which the proof compiler runs against
  clones) *and* against the filesystem — neither command opens a store, so a
  database file that does not exist afterwards is the proof.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
import pytest
from click.testing import CliRunner

from mayhem.cli import boundary_report_cmd
from mayhem.cli.boundary_report_cmd import (
    GATE_PATH,
    RULE_REPORT_SIGNAL_UNKNOWN,
    RULE_REPORT_UNKNOWN_FIELD,
    RULE_REPORT_VALUE_UNKNOWN,
    SURFACE_VIA,
    BoundaryViewRefused,
    boundary,
    boundary_report_view,
    boundary_review_safety_context,
    candidate_review_view,
    render_boundary_report,
    render_candidate_review,
)
from mayhem.cli.errors import MayhemCliError
from mayhem.controller.analytics_service import (
    AUTHORITY_FIELDS,
    RULE_DRAFT_CARRIES_AUTHORITY,
    RULE_DRAFT_VALUE_OUT_OF_LADDER,
    RULE_EVIDENCE_UNSUPPORTED,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from mayhem.domain.experiments import DrillSpec
    from mayhem.domain.search import SearchPolicy

CONTAINER = "testcase-api"
FAULT_ID = "net.latency"
AUTHORED_DURATION_S = 10.0
"""The authored drill's per-fault duration, in seconds.

Also the value the well-behaved candidate proposes, which is what makes the two
compiled plans byte-identical rather than merely the same shape.
"""

COMBINATION = f"{FAULT_ID}/{CONTAINER}"
RULE_DENY_FAULTS = "policy.deny_faults"


# =============================================================================
# Fixtures — fixed graphs, fixed series, fixed documents. Never generated.
# =============================================================================


def _graph() -> TopologyGraph:
    """One container, its service, and its process, wired the way a drill needs.

    Four unrelated services sit alongside them so the fault's dependents closure is
    three nodes of nine — under the surface's 50% ``max_services_pct`` ceiling. A
    three-node graph would put the closure at 100% and every review here would be
    refused by the blast gate before it could say anything about a candidate.
    """
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                container_name=CONTAINER,
                state="running",
            ),
            ServiceNode(id="svc-api", name="api-svc", container_name=CONTAINER),
            ProcessNode(
                id="proc-api",
                name="api-proc",
                pid=4242,
                host_id="h1",
                container_name=CONTAINER,
            ),
            *(ServiceNode(id=f"n-{name}", name=name) for name in "defg"),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
        ),
    )


def _drill_body(duration_s: float = AUTHORED_DURATION_S) -> dict[str, Any]:
    return {
        "kind": "drill",
        "name": "checkout-drill",
        "containers": {
            CONTAINER: {"faults": [{"fault": FAULT_ID, "duration": f"{duration_s:g}s"}]}
        },
        "execution": [{"sequential": [CONTAINER]}],
    }


def _spec(duration_s: float = AUTHORED_DURATION_S) -> DrillSpec:
    from mayhem.spec import parse_drill

    return parse_drill(_drill_body(duration_s))


def _policy_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "checkout-latency",
        "start": 1.0,
        "step": 100.0,
        "max_steps": 200,
        "resolution": 0.25,
        "combination_budget": 4,
        "budget_ref": {"kind": "damage-seconds", "label": "run-1/damage-quota"},
    }
    body.update(overrides)
    return body


def _policy(**overrides: Any) -> SearchPolicy:
    from mayhem.domain.search import SearchPolicy as _Policy

    return _Policy.model_validate(_policy_body(**overrides))


def _candidate_body(value: float = AUTHORED_DURATION_S, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "step": {
            "index": 0,
            "value": value,
            "phase": "escalation",
            "combination": COMBINATION,
            "budget_remaining": 100.0,
            "expected_cost": 1.0,
            "budget_ref": {"kind": "damage-seconds", "label": "run-1/damage-quota"},
        },
        "rationale": "raise the impairment until checkout stops tolerating it",
    }
    body.update(extra)
    return body


# -- the recorded-search document ------------------------------------------------


def _series(base: float, spread: float, count: int = 9) -> list[float]:
    """A fixed, reproducible sample series. Never random: a statistic test that
    depended on a seed would be a test of the seed."""
    return [round(base + spread * (index % 5 - 2), 3) for index in range(count)]


def _search_body(
    *,
    loss_breach_index: int = 1,
    starve: Sequence[int] = (),
    latency_window_count: int = 9,
    latency_baseline_count: int = 9,
    loss_window_count: int = 9,
    loss_baseline_count: int = 9,
    failure_cases: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """A search whose ladder crosses at 7.0, with a latency and a loss signal.

    The two metrics cross at **different rungs**: latency at 7.0, loss at 4.0. That
    is what makes "the service tolerates latency ≤ X, loss ≤ Y" two reports from
    one engine function rather than one number rendered twice — the two brackets
    cannot agree unless the arithmetic is wrong.

    ``starve`` collapses the during-fault window at the named rungs to three
    samples, which is below the domain's floor. Used by the negative control that
    starves *both* metrics' own boundary rung, so nothing in the report may render
    as a tolerance.
    """
    latency_bases = (100.0, 101.0, 160.0)
    loss_bases = [1.0, 1.0, 1.0]
    loss_bases[loss_breach_index] = 2.0
    latency_counts = [
        latency_window_count if rung not in starve else 3 for rung in range(3)
    ]
    loss_counts = [loss_window_count if rung not in starve else 3 for rung in range(3)]
    return {
        "run_id": "r-boundary-0001",
        "policy": _policy_body(start=1.0, step=3.0, max_steps=12, resolution=3.0),
        "trials": [
            {"index": 0, "value": 1.0, "combination": COMBINATION, "breached": False},
            {"index": 1, "value": 4.0, "combination": COMBINATION, "breached": False},
            {"index": 2, "value": 7.0, "combination": COMBINATION, "breached": True},
        ],
        "signals": [
            {
                "name": "latency",
                "unit": "ms",
                "percentile": 99.0,
                "materiality_pct": 20.0,
                "window": {"warmup": 2, "measured": 7, "cooldown": 0},
                "captures": [
                    {
                        "index": rung,
                        "baseline": _series(100.0, 2.0, latency_baseline_count),
                        "window": _series(latency_bases[rung], 2.0, latency_counts[rung]),
                    }
                    for rung in range(3)
                ],
            },
            {
                "name": "loss",
                "unit": "%",
                "percentile": 99.0,
                "materiality_pct": 5.0,
                "window": {"warmup": 1, "measured": 8, "cooldown": 0},
                "captures": [
                    {
                        "index": rung,
                        "baseline": _series(1.0, 0.1, loss_baseline_count),
                        "window": _series(loss_bases[rung], 0.1, loss_counts[rung]),
                    }
                    for rung in range(3)
                ],
            },
        ],
        "failure_cases": [dict(case) for case in failure_cases]
        or [
            {
                "fault_ids": ["fs.disk_fill"],
                "target_ids": ["ctr-api"],
                "reproduced": True,
                "combination": "disk-fill/ctr-api",
            },
            {"fault_ids": ["fs.disk_fill"], "target_ids": ["ctr-api"]},
        ],
    }


def _write(tmp_path: Path, name: str, body: Any) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    return path


def _invoke(*args: str) -> tuple[int, str]:
    """Invoke the group the way :func:`mayhem.cli.app.main` does, and return
    ``(exit_code, output)``.

    ``CliRunner`` leaves a :class:`MayhemCliError` in ``result.exception`` and
    prints nothing at all, so a suite asserting that a refusal is *readable* would
    otherwise be asserting an empty string. This renders the envelope the way
    ``mayhem.cli.app._fail_error`` renders it — message, code, remediation, and
    the sorted ``details`` that carry the rule id.
    """
    runner = CliRunner()
    try:
        result = runner.invoke(boundary, list(args), catch_exceptions=False)
    except MayhemCliError as exc:
        lines = [f"error: safety refused: {exc.message} [{exc.code}]"]
        if exc.remediation:
            lines.append(f"  remediation: {exc.remediation}")
        lines.extend(f"  {key}: {exc.details[key]}" for key in sorted(exc.details))
        return int(exc.exit_code), "\n".join(lines)
    return result.exit_code, result.output


def _report(tmp_path: Path, body: Mapping[str, Any] | None = None, *args: str) -> tuple[int, str]:
    """Invoke ``boundary report`` end to end through the real Click group."""
    path = _write(tmp_path, "search.json", dict(body or _search_body()))
    return _invoke("report", "--search", str(path), *args)


def _review(
    tmp_path: Path,
    *,
    candidate: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    args: Sequence[str] = (),
) -> tuple[int, str]:
    """Invoke ``boundary review`` end to end through the real Click group."""
    candidate_path = _write(tmp_path, "candidate.json", dict(candidate or _candidate_body()))
    policy_path = _write(tmp_path, "policy.json", dict(policy or _policy_body()))
    spec_path = _write(tmp_path, "drill.yaml", _drill_body(AUTHORED_DURATION_S))
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(_graph().model_dump_json(), encoding="utf-8")
    return _invoke(
        "review",
        "--candidate",
        str(candidate_path),
        "--policy",
        str(policy_path),
        "--spec",
        str(spec_path),
        "--graph",
        str(graph_path),
        *args,
    )


def _view(tmp_path: Path, body: Mapping[str, Any] | None = None, **kwargs: Any) -> Any:
    from mayhem.cli.boundary_report_cmd import search_document

    path = _write(tmp_path, "search.json", dict(body or _search_body()))
    return boundary_report_view(search_document(path), **kwargs)


# =============================================================================
# The documented invocations and the surface's shape
# =============================================================================


DOCUMENTED: tuple[tuple[str, ...], ...] = (
    ("report", "--search", "SEARCH.json"),
    ("report", "--search", "SEARCH.json", "--signal", "latency"),
    ("report", "--search", "SEARCH.json", "--json"),
    (
        "review",
        "--candidate",
        "CANDIDATE.json",
        "--policy",
        "POLICY.json",
        "--spec",
        "DRILL.yaml",
        "--graph",
        "GRAPH.json",
    ),
    (
        "review",
        "--candidate",
        "CANDIDATE.json",
        "--policy",
        "POLICY.json",
        "--spec",
        "DRILL.yaml",
        "--graph",
        "GRAPH.json",
        "--json",
    ),
    (
        "review",
        "--candidate",
        "CANDIDATE.json",
        "--policy",
        "POLICY.json",
        "--spec",
        "DRILL.yaml",
        "--graph",
        "GRAPH.json",
        "--deny-fault",
        "fs.disk_fill",
    ),
)


@pytest.mark.parametrize("argv", DOCUMENTED)
def test_every_documented_invocation_resolves_on_the_group(argv: tuple[str, ...]) -> None:
    """Each documented spelling resolves to a leaf that declares its own options.

    The group is invoked directly, so ``argv`` is what follows ``mayhem boundary``.
    Option tokens are checked against the options the *consuming* node declares,
    which is the same discipline ``test_release_contract.py`` applies.
    """
    sub_name, *tokens = argv
    ctx = click.Context(boundary)
    sub = boundary.get_command(ctx, sub_name)
    assert sub is not None, sub_name
    declared = {
        token
        for param in sub.params
        for token in getattr(param, "opts", []) + getattr(param, "secondary_opts", [])
    }
    options = [token for token in tokens if token.startswith("--")]
    values = [
        token
        for index, token in enumerate(tokens)
        if index and tokens[index - 1] in options
    ]
    assert set(options) <= declared, (argv, sorted(declared - set(options)))
    assert not any(value.startswith("--") for value in values), argv


def test_the_group_is_one_group_with_two_read_only_commands() -> None:
    assert isinstance(boundary, click.Group)
    assert sorted(boundary.commands) == ["report", "review"]


def test_help_names_the_document_each_command_needs() -> None:
    output = CliRunner().invoke(boundary, ["--help"]).output
    for command in ("report", "review"):
        assert command in output
    for option in ("--search", "--signal"):
        assert option in CliRunner().invoke(boundary, ["report", "--help"]).output
    review_help = CliRunner().invoke(boundary, ["review", "--help"]).output
    for option in ("--candidate", "--policy", "--spec", "--graph", "--deny-fault"):
        assert option in review_help


BYPASS_FLAGS = (
    "--force",
    "--yes",
    "--approve",
    "--authorized",
    "--authorization",
    "--skip-gate",
    "--skip-gates",
    "--no-gate",
    "--bypass",
    "--allow-critical",
    "--max-services-pct",
    "--max-duration-per-fault-s",
    "--max-hosts",
    "--max-concurrent-faults",
    "--damage-budget",
)


@pytest.mark.parametrize("bypass", BYPASS_FLAGS)
def test_neither_command_declares_a_bypass_or_a_ceiling_flag(bypass: str) -> None:
    """No bypass, and no flag that would hand a caller the gate that checks it.

    The last four are the blast-radius ceilings: they are module constants on this
    surface, exactly as they are on ``advisor``. A caller handed a flag for the
    ceiling is handed the ceiling.
    """
    ctx = click.Context(boundary)
    for name in sorted(boundary.commands):
        command = boundary.get_command(ctx, name)
        assert command is not None
        declared = {
            token
            for param in command.params
            for token in getattr(param, "opts", []) + getattr(param, "secondary_opts", [])
        }
        assert bypass not in declared, (name, bypass)


def test_the_module_declares_the_authority_field_keys_as_a_projection() -> None:
    """``AUTHORITY_FIELD_KEYS`` cannot drift from the domain's one scan."""
    assert set(boundary_report_cmd.AUTHORITY_FIELD_KEYS) == set(AUTHORITY_FIELDS)
    assert list(boundary_report_cmd.AUTHORITY_FIELD_KEYS) == sorted(
        boundary_report_cmd.AUTHORITY_FIELD_KEYS
    )


def test_the_surface_never_constructs_a_search_plan_with_an_approval() -> None:
    """Structural, not behavioural: no ``SearchPlan(..., approval=...)`` exists here.

    The AI boundary is the domain's, and a surface is exactly the kind of place a
    later edit would smuggle a token in. Walking this module's own AST is the
    assertion that survives such an edit being written by accident.
    """
    tree = ast.parse(Path(boundary_report_cmd.__file__).read_text(encoding="utf-8"))
    offenders = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "SearchPlan"
        and any(keyword.arg == "approval" for keyword in node.keywords)
    ]
    assert offenders == []


def test_the_surface_scans_for_authority_fields_nowhere() -> None:
    """The authority scan is the domain's, and this module never re-implements it.

    Over the AST rather than the text: no assignment anywhere in this module binds
    a set or tuple of authority field names, so a second scan cannot appear here
    without one of these two assertions failing.
    """
    tree = ast.parse(Path(boundary_report_cmd.__file__).read_text(encoding="utf-8"))
    assignments = [
        target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    ]
    assert "AUTHORITY_FIELDS" not in assignments
    assert not [
        name for name in assignments if "AUTHORITY" in name and name != "AUTHORITY_FIELD_KEYS"
    ]


def test_the_gate_core_declares_no_origin_parameter() -> None:
    """The acceptance criterion's mechanism, asserted on the signature itself."""
    import inspect

    parameters = set(inspect.signature(boundary_report_cmd._gate).parameters)
    assert parameters == {
        "spec",
        "run_id",
        "graph",
        "ctx",
        "config_snapshot_id",
        "topology_snapshot_id",
        "environment_fingerprint",
        "subject",
    }
    assert "origin" not in parameters
    assert GATE_PATH == (
        "controller.planner.plan_drill",
        "controller.safety_proof.compile_safety_evidence",
        "controller.safety.simulate_plan_policy",
    )


# =============================================================================
# Boundary reports: tolerance, confidence, withholding
# =============================================================================


def test_a_graded_boundary_renders_a_tolerance_with_its_confidence_attached(
    tmp_path: Path,
) -> None:
    code, output = _report(tmp_path)
    assert code == 0, output
    latency = _signal_row(output, "latency")
    assert "tolerates" in latency
    assert "confidence:" in output
    assert "MATERIAL" in latency or "NO MATERIAL EFFECT" in latency


def test_each_declared_signal_gets_its_own_boundary_from_the_one_engine_function(
    tmp_path: Path,
) -> None:
    """Two metrics, two brackets — not one number rendered twice."""
    view = _view(tmp_path)
    assert [signal.signal for signal in view.signals] == ["latency", "loss"]
    brackets = {signal.signal: signal.bracket for signal in view.signals}
    assert brackets["latency"] != brackets["loss"], brackets
    assert all(signal.reportable for signal in view.signals)


def test_a_boundary_whose_edge_was_not_graded_does_not_render_as_a_tolerance(
    tmp_path: Path,
) -> None:
    """The load-bearing negative control, at the CLI.

    Both metrics cross at rung 2 and both are starved there, so neither boundary
    is measurable. The rung is still *recorded* as a breach, the bracket still
    stands as a fact about the trials, and the metric at its edge was never
    separable from the noise — so the word ``tolerates`` must appear nowhere.
    """
    body = _search_body(loss_breach_index=2, starve=(2,))
    code, output = _report(tmp_path, body)
    assert code == 0, output
    assert "tolerates" not in output
    latency = _signal_row(output, "latency")
    assert "WITHHELD" in latency
    assert "could not be graded" in latency
    # The bracket is still reported: it is a fact about the recorded ladder, not a
    # claim about the metric at its edge.
    assert "bracket:" in latency
    assert "insufficient rungs: [2]" in latency


def test_an_unusable_comparison_is_never_scored_and_never_quoted(tmp_path: Path) -> None:
    """Nothing is scored from a starved rung, and the rung is named.

    A signal's boundary exists only where its *own* comparison was graded — the
    breach flag is read off that comparison rather than invented — so a starved
    boundary rung produces no boundary at all, and the report says so with the
    domain's own insufficiency reason and the index of the rung it could not use.
    """
    body = _search_body(loss_breach_index=2, starve=(2,))
    view = _view(tmp_path, body)
    assert view.reportable_signals == ()
    assert all(signal.refusal for signal in view.signals)
    assert all("could not be graded" in signal.refusal for signal in view.signals)
    assert all(signal.insufficient_trials == (2,) for signal in view.signals)
    assert all(signal.bracket == "(0, none]" for signal in view.signals)


def test_the_rendered_tolerance_is_the_engines_own_wording(tmp_path: Path) -> None:
    """The surface gates the engine's sentence; it does not restate the boundary."""
    from mayhem.cli.boundary_report_cmd import search_document

    path = _write(tmp_path, "search.json", _search_body())
    view = boundary_report_view(search_document(path))
    latency = view.signals[0]
    assert latency.tolerance.endswith("— read on latency p99 ms")
    assert "NOT RESOLVED" in latency.tolerance or "within the declared resolution" in (
        latency.tolerance
    )


def test_the_json_projection_carries_the_same_verdict_as_the_text(tmp_path: Path) -> None:
    text_code, text = _report(tmp_path)
    code, machine = _report(tmp_path, None, "--json")
    assert text_code == 0, text
    assert code == 0, machine
    payload = json.loads(machine)
    assert [row["signal"] for row in payload["signals"]] == ["latency", "loss"]
    assert all(row["reportable"] for row in payload["signals"])
    assert payload["authority"] == "none"
    assert payload["closes_evidence"] == "no"


def test_a_report_with_no_support_renders_a_withholding_not_a_result(tmp_path: Path) -> None:
    """No measurable case was tried, so the reduction rests on nothing.

    ``minimal_failure_case`` withholds rather than returning a minimal case, and
    the rendering must show that withholding — a silently omitted section reads
    as "nothing reproduced".
    """
    body = _search_body(
        failure_cases=[
            {
                "fault_ids": ["fs.disk_fill"],
                "target_ids": ["ctr-api"],
                "reproduced": True,
                "sufficient": False,
                "combination": "unmeasured",
            }
        ]
    )
    code, output = _report(tmp_path, body)
    assert code == 0, output
    assert RULE_EVIDENCE_UNSUPPORTED in output
    assert "withheld sections" in output
    assert "nothing was omitted" in output


def test_an_unsupported_claim_cannot_be_constructed_at_all() -> None:
    """The domain's half of the same rule, re-asserted from this suite's side."""
    from mayhem.controller.analytics_service import AnalyticsClaim, ClaimKind
    from mayhem.domain.hashing import digest

    with pytest.raises(InvariantViolationError) as caught:
        AnalyticsClaim(
            kind=ClaimKind.BOUNDARY,
            subject="checkout-latency",
            claim_digest=digest({"a": 1}),
            support=(),
        )
    assert caught.value.rule == RULE_EVIDENCE_UNSUPPORTED


def test_the_minimal_failure_case_is_reduced_by_the_service_not_by_the_renderer(
    tmp_path: Path,
) -> None:
    from mayhem.controller.analytics_service import FailureCase, minimal_failure_case

    view = _view(tmp_path)
    expected = minimal_failure_case(
        [
            FailureCase(fault_ids=("fs.disk_fill",), target_ids=("ctr-api",), reproduced=True),
            FailureCase(
                fault_ids=("fs.disk_fill",), target_ids=("ctr-api",), reproduced=False
            ),
        ]
    )
    assert view.minimal_case is not None
    assert view.minimal_case.size == expected.size
    assert view.minimal_case.minimal == expected.minimal
    assert view.minimal_case.note == expected.note


def test_an_absent_failure_case_section_says_it_was_not_run(tmp_path: Path) -> None:
    body = _search_body()
    body["failure_cases"] = []
    code, output = _report(tmp_path, body)
    assert code == 0, output
    assert "not run" in output
    assert "not evidence that no minimal case exists" in output


def test_the_window_plan_is_used_and_its_dropped_samples_are_surfaced(tmp_path: Path) -> None:
    """Warm-up is excluded from the graded window by the domain, and said so."""
    body = _search_body(latency_window_count=12)
    view = _view(tmp_path, body)
    latency = view.signals[0]
    assert "warmup 2 / measured 7 / cooldown 0" in latency.window_phases
    assert "dropped 3" in latency.window_phases
    assert "did not supply the declared window" in latency.window_phases


def test_an_unmeasurable_rung_is_never_counted_as_a_clearance(tmp_path: Path) -> None:
    body = _search_body()
    del body["signals"][0]["captures"][1]
    view = _view(tmp_path, body)
    latency = view.signals[0]
    assert 1 in latency.insufficient_trials


# =============================================================================
# Negative controls on the document itself
# =============================================================================


@pytest.mark.parametrize("blank", ["", "  ", "unknown", None, True, [], {}])
def test_a_blank_or_unknown_boundary_value_refuses_rather_than_defaulting(
    tmp_path: Path, blank: Any
) -> None:
    body = _search_body()
    body["trials"][2]["value"] = blank
    path = _write(tmp_path, "search.json", body)
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_cmd.search_document(path)
    assert caught.value.rule == RULE_REPORT_VALUE_UNKNOWN
    assert "refused rather than defaulted" in str(caught.value)


def test_a_non_finite_boundary_value_is_refused(tmp_path: Path) -> None:
    body = _search_body()
    body["trials"][2]["value"] = float("inf")
    path = _write(tmp_path, "search.json", body)
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_cmd.search_document(path)
    assert caught.value.rule == RULE_REPORT_VALUE_UNKNOWN


def test_an_undeclared_signal_is_refused_rather_than_rendered_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, "search.json", _search_body())
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_view(
            boundary_report_cmd.search_document(path), only_signal="throughput"
        )
    assert caught.value.rule == RULE_REPORT_SIGNAL_UNKNOWN
    assert "not a report about that metric with an empty result" in str(caught.value)


def test_a_declared_signal_renders_on_its_own(tmp_path: Path) -> None:
    code, output = _report(tmp_path, None, "--signal", "loss")
    assert code == 0, output
    assert "signal loss" in output
    assert "signal latency" not in output


def test_a_document_with_no_trial_is_refused_rather_than_reported_as_zero(tmp_path: Path) -> None:
    body = _search_body()
    body["trials"] = []
    path = _write(tmp_path, "search.json", body)
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_cmd.search_document(path)
    assert caught.value.rule == RULE_REPORT_UNKNOWN_FIELD
    assert "boundary of zero" in str(caught.value)


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda body: body.update({"extra": 1}), "extra"),
        (lambda body: body["policy"].update({"leap": 5}), "leap"),
        (lambda body: body["trials"][0].update({"secret": "x"}), "secret"),
        (lambda body: body["signals"][0].update({"hidden": True}), "hidden"),
        (lambda body: body["signals"][0]["window"].update({"phase": 1}), "phase"),
        (lambda body: body["failure_cases"][0].update({"extra": 2}), "extra"),
    ],
)
def test_an_unknown_field_anywhere_in_the_document_is_refused(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None], needle: str
) -> None:
    body = _search_body()
    mutate(body)
    path = _write(tmp_path, "search.json", body)
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_cmd.search_document(path)
    assert caught.value.rule == RULE_REPORT_UNKNOWN_FIELD
    assert needle in str(caught.value)


def test_a_policy_without_a_budget_reference_is_refused(tmp_path: Path) -> None:
    body = _search_body()
    del body["policy"]["budget_ref"]
    path = _write(tmp_path, "search.json", body)
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_cmd.search_document(path)
    assert "no budget_ref" in str(caught.value)


# =============================================================================
# Candidate review: the acceptance criterion
# =============================================================================


def _review_view(candidate: Mapping[str, Any] | None = None, **kwargs: Any) -> Any:
    ctx = boundary_review_safety_context()
    return candidate_review_view(
        candidate=dict(candidate or _candidate_body()),
        policy=_policy(),
        spec=_spec(),
        graph=_graph(),
        ctx=ctx,
        **kwargs,
    )


def test_a_generated_candidate_is_compiled_into_the_same_type_an_authored_plan_uses() -> None:
    """Types, not strings: both arms leave :func:`_gate` holding an ``ExecutionPlan``."""
    view = _review_view()
    assert view.authored.plan_type == "ExecutionPlan"
    assert view.generated.plan_type == view.authored.plan_type


def test_both_arms_reach_the_identical_plan_drill_proof_policy_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spy. This is the test that fails if a generated candidate takes a shortcut.

    Each of the three gate functions is wrapped so it records its own name and
    delegates to the real one. Both arms must produce the *identical* sequence,
    and the sequence must be exactly :data:`GATE_PATH` twice.
    """
    calls: list[str] = []

    def _spy(name: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            return real(*args, **kwargs)

        return wrapper

    monkeypatch.setattr(
        boundary_report_cmd,
        "plan_drill",
        _spy("controller.planner.plan_drill", boundary_report_cmd.plan_drill),
    )
    monkeypatch.setattr(
        boundary_report_cmd,
        "compile_safety_evidence",
        _spy(
            "controller.safety_proof.compile_safety_evidence",
            boundary_report_cmd.compile_safety_evidence,
        ),
    )
    monkeypatch.setattr(
        boundary_report_cmd,
        "simulate_plan_policy",
        _spy(
            "controller.safety.simulate_plan_policy",
            boundary_report_cmd.simulate_plan_policy,
        ),
    )

    view = _review_view()

    assert calls == [*GATE_PATH, *GATE_PATH], calls
    assert view.same_gates is True
    assert view.generated.gates_reached == GATE_PATH
    assert view.authored.gates_reached == GATE_PATH


def test_the_two_compiled_plans_are_byte_identical_when_the_rung_is_the_authored_one() -> None:
    """The strongest form of "indistinguishable downstream of compilation".

    Not "the report reads the same": the two ``ExecutionPlan`` digests are equal,
    so an origin stamped anywhere in the plan would change this and fail.
    """
    view = _review_view()
    assert view.identical_plan is True
    assert view.authored.plan_shape_digest == view.generated.plan_shape_digest
    assert view.authored.plan_type == view.generated.plan_type
    assert view.indistinguishable is True


def test_the_planner_mints_a_fresh_execution_group_id_per_call(tmp_path: Path) -> None:
    """Why :func:`plan_shape_digest` exists, pinned rather than assumed.

    Two compiles of the *same authored spec* by the same planner are not
    byte-identical, so "the two compiled plans are the same plan" cannot be
    asserted on the compiler's own digest. Holding out the one per-call identifier
    is the strongest claim two independent compiles support — and it still fails
    if an origin were stamped anywhere on the plan.
    """
    from mayhem.cli.boundary_report_cmd import (
        _gate,
        plan_shape_digest,
    )

    ctx = boundary_review_safety_context()
    common = {
        "run_id": "r-boundary-review",
        "graph": _graph(),
        "ctx": ctx,
        "config_snapshot_id": "review",
        "topology_snapshot_id": "review",
        "environment_fingerprint": "",
    }
    first, first_compilation, _ = _gate(_spec(), subject="authored", **common)
    second, second_compilation, _ = _gate(_spec(), subject="authored", **common)
    assert first_compilation.plan_digest != second_compilation.plan_digest
    assert plan_shape_digest(first) == plan_shape_digest(second)
    del tmp_path


def test_the_review_runs_the_through_the_cli_with_both_arms_named(tmp_path: Path) -> None:
    code, output = _review(tmp_path)
    assert code == 0, output
    assert "generated candidate" in output
    assert "authored plan" in output
    assert "indistinguishable downstream of compilation: true" in output
    assert "identical compiled plan: true" in output
    for gate in GATE_PATH:
        assert gate in output


def test_a_candidate_proposing_another_rung_differs_in_numbers_not_in_type_or_gates() -> None:
    view = _review_view(_candidate_body(value=25.0))
    assert view.identical_plan is False
    assert view.indistinguishable is True
    assert view.authored.plan_type == view.generated.plan_type
    assert view.same_gates is True


def test_a_generated_candidate_is_refused_by_the_same_gate_that_refuses_the_authored_one() -> None:
    """A candidate the config-policy gate refuses, and the refusal names the gate.

    Identical treatment is the claim; identical rule ids on both arms is how it is
    shown. The candidate clears ``compile_candidate`` — it is a valid rung of the
    declared ladder — and is refused afterwards by ``policy.deny_faults``, exactly
    as the authored plan it perturbs is.
    """
    ctx = boundary_review_safety_context(deny_faults=frozenset({FAULT_ID}))
    view = candidate_review_view(
        candidate=_candidate_body(),
        policy=_policy(),
        spec=_spec(),
        graph=_graph(),
        ctx=ctx,
    )
    assert view.generated.refusing_gates == (RULE_DENY_FAULTS,)
    assert view.generated.refusing_gates == view.authored.refusing_gates
    assert view.same_verdict is True
    assert view.generated.admitted_by_gate is False
    assert view.authored.admitted_by_gate is False
    assert view.indistinguishable is True

    rendered = "\n".join(render_candidate_review(view))
    assert RULE_DENY_FAULTS in rendered
    assert "gate: refused" in rendered


def test_the_same_refusal_surfaces_through_the_cli_and_names_the_gate(tmp_path: Path) -> None:
    """The refusal reaches a reader through the command, not only through the view."""
    code, output = _review(tmp_path, args=("--deny-fault", FAULT_ID,))
    assert code == 0, output
    assert RULE_DENY_FAULTS in output
    assert "gate: refused" in output


def test_the_config_policy_half_can_only_be_tightened_from_the_command(
    tmp_path: Path,
) -> None:
    """``--deny-fault`` narrows what may be reviewed and never widens it."""
    allowed_code, allowed = _review(tmp_path)
    denied_code, denied = _review(tmp_path, args=("--deny-fault", FAULT_ID,))
    assert allowed_code == 0, allowed
    assert denied_code == 0, denied
    assert RULE_DENY_FAULTS not in allowed
    assert RULE_DENY_FAULTS in denied


# =============================================================================
# Authority discipline
# =============================================================================


@pytest.mark.parametrize("field", sorted(AUTHORITY_FIELDS))
def test_a_draft_carrying_any_authority_field_is_refused_by_the_domain(
    tmp_path: Path, field: str
) -> None:
    """The domain's scan, reached through the surface, naming its rule.

    A candidate the review *cannot* render at all is the correct outcome: there is
    nothing to show about a draft that tried to arrive already authorized.
    """
    nested = {"meta": {field: "sre"}} if field in {"approved_by", "token"} else None
    body = _candidate_body(**({field: "sre"} if nested is None else {}))
    if nested is not None:
        body["step"]["meta"] = nested["meta"]
    code, output = _review(tmp_path, candidate=body)
    assert code != 0
    assert RULE_DRAFT_CARRIES_AUTHORITY in output


def test_an_out_of_ladder_rung_is_refused_before_any_gate_runs(tmp_path: Path) -> None:
    narrow = _policy_body(start=1.0, step=3.0, max_steps=12)
    code, output = _review(tmp_path, candidate=_candidate_body(value=100.0), policy=narrow)
    assert code != 0
    assert RULE_DRAFT_VALUE_OUT_OF_LADDER in output


def test_a_draft_may_not_reprice_the_search(tmp_path: Path) -> None:
    body = _candidate_body()
    body["step"]["expected_cost"] = 0.01
    code, output = _review(tmp_path, candidate=body)
    assert code != 0
    assert "analytics.draft_step_cost_mismatch" in output


def test_a_candidate_may_not_declare_its_own_ladder(tmp_path: Path) -> None:
    """The policy is a separate, authored input — not something a draft supplies.

    A candidate that carried its own policy block would be carrying its own budget
    and its own step cost, so it is refused by the domain's field discipline with
    the rule that names it — not by a second refusal here.
    """
    code, output = _review(tmp_path, candidate=_candidate_body(policy=_policy_body()))
    assert code != 0
    assert "analytics.draft_unknown_field" in output
    assert "policy" in output


def test_an_untrusted_draft_never_renders_as_authorized_or_approved() -> None:
    """The negative control, over the draft's identity block and the whole payload.

    Two assertions, both about the *draft*, and both scoped deliberately.

    * Over the ``generated candidate`` block of the rendered review: the surface's
      vocabulary for a draft is ``origin``, ``trust`` and ``authority``, so neither
      the substrings ``approv`` nor ``authoriz`` can appear in it at all — there is
      no boolean beside those words that could later read ``true``.
    * Over the whole JSON projection: no **key** anywhere is named after an approval
      or an authorization, no value reads ``approved``/``authorized``/``granted``,
      and the draft's ``authority`` is the literal ``none``.

    What is deliberately *not* asserted is that the word "approval" never appears
    anywhere: the proof's own ``required_approvals`` obligation is a real gate line
    and hiding it would hide a gate. It is rendered as that line's own state and
    with no value beside it that could be read as a grant.
    """
    view = _review_view()
    rendered = _section(
        "\n".join(render_candidate_review(view)), "generated candidate", "gates reached"
    )
    assert "approv" not in rendered.lower()
    assert "authoriz" not in rendered.lower()
    assert "trust: untrusted" in rendered
    assert "authority: none" in rendered

    payload = view.to_dict()
    assert not [
        key for key in _keys(payload) if _is_authority_word(key)
    ], sorted(_keys(payload))
    assert not [
        value
        for value in _values(payload)
        if isinstance(value, str) and value.strip().lower() in _GRANT_WORDS
    ]
    candidate = payload["candidate"]
    assert isinstance(candidate, dict)
    assert candidate["authority"] == "none"
    assert candidate["trust"] == "untrusted"
    assert candidate["origin"] == "generated"
    assert view.generated.approval_line_state in {"requirements_only", "not_evaluated"}


def test_the_generated_plan_carries_no_approval_and_the_type_forbids_one() -> None:
    from mayhem.controller.analytics_service import compile_candidate
    from mayhem.domain.search import Approval, SearchOrigin, SearchPlan

    plan = compile_candidate(_candidate_body(), _policy())
    assert isinstance(plan, SearchPlan)
    assert plan.origin is SearchOrigin.GENERATED
    assert plan.approval is None
    with pytest.raises(InvariantViolationError) as caught:
        SearchPlan(
            step=plan.step,
            origin=SearchOrigin.GENERATED,
            approval=Approval(approved_by="sre", plan_digest=plan.plan_digest),
        )
    assert caught.value.rule == "search.generated_plan_cannot_be_approved"


def test_the_review_names_the_one_door_it_went_through() -> None:
    view = _review_view()
    assert view.via == SURFACE_VIA
    assert SURFACE_VIA in "\n".join(render_candidate_review(view))


# =============================================================================
# Mutation evidence
# =============================================================================


def test_the_review_mutates_nothing_on_the_context_it_was_handed() -> None:
    """The proof compiler runs every probe against a clone; this measures it.

    ``ctx.decisions`` is not asserted to be empty by the surface — it *reports*
    the length — so the assertion here is against the caller's own object.
    """
    ctx = boundary_review_safety_context()
    view = candidate_review_view(
        candidate=_candidate_body(),
        policy=_policy(),
        spec=_spec(),
        graph=_graph(),
        ctx=ctx,
    )
    assert ctx.decisions == []
    assert ctx.warnings == []
    assert view.safety_decisions_recorded == 0
    assert view.safety_warnings_recorded == 0
    assert "0 safety decision(s)" in "\n".join(render_candidate_review(view))


def test_neither_command_opens_a_store(tmp_path: Path) -> None:
    """A filesystem assertion: no database appears, and no ``mayhem.db`` is made."""
    from mayhem.cli import services

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a read + decide surface must not open a store")

    original = services.open_store
    services.open_store = _forbidden  # type: ignore[assignment]
    try:
        assert _report(tmp_path)[0] == 0
        assert _review(tmp_path)[0] == 0
    finally:
        services.open_store = original  # type: ignore[assignment]
    assert list(tmp_path.glob("*.db")) == []
    assert list(tmp_path.glob("*.sqlite*")) == []


def test_the_report_command_writes_no_file(tmp_path: Path) -> None:
    path = _write(tmp_path, "search.json", _search_body())
    before = sorted(item.name for item in tmp_path.iterdir())
    code, output = _invoke("report", "--search", str(path), "--json")
    assert code == 0, output
    assert sorted(item.name for item in tmp_path.iterdir()) == before


def test_a_refused_candidate_leaves_nothing_behind(tmp_path: Path) -> None:
    """A refusal leaves the directory holding exactly the four documents it read."""
    code, _ = _review(
        tmp_path,
        candidate=_candidate_body(value=100.0),
        policy=_policy_body(start=1.0, step=3.0, max_steps=12),
    )
    assert code != 0
    assert sorted(item.name for item in tmp_path.iterdir()) == [
        "candidate.json",
        "drill.yaml",
        "graph.json",
        "policy.json",
    ]


def test_running_the_review_twice_changes_nothing(tmp_path: Path) -> None:
    """Idempotent, modulo the one identifier ``plan_drill`` mints per call.

    Two runs of a read + decide command must agree. They cannot agree on the
    compiler's ``plan_digest`` — see
    :func:`test_the_planner_mints_a_fresh_execution_group_id_per_call` — so the
    comparison holds out that one field and asserts the rest byte for byte, plus
    the shape digest that survives it.
    """
    first_code, first = _review(tmp_path, args=("--json",))
    second_code, second = _review(tmp_path, args=("--json",))
    assert first_code == 0, first
    assert second_code == 0, second
    assert _without_plan_digest(json.loads(first)) == _without_plan_digest(
        json.loads(second)
    )
    assert json.loads(first)["acceptance"] == json.loads(second)["acceptance"]
    assert json.loads(first)["mutation"] == {
        "safety_decisions_recorded": 0,
        "safety_warnings_recorded": 0,
    }


# =============================================================================
# View-model guarantees a Click callback cannot weaken
# =============================================================================


def test_the_refusal_happens_in_the_view_layer_not_the_callback(tmp_path: Path) -> None:
    """A refusal raised by the document reader reaches the caller as an envelope."""
    body = _search_body()
    body["signals"][0]["unit"] = ""
    path = _write(tmp_path, "search.json", body)
    with pytest.raises(BoundaryViewRefused) as caught:
        boundary_report_cmd.search_document(path)
    assert caught.value.rule == RULE_REPORT_VALUE_UNKNOWN
    assert "is blank" in str(caught.value)
    assert isinstance(caught.value, InvariantViolationError)


def test_the_cli_envelope_names_the_rule_the_view_layer_refused_on(tmp_path: Path) -> None:
    code, output = _report(tmp_path, None, "--signal", "throughput")
    assert code != 0
    assert RULE_REPORT_SIGNAL_UNKNOWN in output


def test_every_renderer_takes_one_view_and_no_renderer_invents_a_tolerance() -> None:
    """Both projections read one structure, so a UI inherits the same rule.

    The second half is over the AST of :func:`render_boundary_report`: it must not
    contain a string literal spelling the word ``tolerates``, because the only place
    that word may be produced is :func:`_tolerates`.
    """
    import inspect

    for renderer in (render_boundary_report, render_candidate_review):
        assert list(inspect.signature(renderer).parameters) == ["view"], renderer
    tree = ast.parse(Path(boundary_report_cmd.__file__).read_text(encoding="utf-8"))
    renderers = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("render_")
    ]
    assert renderers
    for node in renderers:
        docstring = node.body[0] if node.body else None
        literals = [
            child.value
            for child in ast.walk(node)
            if isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and child is not getattr(docstring, "value", None)
        ]
        assert not [text for text in literals if "tolerates" in text], node.name


def test_the_view_is_the_only_thing_rendered_and_it_carries_no_authority(tmp_path: Path) -> None:
    view = _view(tmp_path)
    payload = view.to_dict()
    assert payload["authority"] == "none"
    assert payload["closes_evidence"] == "no"
    assert "approv" not in json.dumps(payload).lower()
    assert "authoriz" not in json.dumps(payload).lower()


def test_a_report_over_two_signals_is_reproducible(tmp_path: Path) -> None:
    first = _view(tmp_path).to_dict()
    second = _view(tmp_path).to_dict()
    assert first == second


# =============================================================================
# Helpers
# =============================================================================


def _signal_row(output: str, name: str) -> str:
    """One signal's block out of the rendered report, up to the next heading."""
    lines = output.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.strip().startswith(f"signal {name} ")
    )
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index] and not lines[index].startswith("  ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _section(text: str, heading: str, following: str) -> str:
    """The lines between two headings — the smallest slice a claim about one block
    can be made over without dragging the rest of the report in."""
    start = text.index(heading) + len(heading)
    return text[start : text.index(following, start)]


_AUTHORITY_WORDS = ("approv", "authoriz", "grant")
_GRANT_WORDS = frozenset(
    {"approved", "authorized", "authorised", "granted", "approval", "authorization"}
)


def _is_authority_word(key: str) -> bool:
    lowered = key.lower()
    return lowered in _AUTHORITY_WORDS and lowered != "authority"


def _keys(node: object) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(str(key))
            found |= _keys(value)
    elif isinstance(node, list):
        for item in node:
            found |= _keys(item)
    return found


def _values(node: object) -> list[object]:
    found: list[object] = []
    if isinstance(node, dict):
        for value in node.values():
            found.append(value)
            found.extend(_values(value))
    elif isinstance(node, list):
        for item in node:
            found.append(item)
            found.extend(_values(item))
    return found


def _without_plan_digest(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """The projection with every planner-per-call plan digest held out."""
    return {
        key: (
            {inner: item for inner, item in value.items() if inner != "plan_digest"}
            if isinstance(value, dict)
            else value
        )
        for key, value in payload.items()
    }
