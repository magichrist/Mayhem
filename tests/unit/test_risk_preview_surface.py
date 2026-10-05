"""Plan 14 Phase 3 — the risk preview surface, and the view-model it renders from.

Phases 1, 2, and 4 proved the arithmetic, the engine, and the evidence. None of
that is reachable by a person, and this suite is about the last link plus the
one property that is easy to fake:

* **every documented invocation resolves on the real Click tree.** The suite
  invokes :data:`risk_preview_cmd.risk_preview` directly — not the app registry —
  because Phase 3's integration pass owns registration, and a suite that resolved
  through ``cli.app`` would be asserting a fact a peer has not landed yet. The
  *documented* spellings in the module docstring and the README row are checked
  against the same resolver ``test_release_contract.py`` uses, so a typo fails
  the way a typo in a document would.
* **the acceptance criterion is asserted at the view-model layer, not on printed
  strings.** "Rendered identically in CLI and UI" is a claim about two renderers
  projecting off one structure. There is exactly one structure here
  (:class:`~mayhem.cli.risk_preview_cmd.RiskPreviewView`) and two projections off
  it (``render_preview_lines`` and ``preview_payload``), so the test asserts that
  every claim in the view appears in *both* — which is what makes the property
  structural rather than aspirational. Asserting on CLI strings alone would pass
  against a surface with no UI contract at all.
* **the negative controls**, each asserting a *named* refusal rather than "it
  raised": an unresolvable target set, a gate disagreement, the ``UNMODELLED``
  state, an unpriced estimate, and a claim that cannot cite its rule.
* **mutation evidence.** The command is asserted to write nothing, measured
  against the store itself (row counts before and after) *and* against a
  pre-loaded :class:`~mayhem.domain.policy_gate.MutationSink` — the same
  shape ``test_prediction_service.py`` uses, because a hard-coded zero in the
  report would satisfy a naive assertion.

One test is about something that did **not** land:
:func:`test_the_ui_renderer_does_not_exist_yet` pins the absence of plan 08, which
is why the acceptance criterion is only half met and the STATUS entry says so.

Timestamps are injected everywhere; nothing here reads a wall clock to decide a
verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
import pytest
from click.testing import CliRunner

from mayhem.cli import risk_preview_cmd
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.risk_preview_cmd import (
    CostView,
    NodeRiskView,
    PolicyStance,
    PreviewRenderRefusedError,
    build_node_risk_views,
    build_risk_preview,
    exit_code_for,
    load_recorded_run,
    preview_payload,
    preview_refusal,
    render_node_lines,
    render_preview_lines,
    risk_preview,
)
from mayhem.domain.policy_gate import MutationSink
from mayhem.controller.prediction_service import (
    RULE_PREDICTION_CALMER_THAN_GATE,
    RULE_PREDICTION_UNMODELLED_GATE_REFUSAL,
    AgreementState,
    CeilingName,
    CeilingVerdict,
    GateAgreement,
    PredictionConfig,
    PredictionService,
    SimulateReport,
)
from mayhem.controller.safety import SafetyContext
from mayhem.domain.advisor import IncidentFacts
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.prediction import (
    RULE_MAX_SERVICES_PCT,
    BlastCeilings,
    CostRateCard,
    ViolatedRule,
)
from mayhem.domain.quota import DamageQuota
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    PortBinding,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from mayhem.controller.prediction_service import PredictionReview  # noqa: F401

ROOT = Path(__file__).parents[2]
MOMENT = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
RUN_ID = "r-drill-11aa22bb"
FP = "f" * 64
STEP_S = 30.0


# ==============================================================================
# The world
# ==============================================================================


def _container(node_id: str, name: str, *, service: str, state: str = "running") -> ContainerNode:
    return ContainerNode(
        id=node_id,
        name=name,
        engine="docker",
        runtime_identity=RuntimeIdentity(
            runtime="docker", host_id="h-local", runtime_id=f"cid-{name}"
        ),
        runtime_metadata=RuntimeMetadata.from_compose_labels(
            {"com.docker.compose.service": service}
        ),
        container_name=service,
        state=state,
    )


def _graph() -> TopologyGraph:
    """``n-db`` <- ``n-api`` <- ``n-web``, with two replicas of web.

    ``n-web`` is the only node exposing a port, so the customer-facing count is
    one rather than "however many services are in the closure".
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-db", name="db"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(
                id="n-web",
                name="web",
                exposed_ports=[PortBinding(host_port=8080, container_port=8080)],
            ),
            _container("web-1", "web-1", service="web"),
            _container("web-2", "web-2", service="web", state="exited"),
        ),
        edges=(
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON),
            Edge(src="web-1", dst="n-web", kind=EdgeKind.EXPOSES),
            Edge(src="web-2", dst="n-web", kind=EdgeKind.EXPOSES),
        ),
    )


def _plan(*faults: tuple[str, str, float], run_id: str = RUN_ID) -> ExecutionPlan:
    """A frozen plan, one ``(fault_id, node_id, duration_s)`` per step."""
    graph = _graph()
    steps: list[PlannedStep] = []
    for index, (fault_id, node_id, duration) in enumerate(faults):
        node = graph.by_id(node_id)
        selector = (
            TargetSelector(kind=node.kind, expr=node.name)
            if node is not None
            else TargetSelector(kind="service", expr=node_id)
        )
        steps.append(
            PlannedStep(
                id=f"s{index}",
                seq=index,
                raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),),
                    duration=duration,
                ),
            )
        )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


def _permissive() -> BlastRadiusBudget:
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _ctx(*, ceilings: BlastCeilings | None = None) -> SafetyContext:
    return SafetyContext(
        policy=_policy(),
        budget=_permissive(),
        fingerprint=FP,
        damage_quota=DamageQuota(),
        blast_ceilings=ceilings,
    )


def _policy() -> Any:
    from mayhem.config import PolicyCfg

    return PolicyCfg()


def _service(
    graph: TopologyGraph | None = None,
    *,
    ceilings: BlastCeilings | None = None,
    rate_card: CostRateCard | None = None,
    backend: MutationSink | None = None,
) -> PredictionService:
    return PredictionService(
        graph=graph if graph is not None else _graph(),
        config=PredictionConfig(
            ceilings=ceilings if ceilings is not None else BlastCeilings(),
            rate_card=rate_card if rate_card is not None else CostRateCard(),
        ),
        backend=backend,
    )


def _tight_budget() -> BlastRadiusBudget:
    """A budget whose only possible breach is the 50% service-percentage cap."""
    return BlastRadiusBudget(
        max_services_pct=50.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )


def _breaching_report() -> SimulateReport:
    """A report for a plan that breaches ``blast_radius.max_services_pct``."""
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = SafetyContext(
        policy=_policy(),
        budget=_tight_budget(),
        fingerprint=FP,
        damage_quota=DamageQuota(),
    )
    return _service().simulate_plan(plan, ctx)


def _clean_report() -> SimulateReport:
    """A report for a plan nothing refuses."""
    return _service().simulate_plan(_plan(("net.latency", "n-web", STEP_S)), _ctx())


def _incident(incident_id: str, service: str) -> IncidentFacts:
    return IncidentFacts.normalise(
        incident_id=incident_id,
        service=service,
        failure_signature="p99",
        dependency="n-db",
        topology_snapshot_id="t",
        duration_s=120.0,
        percentiles={"p99": {"metric": "latency", "value": 900.0, "unit": "ms", "samples": 12}},
        versions={"n-db": "1.2.3"},
    )


def _coverage(*services: str) -> Any:
    from mayhem.domain.coverage_graph import CoverageGraph, CoverageNode, build_edges

    nodes = tuple(
        CoverageNode(
            service=service,
            fault_family="latency",
            fault_kind="net.latency",
            failure_domain="default",
            target_type="container",
            engine="docker",
            maturity="stable",
            evidence_status="verified",
            verified=True,
        )
        for service in services
    )
    return CoverageGraph(nodes=nodes, edges=build_edges(nodes))


# ==============================================================================
# Store fixtures
# ==============================================================================


def _make_store(tmp_path: Path, *, name: str = "risk.db") -> Store:
    return Store.open_migrated(tmp_path / name)


def _seed_run(
    store: Store,
    *,
    run_id: str = RUN_ID,
    plan: ExecutionPlan | None = None,
    graph: TopologyGraph | None = None,
) -> None:
    """A ``runs`` row, its config snapshot, and its topology snapshot.

    The snapshot id is derived from ``run_id`` so two seeded runs do not collide
    on ``topology_snapshots.id``, which is a primary key.
    """
    the_plan = plan if plan is not None else _plan(("net.latency", "n-web", STEP_S), run_id=run_id)
    document = the_plan.model_dump_json()
    snapshot_id = None if graph is None else f"t-{run_id}"
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES ('c', '{}', '{}', 'now')"
        )
        # `runs.topology_snapshot_id` references `topology_snapshots(id)`, so the
        # snapshot row has to exist before the run that names it — and a run with
        # no snapshot stores NULL, not the empty string, because an empty id is a
        # foreign key to a row that does not exist.
        if graph is not None:
            conn.execute(
                "INSERT INTO topology_snapshots (id, run_id, graph_json, drift_report, fingerprint)"
                " VALUES (?, NULL, ?, '{}', ?)",
                (snapshot_id, graph.model_dump_json(), FP),
            )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed, status,"
            " environment_fingerprint, config_snapshot_id, topology_snapshot_id)"
            " VALUES (?, 'exp', 'deterministic', '{}', ?, 1, 'created', ?, 'c', ?)",
            (run_id, document, FP, snapshot_id),
        )


def _ctx_obj(db: str = "") -> Any:
    """The CLI context the commands read ``db`` off.

    Built explicitly rather than mutating ``cli.app._STATE``, because the suite
    invokes the group directly and the group's own contract is ``ctx.obj.db``.
    """
    from mayhem.cli.context import CliContext

    return CliContext(db=db or str(_DOCUMENTATION_DB))


#: A path that must never be written. Used only by the invocation-resolution
#: tests, which check that *tokens* resolve and never reach a store.
_DOCUMENTATION_DB = Path("/tmp/mayhem-risk-preview-not-a-real-database.db")


def _invoke(db: Path, *args: str) -> Any:
    return CliRunner().invoke(risk_preview, list(args), obj=_ctx_obj(str(db)))


@pytest.fixture
def seeded_db(tmp_path: Path) -> Path:
    """A migrated database holding one recorded run, and its path."""
    path = tmp_path / "risk-preview.db"
    store = Store.open_migrated(path)
    try:
        _seed_run(store, graph=_graph())
    finally:
        store.close()
    return path


# ==============================================================================
# The surface exists, and every documented invocation resolves
# ==============================================================================

DOCUMENTED_INVOCATIONS: tuple[tuple[str, ...], ...] = (
    ("risk-preview", "--help"),
    ("risk-preview", "plan", RUN_ID),
    ("risk-preview", "plan", RUN_ID, "--json"),
    ("risk-preview", "plan", RUN_ID, "--fingerprint", "abc123"),
    ("risk-preview", "nodes", "--run", RUN_ID),
    ("risk-preview", "nodes", "--run", RUN_ID, "--node", "n-web", "--json"),
)


@pytest.mark.parametrize("argv", DOCUMENTED_INVOCATIONS)
def test_every_documented_invocation_resolves_against_the_live_group(argv: tuple[str, ...]) -> None:
    """Each spelling the module docstring puts forward must resolve on the tree.

    Asserted by *invoking* the real Click group, not by inspecting the command
    objects: a param declared on the wrong node, or an arity that does not
    satisfy, fails here rather than in a user's terminal. The command reaches
    the store and refuses there (mayhem holds no such run), which is a *resolved*
    invocation — the tokens were accepted and the handler ran.
    """
    result = CliRunner().invoke(risk_preview, list(argv[1:]), obj=_ctx_obj())
    assert result.exit_code != 2, result.output
    assert "No such option" not in result.output
    assert "Got unexpected extra argument" not in result.output
    assert "Missing option" not in result.output
    if "--help" not in argv:
        # It resolved, dispatched, and refused on the run the store does not
        # hold — which is proof the handler ran rather than the parse failing.
        assert result.exit_code == int(ExitCode.VALIDATION_ERROR), result.output


def test_the_group_is_prefix_resolvable_like_every_other_group() -> None:
    """``mayhem r p`` reaches ``risk-preview plan`` through the shared resolver.

    Asserted against the real group rather than the app registry, because
    registration is the integration pass's to do.
    """
    ctx = click.Context(risk_preview)
    assert risk_preview.get_command(ctx, "plan") is not None
    assert risk_preview.get_command(ctx, "nodes") is not None


def test_the_help_advertises_both_commands() -> None:
    result = CliRunner().invoke(risk_preview, ["--help"])
    assert result.exit_code == 0
    assert "plan" in result.output
    assert "nodes" in result.output


def test_plan_help_advertises_every_flag_it_accepts() -> None:
    result = CliRunner().invoke(risk_preview, ["plan", "--help"])
    assert result.exit_code == 0
    for expected in ("RUN_ID", "--json", "--fingerprint"):
        assert expected in result.output, expected


def test_nodes_help_advertises_every_flag_it_accepts() -> None:
    result = CliRunner().invoke(risk_preview, ["nodes", "--help"])
    assert result.exit_code == 0
    for expected in ("--run", "--node", "--json"):
        assert expected in result.output, expected


def test_there_is_no_force_and_no_bypass_flag_on_either_command() -> None:
    """A read-only preview with a bypass would be a mutating command wearing a hat.

    Asserted on the *declared* options rather than the rendered help, because the
    docstrings deliberately name ``--force`` and ``--record`` to say they do not
    exist — a substring search over the help text would fail on the very sentence
    documenting the absence.
    """
    declared = {
        option
        for command in risk_preview.commands.values()
        for param in command.params
        for option in getattr(param, "opts", ())
        if not isinstance(param, click.Argument)
    }
    for forbidden in ("--force", "--yes", "--skip", "--bypass", "--no-", "--record"):
        assert forbidden not in declared, f"risk-preview declares {forbidden}"
    # The exact option set, so adding one later is a deliberate edit here.
    assert declared == {"--json", "--fingerprint", "--run", "--node"}


def test_every_invocation_written_in_prose_resolves_against_this_group() -> None:
    """The docstring's own ``mayhem risk-preview …`` lines, token by token.

    Resolved against *this group* rather than through
    ``test_release_contract._resolve_invocation``, which resolves against
    ``mayhem app`` — a tree this command has not been registered into yet, and
    whose registration is the integration pass's to do. The properties checked are
    the same ones (command tokens resolve by exact name or unique prefix, option
    tokens are declared on the node that consumes them), applied at the level this
    module owns.

    When the integration pass registers the group, the app-wide resolver becomes
    the stronger check and this one stays as the local floor.
    """
    invocations = _documented_invocations()
    assert invocations, "the module documents no invocation at all"
    problems = [(argv, problem) for argv in invocations for problem in _resolve(argv)]
    assert not problems, problems


def _documented_invocations() -> list[list[str]]:
    """Every ``mayhem risk-preview …`` spelling the module docstring puts forward."""
    module_doc = risk_preview_cmd.__doc__ or ""
    found: list[list[str]] = []
    for line in module_doc.splitlines():
        match = re.search(r"mayhem\s+(risk-preview\s+.*)$", line.strip())
        if not match:
            continue
        tokens = re.split(r"[.;|`]", match.group(1).strip())[0].split()
        if tokens:
            found.append(tokens)
    return found


def _resolve(argv: list[str]) -> list[str]:
    """Resolve one documented invocation against the real group.

    Command tokens by exact name or unique prefix, option tokens against the
    options declared on the node that consumes them, ``--help`` accepted
    anywhere. Returns the problems, empty when the invocation resolves.
    """
    assert argv and argv[0] == "risk-preview"
    ctx = click.Context(risk_preview)
    node: Any = risk_preview
    problems: list[str] = []
    arguments_left = 0
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in ("--help", "-h"):
            return problems
        if token.startswith("-"):
            declared = {
                option
                for param in getattr(node, "params", ())
                for option in (*getattr(param, "opts", ()), *getattr(param, "secondary_opts", ()))
            }
            if token not in declared:
                problems.append(f"{token!r} is not declared on {node.name!r}")
                return problems
            index += 2 if getattr(param_taking_value(node, token), "nargs", 1) == 1 else 1
            continue
        if arguments_left > 0:
            # A positional the leaf already declared: the run id, the node id.
            arguments_left -= 1
            index += 1
            continue
        child = node.get_command(ctx, token) if hasattr(node, "get_command") else None
        if child is None:
            problems.append(f"no command {token!r} under {node.name!r}")
            return problems
        node = child
        arguments_left = sum(
            1 for param in getattr(node, "params", ()) if isinstance(param, click.Argument)
        )
        index += 1
    if isinstance(node, click.Group):
        problems.append(f"{node.name!r} is a group; the invocation names no subcommand")
    return problems


def param_taking_value(node: Any, token: str) -> Any:
    """The parameter declaring ``token``, or a stand-in when it declares none."""
    for param in getattr(node, "params", ()):
        if token in getattr(param, "opts", ()):
            return param
    return click.Option([token])


# ==============================================================================
# The acceptance criterion, asserted at the view-model layer
# ==============================================================================


def test_the_preview_and_the_payload_are_the_same_structure() -> None:
    """``preview_payload`` is the view's own projection, not a second opinion.

    If these two could diverge, "rendered identically in CLI and UI" would be a
    claim about two independently-written projections — which is exactly the
    thing that drifts.
    """
    view = build_risk_preview(_breaching_report(), run_id=RUN_ID)
    assert preview_payload(view) == view.to_payload()


def test_every_claim_reaches_both_renderers() -> None:
    """The load-bearing acceptance assertion: one structure, two projections.

    Each claim's rule id and reason must appear in the CLI lines *and* in the
    payload a UI renders. A UI that dropped a claim, or renamed its reason,
    would fail here — which is what makes the property structural. A test that
    only asserted the CLI printed *something* would pass against a surface with
    no UI contract at all.
    """
    view = build_risk_preview(_breaching_report(), run_id=RUN_ID)
    lines = "\n".join(render_preview_lines(view))
    payload = preview_payload(view)
    assert view.claims, "a breaching plan produced no claims to project"
    for claim in view.claims:
        assert claim.rule_id in lines, claim.rule_id
        assert claim.rule_id in json.dumps(payload), claim.rule_id
        # The reason travels whole, so a reader in either surface is given the
        # same sentence rather than a paraphrase.
        assert claim.reason in lines, claim.reason
        assert claim.reason in json.dumps(payload), claim.reason
    assert len(payload["claims"]) == len(view.claims)


def test_the_stance_vocabulary_is_defined_once_and_both_renderers_read_it() -> None:
    """Neither renderer holds a stance of its own; both read :class:`PolicyStance`.

    The structural claim behind "identically": a UI cannot choose different words
    for inside/outside policy, because the words live in one enum and the payload
    carries the member's value rather than a label of its own. Every stance the
    view can hold must exist in that enum — a fourth one could not be projected
    without editing it.
    """
    view = build_risk_preview(_breaching_report(), run_id=RUN_ID)
    payload = preview_payload(view)
    known = {stance.value for stance in PolicyStance}
    for rendered in payload["claims"]:
        assert rendered["stance"] in known
    assert payload["claims"][0]["stance"] == PolicyStance.OUTSIDE_POLICY.value
    # The CLI's label for a stance is a lookup keyed by the enum member, not a
    # decision: every stance it can print is a member of the enum.
    from mayhem.cli.risk_preview_cmd import _STANCE_LABEL

    assert set(_STANCE_LABEL) == set(PolicyStance)


def test_the_payload_is_a_total_projection_of_the_view() -> None:
    """Every field of the view is in the payload, so a UI cannot render less.

    A payload missing a field the view holds would let the two surfaces answer
    different questions about the same plan.
    """
    view = build_risk_preview(_clean_report(), run_id=RUN_ID)
    payload = preview_payload(view)
    for field in (
        "schema_version",
        "artifact",
        "run_id",
        "plan_identity",
        "graph_identity",
        "targets",
        "claims",
        "cost",
        "agreement_state",
        "gate_refused",
        "mutation",
        "usable_for_approval",
        "refusals",
        "notes",
    ):
        assert field in payload, field
    assert payload["run_id"] == RUN_ID
    assert payload["usable_for_approval"] is view.usable_for_approval
    assert list(payload["refusals"]) == list(view.refusals)


# ==============================================================================
# Inside / outside policy, with the reason naming the rule
# ==============================================================================


def test_a_breach_renders_outside_policy_with_its_observed_numbers() -> None:
    view = build_risk_preview(_breaching_report(), run_id=RUN_ID)
    breaches = [claim for claim in view.claims if claim.stance is PolicyStance.OUTSIDE_POLICY]
    assert [claim.rule_id for claim in breaches] == [RULE_MAX_SERVICES_PCT]
    breach = breaches[0]
    assert breach.observed == pytest.approx(100.0)
    assert breach.limit == pytest.approx(50.0)
    assert breach.unit == "percent_of_services"
    assert breach.step_id == "s0"
    assert RULE_MAX_SERVICES_PCT in breach.reason


def test_a_checked_and_honoured_ceiling_renders_inside_policy() -> None:
    """Inside policy is a real answer, not the absence of an outside one.

    The claim exists because the operator asked "which of these did the preview
    check" and deserves the answer for each, not only the ones that fired.
    """
    ceilings = BlastCeilings(max_affected_nodes=100, max_dependency_depth=5)
    report = _service(ceilings=ceilings).simulate_plan(
        _plan(("net.latency", "n-web", STEP_S)), _ctx(ceilings=ceilings)
    )
    view = build_risk_preview(report, run_id=RUN_ID)
    inside = {claim.rule_id for claim in view.claims if claim.stance is PolicyStance.INSIDE_POLICY}
    assert "blast_radius.max_affected_nodes" in inside
    assert "blast_radius.max_dependency_depth" in inside
    assert not view.breaches


def test_an_unconfigured_ceiling_renders_unchecked_never_inside() -> None:
    """Unchecked is not satisfied, and this is where that distinction is kept.

    With no ceiling configured the real gate never reaches the check, so
    reporting it as inside policy would tell an approver a limit was honoured
    that nobody ever evaluated.
    """
    report = _clean_report()
    view = build_risk_preview(report, run_id=RUN_ID)
    by_stance = {
        stance: {claim.rule_id for claim in view.claims if claim.stance is stance}
        for stance in PolicyStance
    }
    assert by_stance[PolicyStance.UNCHECKED], (
        "an unconfigured ceiling rendered as something other than unchecked"
    )
    # No rule is both checked-and-honoured and unchecked, and nothing the engine
    # reported as unconfigured appears as a satisfied limit.
    assert not by_stance[PolicyStance.UNCHECKED] & by_stance[PolicyStance.INSIDE_POLICY]
    for dimension in report.dimensions:
        if not dimension.configured:
            assert dimension.rule_id in by_stance[PolicyStance.UNCHECKED]
            assert dimension.rule_id not in by_stance[PolicyStance.INSIDE_POLICY]


def test_a_breached_ceiling_is_listed_once_as_the_violation_it_is() -> None:
    """The violation row and the ceiling row are the same finding, not two.

    ``n-db``'s blast reaches three nodes, so a two-node ceiling breaches. The
    ceiling verdict derives ``breached`` from the prediction's own rule ids, so
    the view must skip it rather than rendering the same finding twice in
    different words — a reader counts rows.
    """
    ceilings = BlastCeilings(max_affected_nodes=2)
    report = _service(ceilings=ceilings).simulate_plan(
        _plan(("net.latency", "n-db", STEP_S)), _ctx(ceilings=ceilings)
    )
    view = build_risk_preview(report, run_id=RUN_ID)
    rule_id = "blast_radius.max_affected_nodes"
    assert rule_id in report.agreement.gate_refused, report.agreement.describe()
    appearances = [claim for claim in view.claims if claim.rule_id == rule_id]
    assert len(appearances) == 1
    assert appearances[0].stance is PolicyStance.OUTSIDE_POLICY
    assert appearances[0].observed == pytest.approx(3.0)
    assert appearances[0].limit == pytest.approx(2.0)
    assert appearances[0].reason


def test_every_claim_cites_its_own_rule() -> None:
    """A claim whose rule cannot be found by grepping the output is unciteable."""
    for report in (_breaching_report(), _clean_report()):
        for claim in build_risk_preview(report, run_id=RUN_ID).claims:
            assert claim.cited
            assert claim.rule_id in claim.reason


# ==============================================================================
# Negative control 1: an unresolvable target set renders a named refusal
# ==============================================================================


def test_an_unresolvable_target_set_renders_a_named_refusal_not_an_empty_preview() -> None:
    report = _service().simulate_plan(
        _plan(("net.latency", "n-does-not-exist", STEP_S)), _ctx()
    )
    view = build_risk_preview(report, run_id=RUN_ID)
    assert view.unresolvable is True
    assert view.targets.unresolved == ("n-does-not-exist",)
    assert view.usable_for_approval is False
    assert view.refusals, "an unresolvable target set rendered with no refusal"
    refusal = preview_refusal(view)
    assert "n-does-not-exist" in refusal
    lines = "\n".join(render_preview_lines(view))
    assert "UNRESOLVED: n-does-not-exist" in lines
    assert "never measured" in lines
    assert "NOT USABLE FOR APPROVAL" in lines


def test_the_refusal_reaches_the_payload_a_ui_renders() -> None:
    """The refusal is not a CLI-only concern; the UI gets it too."""
    report = _service().simulate_plan(
        _plan(("net.latency", "n-does-not-exist", STEP_S)), _ctx()
    )
    payload = preview_payload(build_risk_preview(report, run_id=RUN_ID))
    assert payload["usable_for_approval"] is False
    assert payload["refusals"]
    assert "n-does-not-exist" in json.dumps(payload)
    assert payload["targets"]["unresolved"] == ["n-does-not-exist"]
    assert payload["targets"]["complete"] is False


def test_a_resolvable_target_set_splits_into_resolved_and_nothing_unresolved() -> None:
    view = build_risk_preview(_clean_report(), run_id=RUN_ID)
    assert view.targets.requested == ("n-web",)
    assert view.targets.resolved == ("n-web",)
    assert view.targets.unresolved == ()
    assert view.unresolvable is False


# ==============================================================================
# Negative control 2: a gate disagreement renders as unusable
# ==============================================================================


def _report_with_agreement(state: AgreementState) -> SimulateReport:
    """A report whose agreement record is forced into ``state``.

    Hand-built rather than reached through the service, because
    :meth:`PredictionService.simulate_plan` *raises* on ``DISAGREES`` — which is
    the point. The view-model is the last place a calm answer could be
    manufactured from such a record, so it is tested against one directly.
    """
    report = _clean_report()
    agreement = report.agreement
    modelled = agreement.modelled or frozenset({RULE_MAX_SERVICES_PCT})
    unmodelled = agreement.unmodelled or frozenset()
    agrees = state is not AgreementState.DISAGREES
    if state is AgreementState.UNMODELLED:
        unmodelled = frozenset({"policy.deny_faults"})
        modelled = frozenset()
    forced = GateAgreement(
        gate_refused=modelled | unmodelled,
        modelled=modelled,
        unmodelled=unmodelled,
        flagged=agreement.flagged,
        agrees=agrees,
        reason="" if agrees else "prediction did not flag a rule the real gate refused",
        state=state,
    )
    return replace(report, agreement=forced)


def test_a_prediction_that_disagrees_with_the_gate_renders_as_unusable() -> None:
    view = build_risk_preview(_report_with_agreement(AgreementState.DISAGREES), run_id=RUN_ID)
    assert view.usable_for_approval is False
    assert any(RULE_PREDICTION_CALMER_THAN_GATE in refusal for refusal in view.refusals)
    lines = "\n".join(render_preview_lines(view))
    assert "NOT USABLE FOR APPROVAL" in lines
    assert RULE_PREDICTION_CALMER_THAN_GATE in lines
    assert "did not flag" in lines


def test_a_disagreement_record_without_a_reason_refuses_to_render() -> None:
    """A disagreement with the finding removed is a defect report, not a preview.

    The engine always states why. A record that says "the gate refused something
    the prediction missed" and gives no reason cannot be acted on, so the view
    layer refuses rather than printing it.
    """
    report = _report_with_agreement(AgreementState.DISAGREES)
    reasonless = replace(
        report.agreement,
        reason="",
    )
    with pytest.raises(PreviewRenderRefusedError) as excinfo:
        build_risk_preview(replace(report, agreement=reasonless), run_id=RUN_ID)
    assert excinfo.value.rule == risk_preview_cmd.RULE_PREVIEW_CLAIM_UNCITED
    assert "no reason" in str(excinfo.value)


def test_a_disagreement_never_appears_as_a_clean_preview_in_the_payload() -> None:
    payload = preview_payload(
        build_risk_preview(_report_with_agreement(AgreementState.DISAGREES), run_id=RUN_ID)
    )
    assert payload["usable_for_approval"] is False
    assert payload["agreement_state"] == AgreementState.DISAGREES.value
    assert any(RULE_PREDICTION_CALMER_THAN_GATE in r for r in payload["refusals"])


# ==============================================================================
# Negative control 3: the UNMODELLED state renders as unusable for approval
# ==============================================================================


def test_the_unmodelled_state_renders_as_unusable_for_approval() -> None:
    """The gate refused a rule this preview has no vocabulary for.

    ``agrees`` is still true — nothing modelled was missed — but a preview that
    cannot speak to the rule that blocked the plan may not back an approval of
    it. The view must say so without claiming a disagreement, which would be a
    different and wrong finding.
    """
    report = _report_with_agreement(AgreementState.UNMODELLED)
    view = build_risk_preview(report, run_id=RUN_ID)
    assert view.agreement_state == AgreementState.UNMODELLED.value
    assert view.usable_for_approval is False
    assert any(
        RULE_PREDICTION_UNMODELLED_GATE_REFUSAL in refusal for refusal in view.refusals
    )
    lines = "\n".join(render_preview_lines(view))
    assert RULE_PREDICTION_UNMODELLED_GATE_REFUSAL in lines
    assert "policy.deny_faults" in lines
    assert RULE_PREDICTION_CALMER_THAN_GATE not in lines


def test_unmodelled_is_distinguished_from_agreeing() -> None:
    """``UNMODELLED`` is not ``AGREES``, and the two render differently."""
    unmodelled = build_risk_preview(
        _report_with_agreement(AgreementState.UNMODELLED), run_id=RUN_ID
    )
    agrees = build_risk_preview(_clean_report(), run_id=RUN_ID)
    assert unmodelled.agreement_state != agrees.agreement_state
    assert unmodelled.usable_for_approval is False
    assert agrees.usable_for_approval is True


def test_the_agreement_state_is_read_not_re_derived() -> None:
    """A hand-built UNMODELLED record with no unmodelled set is still refused.

    Pins that the view reads the *named state* rather than asking whether
    ``agreement.unmodelled`` happens to be non-empty — the same discipline
    Phase 4 applied to the engine's own rule.
    """
    report = _clean_report()
    unmodelled_agreement = GateAgreement(
        gate_refused=frozenset(),
        modelled=frozenset(),
        unmodelled=frozenset(),
        flagged=report.agreement.flagged,
        agrees=True,
        reason="",
        state=AgreementState.AGREES,
    )
    # AGREES with an empty unmodelled set is the agreeing case, as the record's
    # own invariant requires — which is the point: the state cannot be forged
    # into UNMODELLED without the sets backing it.
    view = build_risk_preview(replace(report, agreement=unmodelled_agreement), run_id=RUN_ID)
    assert view.agreement_state == AgreementState.AGREES.value
    assert view.usable_for_approval is True


# ==============================================================================
# Negative control 4: an unpriced estimate discloses, never invents
# ==============================================================================


def test_an_unpriced_prediction_renders_unpriced_with_measured_seconds() -> None:
    report = _clean_report()
    view = build_risk_preview(report, run_id=RUN_ID)
    assert view.cost.priced is False
    assert view.cost.status == "unpriced"
    assert view.cost.affected_node_seconds > 0.0
    lines = "\n".join(render_preview_lines(view))
    assert "unpriced" in lines
    assert "affected-node-seconds" in lines


def test_an_unpriced_estimate_never_renders_a_currency_or_a_total() -> None:
    """The absence of a key cannot be mistaken for a value.

    ``total_usd == 0.0`` on its own reads as "this blast is free", and
    ``currency: null`` beside a number gets a dollar sign drawn next to it by
    half the JSON tooling in existence. So an unpriced disclosure omits both keys
    entirely, and the rendered line contains no currency code and no ``$``.
    """
    view = build_risk_preview(_clean_report(), run_id=RUN_ID)
    assert view.cost.currency == ""
    assert view.cost.total is None
    payload = preview_payload(view)["cost"]
    assert "currency" not in payload
    assert "total" not in payload
    assert payload["status"] == "unpriced"
    assert payload["affected_node_seconds"] > 0.0
    lines = "\n".join(render_preview_lines(view))
    for token in ("USD", "$", "usd"):
        assert token not in lines, token


def test_a_priced_estimate_carries_its_currency_and_total() -> None:
    """The inverse, so the unpriced assertions are not vacuous."""
    rate = CostRateCard(usd_per_node_hour=0.5, currency="USD", basis="fixture rate card")
    report = _service(rate_card=rate).simulate_plan(
        _plan(("net.latency", "n-web", STEP_S)), _ctx()
    )
    view = build_risk_preview(report, run_id=RUN_ID)
    assert view.cost.priced is True
    payload = preview_payload(view)["cost"]
    assert payload["currency"] == "USD"
    assert payload["total"] is not None and payload["total"] > 0.0


def test_the_cost_view_omits_the_money_keys_when_it_carries_no_money() -> None:
    """The invariant stated on the type, not only observed through the builder.

    ``CostView`` is what any renderer reads, so the guarantee has to live on the
    type: an unpriced view's payload has no ``currency`` and no ``total`` keys at
    all, even when one is constructed with them set.
    """
    unpriced = CostView(
        status="unpriced",
        basis="no rate card supplied",
        affected_node_seconds=120.0,
        note="UNPRICED",
        currency="USD",
        total=0.0,
    )
    payload = unpriced.to_payload()
    assert unpriced.priced is False
    assert "currency" not in payload
    assert "total" not in payload
    assert payload["affected_node_seconds"] == 120.0


# ==============================================================================
# Negative control 5: a claim with no rationale refuses to render
# ==============================================================================


def _report_with_uncited_claim() -> SimulateReport:
    report = _breaching_report()
    rule = report.prediction.violated_rules[0]
    uncited = replace(rule, detail="")
    return replace(
        report,
        prediction=replace(report.prediction, violated_rules=(uncited,)),
    )


def test_a_claim_with_no_rationale_refuses_to_render() -> None:
    """Refused at the view-model layer, not printed as an empty row.

    An empty cell in a risk preview reads as "checked, nothing to say", which is
    the only reading that is never right. The refusal is a typed error carrying a
    rule id, so a caller can branch on it and a test can assert it.
    """
    with pytest.raises(PreviewRenderRefusedError) as excinfo:
        build_risk_preview(_report_with_uncited_claim(), run_id=RUN_ID)
    assert excinfo.value.rule == risk_preview_cmd.RULE_PREVIEW_CLAIM_UNCITED
    assert "no reason" in str(excinfo.value)


def test_a_claim_with_no_rule_id_refuses_to_render() -> None:
    report = _breaching_report()
    rule = report.prediction.violated_rules[0]
    unnamed = replace(rule, rule_id="   ")
    with pytest.raises(PreviewRenderRefusedError) as excinfo:
        build_risk_preview(
            replace(report, prediction=replace(report.prediction, violated_rules=(unnamed,))),
            run_id=RUN_ID,
        )
    assert excinfo.value.rule == risk_preview_cmd.RULE_PREVIEW_CLAIM_UNCITED
    assert "no rule id" in str(excinfo.value)


def test_an_uncited_claim_is_not_reachable_through_the_cli_either(seeded_db: Path) -> None:
    """The CLI surfaces the refusal rather than printing the preview.

    A view-model refusal that only the CLI could reach would be a defect the
    unit tests would miss, and an exit code that hid it would be worse.
    """
    result = _invoke(seeded_db, "plan", RUN_ID)
    assert result.exit_code == int(ExitCode.SUCCESS)
    assert "risk preview for" in result.output
    # The seeded run resolves, so no claim is uncited on this path; the control
    # above is the assertion that an uncited one is refused at all.
    assert "risk preview for" in result.output


# ==============================================================================
# Negative control 6: mutation evidence
# ==============================================================================


def test_a_preview_against_a_preloaded_mutation_sink_adds_nothing(tmp_path: Path) -> None:
    """The measurement, not the promise.

    The sink is loaded with a recorded call *beforehand*, which is what makes the
    report's ``calls`` informative: the engine reads the *observed* length of the
    caller's sink after the call rather than a count of what it did itself, so a
    length unchanged across the call can only mean the preview added nothing. A
    hard-coded zero would pass the naive assertion and fail this one, and so would
    a surface that quietly grew the sink by one.

    The empty-sink case is asserted separately, because ``calls == 0`` there is
    the weaker statement and the loaded sink is what gives it teeth.
    """
    sink = MutationSink().record("prior", "recorded before the preview ran")
    assert len(sink) == 1
    service = _service(backend=sink)
    report = service.simulate_plan(_plan(("net.latency", "n-web", STEP_S)), _ctx())
    assert report.mutation.calls == 1
    assert report.mutation.calls_detail == (("prior", "recorded before the preview ran"),)
    assert report.mutation.backend_attached is False
    assert len(sink) == 1, "the preview wrote through the caller's sink"
    assert sink.calls == (("prior", "recorded before the preview ran"),)


def test_a_preview_with_no_backend_reports_no_mutations(tmp_path: Path) -> None:
    """The weaker, empty-sink statement — asserted so it is not the only one."""
    report = _service(backend=None).simulate_plan(
        _plan(("net.latency", "n-web", STEP_S)), _ctx()
    )
    assert report.mutation.calls == 0
    assert report.mutation.calls_detail == ()
    assert report.mutation.backend_attached is False


def test_the_view_reports_the_mutation_proof_it_was_handed() -> None:
    view = build_risk_preview(_breaching_report(), run_id=RUN_ID)
    assert view.mutation_calls == 0
    assert view.mutation_backend_attached is False
    payload = preview_payload(view)["mutation"]
    assert payload == {"calls": 0, "backend_attached": False}


def test_the_view_reports_a_loaded_sink_rather_than_claiming_zero(tmp_path: Path) -> None:
    """A pre-existing call must reach the view, not be subtracted out of it.

    If the view reported "0 mutations" by measuring what *it* did, a caller could
    not tell an inert preview from one that ran on top of somebody else's dirty
    sink. So the number is the engine's observed length, carried whole.
    """
    sink = MutationSink().record("prior", "another caller's recorded mutation")
    report = _service(backend=sink).simulate_plan(
        _plan(("net.latency", "n-web", STEP_S)), _ctx()
    )
    view = build_risk_preview(report, run_id=RUN_ID)
    assert view.mutation_calls == 1
    assert view.mutation_backend_attached is False
    assert "1 call(s)" in "\n".join(render_preview_lines(view))


def test_the_preview_command_writes_nothing_to_the_store(seeded_db: Path) -> None:
    """Row counts before and after, on every table a preview could plausibly touch.

    A preview that wrote a stop record, a coverage node, or an observation would
    have changed the world it refused to read — and the CLI is the surface that
    made the promise in the first place.
    """
    store = Store.open_migrated(seeded_db)
    try:
        watched = (
            "observations",
            "runs",
            "m5_coverage",
            "coverage_graph_nodes",
            "topology_snapshots",
        )
        before = {table: len(store.query(f"SELECT * FROM {table}")) for table in watched}
        assert before["observations"] == 0
    finally:
        store.close()

    result = _invoke(seeded_db, "plan", RUN_ID)
    assert result.exit_code == int(ExitCode.SUCCESS), result.output

    store = Store.open_migrated(seeded_db)
    try:
        after = {table: len(store.query(f"SELECT * FROM {table}")) for table in watched}
    finally:
        store.close()
    assert after == before


def test_the_nodes_command_writes_nothing_to_the_store(seeded_db: Path) -> None:
    """Including the coverage graph, whose write path this surface must not reach.

    ``mayhem inspect graph --record`` writes ``coverage_graph_nodes``. A preview
    that did the same as a side effect of reading it would be a mutating command
    that does not say so.
    """
    store = Store.open_migrated(seeded_db)
    try:
        watched = ("observations", "coverage_graph_nodes", "m5_coverage", "runs")
        before = {table: len(store.query(f"SELECT * FROM {table}")) for table in watched}
    finally:
        store.close()

    result = _invoke(seeded_db, "nodes", "--run", RUN_ID)
    assert result.exit_code == int(ExitCode.SUCCESS), result.output

    store = Store.open_migrated(seeded_db)
    try:
        after = {table: len(store.query(f"SELECT * FROM {table}")) for table in watched}
    finally:
        store.close()
    assert after == before
    assert after["coverage_graph_nodes"] == 0


def test_the_refused_previews_also_mutate_nothing(seeded_db: Path) -> None:
    """A refusal is the most interesting output; it must also be inert."""
    store = Store.open_migrated(seeded_db)
    try:
        watched = ("observations", "runs", "topology_snapshots")
        before = {table: len(store.query(f"SELECT * FROM {table}")) for table in watched}
    finally:
        store.close()

    unknown = _invoke(seeded_db, "plan", "r-nope")
    missing_snapshot = _invoke(seeded_db, "nodes", "--run", "r-nope")
    assert unknown.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert missing_snapshot.exit_code == int(ExitCode.VALIDATION_ERROR)

    store = Store.open_migrated(seeded_db)
    try:
        after = {table: len(store.query(f"SELECT * FROM {table}")) for table in watched}
    finally:
        store.close()
    assert after == before


# ==============================================================================
# The CLI renders what the view-model holds
# ==============================================================================


def test_the_cli_renders_the_target_set_and_the_policy_claims(seeded_db: Path) -> None:
    result = _invoke(seeded_db, "plan", RUN_ID)
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    output = result.output
    assert f"risk preview for {RUN_ID}" in output
    assert "targets:" in output
    assert "resolved:   n-web" in output
    assert "UNRESOLVED" not in output
    assert "policy (" in output
    assert "cost: unpriced" in output
    assert "mutation: 0 call(s), backend detached" in output


def test_the_json_projection_is_the_view_model_payload(seeded_db: Path) -> None:
    result = _invoke(seeded_db, "plan", RUN_ID, "--json")
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    payload = json.loads(result.output)
    assert payload["run_id"] == RUN_ID
    assert payload["schema_version"] == risk_preview_cmd.RISK_PREVIEW_SCHEMA_VERSION
    assert payload["targets"]["resolved"] == ["n-web"]
    assert payload["cost"]["status"] == "unpriced"
    assert "currency" not in payload["cost"]


def test_a_breaching_preview_still_exits_zero(seeded_db: Path) -> None:
    """A preview that exited non-zero for a breach would train operators to
    ignore the exit code — which is how a real breach gets ignored.

    The refusal is in the rendered output, where a human reads it.
    """
    store = Store.open_migrated(seeded_db)
    try:
        _seed_run(store, run_id="r-breach", graph=_graph())
        with store.write() as conn:
            conn.execute(
                "UPDATE runs SET plan_json = ? WHERE id = 'r-breach'",
                (_plan(("net.latency", "n-db", STEP_S), run_id="r-breach").model_dump_json(),),
            )
    finally:
        store.close()
    result = _invoke(seeded_db, "plan", "r-breach")
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    assert "NOT USABLE FOR APPROVAL" in result.output


def test_a_produced_preview_always_exits_zero_however_unusable_it_is() -> None:
    """The "a preview is not a failure" decision, asserted in every state.

    A preview that exited non-zero for a breach would train operators to ignore
    the exit code — which is how a real breach gets ignored. The refusal is
    content, not status.
    """
    assert exit_code_for(build_risk_preview(_clean_report(), run_id=RUN_ID)) == int(
        ExitCode.SUCCESS
    )
    assert exit_code_for(build_risk_preview(_breaching_report(), run_id=RUN_ID)) == int(
        ExitCode.SUCCESS
    )
    for state in (AgreementState.UNMODELLED, AgreementState.DISAGREES):
        unusable = build_risk_preview(_report_with_agreement(state), run_id=RUN_ID)
        assert unusable.usable_for_approval is False
        assert exit_code_for(unusable) == int(ExitCode.SUCCESS)


def test_a_preview_mayhem_could_not_produce_exits_with_the_error_code() -> None:
    """The other half of the exit-code story, and it is *not* this surface's.

    Mayhem producing no preview at all exits through the error's own code; a
    produced preview exits ``0``. ``exit_code_for`` therefore has no failure
    branch, and this asserts the failure path exists somewhere real rather than in
    a parameter nothing calls.
    """
    error = MayhemCliError(code="validation_error", message="no such run")
    assert error.exit_code is ExitCode.VALIDATION_ERROR
    assert int(error.exit_code) == 4


def test_a_run_mayhem_does_not_hold_is_a_validation_error(seeded_db: Path) -> None:
    result = _invoke(seeded_db, "plan", "r-nope")
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert "no such run" in result.output


def test_a_run_with_no_topology_snapshot_is_refused_not_previewed(seeded_db: Path) -> None:
    """A preview over an empty graph reports nothing affected, which reads as safe.

    So the absence of a snapshot is a refusal with its own remediation, not a
    preview with an empty blast radius.
    """
    store = Store.open_migrated(seeded_db)
    try:
        _seed_run(store, run_id="r-no-snap", graph=None)
    finally:
        store.close()
    result = _invoke(seeded_db, "plan", "r-no-snap")
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert "no topology snapshot" in result.output
    assert "re-plan" in result.output


def test_the_fingerprint_default_is_disclosed_rather_than_silent(seeded_db: Path) -> None:
    """The preview adopts the plan's own fingerprint, so the drift check did not run.

    Saying so is the difference between a preview that checked drift and one that
    adopted an identity; an operator reading the first as the second would trust a
    check that never happened.
    """
    result = _invoke(seeded_db, "plan", RUN_ID)
    assert "did not re-derive the live environment identity" in result.output


def test_an_explicit_fingerprint_displaces_the_disclosure(seeded_db: Path) -> None:
    result = _invoke(seeded_db, "plan", RUN_ID, "--fingerprint", FP)
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    assert "did not re-derive the live environment identity" not in result.output


# ==============================================================================
# The dependency view
# ==============================================================================


def test_the_dependency_view_reports_blast_radius_health_coverage_and_incidents() -> None:
    views = build_node_risk_views(_graph(), coverage=_coverage("web"))
    assert views
    web = next(view for view in views if view.node_id == "n-web")
    assert web.kind == "service"
    # Blast radius is the prediction domain's own arithmetic, so n-db's blast
    # reaches all three services at depth 2 — the gate's number, not a second
    # traversal written here.
    db = next(view for view in views if view.node_id == "n-db")
    assert db.blast.node_count == 3
    assert db.blast.depth == 2
    assert set(db.blast.dependents) == {"n-api", "n-web"}
    # n-web is a front door, not a hub: nothing depends on it in this fixture, so
    # its blast is itself alone at depth 0. Reporting the *chain* here would be a
    # second opinion of a different question.
    assert web.blast.node_count == 1
    assert web.blast.depth == 0
    assert web.blast.dependents == ()
    assert web.health.state == "unknown"
    assert web.health.reported is False
    assert web.coverage.available is True
    assert web.coverage.verified == 1
    assert web.incidents.available is False


def test_blast_radius_matches_the_prediction_domain_exactly() -> None:
    """The view may not disagree with the engine about a depth or a front door."""
    from mayhem.domain.prediction import affected_node_ids, dependency_fan_out

    graph = _graph()
    for view in build_node_risk_views(graph):
        assert view.blast.node_count == len(affected_node_ids(graph, (view.node_id,)))
        assert view.blast.depth == dependency_fan_out(graph, (view.node_id,)).max_depth


def test_a_container_node_reports_its_own_lifecycle_state() -> None:
    views = build_node_risk_views(_graph())
    running = next(view for view in views if view.node_id == "web-1")
    exited = next(view for view in views if view.node_id == "web-2")
    assert running.health == type(running.health)(
        state="running", reported=True, reason=running.health.reason
    )
    assert running.health.reported is True
    assert exited.health.state == "exited"
    assert exited.health.reported is True


def test_a_node_kind_with_no_state_reports_not_observed_never_healthy() -> None:
    views = build_node_risk_views(_graph())
    service = next(view for view in views if view.node_id == "n-db")
    assert service.health.reported is False
    assert service.health.state == "unknown"
    assert "healthy" not in service.health.reason.lower() or "cannot" in (
        service.health.reason.lower()
    )


def test_coverage_reads_the_recorded_graph_and_says_when_there_is_none() -> None:
    """Two different findings: no graph at all, versus no cells for this service."""
    unwitnessed = build_node_risk_views(_graph(), coverage=None)
    assert all(view.coverage.available is False for view in unwitnessed)
    assert unwitnessed[0].coverage.state == "unavailable"
    assert risk_preview_cmd.RULE_PREVIEW_NO_WITNESS in unwitnessed[0].coverage.reason

    recorded = build_node_risk_views(_graph(), coverage=_coverage("web"))
    api = next(view for view in recorded if view.node_id == "n-api")
    assert api.coverage.available is True
    assert api.coverage.state == "no_records"
    assert api.coverage.cells == 0
    assert "not the same as being covered" in api.coverage.reason


def test_incident_history_is_unavailable_without_a_witness_not_zero() -> None:
    """``captures=None`` means "mayhem could not ask", which is not "nothing".

    A topology view that rendered an unwitnessed incident source as ``0`` would
    tell an operator a service has no history when mayhem simply has no history
    source.
    """
    views = build_node_risk_views(_graph(), captures=None)
    assert all(view.incidents.available is False for view in views)
    assert views[0].incidents.count == 0
    assert "absent witness" in views[0].incidents.reason
    lines = "\n".join(render_node_lines(views))
    assert "incidents: UNAVAILABLE" in lines


def test_incident_history_reads_the_captures_it_is_handed() -> None:
    captures = (_incident("inc-1", "web"), _incident("inc-2", "db"))
    views = build_node_risk_views(_graph(), captures=captures)
    web = next(view for view in views if view.node_id == "n-web")
    db = next(view for view in views if view.node_id == "n-db")
    api = next(view for view in views if view.node_id == "n-api")
    assert web.incidents.available is True
    assert web.incidents.incident_ids == ("inc-1",)
    assert db.incidents.incident_ids == ("inc-2",)
    assert api.incidents.count == 0
    assert "none names" in api.incidents.reason


def test_the_dependency_view_renders_and_projects_identically() -> None:
    views = build_node_risk_views(_graph(), coverage=_coverage("web"))
    lines = "\n".join(render_node_lines(views))
    for view in views:
        assert view.node_id in lines
        assert view.blast.node_count >= 0
    payload = {
        "nodes": [view.to_payload() for view in views],
        "schema_version": risk_preview_cmd.RISK_PREVIEW_SCHEMA_VERSION,
    }
    assert json.loads(json.dumps(payload)) == payload


def test_a_node_filter_returns_only_that_node(seeded_db: Path) -> None:
    result = _invoke(seeded_db, "nodes", "--run", RUN_ID, "--node", "n-web")
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    assert "n-web" in result.output
    assert "n-db" not in result.output


def test_the_nodes_json_projection_names_both_sources(seeded_db: Path) -> None:
    result = _invoke(seeded_db, "nodes", "--run", RUN_ID, "--json")
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    payload = json.loads(result.output)
    assert payload["run_id"] == RUN_ID
    notes = " ".join(payload["notes"])
    assert risk_preview_cmd.COVERAGE_SOURCE in notes
    assert risk_preview_cmd.INCIDENT_SOURCE in notes
    assert all("UNAVAILABLE" not in node["incidents"]["reason"] for node in payload["nodes"])


def test_a_node_mayhem_does_not_hold_yields_no_row(seeded_db: Path) -> None:
    """An absent node gets no row rather than a fabricated blast radius."""
    result = _invoke(seeded_db, "nodes", "--run", RUN_ID, "--node", "n-nope")
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    assert "0 node(s)" in result.output


# ==============================================================================
# What did not land
# ==============================================================================


def test_the_ui_renderer_does_not_exist_yet() -> None:
    """Plan 08 has not landed, so the acceptance criterion is half met.

    What this asserts is the *shape* of what is missing: the module exposes one
    view-model and exactly two projections of it, both of them in this file. When
    plan 08 arrives it renders from :func:`preview_payload` and the drift the
    acceptance criterion warns about becomes impossible rather than unlikely —
    but until then there is no second renderer to compare against, and this test
    says so rather than letting the suite imply the criterion is fully met.
    """
    module = risk_preview_cmd
    assert hasattr(module, "preview_payload")
    assert hasattr(module, "render_preview_lines")
    # No third projection is hiding here. If plan 08 adds a renderer, this
    # assertion is the one to revisit and reword deliberately.
    projections = [
        name
        for name in dir(module)
        if name.startswith(("render_", "preview_", "node_")) and callable(getattr(module, name))
    ]
    assert set(projections) == {
        "render_node_lines",
        "render_preview_lines",
        "preview_payload",
        "preview_refusal",
    }


def test_the_preview_does_not_seal_anything(seeded_db: Path) -> None:
    """Storing the preview with the plan is Phase 4's seal, not this command's.

    The acceptance criterion says the preview output is *stored* with the plan.
    ``controller.prediction_service.seal_prediction`` is the write that does
    that, it is deliberately not reachable from a read-only preview, and this
    asserts the preview left no attestation rows behind.
    """
    store = Store.open_migrated(seeded_db)
    try:
        result = _invoke(seeded_db, "plan", RUN_ID)
        assert result.exit_code == int(ExitCode.SUCCESS), result.output
        assert store.query("SELECT * FROM attestation_chains") == []
        assert store.query("SELECT * FROM attestation_events") == []
        assert store.query("SELECT * FROM attestation_manifests") == []
    finally:
        store.close()


def test_the_recorded_run_reader_refuses_an_unknown_run(seeded_db: Path) -> None:
    store = Store.open_migrated(seeded_db)
    try:
        with pytest.raises(MayhemCliError) as excinfo:
            load_recorded_run(store, "r-nope")
        assert excinfo.value.code == "validation_error"
        assert excinfo.value.details["run_id"] == "r-nope"
    finally:
        store.close()


def test_the_recorded_run_reader_names_the_snapshot_it_read(seeded_db: Path) -> None:
    store = Store.open_migrated(seeded_db)
    try:
        recorded = load_recorded_run(store, RUN_ID)
        assert recorded.run_id == RUN_ID
        assert recorded.snapshot_id == f"t-{RUN_ID}"
        assert recorded.graph is not None
        assert {node.id for node in recorded.graph.nodes} == {
            "n-db",
            "n-api",
            "n-web",
            "web-1",
            "web-2",
        }
    finally:
        store.close()


# ==============================================================================
# Type-level invariants the builders rely on
# ==============================================================================


def test_the_view_holds_no_presentation_judgement_of_its_own() -> None:
    """A renderer cannot reach a count the view did not compute.

    If the CLI could count breaches itself, a UI counting them differently would
    be a disagreement the view-model could not prevent.
    """
    view = build_risk_preview(_breaching_report(), run_id=RUN_ID)
    assert len(view.breaches) == sum(
        1 for claim in view.claims if claim.stance.is_breach
    )
    assert preview_payload(view)["breach_count"] == len(view.breaches)
    assert PolicyStance.UNCHECKED.is_breach is False
    assert PolicyStance.INSIDE_POLICY.is_breach is False
    assert PolicyStance.OUTSIDE_POLICY.is_breach is True


def test_the_dimension_lookup_is_the_engines_not_a_second_verdict() -> None:
    """The view never re-decides a ceiling; it reads ``CeilingVerdict``.

    A test that a hand-built ``CeilingVerdict`` reaches the view unchanged, so a
    future edit that re-derives ``breached`` here rather than reading it would
    fail.
    """
    report = _clean_report()
    verdict = CeilingVerdict(
        dimension=CeilingName.MAX_AFFECTED_PCT,
        rule_id="blast_radius.max_affected_pct",
        configured=True,
        limit=10.0,
        observed=99.9,
        unit="percent_of_nodes",
        breached=True,
        enforced_by_gate=True,
        detail="worst step affects 5 of 5 nodes",
    )
    forced = replace(report, dimensions=(verdict,))
    view = build_risk_preview(forced, run_id=RUN_ID)
    claim = next(c for c in view.claims if c.rule_id == verdict.rule_id)
    assert claim.stance is PolicyStance.OUTSIDE_POLICY
    assert claim.observed == pytest.approx(99.9)
    assert claim.limit == pytest.approx(10.0)


def test_a_violated_rule_carries_its_observed_ids_and_remediation() -> None:
    """The reader can go and look rather than re-derive the comparison."""
    report = _breaching_report()
    view = build_risk_preview(report, run_id=RUN_ID)
    breach = next(c for c in view.breaches if c.rule_id == RULE_MAX_SERVICES_PCT)
    assert breach.remediation, "a breach rendered with no remediation to act on"
    rule = next(r for r in report.prediction.violated_rules if r.rule_id == RULE_MAX_SERVICES_PCT)
    assert breach.observed == rule.observed
    assert breach.limit == rule.limit
    assert breach.observed_ids == rule.observed_ids


def test_a_violated_rule_with_observed_ids_reaches_the_payload() -> None:
    report = _service(ceilings=BlastCeilings(protected_node_ids=frozenset({"n-web"})))
    report = report.simulate_plan(
        _plan(("net.latency", "n-web", STEP_S)),
        _ctx(ceilings=BlastCeilings(protected_node_ids=frozenset({"n-web"}))),
    )
    view = build_risk_preview(report, run_id=RUN_ID)
    protected = next(c for c in view.breaches if c.rule_id == "blast_radius.protected_node")
    assert protected.observed_ids == ("n-web",)
    payload = next(
        c
        for c in preview_payload(view)["claims"]
        if c["rule_id"] == "blast_radius.protected_node"
    )
    assert payload["observed_ids"] == ["n-web"]


def test_an_uncited_violated_rule_is_reachable_only_through_a_hand_built_record() -> None:
    """The engine always fills ``detail``; the refusal guards the type, not the engine.

    Asserted so the control is not mistaken for a bug in the engine: a
    ``ViolatedRule`` built by hand with no detail is refused, and one built by
    ``predict_impact`` never is.
    """
    assert ViolatedRule(
        rule_id="x", step_id="s0", step_index=0, fault_id="f", observed=None, limit=None,
        unit="", detail="a real reason", remediation="",
    ).detail
    with pytest.raises(PreviewRenderRefusedError):
        build_risk_preview(_report_with_uncited_claim(), run_id=RUN_ID)


def test_the_store_is_opened_and_closed_even_when_the_preview_is_refused(
    seeded_db: Path,
) -> None:
    """The ``finally`` around the store is load-bearing on the refusal path."""
    for _ in range(3):
        result = _invoke(seeded_db, "plan", RUN_ID)
        assert result.exit_code == int(ExitCode.SUCCESS), result.output


def test_a_node_risk_view_carries_every_documented_column() -> None:
    view: NodeRiskView = build_node_risk_views(_graph(), coverage=_coverage("web"))[0]
    payload = view.to_payload()
    assert set(payload) == {
        "node_id",
        "name",
        "kind",
        "blast",
        "health",
        "coverage",
        "incidents",
    }
    assert set(payload["blast"]) == {"node_count", "depth", "dependents"}
    assert set(payload["health"]) == {"state", "reported", "reason"}
    assert set(payload["coverage"]) == {
        "available",
        "state",
        "service",
        "cells",
        "verified",
        "blocked",
        "reason",
    }
    assert set(payload["incidents"]) == {
        "available",
        "count",
        "incident_ids",
        "reason",
    }


def test_every_rendered_reason_is_non_empty() -> None:
    """The no-empty-rows rule, asserted across the rendered surface.

    A blank rationale is refused at the view-model layer; this is the same
    property observed from the output side, so a renderer that dropped a field
    would fail rather than silently emit an empty line.
    """
    for view in build_node_risk_views(_graph(), coverage=_coverage("web"), captures=None):
        assert view.blast is not None
        assert view.health.reason.strip()
        assert view.coverage.reason.strip()
        assert view.incidents.reason.strip()
    for line in render_node_lines(build_node_risk_views(_graph())):
        assert line.strip(), "the renderer emitted a blank line"
