"""``mayhem risk-preview`` — the plan display and the dependency view, phase 3.

Plan 14 Phase 1 (:mod:`mayhem.domain.prediction`) computed a prediction, Phase 2
(:mod:`mayhem.controller.prediction_service`) assembled it beside the real gate's
own refusal set, and Phase 4 sealed it and named the agreement state. None of
that is reachable by a person. This module is the surface, and it is two
commands:

* ``mayhem risk-preview plan RUN_ID`` — the plan's **resolvable target set**
  together with its **risk preview**: every predicted effect reported as inside
  or outside policy with the reason that names the rule.
* ``mayhem risk-preview nodes --run RUN_ID`` — the topology dependency view:
  per node, blast radius, health, coverage, and incident history.

The acceptance criterion is "preview output stored with the plan and rendered
identically in CLI and UI (08)", and the part of it that is easy to fake is the
second half. So the presentation shape is built **here, as a pure function of
engine output**, and the CLI is only its first renderer:

    build_risk_preview(report)  ->  RiskPreviewView   # pure
                                      |-> render_preview_lines(view)   # the CLI
                                      `-> preview_payload(view)        # any UI

:meth:`RiskPreviewView.to_payload` is the structure a UI renders, and
:func:`preview_payload` is that same structure as data. Neither renderer holds
its own vocabulary: there is no word for "inside policy" in this module and no
field for one in a renderer, because a UI that wanted a different word would
have to change :class:`PolicyStance` and every surface would follow. That is
what makes "rendered identically" a property of the code rather than a claim in
a document — the CLI test in ``tests/unit/test_risk_preview_surface.py``
asserts at the view-model layer for exactly this reason.

Seven commitments shape the code, and each is negative: what this module must
refuse to do.

**The view-model layer refuses to render an uncited claim.** A claim is a
recommendation somebody could act on, so it carries the rule id and the reason
that rule fired. :func:`build_risk_preview` raises :class:`PreviewRenderRefusedError`
rather than emitting a row with an empty reason — an empty row in a risk preview
is read as "checked, nothing to say", which is the one reading that is always
wrong.

**An unresolvable target renders a named refusal, not an empty preview.** The
target set is split into what the graph holds and what it does not, and the
unresolved ids are *named*. :func:`mayhem.domain.prediction.approval_refusal_reason`
supplies the sentence; this module does not soften it, and
:attr:`RiskPreviewView.usable_for_approval` is false while it is non-empty.

**A disagreement or an unmodelled refusal renders as unusable, never as a clean
preview.** :attr:`AgreementState` is read rather than re-derived: a
``DISAGREES`` record (which :meth:`PredictionService.simulate_plan` raises on, so
one should never reach this layer) still cannot be turned into a tidy preview
here, and an ``UNMODELLED`` one is carried as a refusal naming the rules the
gate refused that this preview has no vocabulary for. The view layer is the last
place a calm answer could be manufactured, so it is written to refuse.

**An unpriced estimate is disclosed, never invented.** There is no price table
in this repository, so :class:`CostView` carries ``status="unpriced"``, the
*measured* ``affected_node_seconds``, and — deliberately — **no** currency and
**no** total. :meth:`CostView.to_payload` omits both keys entirely rather than
emitting ``None`` or ``0.0``, because a JSON consumer rendering ``currency: null``
next to a number will draw a dollar sign.

**Coverage and incidents are read, not re-derived.** Blast radius per node comes
from :func:`mayhem.domain.prediction.affected_node_ids` and
:func:`~mayhem.domain.prediction.dependency_fan_out` — the prediction domain's
own arithmetic, the same functions the gate's numbers come from. Coverage comes
from :class:`mayhem.infra.coverage_repository.CoverageGraphRepository`, and
incident history from the :class:`~mayhem.controller.advisor_service.IncidentPort`
shape. A second opinion of any of the three could disagree with the engine that
would actually run the plan, which is the failure this whole module is built to
prevent.

**An unwitnessed source renders as unavailable, never as zero.** The CLI has no
incident manager to ask, so :meth:`NodeIncidentView` reports
``available=False`` with the port named. "Mayhem could not ask" and "mayhem
asked and there was nothing" are different findings and a topology view that
conflates them tells an operator a service has no history when mayhem simply has
no history source. Health is the same shape: a node kind the topology model
carries no lifecycle state for reports ``reported=False``, never "healthy".

**Nothing here mutates.** There is no ``--force``, no ``--record``, no bypass
flag, and no write path at all: the store is opened, queried, and closed. The
gate probe inside :meth:`PredictionService.simulate_plan` clones its context for
the same reason :mod:`mayhem.controller.preflight` does — a preview must not
append its own decisions to the safety record a real run is judged by — and the
report carries the measured mutation proof
(:attr:`~mayhem.controller.prediction_service.MutationProof`) so the claim is a
length read off a real object rather than a promise in a docstring.

Invocations that resolve against this command::

    mayhem risk-preview --help
    mayhem risk-preview plan r-drill-a1b2c3d4
    mayhem risk-preview plan r-drill-a1b2c3d4 --json
    mayhem risk-preview plan r-drill-a1b2c3d4 --fingerprint abc123
    mayhem risk-preview nodes --run r-drill-a1b2c3d4
    mayhem risk-preview nodes --run r-drill-a1b2c3d4 --node n-web --json

.. note::

   **The UI half of the acceptance criterion lands as a projection, not a page.**
   :func:`mayhem.controller.api_service.risk_preview_payload` builds this same
   view-model and returns this same payload, so the CLI and the UI project off
   one structure rather than agreeing today and drifting tomorrow. There is still
   no plan-08 page to click through — the wiring is the shared projection plus
   the stored bytes (see :func:`mayhem.controller.prediction_service.seal_prediction`),
   and the suite asserts the identity at the view-model layer. See the Phase 3
   entry in ``docs/v1.1.0/14_TOPOLOGY_BLAST_RADIUS.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group

# Re-exported, not re-implemented: the recorded-run loader belongs to the shared
# service layer now that `plan prove` reads the same two blobs, and two readers
# of `runs.plan_json` would give two different answers for one missing run.
from mayhem.cli.services import RecordedRun, gate_context_for_plan, load_recorded_run
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.controller.prediction_service import SimulateReport
    from mayhem.domain.advisor import IncidentFacts
    from mayhem.domain.coverage_graph import CoverageGraph
    from mayhem.domain.prediction import BlastCeilings
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "RISK_PREVIEW_SCHEMA_VERSION",
    "RULE_PREVIEW_CLAIM_UNCITED",
    "RULE_PREVIEW_NO_WITNESS",
    "CostView",
    "NodeBlastView",
    "NodeCoverageView",
    "NodeHealthView",
    "NodeIncidentView",
    "NodeRiskView",
    "PolicyClaim",
    "PolicyStance",
    "PreviewRenderRefusedError",
    "RecordedRun",
    "RiskPreviewView",
    "TargetSetView",
    "build_node_risk_views",
    "build_risk_preview",
    "exit_code_for",
    "load_recorded_run",
    "nodes",
    "plan_cmd",
    "preview_payload",
    "preview_refusal",
    "render_node_lines",
    "render_preview_lines",
    "risk_preview",
]


# =============================================================================
# Vocabulary this module owns
# =============================================================================

#: Version of the presentation structure. Bumped when a field's meaning changes,
#: never when one is added — the payload is additive and a consumer reading an
#: older one must not be broken by a newer renderer.
RISK_PREVIEW_SCHEMA_VERSION = "1.0"

#: Rule id for a claim that could not be cited. See :func:`build_risk_preview`.
RULE_PREVIEW_CLAIM_UNCITED = "preview.claim_uncited"

#: Rule id for a per-node field whose source mayhem could not witness. A view
#: that renders this as a zero is claiming an observation nobody made.
RULE_PREVIEW_NO_WITNESS = "preview.no_witness"

#: Which sources the ``nodes`` view reads, named in the output so an operator
#: knows what was asked and what was not.
COVERAGE_SOURCE = "coverage_graph_nodes"
INCIDENT_SOURCE = "advisor.IncidentPort"


# =============================================================================
# The view-model layer: pure, and the only place presentation vocabulary lives
# =============================================================================


class PreviewRenderRefusedError(InvariantViolationError):
    """A claim could not be rendered because it could not be cited.

    An :class:`~mayhem.domain.errors.InvariantViolationError` so it carries a
    ``rule`` a caller can branch on and a test can assert, rather than a message
    with a rule name buried in it. Raised instead of emitting a row with an empty
    reason: a blank cell in a risk preview is read as "checked, nothing to say",
    which is the only reading that is never right.
    """


class PolicyStance(StrEnum):
    """Whether a predicted effect is inside or outside policy, or unchecked.

    The three members are the whole vocabulary, and the third is the reason this
    is an enum rather than a pair of strings. An unconfigured ceiling was **not
    checked**, and ``INSIDE_POLICY`` would report it as satisfied — a reader
    would take "no limit was configured, so nothing fired" as "the limit was
    honoured". Both are true; only one of them is actionable.
    """

    INSIDE_POLICY = "inside_policy"
    OUTSIDE_POLICY = "outside_policy"
    UNCHECKED = "unchecked"

    @property
    def is_breach(self) -> bool:
        """Only :attr:`OUTSIDE_POLICY` is a breach.

        :attr:`UNCHECKED` is deliberately excluded. An unchecked ceiling that
        counted as a breach would train a reader to ignore the word, which is
        how a real ceiling breach gets ignored.
        """
        return self is PolicyStance.OUTSIDE_POLICY


@dataclass(frozen=True, slots=True)
class PolicyClaim:
    """One predicted effect, and the rule that decided it.

    ``reason`` is not optional and not allowed to be blank: it is the claim's
    entire justification, and it is composed to carry ``rule_id`` so the rule can
    be found by grepping the rendered output. ``observed``/``limit`` are the pair
    the comparison actually used — the same values
    :class:`~mayhem.domain.prediction.ViolatedRule` was built with — rather than
    a re-derivation, because a reader who has to redo the arithmetic to find out
    what the decision was made on will eventually get their own answer.
    """

    rule_id: str
    stance: PolicyStance
    reason: str
    step_id: str
    step_index: int
    observed: float | None
    limit: float | None
    unit: str
    remediation: str = ""
    observed_ids: tuple[str, ...] = ()

    @property
    def cited(self) -> bool:
        """Whether this claim names its rule and says why it fired."""
        return bool(self.rule_id.strip()) and bool(self.reason.strip())

    def to_payload(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "stance": self.stance.value,
            "reason": self.reason,
            "step_id": self.step_id,
            "step_index": self.step_index,
            "observed": self.observed,
            "limit": self.limit,
            "unit": self.unit,
            "remediation": self.remediation,
            "observed_ids": list(self.observed_ids),
        }


@dataclass(frozen=True, slots=True)
class TargetSetView:
    """The plan's target set, split into what the graph holds and what it does not.

    ``requested`` is what the plan asked for, ``resolved`` what the topology
    actually contained, and ``unresolved`` what was never measured at all. The
    third is why this is a dataclass and not a list: a preview that printed only
    the resolved ids would show an operator a smaller blast than the plan
    requests and never say so.
    """

    requested: tuple[str, ...] = ()
    resolved: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    affected: tuple[str, ...] = ()
    fan_out_depth: int = 0

    @property
    def complete(self) -> bool:
        """Whether every requested target resolved against the graph."""
        return not self.unresolved

    def to_payload(self) -> dict[str, Any]:
        return {
            "requested": list(self.requested),
            "resolved": list(self.resolved),
            "unresolved": list(self.unresolved),
            "complete": self.complete,
            "affected": list(self.affected),
            "fan_out_depth": self.fan_out_depth,
        }


@dataclass(frozen=True, slots=True)
class CostView:
    """The cost disclosure, or the explicit statement that nobody priced it.

    ``currency`` is ``""`` and ``total`` is ``None`` whenever :attr:`priced` is
    false, and :meth:`to_payload` then omits both keys **entirely** rather than
    emitting ``null``. A consumer that renders ``total: null`` next to a measured
    number draws a currency sign, and ``null`` reads as "zero, we just have no
    units" to half the JSON tooling in existence. The absence of a key cannot be
    mistaken for a value.

    ``affected_node_seconds`` is always populated: it is measured, not money, and
    it is what a caller holding its own rate card needs in order to price the
    same blast without re-deriving anything.
    """

    status: str
    basis: str
    affected_node_seconds: float
    note: str
    currency: str = ""
    total: float | None = None

    @property
    def priced(self) -> bool:
        return self.status == "priced"

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "basis": self.basis,
            "affected_node_seconds": self.affected_node_seconds,
            "note": self.note,
        }
        if self.priced:
            # Only a priced disclosure carries money. An unpriced one does not
            # carry a currency code either: "USD" beside a number is a claim
            # about a number that does not exist.
            payload["currency"] = self.currency
            payload["total"] = self.total
        return payload


@dataclass(frozen=True, slots=True)
class RiskPreviewView:
    """Everything one plan display carries, resolved.

    The presentation structure a UI renders and the CLI prints. It is built by
    :func:`build_risk_preview` from a
    :class:`~mayhem.controller.prediction_service.SimulateReport` and holds no
    presentation decisions of its own — every stance, reason, and refusal in it
    was decided by the engine, and this module's only judgement is whether the
    thing can be *shown*.
    """

    schema_version: str
    artifact: str
    run_id: str
    plan_identity: str
    graph_identity: str
    targets: TargetSetView
    claims: tuple[PolicyClaim, ...]
    cost: CostView
    agreement_state: str
    gate_refused: tuple[str, ...]
    mutation_calls: int
    mutation_backend_attached: bool
    usable_for_approval: bool
    refusals: tuple[str, ...]
    notes: tuple[str, ...] = ()

    @property
    def breaches(self) -> tuple[PolicyClaim, ...]:
        """Only the claims that went outside policy."""
        return tuple(claim for claim in self.claims if claim.stance.is_breach)

    @property
    def unresolvable(self) -> bool:
        """Whether part of the target set was never measured."""
        return not self.targets.complete

    def to_payload(self) -> dict[str, Any]:
        """The whole view, as data. This is what a UI renders."""
        return {
            "schema_version": self.schema_version,
            "artifact": self.artifact,
            "run_id": self.run_id,
            "plan_identity": self.plan_identity,
            "graph_identity": self.graph_identity,
            "targets": self.targets.to_payload(),
            "claims": [claim.to_payload() for claim in self.claims],
            "breach_count": len(self.breaches),
            "cost": self.cost.to_payload(),
            "agreement_state": self.agreement_state,
            "gate_refused": list(self.gate_refused),
            "mutation": {
                "calls": self.mutation_calls,
                "backend_attached": self.mutation_backend_attached,
            },
            "usable_for_approval": self.usable_for_approval,
            "refusals": list(self.refusals),
            "notes": list(self.notes),
        }


def _claim(
    rule_id: str,
    stance: PolicyStance,
    reason: str,
    *,
    step_id: str = "",
    step_index: int = 0,
    observed: float | None = None,
    limit: float | None = None,
    unit: str = "",
    remediation: str = "",
    observed_ids: tuple[str, ...] = (),
) -> PolicyClaim:
    """Build one claim, refusing to build an uncited one.

    The refusal is here rather than in a renderer so that no surface can be
    handed a claim it would have to print badly. The rule id is appended to the
    reason when the reason does not already carry it, which is what makes the
    rendered output greppable by rule — a claim whose rule can only be found by
    reading prose is a claim nobody can look up when they need it.
    """
    text = reason.strip()
    if not rule_id.strip():
        raise PreviewRenderRefusedError(
            RULE_PREVIEW_CLAIM_UNCITED,
            "refusing to render a policy claim with no rule id: an effect reported "
            "against no rule cannot be traced to the check that produced it, and a "
            "reader who cannot find the rule cannot re-run the comparison",
        )
    if not text:
        raise PreviewRenderRefusedError(
            RULE_PREVIEW_CLAIM_UNCITED,
            f"refusing to render a claim against {rule_id!r} with no reason: a blank "
            "rationale in a risk preview renders as an empty row, which reads as "
            "'checked and nothing to say' — the one reading that is never right",
        )
    if rule_id not in text:
        text = f"{text} [{rule_id}]"
    return PolicyClaim(
        rule_id=rule_id,
        stance=stance,
        reason=text,
        step_id=step_id,
        step_index=step_index,
        observed=observed,
        limit=limit,
        unit=unit,
        remediation=remediation,
        observed_ids=observed_ids,
    )


def build_risk_preview(report: SimulateReport, *, run_id: str = "") -> RiskPreviewView:
    """The presentation structure for one plan, as a pure function of the report.

    Pure: no IO, no clock, no randomness, and it reads nothing but ``report``.
    Two renderers projecting off one object is what keeps plan 08's UI and this
    CLI from drifting, so the projection cannot be where the judgement lives —
    every stance and every refusal below is read off
    :class:`~mayhem.controller.prediction_service.SimulateReport` or one of its
    members.

    The claims come from two places and no others:

    * every :class:`~mayhem.domain.prediction.ViolatedRule` in the prediction,
      as :attr:`PolicyStance.OUTSIDE_POLICY`, carrying the ``(observed, limit)``
      pair the comparison used;
    * every :class:`~mayhem.controller.prediction_service.CeilingVerdict`, as
      :attr:`PolicyStance.OUTSIDE_POLICY` when it reports a breach,
      :attr:`PolicyStance.INSIDE_POLICY` when a limit was configured and none
      fired, and :attr:`PolicyStance.UNCHECKED` when no limit was configured at
      all.

    A breached ceiling whose rule is also in the prediction's violated set is not
    listed twice: it appears as the violation it is, with the per-step observed
    and limit, rather than as the same finding twice in different words. A ceiling
    that claims a breach the prediction does not carry *is* rendered — as a
    breach — because dropping it would make a record whose fields disagree about a
    breach hide that breach.

    Raises:
        PreviewRenderRefusedError: If any claim would render without a rule id or a
            reason. Nothing is returned in that case; there is no half-built
            preview for a caller to print anyway.
    """
    from mayhem.controller.prediction_service import (
        RULE_PREDICTION_CALMER_THAN_GATE,
        RULE_PREDICTION_UNMODELLED_GATE_REFUSAL,
        AgreementState,
    )

    prediction = report.prediction
    claims: list[PolicyClaim] = [
        _claim(
            rule.rule_id,
            PolicyStance.OUTSIDE_POLICY,
            rule.detail,
            step_id=rule.step_id,
            step_index=rule.step_index,
            observed=rule.observed,
            limit=rule.limit,
            unit=rule.unit,
            remediation=rule.remediation,
            observed_ids=rule.observed_ids,
        )
        for rule in prediction.violated_rules
    ]
    flagged = prediction.rule_ids
    for verdict in report.dimensions:
        if verdict.breached and verdict.rule_id in flagged:
            # Already rendered above as the violation it is. A second row here
            # would be the same finding twice with different wording, and a
            # reader counts rows.
            #
            # The rule id is checked as well as the flag because the flag alone
            # would silently drop a ceiling that claims a breach the prediction
            # does not carry — a record whose ``breached`` and ``rule_ids``
            # disagree would render *no* row for a dimension it says failed,
            # which is the quietest possible way to hide a breach. Since the
            # ceiling verdict derives its flag from the prediction's rule ids
            # this branch is unreachable through the engine; it is here so a
            # hand-built record cannot make a finding disappear.
            continue
        claims.append(
            _claim(
                verdict.rule_id,
                (
                    PolicyStance.OUTSIDE_POLICY
                    if verdict.breached
                    else (
                        PolicyStance.INSIDE_POLICY if verdict.configured else PolicyStance.UNCHECKED
                    )
                ),
                verdict.detail,
                observed=verdict.observed,
                limit=verdict.limit,
                unit=verdict.unit,
            )
        )

    requested = tuple(report.targets)
    unresolved = tuple(prediction.unresolved_target_ids)
    resolved = tuple(sorted(set(requested).difference(unresolved)))
    targets = TargetSetView(
        requested=requested,
        resolved=resolved,
        unresolved=unresolved,
        affected=tuple(prediction.affected_node_ids),
        fan_out_depth=prediction.fan_out.max_depth,
    )

    disclosure = report.cost
    cost = CostView(
        status=disclosure.status,
        basis=disclosure.basis,
        affected_node_seconds=disclosure.affected_node_seconds,
        note=disclosure.note,
        currency=disclosure.currency if disclosure.priced else "",
        total=disclosure.total_usd if disclosure.priced else None,
    )

    refusals: list[str] = []
    if report.approval_refusal:
        refusals.append(report.approval_refusal)
    state = report.agreement_state
    if state is AgreementState.DISAGREES:
        # Unreachable through the service, which raises. Reachable through a
        # hand-built record, and this is the last place a calm answer could be
        # manufactured, so it is refused here too rather than trusted to be
        # impossible. The engine's own reason is quoted rather than restated.
        reason = report.agreement.reason.strip()
        if not reason:
            raise PreviewRenderRefusedError(
                RULE_PREVIEW_CLAIM_UNCITED,
                "refusing to render a preview whose agreement record says the gate "
                "refused a rule the prediction did not flag, but gives no reason: a "
                "disagreement without a stated cause is a defect report with the "
                "finding removed",
            )
        refusals.append(f"{RULE_PREDICTION_CALMER_THAN_GATE}: {reason}")
    elif state is AgreementState.UNMODELLED and not any(
        RULE_PREDICTION_UNMODELLED_GATE_REFUSAL in refusal for refusal in refusals
    ):
        # The engine's own ``approval_refusal`` already carries this sentence for
        # every report it builds, so this branch is the belt to its braces: it
        # reads the *named state* rather than trusting a string the report
        # happened to carry. A record whose state says UNMODELLED must render as
        # unusable whatever else its fields say — the state is the finding.
        refusals.append(
            f"{RULE_PREDICTION_UNMODELLED_GATE_REFUSAL}: the real gate refused "
            f"{sorted(report.agreement.unmodelled)}, which this preview does not model, "
            "so it cannot speak to the rule that blocks this plan"
        )

    notes = tuple(report.notes)
    return RiskPreviewView(
        schema_version=RISK_PREVIEW_SCHEMA_VERSION,
        artifact=report.artifact,
        run_id=run_id,
        plan_identity=prediction.plan_identity,
        graph_identity=prediction.graph_identity,
        targets=targets,
        claims=tuple(claims),
        cost=cost,
        agreement_state=state.value,
        gate_refused=tuple(sorted(report.agreement.gate_refused)),
        mutation_calls=report.mutation.calls,
        mutation_backend_attached=report.mutation.backend_attached,
        usable_for_approval=not refusals,
        refusals=tuple(refusals),
        notes=notes,
    )


# =============================================================================
# The dependency view: per-node blast radius, health, coverage, incidents
# =============================================================================


@dataclass(frozen=True, slots=True)
class NodeBlastView:
    """How far damage from this node reaches, per the prediction domain's arithmetic.

    Computed by :func:`~mayhem.domain.prediction.affected_node_ids` and
    :func:`~mayhem.domain.prediction.dependency_fan_out` — the same functions
    ``check_blast_radius`` and ``predict_impact`` use. A second traversal written
    here could report a different depth or a different front door than the gate
    will, and a topology view that disagrees with the engine is worse than no
    view at all.
    """

    node_count: int
    depth: int
    dependents: tuple[str, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "node_count": self.node_count,
            "depth": self.depth,
            "dependents": list(self.dependents),
        }


@dataclass(frozen=True, slots=True)
class NodeHealthView:
    """What the topology itself reports about a node's lifecycle.

    ``reported`` is the load-bearing field. A node kind the topology model
    carries no ``state`` for has not been observed, and reporting it as healthy
    would be an observation nobody made.
    """

    state: str
    reported: bool
    reason: str

    def to_payload(self) -> dict[str, Any]:
        return {"state": self.state, "reported": self.reported, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class NodeCoverageView:
    """How much of this service's resilience surface has actually been exercised.

    ``available`` separates "mayhem holds no coverage graph" from "mayhem read
    the coverage graph and this service has no cells". The second is a finding
    about the service; the first is a finding about the database, and a view
    that renders both as ``0`` has thrown away the distinction.
    """

    available: bool
    state: str
    service: str
    cells: int
    verified: int
    blocked: int
    reason: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "state": self.state,
            "service": self.service,
            "cells": self.cells,
            "verified": self.verified,
            "blocked": self.blocked,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class NodeIncidentView:
    """Incident captures naming this service, or the reason mayhem has none.

    ``available=False`` means mayhem has no incident source bound. That is not
    the same as "no incidents", and the field exists so the two cannot render
    identically.
    """

    available: bool
    count: int
    incident_ids: tuple[str, ...]
    reason: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "count": self.count,
            "incident_ids": list(self.incident_ids),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class NodeRiskView:
    """One node's row in the topology dependency view."""

    node_id: str
    name: str
    kind: str
    blast: NodeBlastView
    health: NodeHealthView
    coverage: NodeCoverageView
    incidents: NodeIncidentView

    def to_payload(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "kind": self.kind,
            "blast": self.blast.to_payload(),
            "health": self.health.to_payload(),
            "coverage": self.coverage.to_payload(),
            "incidents": self.incidents.to_payload(),
        }


def _health_for(graph: TopologyGraph, node_id: str) -> NodeHealthView:
    """The node's own reported lifecycle state, or an explicit "not observed"."""
    node = graph.by_id(node_id)
    if node is None:
        return NodeHealthView(
            state="unknown",
            reported=False,
            reason=f"{node_id} is not in the graph, so mayhem cannot report its health",
        )
    state = str(getattr(node, "state", "") or "")
    if not state:
        return NodeHealthView(
            state="unknown",
            reported=False,
            reason=(
                f"the topology model carries no lifecycle state for a {node.kind.value} "
                "node, so mayhem cannot say whether it is healthy"
            ),
        )
    return NodeHealthView(
        state=state,
        reported=True,
        reason=f"{node.kind.value} node reports state {state!r} in the topology snapshot",
    )


def _coverage_for(graph: CoverageGraph, service: str) -> NodeCoverageView:
    """This service's cells in the recorded coverage graph."""
    cells = tuple(node for node in graph.nodes if node.service == service)
    if not cells:
        return NodeCoverageView(
            available=True,
            state="no_records",
            service=service,
            cells=0,
            verified=0,
            blocked=0,
            reason=(
                f"mayhem read the coverage graph and it holds no cell for {service!r}: "
                "this service has no recorded resilience coverage at all, which is not "
                "the same as being covered"
            ),
        )
    verified = sum(1 for cell in cells if cell.verified)
    blocked = sum(1 for cell in cells if cell.evidence_status == "blocked")
    return NodeCoverageView(
        available=True,
        state="recorded",
        service=service,
        cells=len(cells),
        verified=verified,
        blocked=blocked,
        reason=(
            f"{len(cells)} coverage cell(s) recorded for {service!r}: {verified} verified, "
            f"{blocked} blocked"
        ),
    )


def _incidents_for(captures: Sequence[IncidentFacts] | None, service: str) -> NodeIncidentView:
    """Incident captures naming this service, or why mayhem has none."""
    if captures is None:
        return NodeIncidentView(
            available=False,
            count=0,
            incident_ids=(),
            reason=(
                "mayhem has no incident source bound ("
                f"{INCIDENT_SOURCE} is unbound from the CLI), so it cannot say whether "
                f"{service!r} has incident history — this is an absent witness, not an "
                "absence of incidents"
            ),
        )
    named = tuple(sorted(capture.incident_id for capture in captures if _names(capture, service)))
    return NodeIncidentView(
        available=True,
        count=len(named),
        incident_ids=named,
        reason=(
            f"{len(named)} incident capture(s) name {service!r}"
            if named
            else f"mayhem read {len(captures)} incident capture(s); none names {service!r}"
        ),
    )


def _names(capture: IncidentFacts, service: str) -> bool:
    """Whether an incident capture is about ``service``."""
    return capture.service == service


def build_node_risk_views(
    graph: TopologyGraph,
    *,
    coverage: CoverageGraph | None = None,
    captures: Sequence[IncidentFacts] | None = None,
    node_ids: Sequence[str] | None = None,
) -> tuple[NodeRiskView, ...]:
    """One dependency-view row per node: blast radius, health, coverage, incidents.

    Pure, and a *reader* of every source it renders rather than a second
    derivation of any of them. Blast radius comes from
    :func:`mayhem.domain.prediction.affected_node_ids` and
    :func:`~mayhem.domain.prediction.dependency_fan_out`; coverage from a
    :class:`~mayhem.domain.coverage_graph.CoverageGraph` the caller read; incident
    history from captures shaped like
    :class:`~mayhem.domain.advisor.IncidentFacts`.

    ``coverage=None`` and ``captures=None`` are the "no witness" cases and render
    as such. They are parameters rather than exceptions because a topology view
    over a database with no coverage rows is a legitimate thing to ask for, and
    the honest answer is a view that says which of its columns it could not fill.

    A ``node_ids`` that names an absent node produces no row for it — the caller
    filtered on a node mayhem does not hold, and inventing a row would report a
    blast radius for a node that does not exist.
    """
    from mayhem.domain.prediction import affected_node_ids, dependency_fan_out

    wanted = tuple(node_ids) if node_ids is not None else tuple(node.id for node in graph.nodes)
    views: list[NodeRiskView] = []
    for node_id in wanted:
        node = graph.by_id(node_id)
        if node is None:
            continue
        fan_out = dependency_fan_out(graph, (node_id,))
        blast_nodes = affected_node_ids(graph, (node_id,))
        service = node.name
        views.append(
            NodeRiskView(
                node_id=node.id,
                name=node.name,
                kind=node.kind.value,
                blast=NodeBlastView(
                    node_count=len(blast_nodes),
                    depth=fan_out.max_depth,
                    dependents=fan_out.dependent_ids,
                ),
                health=_health_for(graph, node.id),
                coverage=(
                    _unwitnessed_coverage(node_id)
                    if coverage is None
                    else _coverage_for(coverage, service)
                ),
                incidents=_incidents_for(captures, service),
            )
        )
    return tuple(views)


def _unwitnessed_coverage(node_id: str) -> NodeCoverageView:
    """The coverage column for a database mayhem holds no coverage graph for."""
    return NodeCoverageView(
        available=False,
        state="unavailable",
        service="",
        cells=0,
        verified=0,
        blocked=0,
        reason=(
            f"mayhem has no coverage graph to read, so it cannot say what is covered "
            f"for {node_id!r}; the coverage source ({COVERAGE_SOURCE}) was not "
            f"available [{RULE_PREVIEW_NO_WITNESS}]"
        ),
    )


# =============================================================================
# Renderers: projections off the view-model, and nothing else
# =============================================================================


def preview_payload(view: RiskPreviewView) -> dict[str, Any]:
    """The view as data. What a UI renders, and what may be stored with the plan.

    One function, so ``preview_payload(view) == view.to_payload()`` is an
    identity a test can assert rather than an agreement two renderers happen to
    have reached.
    """
    return view.to_payload()


_STANCE_LABEL: dict[PolicyStance, str] = {
    PolicyStance.INSIDE_POLICY: "INSIDE ",
    PolicyStance.OUTSIDE_POLICY: "OUTSIDE",
    PolicyStance.UNCHECKED: "UNCHECK",
}


def render_preview_lines(view: RiskPreviewView) -> list[str]:
    """The CLI's rendering of one plan display.

    Reads :class:`RiskPreviewView` and its members only. It holds no stance
    logic, decides no usability, and computes no counts — every word about
    whether a plan is inside policy was decided by :func:`build_risk_preview`,
    which is why the strings here can be reworded freely without any risk of
    changing what the preview claims.
    """
    headline = f"risk preview for {view.run_id} ({view.artifact})"
    lines = [headline]
    targets = view.targets
    lines.append(
        f"  targets: {len(targets.resolved)} resolved, {len(targets.unresolved)} unresolved, "
        f"{len(targets.affected)} node(s) affected, fan-out depth {targets.fan_out_depth}"
    )
    for node_id in targets.resolved:
        lines.append(f"    resolved:   {node_id}")
    for node_id in targets.unresolved:
        lines.append(style.warn(f"    UNRESOLVED: {node_id} — never measured", err=False))
    lines.append(f"  policy ({len(view.claims)} claim(s), {len(view.breaches)} outside):")
    for claim in view.claims:
        lines.append(f"    {_claim_line(claim)}")
    lines.append(f"  cost: {view.cost.status} — {view.cost.note}")
    lines.append(
        f"  gate: {', '.join(view.gate_refused) if view.gate_refused else 'admitted'} "
        f"[agreement: {view.agreement_state}]"
    )
    lines.append(
        f"  mutation: {view.mutation_calls} call(s), backend "
        f"{'attached' if view.mutation_backend_attached else 'detached'}"
    )
    for refusal in view.refusals:
        lines.append(style.warn(f"  NOT USABLE FOR APPROVAL: {refusal}", err=False))
    if view.usable_for_approval:
        lines.append(style.ok("  usable for approval: yes", err=False))
    return lines


def _claim_line(claim: PolicyClaim) -> str:
    label = _STANCE_LABEL[claim.stance]
    measurement = ""
    if claim.observed is not None and claim.limit is not None:
        measurement = f" ({claim.observed:g}/{claim.limit:g} {claim.unit})".rstrip()
    elif claim.unit:
        measurement = f" ({claim.unit})"
    where = f" step {claim.step_index}:{claim.step_id}" if claim.step_id else ""
    line = f"{label} {claim.rule_id}{where}{measurement} — {claim.reason}"
    if claim.remediation:
        line = f"{line} [remediation: {claim.remediation}]"
    return style.orange(line, err=False) if claim.stance.is_breach else line


def render_node_lines(views: Sequence[NodeRiskView]) -> list[str]:
    """The CLI's rendering of the topology dependency view."""
    lines = [f"dependency view: {len(views)} node(s)"]
    for view in views:
        lines.append(f"  {view.node_id} ({view.kind}) {view.name}")
        lines.append(f"    blast radius: {view.blast.node_count} node(s), depth {view.blast.depth}")
        if view.blast.dependents:
            lines.append(f"      dependents: {', '.join(view.blast.dependents)}")
        lines.append(
            f"    health: {view.health.state} "
            f"({'reported' if view.health.reported else 'NOT OBSERVED'}) — {view.health.reason}"
        )
        coverage = view.coverage
        coverage_word = "available" if coverage.available else "UNAVAILABLE"
        lines.append(
            f"    coverage [{coverage.state}, {coverage_word}]: {coverage.cells} cell(s), "
            f"{coverage.verified} verified, {coverage.blocked} blocked — {coverage.reason}"
        )
        incidents = view.incidents
        if not incidents.available:
            lines.append(style.warn(f"    incidents: UNAVAILABLE — {incidents.reason}", err=False))
        else:
            lines.append(f"    incidents: {incidents.count} capture(s) — {incidents.reason}")
    return lines


def exit_code_for(view: RiskPreviewView | None = None) -> int:
    """The exit code one invocation reports after a preview was produced.

    Always ``SUCCESS``, **including for a preview that is not usable for
    approval**. A preview that exited non-zero when the plan breaches a ceiling
    would train operators to ignore the exit code, which is how a real breach
    gets ignored; the refusal is in the rendered output, where a human reads it.

    The failure case is *not* here: mayhem could not produce a preview at all
    (no such run, no readable plan, an uncitable claim), and that exits through
    :func:`_fail` with the code the :class:`~mayhem.cli.errors.MayhemCliError`
    carries. ``view`` is accepted so a caller can read the intent at the call
    site — and so this stays the one place the "a preview is not a failure"
    decision is written rather than an ``ExitCode.SUCCESS`` repeated inline.
    """
    return int(ExitCode.SUCCESS)


def preview_refusal(view: RiskPreviewView) -> str:
    """Every reason this preview may not back an approval, joined for display."""
    return " | ".join(view.refusals)


# =============================================================================
# Reading what the store already holds
# =============================================================================


# =============================================================================
# Assembling the report the view-model consumes
# =============================================================================


FINGERPRINT_NOTE = (
    "environment fingerprint adopted from the recorded plan: mayhem did not re-derive "
    "the live environment identity, so the fingerprint drift check did not run. Pass "
    "--fingerprint to ask the stricter question."
)
CEILINGS_NOTE = (
    "no plan-14 ceilings configured: all five report as unchecked, which is not the "
    "same as satisfied. Configure them to have them evaluated."
)


def _report_for(
    recorded: RecordedRun,
    *,
    fingerprint: str = "",
    ceilings: BlastCeilings | None = None,
) -> SimulateReport:
    """Run the preview engine over one recorded run and return its report."""
    from mayhem.controller.prediction_service import PredictionConfig, PredictionService

    if recorded.graph is None:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"run {recorded.run_id!r} recorded no topology snapshot, so mayhem has "
                "no graph to measure a blast radius against. A preview over an empty "
                "graph reports nothing affected, which would read as 'this plan is safe' "
                "rather than 'mayhem could not look'"
            ),
            details={"run_id": recorded.run_id, "topology_snapshot_id": recorded.snapshot_id},
            remediation="re-plan the run against current topology, then preview it again",
        )
    config = PredictionConfig()
    if ceilings is not None:
        config = PredictionConfig(ceilings=ceilings)
    service = PredictionService(graph=recorded.graph, config=config)
    ctx = gate_context_for_plan(
        fingerprint=fingerprint or recorded.environment_fingerprint,
        ceilings=ceilings,
    )
    return service.simulate_plan(recorded.plan, ctx)


# =============================================================================
# The Click commands
# =============================================================================

risk_preview = make_group(
    "risk-preview",
    "Preview a plan's blast radius and policy risk, and read the dependency view.",
)


def _db_for(ctx: click.Context) -> str:
    """The database this invocation reads.

    The root group's ``--db`` arrives as ``ctx.obj.db``, the same channel every
    other read-only surface uses; ``mayhem.db`` is the fallback for an invocation
    that carries no context object at all, which is the same default
    ``cli.services.open_store`` callers get.
    """
    return str(getattr(ctx.obj, "db", "") or "") or "mayhem.db"


def _fail(ctx: click.Context, exc: MayhemCliError) -> None:
    """Emit a refusal in this surface's own contract and exit with its code.

    This group is invoked directly in tests and by the integration pass's
    registration, in both cases without going through ``cli.app.main``'s
    exception mapping. Rendering and exiting here means the exit code is a
    property of *this* surface rather than of whichever wrapper happens to
    dispatch it — so a caller that runs the group directly sees the documented
    code rather than Click's generic 1.
    """
    exc.emit(debug=bool(getattr(ctx.obj, "debug", False)) if ctx.obj else False)
    ctx.exit(int(exc.exit_code))


@risk_preview.command("plan")
@click.argument("run_id")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the presentation structure as JSON instead of the rendered lines.",
)
@click.option(
    "--fingerprint",
    "fingerprint",
    default="",
    metavar="FP",
    help="Environment fingerprint to evaluate against. Defaults to the plan's own "
    "recorded identity, which means the drift check does not run.",
)
@click.pass_context
def plan_cmd(ctx: click.Context, run_id: str, as_json: bool, fingerprint: str) -> None:
    """Show a run's target set and the risk preview of what it would do.

    Read-only. There is no ``--force``, no ``--record``, and no way to make this
    write anything: the store is opened, queried, and closed, and the gate probe
    inside the engine runs against a cloned context so it appends nothing to the
    safety record a real run is judged by.

    Exits ``0`` even when the preview is not usable for approval — a preview that
    exited non-zero for a breach would train operators to ignore the exit code.
    The refusal is in the rendered output.
    """
    from mayhem.cli.output import echo_machine
    from mayhem.cli.services import open_store

    db = _db_for(ctx)
    store = open_store(db)
    try:
        recorded = load_recorded_run(store, run_id)
        report = _report_for(recorded, fingerprint=fingerprint)
    except MayhemCliError as exc:
        _fail(ctx, exc)
        raise
    finally:
        store.close()

    try:
        view = build_risk_preview(report, run_id=recorded.run_id)
    except PreviewRenderRefusedError as exc:
        _fail(
            ctx,
            MayhemCliError(
                code="validation_error",
                message=f"refusing to render a preview for {recorded.run_id!r}: {exc}",
                details={"run_id": recorded.run_id, "rule": exc.rule},
                remediation="this is a defect in the preview engine, not in your request",
            ),
        )
        raise

    payload = preview_payload(view)
    payload["notes"] = [
        *payload["notes"],
        FINGERPRINT_NOTE if not fingerprint else "",
        CEILINGS_NOTE,
    ]
    payload["notes"] = [note for note in payload["notes"] if note]
    if echo_machine(payload, as_json=as_json):
        ctx.exit(exit_code_for(view))
    for line in render_preview_lines(view):
        click.echo(line)
    for note in payload["notes"][len(view.notes) :]:
        click.echo(f"  note: {note}")
    ctx.exit(exit_code_for(view))


@risk_preview.command("nodes")
@click.option(
    "--run",
    "run_id",
    required=True,
    metavar="RUN_ID",
    help="The run whose recorded topology snapshot the dependency view is read over.",
)
@click.option(
    "--node",
    "node_id",
    default="",
    metavar="NODE_ID",
    help="Restrict the view to one node. Omit it for every node in the snapshot.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the presentation structure as JSON instead of the rendered lines.",
)
@click.pass_context
def nodes(ctx: click.Context, run_id: str, node_id: str, as_json: bool) -> None:
    """Read the dependency view: blast radius, health, coverage, incidents per node.

    Blast radius is read from :mod:`mayhem.domain.prediction`, the same
    arithmetic the gate uses. Coverage is read from the recorded coverage graph.
    Incident history has **no witness** on this surface — the CLI binds no
    incident manager — so the incidents column renders ``UNAVAILABLE`` with the
    port named rather than a zero.
    """
    from mayhem.cli.output import echo_machine
    from mayhem.cli.services import open_store
    from mayhem.infra.coverage_repository import CoverageGraphRepository

    db = _db_for(ctx)
    store = open_store(db)
    try:
        recorded = load_recorded_run(store, run_id)
        if recorded.graph is None:
            raise MayhemCliError(
                code="validation_error",
                message=(
                    f"run {recorded.run_id!r} recorded no topology snapshot, so mayhem has "
                    "no dependency graph to read"
                ),
                details={"run_id": run_id},
                remediation="re-plan the run against current topology",
            )
        # Read-only on purpose: `graph()` selects, it never records. The
        # `mayhem inspect graph --record` write path exists and is deliberately
        # not reachable from here.
        coverage = CoverageGraphRepository(store).graph()
        views = build_node_risk_views(
            recorded.graph,
            coverage=coverage,
            captures=None,
            node_ids=(node_id,) if node_id else None,
        )
    except MayhemCliError as exc:
        _fail(ctx, exc)
        raise
    finally:
        store.close()

    payload = {
        "schema_version": RISK_PREVIEW_SCHEMA_VERSION,
        "run_id": run_id,
        "topology_snapshot_id": recorded.snapshot_id,
        "nodes": [view.to_payload() for view in views],
        "notes": [
            f"coverage source: {COVERAGE_SOURCE}",
            f"incident source: {INCIDENT_SOURCE} — unbound on this surface, so incident "
            "history renders UNAVAILABLE rather than zero",
        ],
    }
    if echo_machine(payload, as_json=as_json):
        ctx.exit(exit_code_for())
    for line in render_node_lines(views):
        click.echo(line)
    for note in payload["notes"]:
        click.echo(f"  note: {note}")
    ctx.exit(exit_code_for())
