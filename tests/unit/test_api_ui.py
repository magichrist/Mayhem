"""The control-plane UI renders from API payloads, and from plans 14, 15, and 21's
own view-models (plan 08, Phase 3).

Three things are asserted here, and they are the three the plan asks for.

* **The UI cannot drift from the CLI, because it renders the CLI's own view
  models.** Plans 14, 15, and 21 each landed a pure view-model layer and each
  recorded the *absence of a second renderer* as the open half of its acceptance
  criterion. This file builds those view-models — the real frozen dataclasses from
  those modules, not dicts shaped like them — projects them the way the CLI does,
  and asserts the page renders from that projection. The drift test is therefore
  not "CLI and UI agree", which two renderers could satisfy by accident; it is
  "the UI page is rendered from the same payload the CLI renders", which is an
  identity because the payload is the input.

* **The UI principle holds mechanically.** Every :class:`~mayhem.controller.api_ui.Page`
  carries the API payload it was rendered from, so "everything visible in the UI
  maps back to a machine-readable API object" is a field on every page rather than
  a design principle. A page with a missing object is *refused*, not rendered
  empty.

* **The honesty refusals still hold on the HTML side.** A dashboard number with
  no evidence link does not render. An untraceable recommendation cannot reach the
  page at all, because plan 21's :func:`~mayhem.cli.advisor_cmd.ranked_views`
  refuses it before any renderer exists. An unwitnessed value renders as
  unavailable, never as zero. A stop control carries no bypass.

Negative controls
-----------------

Six, each executable, each breaking one property and asserting the refusal:

* a payload missing the key a page is about → ``ui.no_api_object``;
* a dashboard number stripped of its evidence → ``ui.number_without_evidence``;
* an unwitnessed value defaulted to zero by a "helpful" renderer → asserted by
  checking the page says ``WITHHELD`` and not ``0``;
* an unrenderable page id → a refusal naming the pages that exist;
* a preview marked not-usable-for-approval → the page offers no submit control
  (proved by *adding* a usable preview and watching one appear, so the assertion
  is not vacuous);
* the stop panel → asserted to contain no force/skip control, and asserted by
  constructing the forbidden word and showing the check is not trivially true.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from mayhem.cli.advisor_cmd import (
    ADVISORY_STANDING,
    AdvisorDashboard,
    RankedRecommendation,
    SuppressedView,
    TracedCriterion,
    TracedFact,
)
from mayhem.cli.boundary_report_cmd import (
    AUTHORITY_NONE,
    BoundaryReportView,
    MinimalCaseView,
    SignalBoundaryView,
)
from mayhem.cli.risk_preview_cmd import (
    CostView,
    PolicyClaim,
    PolicyStance,
    RiskPreviewView,
    TargetSetView,
    preview_payload,
    render_preview_lines,
)
from mayhem.controller.api_ui import (
    RULE_UI_NO_API_OBJECT,
    RULE_UI_NUMBER_WITHOUT_EVIDENCE,
    UI_PAGES,
    PageId,
    UiRenderRefusedError,
    render_approvals_page,
    render_boundary_page,
    render_builder_page,
    render_dashboard,
    render_evidence_page,
    render_page,
    render_recommendations_page,
    render_run_page,
    render_stop_panel,
    ui_pages,
)

# ═════════════════════════════════════════════════════════════════════════════
# View-models, built as the owning modules define them
# ═════════════════════════════════════════════════════════════════════════════


def _preview_view(*, usable: bool = True) -> RiskPreviewView:
    """Plan 14's :class:`RiskPreviewView`, constructed directly.

    Built as the real frozen dataclass rather than as a dict shaped like it, so a
    field this module reads cannot be one the view-model does not actually produce:
    the assertion below *is* the check, and a dict would make it vacuous.
    """
    return RiskPreviewView(
        schema_version="1.0",
        artifact="risk-preview",
        run_id="r-ui-0001",
        plan_identity="a" * 64,
        graph_identity="b" * 64,
        targets=TargetSetView(
            requested=("checkout",),
            resolved=("checkout",),
            unresolved=(),
            affected=("checkout", "payments"),
            fan_out_depth=2,
        ),
        claims=(
            PolicyClaim(
                rule_id="blast_radius.max_hosts",
                stance=PolicyStance.INSIDE_POLICY,
                reason="2 of 3 hosts affected, ceiling is 2 [blast_radius.max_hosts]",
                step_id="step-1",
                step_index=0,
                observed=2.0,
                limit=2.0,
                unit="hosts",
            ),
            PolicyClaim(
                rule_id="damage_budget.max_total",
                stance=PolicyStance.OUTSIDE_POLICY,
                reason="observed p99 +310ms over a 200ms budget [damage_budget.max_total]",
                step_id="step-1",
                step_index=0,
                observed=310.0,
                limit=200.0,
                unit="ms",
                remediation="narrow the target selector",
            ),
        ),
        cost=CostView(
            status="unpriced",
            basis="measured",
            affected_node_seconds=2.0,
            note="measured 2 affected-node seconds; this repository has no price table",
        ),
        agreement_state="AGREES",
        gate_refused=(),
        mutation_calls=0,
        mutation_backend_attached=False,
        usable_for_approval=usable,
        refusals=() if usable else ("a predicted effect went outside policy",),
    )


def _boundary_view(*, reportable: bool = True) -> BoundaryReportView:
    """Plan 15's :class:`BoundaryReportView`, constructed directly."""
    return BoundaryReportView(
        run_id="r-ui-0001",
        policy_name="checkout-resilience",
        strategy="ladder",
        origin="recorded",
        recorded_note="ladder crossed at 7.0",
        recorded_bracket="4.0 < boundary <= 7.0",
        recorded_trials=3,
        recorded_resolved=True,
        stop_reason="breach_found",
        budget_remaining=9.0,
        signals=(
            SignalBoundaryView(
                signal="latency",
                unit="ms",
                statistic="p99",
                reportable=reportable,
                tolerance="tolerates p99 <= 7.0 ms" if reportable else "",
                confidence="9 baseline and 9 during-fault samples",
                refusal=(
                    ""
                    if reportable
                    else "the during-fault window at the boundary held only 3 samples, "
                    "below the floor the domain requires"
                ),
                bracket="4.0 < boundary <= 7.0",
                resolved=True,
                resolution=7.0,
                trials=3,
                insufficient_trials=(2,) if not reportable else (),
                graded_verdict="degraded within tolerance",
                effect_size="p99 on a 95% interval; Cohen's d 1.20 (large)",
                window_phases="warmup 2, measured 7, cooldown 0",
                support_refs=("signal/latency/p99",),
                withheld_rule="",
                withheld_reason="",
            ),
        ),
        minimal_case=MinimalCaseView(
            found=True,
            size=1,
            minimal=True,
            considered=3,
            combination="net.latency",
            note="latency alone reproduces it",
            support_refs=("failure_case/latency",),
            withheld_rule="",
            withheld_reason="",
        ),
        evidence_complete=True,
        notes=(),
    )


def _ranked() -> RankedRecommendation:
    """Plan 21's :class:`RankedRecommendation`, constructed directly."""
    return RankedRecommendation(
        position=1,
        recommendation_id="rec-1",
        experiment_id="exp-checkout",
        origin="recorded",
        authority="none",
        failure_mode="latency",
        cell_key="checkout/latency",
        cell_ref="checkout · latency",
        cell_state="gap",
        landscape_id="land-1",
        topology_node_ids=("checkout",),
        graph_identity="b" * 64,
        criteria_name="customer-facing-first",
        declared_criteria=(
            TracedCriterion(
                name="customer_facing",
                weight=0.7,
                question="is this node customer-facing?",
                value=1.0,
                contribution=0.7,
                evidence="topology/edge",
            ),
        ),
        priority_total=0.7,
        weighted_sum=0.7,
        total_weight=1.0,
        rationale="checkout is customer-facing and the latency cell has never been run",
        hypothesis="p99 rises under packet loss on checkout",
        suggested_probes=("histogram:p99",),
        stop_conditions=("p99 > 400ms for 30s",),
        cited_facts=(
            TracedFact(kind="topology", ref="topology/edge", detail="checkout is customer-facing"),
        ),
        submits_through="mayhem advisor submit",
    )


def _advisor_dashboard() -> AdvisorDashboard:
    return AdvisorDashboard(
        artifact="advisor",
        landscape_id="land-1",
        criteria_name="customer-facing-first",
        declared_criteria=(),
        topology_snapshot_id="topo-0001",
        graph_identity="b" * 64,
        ranked=(_ranked(),),
        drafts=(),
        suppressed=(
            SuppressedView(
                cell_key="payments/loss",
                reason="the loss cell is already covered by a recorded run",
                detail="a recorded run exercised it on 2026-05-01",
            ),
        ),
        mutation_backend_attached=False,
        mutation_calls=0,
        notes=(),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Plan 14 — the plan display, in both projections
# ═════════════════════════════════════════════════════════════════════════════


class TestTheBuilderRendersPlan14sOwnViewModel:
    def test_the_page_renders_from_the_same_payload_the_cli_reads(self) -> None:
        """The drift test, as an identity.

        ``preview_payload(view)`` is what plan 14 built *for a UI to render*, and
        ``render_preview_lines(view)`` is what its CLI renders. Asserting both
        against the page means the UI shows what the CLI shows because they were
        handed one object — not because anybody compared two renderers.
        """
        view = _preview_view()
        payload = preview_payload(view)
        page = render_builder_page(
            {"preview": payload, "parameters": []},
            api_path="/api/v1/parameters",
        )
        assert page.api_payload["preview"] == payload

        cli_text = "\n".join(render_preview_lines(view))
        # Every rule the CLI names is named by the page, and vice versa.
        for claim in view.claims:
            assert claim.rule_id in cli_text
            assert claim.rule_id in page.body_html
            assert claim.reason in page.body_html

    def test_a_breach_is_rendered_and_a_breach_count_is_read_not_recomputed(
        self,
    ) -> None:
        view = _preview_view()
        page = render_builder_page(
            {"preview": preview_payload(view), "parameters": []},
            api_path="/api/v1/parameters",
        )
        assert len(view.breaches) == 1
        assert "1 outside" in "\n".join(render_preview_lines(view))
        assert "damage_budget.max_total" in page.body_html
        assert "narrow the target selector" in page.body_html

    def test_the_cost_disclosure_carries_no_currency_and_no_total(self) -> None:
        """Plan 14 refuses to invent money; the page does not undo that."""
        view = _preview_view()
        payload = preview_payload(view)
        assert "currency" not in payload["cost"]
        assert "total" not in payload["cost"]
        page = render_builder_page(
            {"preview": payload, "parameters": []},
            api_path="/api/v1/parameters",
        )
        assert "unpriced" in page.body_html
        assert "$" not in page.body_html and "USD" not in page.body_html

    def test_an_unusable_preview_offers_no_submit_control(self) -> None:
        unusable = _preview_view(usable=False)
        page = render_builder_page(
            {"preview": preview_payload(unusable), "parameters": []},
            api_path="/api/v1/parameters",
        )
        assert "<form" not in page.body_html
        assert "not submittable" in page.body_html

    def test_the_submit_control_appears_for_a_usable_preview(self) -> None:
        """The negative control for the one above.

        Without this, "no submit control" would pass for a renderer that never
        emits one. Here the same renderer emits one when the view-model says the
        preview is usable, so the absence above is about ``usable_for_approval``
        and nothing else.
        """
        usable = _preview_view(usable=True)
        page = render_builder_page(
            {"preview": preview_payload(usable), "parameters": []},
            api_path="/api/v1/parameters",
        )
        assert "<form" in page.body_html
        assert "/api/v1/plans" in page.body_html

    def test_the_controls_are_projected_from_the_catalog_payload(self) -> None:
        from mayhem.controller.api_service import parameter_controls

        controls = [row.to_payload() for row in parameter_controls(["mem.leak"])]
        page = render_builder_page(
            {"preview": preview_payload(_preview_view()), "parameters": controls},
            api_path="/api/v1/parameters",
        )
        assert 'type="range"' in page.body_html, "a bounded numeric renders as a slider"
        assert "risk=" in page.body_html
        assert "mem.leak" in page.body_html


# ═════════════════════════════════════════════════════════════════════════════
# Plan 15 — the boundary report
# ═════════════════════════════════════════════════════════════════════════════


class TestTheBoundaryPageRendersPlan15sOwnViewModel:
    def test_a_reportable_signal_prints_its_tolerance(self) -> None:
        view = _boundary_view(reportable=True)
        page = render_boundary_page({"boundary": view.to_dict()}, api_path="/api/v1/boundaries")
        assert page.api_payload["boundary"] == view.to_dict()
        assert "tolerates p99 &lt;= 7.0 ms" in page.body_html
        assert "WITHHELD" not in page.body_html

    def test_an_unreportable_signal_is_printed_as_withheld_never_as_zero(self) -> None:
        view = _boundary_view(reportable=False)
        page = render_boundary_page({"boundary": view.to_dict()}, api_path="/api/v1/boundaries")
        assert "WITHHELD" in page.body_html
        assert "3 samples" in page.body_html
        # The negative control on the finding itself: a withheld tolerance must
        # not read as a tolerance of nothing.
        assert "tolerates p99 &lt;= 0" not in page.body_html

    def test_the_page_states_that_the_surface_granted_nothing(self) -> None:
        view = _boundary_view()
        assert view.authority == AUTHORITY_NONE
        page = render_boundary_page({"boundary": view.to_dict()}, api_path="/api/v1/boundaries")
        assert AUTHORITY_NONE in page.body_html
        assert any("granted nothing" in caveat for caveat in page.caveats)

    def test_an_untraceable_recommendation_never_reaches_a_renderer(self) -> None:
        """Plan 21's refusal lives *in the view-model*.

        :func:`~mayhem.cli.advisor_cmd.ranked_views` raises for a recommendation
        whose rationale cannot be traced. Deleting the Click callback cannot make
        the UI permissive, because the refusal happens before a payload exists to
        render. Asserted by calling it, not by reading the source.
        """
        from mayhem.cli.advisor_cmd import (
            RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE,
            AdvisorViewRefused,
            ranked_views,
        )
        from mayhem.domain.advisor import CustomerCriterion, PriorityCriteria

        criteria = PriorityCriteria(
            name="customer-facing-first",
            criteria=(
                CustomerCriterion(
                    name="customer_facing",
                    weight=1.0,
                    question="does a customer wait on this?",
                ),
            ),
        )
        untraceable = _untraceable_recommendation(criteria)
        assert untraceable.render_refusal_reason(), (
            "the fixture must be untraceable, or the refusal below proves nothing"
        )
        with pytest.raises(AdvisorViewRefused) as caught:
            ranked_views([untraceable], criteria)
        assert caught.value.rule == RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE
        assert "customer_facing" in str(caught.value)

    def test_a_traceable_recommendation_is_rendered_by_the_same_function(
        self,
    ) -> None:
        """The negative control for the refusal above.

        Without it, "an untraceable recommendation never reaches a renderer"
        could pass for a ``ranked_views`` that renders nothing at all.
        """
        from mayhem.cli.advisor_cmd import ranked_views
        from mayhem.domain.advisor import (
            CoverageLandscape,
            CriterionReading,
            CustomerCriterion,
            ExperimentCandidate,
            Finding,
            Priority,
            PriorityCriteria,
            Recommendation,
            RecommendationOrigin,
        )
        from mayhem.domain.coverage import CellState, CoverageCell

        declared = CustomerCriterion(
            name="customer_facing",
            weight=1.0,
            question="does a customer wait on this?",
        )
        criteria = PriorityCriteria(name="customer-facing-first", criteria=(declared,))
        cell = CoverageCell(
            target="checkout",
            fault_kind="net.latency",
            execution_context="steady",
            parameter_band="5s",
        )
        finding = Finding(
            finding_id="f-1",
            failure_mode="latency",
            summary="never established",
            cell=cell,
            cell_state=CellState.UNKNOWN,
            landscape=CoverageLandscape(landscape_id="land-1", cells=(cell,)),
            topology_node_ids=("checkout",),
            graph_identity="b" * 64,
        )
        traceable = Recommendation(
            recommendation_id="rec-traceable",
            candidate=ExperimentCandidate(experiment_id="exp-1", hypothesis="h"),
            finding=finding,
            priority=Priority(
                criteria_name=criteria.name,
                readings=(
                    CriterionReading(criterion=declared, value=1.0, evidence="topology/edge"),
                ),
            ),
            rationale="customer_facing: checkout is on the customer path",
            origin=RecommendationOrigin.AUTHORED,
        )
        ranked = ranked_views([traceable], criteria)
        assert len(ranked) == 1
        assert ranked[0].recommendation_id == "rec-traceable"
        assert ranked[0].declared_criteria, "the trace travels with the row"


def _untraceable_recommendation(criteria: Any) -> Any:
    """A real :class:`Recommendation` whose rationale names no declared criterion.

    Built from plan 21's own domain dataclasses rather than by monkeypatching, so
    the refusal below is the engine's refusal and not an artefact of a fake.
    """
    from mayhem.domain.advisor import (
        CoverageLandscape,
        CriterionReading,
        CustomerCriterion,
        ExperimentCandidate,
        Finding,
        Priority,
        Recommendation,
        RecommendationOrigin,
    )
    from mayhem.domain.coverage import CellState, CoverageCell

    cell = CoverageCell(
        target="checkout",
        fault_kind="net.latency",
        execution_context="steady",
        parameter_band="5s",
    )
    declared = CustomerCriterion(
        name="customer_facing",
        weight=1.0,
        question="does a customer wait on this?",
    )
    finding = Finding(
        finding_id="f-1",
        failure_mode="latency",
        summary="the latency cell has never been established",
        cell=cell,
        cell_state=CellState.UNKNOWN,
        landscape=CoverageLandscape(landscape_id="land-1", cells=(cell,)),
        topology_node_ids=("checkout",),
        graph_identity="b" * 64,
    )
    return Recommendation(
        recommendation_id="rec-untraceable",
        candidate=ExperimentCandidate(experiment_id="exp-1", hypothesis="h"),
        finding=finding,
        priority=Priority(
            criteria_name=criteria.name,
            readings=(CriterionReading(criterion=declared, value=1.0, evidence="topology/edge"),),
        ),
        rationale="trust me",
        origin=RecommendationOrigin.AUTHORED,
    )


# ═════════════════════════════════════════════════════════════════════════════
# Plan 21 — the ranked recommendations
# ═════════════════════════════════════════════════════════════════════════════


class TestTheRecommendationsPageRendersPlan21sOwnViewModel:
    def test_the_page_renders_from_the_advisor_dashboards_own_projection(self) -> None:
        dashboard = _advisor_dashboard()
        payload = dashboard.to_dict()
        page = render_recommendations_page(
            {"dashboard": payload}, api_path="/api/v1/recommendations"
        )
        assert page.api_payload["dashboard"] == payload
        assert dashboard.standing == ADVISORY_STANDING
        assert dashboard.grants_approval is False
        assert dashboard.grants_authorization is False
        assert ADVISORY_STANDING in page.body_html

    def test_the_rationale_and_its_traced_criteria_are_both_shown(self) -> None:
        page = render_recommendations_page(
            {"dashboard": _advisor_dashboard().to_dict()},
            api_path="/api/v1/recommendations",
        )
        ranked = _ranked()
        assert ranked.rationale in page.body_html
        assert ranked.criteria_name in page.body_html
        assert str(ranked.priority_total) in page.body_html

    def test_what_was_declined_is_shown_beside_what_was_ranked(self) -> None:
        """The honesty half: the gap between the landscape and the findings."""
        page = render_recommendations_page(
            {"dashboard": _advisor_dashboard().to_dict()},
            api_path="/api/v1/recommendations",
        )
        assert "already covered by a recorded run" in page.body_html


# ═════════════════════════════════════════════════════════════════════════════
# The UI principle, mechanically
# ═════════════════════════════════════════════════════════════════════════════


class TestEveryPageNamesItsApiObject:
    def test_the_page_table_is_closed_and_every_page_has_a_renderer(self) -> None:
        assert set(UI_PAGES) == set(PageId)
        assert {entry["page"] for entry in ui_pages()} == {entry.value for entry in PageId}

    def test_render_page_dispatches_every_id(self) -> None:
        payloads = {
            PageId.DASHBOARD: {"numbers": []},
            PageId.BUILDER: {"preview": {}, "parameters": []},
            PageId.LIVE_RUN: {"run": {"run_id": "r-1"}},
            PageId.BOUNDARIES: {"boundary": {}},
            PageId.RECOMMENDATIONS: {"dashboard": {}},
            PageId.APPROVALS: {"items": []},
            PageId.EVIDENCE: {"evidence": {"ref_id": "ev-1"}},
        }
        for page_id, payload in payloads.items():
            page = render_page(page_id, payload, api_path=f"/api/v1/{page_id.value}")
            assert page.page_id is page_id
            assert page.api_payload is payload

    def test_an_unknown_page_id_is_refused_naming_the_pages_that_exist(self) -> None:
        with pytest.raises(UiRenderRefusedError) as caught:
            render_page("no-such-page", {}, api_path="/x")
        assert caught.value.rule_id == RULE_UI_NO_API_OBJECT
        for entry in PageId:
            assert entry.value in caught.value.message

    @pytest.mark.parametrize(
        "page_id",
        [PageId.DASHBOARD, PageId.BUILDER, PageId.LIVE_RUN, PageId.BOUNDARIES],
    )
    def test_a_payload_missing_the_object_is_refused_not_rendered_empty(
        self, page_id: PageId
    ) -> None:
        """The negative control: an empty page reads as "nothing happened here"."""
        with pytest.raises(UiRenderRefusedError) as caught:
            render_page(page_id, {}, api_path="/api/v1/whatever")
        assert caught.value.rule_id == RULE_UI_NO_API_OBJECT

    def test_every_page_carries_its_payload_and_its_api_path(self) -> None:
        payload = {"evidence": {"ref_id": "ev-1", "run_id": "r-1"}}
        page = render_evidence_page(payload, api_path="/api/v1/runs/r-1/evidence")
        assert page.api_path == "/api/v1/runs/r-1/evidence"
        assert page.api_payload is payload
        assert page.api_path in page.to_html()


# ═════════════════════════════════════════════════════════════════════════════
# The dashboard's evidence rule, on the HTML side
# ═════════════════════════════════════════════════════════════════════════════


class TestTheDashboardRefusesAnUntraceableNumber:
    @pytest.fixture()
    def payload(self) -> dict[str, Any]:
        return {
            "numbers": [
                {
                    "metric": "runs_passed",
                    "value": 3.0,
                    "unit": "runs",
                    "detail": "3 of 10 graded",
                    "evidence": [{"kind": "evidence_ref", "key": "ev-1", "detail": ""}],
                }
            ],
            "absent_metrics": ["coverage"],
            "unlinked_runs": [{"run_id": "r-9", "reason": "no sealed envelope"}],
        }

    def test_a_linked_number_renders_with_its_evidence(self, payload: dict[str, Any]) -> None:
        page = render_dashboard(payload, api_path="/api/v1/dashboard")
        assert "runs_passed" in page.body_html
        assert "evidence_ref/ev-1" in page.body_html
        assert page.evidence_refs

    def test_an_unlinked_number_is_refused(self, payload: dict[str, Any]) -> None:
        stripped = json.loads(json.dumps(payload))
        stripped["numbers"][0]["evidence"] = []
        with pytest.raises(UiRenderRefusedError) as caught:
            render_dashboard(stripped, api_path="/api/v1/dashboard")
        assert caught.value.rule_id == RULE_UI_NUMBER_WITHOUT_EVIDENCE
        assert "runs_passed" in caught.value.message

    def test_an_absent_metric_is_rendered_as_withheld_not_as_zero(
        self, payload: dict[str, Any]
    ) -> None:
        """Coverage with no figure reads as "withheld", which is the honest word."""
        page = render_dashboard(payload, api_path="/api/v1/dashboard")
        assert "withheld" in page.body_html
        assert "coverage" in page.body_html
        assert "coverage 0" not in page.body_html

    def test_an_unlinked_run_is_named_beside_the_numbers(self, payload: dict[str, Any]) -> None:
        page = render_dashboard(payload, api_path="/api/v1/dashboard")
        assert "r-9" in page.body_html
        assert "no sealed envelope" in page.body_html


# ═════════════════════════════════════════════════════════════════════════════
# Plan 10's stop button
# ═════════════════════════════════════════════════════════════════════════════


class TestTheStopControl:
    def test_the_panel_is_one_form_posting_to_the_stop_endpoint(self) -> None:
        panel = render_stop_panel("r-ui-0001")
        assert 'action="/api/v1/runs/r-ui-0001/stop"' in panel
        assert 'method="post"' in panel
        assert 'name="reason"' in panel and "required" in panel

    def test_the_reason_field_is_required(self) -> None:
        """``mayhem stop`` requires it because a stop with no reason cannot seal."""
        panel = render_stop_panel("r-ui-0001")
        assert 'id="reason"' in panel
        assert "cannot be sealed" in panel

    def test_there_is_no_bypass_control(self) -> None:
        """Asserted over *control names*, not over prose.

        The panel says out loud that there is no force option, so a word search
        would find its own explanation. What must not exist is an input the
        browser could submit — and an input the gateway does not read is not a
        bypass, so the assertion is about what the form can carry.
        """
        panel = render_stop_panel("r-ui-0001")
        submitted = set(re.findall(r'<(?:input|select|button)[^>]*name="([^"]+)"', panel))
        assert submitted == {"reason", "idempotency_key"}
        assert not any("force" in name or "skip" in name for name in submitted)

    def test_the_bypass_check_is_not_vacuously_true(self) -> None:
        """The negative control for the check above."""
        forbidden_construct = (
            '<form method="post" action="/api/v1/runs/r-1/stop">'
            '<input type="checkbox" name="force">'
            "</form>"
        )
        names = set(re.findall(r'<(?:input|select|button)[^>]*name="([^"]+)"', forbidden_construct))
        assert "force" in names
        panel = render_stop_panel("r-ui-0001")
        real = set(re.findall(r'<(?:input|select|button)[^>]*name="([^"]+)"', panel))
        assert "force" not in real

    def test_a_run_page_with_no_run_id_renders_no_control_at_all(self) -> None:
        page = render_run_page({"run": {}}, api_path="/api/v1/runs/unknown")
        assert "cannot render a stop control" in page.body_html
        assert "<form" not in page.body_html

    def test_the_run_page_carries_the_timeline_and_the_withheld_sections(self) -> None:
        payload = {
            "run": {"run_id": "r-ui-0001", "verdict": "fail", "status": "completed"},
            "timeline": {
                "points": [
                    {
                        "phase": "baseline",
                        "sequence": 0,
                        "kind": "run.started",
                        "summary": "baseline captured",
                        "event_digest": "c" * 64,
                    }
                ]
            },
            "explanation": {
                "run_id": "r-ui-0001",
                "evidence_ref": "ev-1",
                "claims": [
                    {
                        "section": "impact",
                        "statement": "p99 rose 310ms",
                        "observations": [
                            {"kind": "steady_signal", "key": "verify/p99", "detail": ""}
                        ],
                    }
                ],
                "withheld": [
                    {
                        "section": "root_failure",
                        "reason": "nothing was graded, so no cause is assertable",
                        "missing": ["steady_state verdicts"],
                    }
                ],
            },
        }
        page = render_run_page(payload, api_path="/api/v1/runs/r-ui-0001")
        assert "baseline" in page.body_html
        assert "p99 rose 310ms" in page.body_html
        assert "steady_signal/verify/p99" in page.body_html
        assert "nothing was graded" in page.body_html
        assert page.evidence_refs == ("ev-1",)


# ═════════════════════════════════════════════════════════════════════════════
# The approvals and evidence pages, and their honesty claims
# ═════════════════════════════════════════════════════════════════════════════


class TestApprovalsAndEvidence:
    def test_the_approvals_page_offers_no_write_control(self) -> None:
        payload = {
            "items": [
                {
                    "approval_id": "ap-1",
                    "plan_digest": "a" * 64,
                    "state": "valid",
                    "approver": "u-ana",
                }
            ]
        }
        page = render_approvals_page(payload, api_path="/api/v1/approvals")
        assert "ap-1" in page.body_html
        assert "<form" not in page.body_html
        assert any("writable nowhere over HTTP" in caveat for caveat in page.caveats)

    def test_the_evidence_page_does_not_claim_a_signature(self) -> None:
        payload = {
            "evidence": {
                "ref_id": "ev-1",
                "run_id": "r-1",
                "plan_digest": "a" * 64,
                "complete": True,
                "sealed_at": "2026-06-01T12:00:00+00:00",
            }
        }
        page = render_evidence_page(payload, api_path="/api/v1/runs/r-1/evidence")
        assert "ev-1" in page.body_html
        assert any("not who sealed them" in caveat for caveat in page.caveats)
        assert page.evidence_refs == ("ev-1",)

    def test_an_absent_evidence_reference_is_a_404_not_an_empty_page(self) -> None:
        with pytest.raises(UiRenderRefusedError):
            render_evidence_page({}, api_path="/api/v1/runs/r-1/evidence")


# ═════════════════════════════════════════════════════════════════════════════
# Rendering safety
# ═════════════════════════════════════════════════════════════════════════════


def test_payload_text_is_escaped_not_injected() -> None:
    """A run id or a rationale is data, never markup."""
    payload = {
        "evidence": {
            "ref_id": "<script>alert(1)</script>",
            "run_id": "r-1",
            "plan_digest": "a" * 64,
        }
    }
    page = render_evidence_page(payload, api_path="/api/v1/runs/r-1/evidence")
    assert "<script>" not in page.body_html
    assert "&lt;script&gt;" in page.body_html


def test_the_text_property_strips_tags_for_assertions() -> None:
    page = render_evidence_page(
        {"evidence": {"ref_id": "ev-1", "run_id": "r-1"}},
        api_path="/api/v1/runs/r-1/evidence",
    )
    assert "<" not in page.text
    assert "ev-1" in page.text
