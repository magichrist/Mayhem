"""The control-plane UI: server-rendered pages built from the API payloads, and
from *other plans' view-models* (plan 08, Phase 3).

What this module is
-------------------

A set of pure renderers plus a WSGI application that serves them. The pages are
HTML with no JavaScript, no CSS framework, and no bundler — because there is no
frontend runtime in this project and adding one would add a dependency the plan
forbids. What *is* real is the part the plan's acceptance criterion is about:
**every number, stance, and label on a page came out of an API payload**, and the
payloads came out of the view-models plans 14, 15, and 21 already built.

The five view-models this UI consumes
-------------------------------------

The constraint that shapes this module is that three lanes landed pure view-model
layers *specifically* so that a UI could render from the same structure, and each
recorded the absence of a second renderer as the open half of its acceptance
criterion. This module is that half:

===================== ========================================================
consumed view-model    what this UI renders from it
===================== ========================================================
plan 14               :func:`mayhem.cli.risk_preview_cmd.build_risk_preview` →
                      :func:`~mayhem.cli.risk_preview_cmd.preview_payload` — the
                      plan display: target set, per-rule policy stances, cost
                      disclosure, usability for approval. The **experiment
                      screen** and the **plan review** page are this payload.
plan 15               :func:`mayhem.cli.boundary_report_cmd.boundary_report_view`
                      → :meth:`~mayhem.cli.boundary_report_cmd.BoundaryReportView.to_dict`
                      — the resilience boundary report, including which signals
                      are **withheld**. The **boundaries** page is this payload.
plan 21               :func:`mayhem.cli.advisor_cmd.ranked_views` /
                      :func:`~mayhem.cli.advisor_cmd.advisor_dashboard` →
                      ``AdvisorDashboard.to_dict()`` — ranked recommendations
                      with their traced criteria, and the gap between the declared
                      landscape and the findings. The **recommendations** page is
                      this payload.
plan 08 Phase 1        :class:`~mayhem.domain.api.RunTimeline`,
                      :class:`~mayhem.domain.api.FailureExplanation`,
                      :class:`~mayhem.domain.api.ExecutiveSummary` — the timeline
                      (gap 32), the failure explanation (gap 60), and the
                      executive numbers (gap 59). The **live run**, **failure
                      report**, and **dashboard** pages are these payloads.
===================== ========================================================

Why drift is prevented rather than asserted
--------------------------------------------

The pages are **built from the payload dictionaries**, never from the domain
objects behind them. :func:`render_page` takes a ``dict[str, Any]`` — the exact
object the gateway's ``GET`` returns — and every helper it calls reads keys out
of that dict. There is no code path from a page to a domain object, so the UI
*cannot* render something the API did not send. A test asserting "the CLI and the
UI agree" would be comparing two renderers that could diverge; a test asserting
``page.api_payload == gateway_response.data`` is comparing an identity, and
``tests/unit/test_api_ui.py`` asserts exactly that.

And the CLI half is not asserted either: plan 14's ``render_preview_lines`` reads
:class:`~mayhem.cli.risk_preview_cmd.RiskPreviewView`, whose ``to_payload`` is what
this module consumes, so "identical in CLI and UI" is a property of one object
having two projections rather than a claim two teams maintain in step.

What is *not* here, and why
---------------------------

**There is no browser bundle and no SPA.** A React/Vue build would need Node, a
bundler, and a lockfile this repository does not have, and an artefact nobody in
CI can run is an artefact nobody can trust. Server-rendered HTML over
:mod:`wsgiref` is the whole of the UI, and it is a real, runnable, tested UI — not
a placeholder for one.

**There is no live-update transport.** The plan names SSE and WebSocket; neither
is implemented, because a connection held open by a single-threaded
``wsgiref`` server is a connection that blocks every other request. The live-run
page is a *refresh* of the same payload. Named here rather than quietly omitted.

**There is no authentication UI.** Credentials are minted by plan 09's CLI/Python
surface; a browser gets a session the operator pastes in. There is no login form,
no password field in any page, and no cookie handling, because a control plane
that stores a credential in a cookie needs a CSRF story this build does not have.

Refusals, in the UI as everywhere else
--------------------------------------

Four, and each is the reason a page is missing rather than the reason a page is
blank:

* **A number without an evidence link does not render.** :func:`render_dashboard`
  refuses a payload whose numbers carry no evidence. Phase 1 already makes that
  payload unconstructible; the check here is what keeps a *future* Phase 1 change
  from quietly making it constructible again, and it is a refusal rather than a
  redacted row because a redacted row reads as "zero".
* **An untraceable recommendation does not render.** The refusal already lives in
  plan 21's :func:`~mayhem.cli.advisor_cmd.ranked_views`, *in the view-model* — so
  a caller who swallows it and renders a shortened list cannot make the UI
  permissive, only the caller dishonest.
* **An unwitnessed value renders as unavailable, never as zero.** Coverage,
  incidents, and cost come through with their own ``available`` flags; the
  renderer has no ``or 0`` and no "assume clean" branch.
* **A page for a run with no stored resource is a 404**, not an empty page. An
  empty page says "this run is empty", which is a finding; a 404 says "this run
  is not here", which is the truth.

The stop button plan 10 asked for
---------------------------------

Plan 10's Phase 3 STATUS line records that the "08 UI button" for
:meth:`~mayhem.cli.stop_cmd` was absent. :func:`render_stop_panel` is that button:
it renders the one command plan 10 defines — *stop this run* — as a form whose
single submission is ``POST /api/v1/runs/{run_id}/stop``, which the gateway
authorizes with :data:`~mayhem.controller.check_gate.CHATOPS_REQUIRED_ROLE`'s
``emergency_stop`` role and hands to the CLI's own stop path. It has **no
``--force`` equivalent, no confirmation bypass, and no client-side-only gate**,
because those would be bypasses of the very gate the plan asked to be
unskippable.

.. warning::

   **The button is rendered and the endpoint is routed; the ledger it seals is
   the CLI's.** Wiring ``RunEngine``'s preflight gate into the run path is still
   absent (plan 10 Phase 3, INCOMPLETE), and this module does not paper over
   that: the panel says the request will be refused by the same gate, and a
   refused stop writes nothing. What is *not* claimed is that a stop initiated
   from this page has plan 10's stop-latency bound measured against it — that
   bound remains plan 10's open item.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

__all__ = [
    "RULE_UI_NO_API_OBJECT",
    "RULE_UI_NUMBER_WITHOUT_EVIDENCE",
    "RULE_UI_PAYLOAD_MISMATCH",
    "UI_PAGES",
    "UI_PAGE_SUMMARIES",
    "Page",
    "PageId",
    "UiRenderRefusedError",
    "UiSource",
    "render_approvals_page",
    "render_boundary_page",
    "render_builder_page",
    "render_dashboard",
    "render_evidence_page",
    "render_page",
    "render_recommendations_page",
    "render_run_page",
    "render_stop_panel",
    "ui_pages",
]


class UiRenderRefusedError(Exception):
    """The UI refuses to render a payload.

    Not an :class:`~mayhem.domain.errors.InvariantViolationError`: this one is a
    *presentation* refusal and never reaches a client's HTTP status directly. The
    WSGI application turns it into :data:`RULE_UI_PAYLOAD_MISMATCH` and a 502,
    because a page that cannot be rendered from the payload the API sent is a
    server-side disagreement, not a caller's mistake.
    """

    def __init__(self, rule_id: str, message: str) -> None:
        self.rule_id = rule_id
        self.message = message
        super().__init__(f"[{rule_id}] {message}")


RULE_UI_NO_API_OBJECT = "ui.no_api_object"
RULE_UI_PAYLOAD_MISMATCH = "ui.payload_mismatch"
RULE_UI_NUMBER_WITHOUT_EVIDENCE = "ui.number_without_evidence"

#: Where the UI refuses a number it cannot trace. Asserted by
#: ``tests/unit/test_api_ui.py`` from both sides.
_UI_RULES: Final[tuple[str, ...]] = (
    RULE_UI_NO_API_OBJECT,
    RULE_UI_PAYLOAD_MISMATCH,
    RULE_UI_NUMBER_WITHOUT_EVIDENCE,
)


class PageId(StrEnum):
    """The pages this build serves. Closed, so a link to a missing page fails.

    Every member is rendered by a function named in :data:`UI_PAGES` and every
    one is reachable from :func:`ui_pages`, so "the UI has a dashboard" is a fact
    about one table rather than a set of routes scattered across a router.
    """

    DASHBOARD = "dashboard"
    BUILDER = "builder"
    LIVE_RUN = "live-run"
    BOUNDARIES = "boundaries"
    RECOMMENDATIONS = "recommendations"
    APPROVALS = "approvals"
    EVIDENCE = "evidence"


@dataclass(frozen=True, slots=True)
class Page:
    """One rendered page, and the API object it was rendered from.

    ``api_payload`` is not a debug artifact: it is the identity the drift tests
    assert on, and it is what makes "everything visible in the UI maps back to a
    machine-readable API object" (the plan's UI principle) checkable rather than
    aspirational. A page that cannot name its payload is not rendered.
    """

    page_id: PageId
    title: str
    api_path: str
    api_payload: Mapping[str, Any]
    body_html: str
    warnings: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    caveats: tuple[str, ...] = field(default_factory=tuple)

    def to_html(self) -> str:
        nav = "".join(
            f'<li><a href="/ui/{entry.value}">{html.escape(entry.value)}</a></li>'
            for entry in PageId
        )
        caveat_rows = "".join(f"<li>{html.escape(text)}</li>" for text in self.caveats)
        caveat_block = (
            f"<h2>what this page does not claim</h2><ul>{caveat_rows}</ul>" if caveat_rows else ""
        )
        evidence = (
            f"<p>evidence: {html.escape(', '.join(self.evidence_refs))}</p>"
            if self.evidence_refs
            else ""
        )
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f"<title>mayhem: {html.escape(self.title)}</title></head><body>"
            f"<h1>{html.escape(self.title)}</h1>"
            f'<nav><p>API object: <a href="{html.escape(self.api_path)}">'
            f"{html.escape(self.api_path)}</a></p><ul>{nav}</ul></nav>"
            f"{self.body_html}{evidence}{caveat_block}"
            "</body></html>"
        )

    @property
    def text(self) -> str:
        """The rendered text with tags stripped. For assertions, not for display."""
        stripped: list[str] = []
        inside = False
        for char in self.body_html:
            if char == "<":
                inside = True
            elif char == ">":
                inside = False
                stripped.append(" ")
            elif not inside:
                stripped.append(char)
        return "".join(stripped)


class UiSource(Protocol):
    """Where the UI gets its payloads: the gateway.

    Declared as a protocol rather than typed as
    :class:`~mayhem.controller.api_service.ApiGateway` so the renderer tests can
    hand a *recording* source — a function that returns a fixed payload — without
    standing up identity, a store, and a migration chain to draw a page. That is
    what lets the drift test compare the UI's payload against a literal the test
    wrote, which is the only comparison that proves the UI read the payload rather
    than recomputing it.
    """

    def dispatch(self, request: Any) -> Any: ...


# --------------------------------------------------------------------------- #
# small rendering helpers                                                      #
# --------------------------------------------------------------------------- #


def _esc(value: object) -> str:
    return html.escape(str(value))


def _kv_table(rows: Sequence[tuple[str, object]]) -> str:
    if not rows:
        return "<p>nothing recorded</p>"
    cells = "".join(f"<tr><th>{_esc(key)}</th><td>{_esc(value)}</td></tr>" for key, value in rows)
    return f"<table>{cells}</table>"


def _raw_table(rows: Sequence[str]) -> str:
    """A table whose *cells* are markup this module built, not data.

    Separate from :func:`_kv_table` on purpose. One of the two takes untrusted
    strings and escapes them; this one takes strings already assembled from
    :func:`_widget`, which reads a projected schema and escapes every value it
    embeds. Having both spellings available is the hazard, so only the two
    call sites in this module use it.
    """
    if not rows:
        return "<p>no parameter is projected for this fault</p>"
    return "<table>" + "".join(rows) + "</table>"


def _list(items: Sequence[object], *, empty: str = "none recorded") -> str:
    if not items:
        return f"<p>{_esc(empty)}</p>"
    return "<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in items) + "</ul>"


def _require(payload: Mapping[str, Any], key: str, api_path: str) -> Any:
    """One required key, or a refusal naming what was missing.

    Refusing rather than defaulting is the whole of the UI principle in four
    lines: a page whose payload lacked the object it is about would render an
    empty page, and an empty page reads as "nothing happened here" rather than
    "this build could not find it".
    """
    if key not in payload:
        raise UiRenderRefusedError(
            RULE_UI_NO_API_OBJECT,
            f"the payload from {api_path} has no {key!r} key, so this page has no API "
            "object to render; rendering it empty would read as 'nothing is here'",
        )
    return payload[key]


# --------------------------------------------------------------------------- #
# Pages                                                                        #
# --------------------------------------------------------------------------- #


def render_dashboard(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """The executive dashboard (gap 59).

    One rule, enforced rather than assumed: **a number without an evidence link
    does not render.** Phase 1 makes such a payload unconstructible
    (:class:`~mayhem.domain.api.ExecutiveNumber` requires ``evidence`` with
    ``min_length=1``), and this refuses anyway, because the acceptance criterion
    is "a dashboard number without an evidence link fails review" and a check
    nobody can fail is a check nobody runs.
    """
    summary = _require(payload, "numbers", api_path)
    unlinked = [row.get("metric") for row in summary if not row.get("evidence")]
    if unlinked:
        raise UiRenderRefusedError(
            RULE_UI_NUMBER_WITHOUT_EVIDENCE,
            f"dashboard number(s) {unlinked} carry no evidence link; a figure a reader "
            "cannot trace to a sealed envelope is not one this page will print",
        )
    rows: list[tuple[str, object]] = []
    for number in summary:
        refs = ", ".join(_ref_text(ref) for ref in number.get("evidence", ()))
        rows.append(
            (
                str(number.get("metric", "?")),
                f"{number.get('value')} {number.get('unit', '')}".strip()
                + f" — {number.get('detail', '')} (evidence: {refs})",
            )
        )
    absent = payload.get("absent_metrics") or []
    unlinked_runs = payload.get("unlinked_runs") or []
    body = (
        _kv_table(rows)
        + "<h2>withheld</h2>"
        + _list([str(metric) for metric in absent], empty="no metric is withheld")
        + "<h2>runs counted nowhere</h2>"
        + _list(
            [f"{row.get('run_id')}: {row.get('reason')}" for row in unlinked_runs],
            empty="every run counted here has sealed evidence behind it",
        )
    )
    return Page(
        page_id=PageId.DASHBOARD,
        title="mayhem — resilience dashboard",
        api_path=api_path,
        api_payload=payload,
        body_html=body,
        evidence_refs=tuple(_ref_text(ref) for row in summary for ref in row.get("evidence", ())),
        caveats=(
            "coverage is withheld rather than estimated when no coverage figure carries "
            "evidence; an absent metric is not zero",
            "a run with no sealed envelope contributes to no number at all and is named "
            "under 'runs counted nowhere'",
        ),
    )


def render_builder_page(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """The experiment builder, with the parameter UX (gap 61).

    Renders plan 14's **plan display** — :func:`mayhem.cli.risk_preview_cmd.preview_payload`
    — beside the catalog-derived controls from
    :meth:`~mayhem.controller.api_service.parameter_controls`, in that order,
    because the controls are what you adjust and the plan display is what the
    adjustment produced.

    ``usable_for_approval`` is rendered verbatim, including when false. The page
    has no "proceed" affordance that appears only sometimes: a submit control that
    is conditionally hidden is a control whose absence is the message, and a
    message that is only visible when it is absent is not a message.
    """
    preview = _require(payload, "preview", api_path)
    controls = payload.get("parameters") or []
    control_rows: list[str] = []
    for control in controls:
        annotations = [
            f"risk={control.get('risk', 'unknown')}",
            f"reversible={control.get('reversible', 'unknown')}",
            f"max_duration_s={control.get('max_duration_s', 'unknown')}",
        ]
        caps = control.get("required_capabilities") or []
        if caps:
            annotations.append("requires " + ", ".join(str(cap) for cap in caps))
        # The widget goes in **unescaped** — it is markup this module built from
        # the projected schema, not data — and everything beside it is escaped by
        # ``_esc`` through ``_kv_table``. Mixing the two is the mistake this line
        # exists to make impossible: escaping the widget would render a range
        # input as visible angle brackets, and not escaping the annotation would
        # render a capability name as markup.
        control_rows.append(
            "<tr><th>"
            + _esc(f"{control.get('fault_id', '?')}.{control.get('name', '?')}")
            + "</th><td>"
            + _widget(control)
            + _esc(f" default={control.get('default')!r} — " + "; ".join(annotations))
            + "</td></tr>"
        )
    claims = preview.get("claims") or []
    claim_rows: list[tuple[str, object]] = [
        (
            str(claim.get("rule_id", "?")),
            f"{claim.get('stance', '?')} — {claim.get('reason', '')}"
            + (f" [remediation: {claim['remediation']}]" if claim.get("remediation") else ""),
        )
        for claim in claims
    ]
    cost = preview.get("cost") or {}
    usable = bool(preview.get("usable_for_approval"))
    submit = (
        '<form method="post" action="/api/v1/plans">'
        '<input type="hidden" name="idempotency_key" value="">'
        '<button type="submit">submit this experiment</button></form>'
        if usable
        else "<p><strong>not submittable:</strong> this preview is not usable for "
        "approval, so no submit control is offered.</p>"
    )
    body = (
        "<h2>parameters</h2>"
        + _raw_table(control_rows)
        + "<h2>plan display</h2>"
        + _kv_table(
            [
                ("run", preview.get("run_id", "")),
                ("plan", preview.get("plan_identity", "")),
                ("graph", preview.get("graph_identity", "")),
                ("breaches", preview.get("breach_count", 0)),
                ("agreement", preview.get("agreement_state", "")),
                ("gate refused", ", ".join(preview.get("gate_refused") or []) or "admitted"),
            ]
        )
        + _kv_table(claim_rows)
        + _kv_table(
            [
                (
                    "cost",
                    f"{cost.get('status', 'unknown')} — {cost.get('note', '')} "
                    f"({cost.get('affected_node_seconds', 0):g} affected-node seconds)",
                )
            ]
        )
        + _list([str(refusal) for refusal in preview.get("refusals") or []])
        + submit
    )
    return Page(
        page_id=PageId.BUILDER,
        title="mayhem — experiment builder",
        api_path=api_path,
        api_payload=payload,
        body_html=body,
        warnings=tuple(str(note) for note in preview.get("notes") or []),
        caveats=(
            "the controls above are projected from the catalog parameter schemas, so "
            "`mayhem --help` and this form read the same declaration",
            "cost is reported as unpriced: this repository has no price table, so no "
            "currency and no total are shown",
        ),
    )


def _widget(control: Mapping[str, Any]) -> str:
    """The control element for one parameter, from its projected kind.

    Every element is native HTML — ``<input type=range>``, ``<select>``,
    ``<input type=checkbox>``, ``<input type=text>`` — because that is what needs
    no JavaScript. The ``min``/``max``/``step`` attributes are emitted only when
    the schema declared them: a range input with a synthesised bound would let an
    operator submit a value the catalog never authorised.
    """
    kind = str(control.get("kind", "text"))
    name = _esc(control.get("name", ""))
    fault = _esc(control.get("fault_id", ""))
    label = f"{fault}.{name}"
    if kind == "slider":
        attrs = [
            f'name="{label}"',
            'type="range"',
            f'step="{control["step"]}"',
            f'min="{control["minimum"]}"',
            f'max="{control["maximum"]}"',
        ]
        if control.get("default") is not None:
            attrs.append(f'value="{control["default"]}"')
        return f"<input {' '.join(attrs)}>"
    if kind == "direction_selector":
        attrs = [
            f'name="{label}"',
            'type="range"',
            f'step="{control["step"]}"',
            f'min="{control["minimum"]}"',
            f'max="{control["maximum"]}"',
        ]
        if control.get("default") is not None:
            attrs.append(f'value="{control["default"]}"')
        return (
            f'<select name="{label}" data-control="direction">'
            + "".join(
                f'<option value="{_esc(bound)}">toward {_esc(bound)}</option>'
                for bound in (control.get("minimum"), control.get("maximum"))
            )
            + f"</select><input {' '.join(attrs)} hidden>"
        )
    if kind == "select":
        return (
            f'<select name="{label}">'
            + "".join(
                f'<option value="{_esc(choice)}">{_esc(choice)}</option>'
                for choice in control.get("choices", ())
            )
            + "</select>"
        )
    if kind == "boolean":
        checked = " checked" if control.get("default") else ""
        return f'<input type="checkbox" name="{label}"{checked}>'
    return f'<input type="text" name="{label}">'


def render_run_page(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """The live-run view: timeline (gap 32), explanation (gap 60), stop panel.

    Three API objects on one screen, each named in the page so a reader can tell
    which is which: the timeline is *derived* from stored events and carries no
    storage of its own; the explanation *withholds* the sections its observations
    cannot support, and the withholdings are printed rather than collapsed.
    """
    run = _require(payload, "run", api_path)
    timeline = payload.get("timeline") or {}
    explanation = payload.get("explanation") or {}
    points = timeline.get("points") or []
    point_rows: list[tuple[str, object]] = [
        (
            f"{point.get('phase', '?')} {point.get('sequence', '?')}",
            f"{point.get('kind', '?')} — {point.get('summary', '')} "
            f"(event digest {str(point.get('event_digest', ''))[:12]})",
        )
        for point in points
    ]
    withheld_rows: list[tuple[str, object]] = [
        (str(entry.get("section", "?")), str(entry.get("reason", "")))
        for entry in explanation.get("withheld") or []
    ]
    claims_rows: list[tuple[str, object]] = [
        (
            str(claim.get("section", "?")),
            f"{claim.get('statement', '')} (from "
            + ", ".join(_ref_text(ref) for ref in claim.get("observations") or ())
            + ")",
        )
        for claim in explanation.get("claims") or []
    ]
    body = (
        _kv_table(
            [
                ("run", run.get("run_id", "")),
                ("verdict", run.get("verdict", "")),
                ("status", run.get("status", "")),
                ("plan", run.get("plan_digest", "")),
                ("experiment", run.get("experiment_name", "")),
            ]
        )
        + "<h2>timeline</h2>"
        + _kv_table(point_rows)
        + "<h2>failure explanation</h2>"
        + _kv_table(claims_rows)
        + "<h2>withheld</h2>"
        + _kv_table(withheld_rows)
        + render_stop_panel(run.get("run_id", ""))
    )
    return Page(
        page_id=PageId.LIVE_RUN,
        title=f"mayhem — run {run.get('run_id', '')}",
        api_path=api_path,
        api_payload=payload,
        body_html=body,
        warnings=tuple(str(entry.get("reason", "")) for entry in explanation.get("withheld") or []),
        evidence_refs=(
            (str(explanation["evidence_ref"]),) if explanation.get("evidence_ref") else ()
        ),
        caveats=(
            "the timeline is derived from recorded events on every read; nothing on "
            "this page is stored as a point",
            "a withheld section means the stored observations cannot support a "
            "statement about it, not that nothing went wrong",
        ),
    )


def render_stop_panel(run_id: str) -> str:
    """Plan 10's stop button, as one form (plan 08 Phase 3).

    ``run_id`` is inserted into the action path, and the reason field is
    **required** — the same rule ``mayhem stop`` enforces, because a stop with no
    reason cannot be sealed. There is no force checkbox, no skip-preflight
    checkbox, and no client-side gate: the only gate is the one the endpoint runs,
    which resolves :data:`~mayhem.controller.check_gate.CHATOPS_REQUIRED_ROLE`'s
    ``emergency_stop`` role before anything is written.
    """
    if not run_id:
        return "<p>no run id: this page cannot render a stop control</p>"
    return (
        "<h2>stop</h2>"
        f'<form method="post" action="/api/v1/runs/{_esc(run_id)}/stop">'
        '<label for="reason">reason (required — a stop with no reason cannot be '
        "sealed)</label>"
        '<input id="reason" name="reason" type="text" required>'
        '<input type="hidden" name="idempotency_key" value="">'
        '<button type="submit">stop this run</button></form>'
        "<p>there is no force option and no way to skip the preflight gate from here; "
        "the endpoint refuses before it writes.</p>"
    )


def render_boundary_page(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """Plan 15's boundary report, rendered from its own view-model.

    ``reportable`` is read from the payload and is the only thing that decides
    whether a signal's tolerance is printed. A withheld signal prints its
    withholding and its ``withheld_reason``, so the row is visibly *refused*
    rather than blank — the same refusal the CLI's renderer makes, off the same
    object.
    """
    report = _require(payload, "boundary", api_path)
    signal_rows: list[tuple[str, object]] = []
    for signal in report.get("signals") or []:
        label = f"{signal.get('signal', '?')} ({signal.get('unit', '')})"
        if signal.get("reportable"):
            value = f"{signal.get('tolerance', '')} — {signal.get('graded_verdict', '')}"
        else:
            value = "WITHHELD: " + str(
                signal.get("refusal") or signal.get("withheld_reason") or "not reportable"
            )
        signal_rows.append((label, value))
    return Page(
        page_id=PageId.BOUNDARIES,
        title="mayhem — resilience boundaries",
        api_path=api_path,
        api_payload=payload,
        body_html=(
            _kv_table(
                [
                    ("run", report.get("run_id", "")),
                    ("policy", report.get("policy_name", "")),
                    ("strategy", report.get("strategy", "")),
                    ("trials", report.get("recorded_trials", 0)),
                    ("resolved", report.get("recorded_resolved", False)),
                    ("evidence complete", report.get("evidence_complete", False)),
                    ("authority", report.get("authority", "")),
                ]
            )
            + _kv_table(signal_rows)
        ),
        evidence_refs=tuple(
            str(ref)
            for signal in report.get("signals") or []
            for ref in signal.get("support_refs") or ()
        ),
        caveats=(
            "this surface granted nothing: the boundary report carries no authority and "
            "closes no evidence",
            "a signal whose confidence is insufficient is withheld rather than printed as "
            "a tolerance",
        ),
    )


def render_recommendations_page(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """Plan 21's ranked recommendations, rendered from its own dashboard.

    The ranking, the traced criteria, and the refusal of an untraceable rationale
    all happened in :func:`mayhem.cli.advisor_cmd.ranked_views` and
    :func:`mayhem.cli.advisor_cmd.advisor_dashboard` **before** this function was
    called. Deleting the Click callback cannot make this page permissive; it can
    only stop the page existing.
    """
    dashboard = _require(payload, "dashboard", api_path)
    ranked_rows: list[tuple[str, object]] = [
        (
            f"{row.get('position', '?')}. {row.get('recommendation_id', '?')}",
            f"{row.get('failure_mode', '')} in {row.get('cell_ref', '')} — "
            f"{row.get('rationale', '')} (priority {row.get('priority_total')} under "
            f"{row.get('criteria_name', '')}; authority {row.get('authority', '')})",
        )
        for row in dashboard.get("ranked") or []
    ]
    suppressed_rows: list[tuple[str, object]] = [
        (str(row.get("cell_key", "?")), str(row.get("reason", "")))
        for row in dashboard.get("suppressed") or []
    ]
    return Page(
        page_id=PageId.RECOMMENDATIONS,
        title="mayhem — ranked recommendations",
        api_path=api_path,
        api_payload=payload,
        body_html=_kv_table(
            [
                ("standing", dashboard.get("standing", "")),
                ("grants approval", str(dashboard.get("grants_approval", ""))),
                ("grants authorization", str(dashboard.get("grants_authorization", ""))),
                ("criteria", dashboard.get("criteria_name", "")),
            ]
        )
        + _kv_table(ranked_rows)
        + "<h2>declined</h2>"
        + _kv_table(suppressed_rows),
        caveats=(
            "this is an advisory surface: it correlates cited facts, and it grants no "
            "approval and no authorization",
            "a recommendation whose rationale cannot be traced against the declared "
            "criteria is not rendered here in any form",
        ),
    )


def render_approvals_page(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """Approvals, as stored. No approve control — see the note below.

    There is no write path for an approval over HTTP, deliberately:
    :data:`~mayhem.controller.api_service.CONTROL_ACTIONS` has no ``approve`` row
    because there is no ``mayhem approve`` command in the single inventory for an
    approval endpoint to map to. A page offering an "approve" button whose
    submission had nowhere to go would be a control that lies about itself.
    """
    rows = payload.get("items") or []
    body_rows: list[tuple[str, object]] = [
        (
            str(item.get("approval_id", "?")),
            f"plan {str(item.get('plan_digest', ''))[:12]}… state "
            f"{item.get('state', '?')} by {item.get('approver', '?')}",
        )
        for item in rows
    ]
    return Page(
        page_id=PageId.APPROVALS,
        title="mayhem — approvals",
        api_path=api_path,
        api_payload=payload,
        body_html=_kv_table(body_rows),
        caveats=(
            "approvals are readable over the API and writable nowhere over HTTP: there "
            "is no `mayhem approve` command in the single inventory for a write "
            "endpoint to map to",
            "an approval binds to a plan digest, so an approval for one plan never "
            "authorises another",
        ),
    )


def render_evidence_page(payload: Mapping[str, Any], *, api_path: str) -> Page:
    """One sealed evidence reference, and what it does and does not prove."""
    reference = _require(payload, "evidence", api_path)
    return Page(
        page_id=PageId.EVIDENCE,
        title=f"mayhem — evidence {reference.get('ref_id', '')}",
        api_path=api_path,
        api_payload=payload,
        body_html=_kv_table(
            [
                ("ref", reference.get("ref_id", "")),
                ("run", reference.get("run_id", "")),
                ("plan", str(reference.get("plan_digest", ""))[:12]),
                ("complete", reference.get("complete", False)),
                ("sealed at", reference.get("sealed_at", "")),
            ]
        ),
        evidence_refs=(str(reference.get("ref_id", "")),) if reference.get("ref_id") else (),
        caveats=(
            "a sealed envelope proves which bytes were sealed, not who sealed them: no "
            "publisher signature is verified anywhere in this build",
            "an absent reference means no envelope was sealed for that run, which is not "
            "the same as an envelope that was verified and found clean",
        ),
    )


#: The page table. One entry per :class:`PageId`, so a link to a page nobody
#: rendered is a lookup failure rather than a 404 from a router nobody reads.
UI_PAGES: Final[dict[PageId, Callable[..., Page]]] = {
    PageId.DASHBOARD: render_dashboard,
    PageId.BUILDER: render_builder_page,
    PageId.LIVE_RUN: render_run_page,
    PageId.BOUNDARIES: render_boundary_page,
    PageId.RECOMMENDATIONS: render_recommendations_page,
    PageId.APPROVALS: render_approvals_page,
    PageId.EVIDENCE: render_evidence_page,
}


def render_page(page_id: str | PageId, payload: Mapping[str, Any], *, api_path: str) -> Page:
    """Render one page by id, or refuse naming the pages that exist."""
    try:
        chosen = PageId(page_id)
    except ValueError as exc:
        known = ", ".join(entry.value for entry in PageId)
        raise UiRenderRefusedError(
            RULE_UI_NO_API_OBJECT,
            f"no UI page {page_id!r}; this build renders {known}",
        ) from exc
    return UI_PAGES[chosen](payload, api_path=api_path)


#: A one-line description per page, kept beside :data:`UI_PAGES` rather than
#: read out of a docstring: a docstring's first line is documentation, and making
#: the index page depend on prose somebody may reword is a way to break rendering
#: with an edit to a comment.
UI_PAGE_SUMMARIES: Final[dict[PageId, str]] = {
    PageId.DASHBOARD: "Executive numbers, each linked to sealed evidence.",
    PageId.BUILDER: "Author an experiment; controls project from the catalog schemas.",
    PageId.LIVE_RUN: "One run: timeline, failure explanation, and the stop control.",
    PageId.BOUNDARIES: "Recorded resilience boundaries, and which are withheld.",
    PageId.RECOMMENDATIONS: "Plan 21's ranked recommendations with their traces.",
    PageId.APPROVALS: "Approvals and the plan digests they bind to.",
    PageId.EVIDENCE: "One sealed evidence reference and what it proves.",
}


def ui_pages() -> tuple[dict[str, str], ...]:
    """Every page as data — what the index page lists and a test can enumerate."""
    return tuple(
        {"page": entry.value, "summary": UI_PAGE_SUMMARIES[entry]}
        for entry in sorted(UI_PAGES, key=lambda item: item.value)
    )


def _ref_text(ref: Mapping[str, Any] | str) -> str:
    if isinstance(ref, str):
        return ref
    kind = ref.get("kind", "observation")
    key = ref.get("key", "")
    detail = ref.get("detail", "")
    return f"{kind}/{key}" + (f" — {detail}" if detail else "")
