"""``mayhem lowlevel`` — what the low-level primitives are, and why they will not run.

Plan 04 Phase 3's surface. Two commands:

* ``mayhem lowlevel primitives`` — every declared primitive with its family,
  risk, disposition, mechanism and the limits of that mechanism.
* ``mayhem lowlevel explain PRIMITIVE_ID`` — one primitive in full: its
  parameter grammar, its undo, its residue checks, what it cannot run alongside,
  and the ids a reader might mistake it for.

Why a new group rather than ``discover faults -e``
---------------------------------------------------
``discover faults -e`` explains a **fault id**. Four of the twenty-two primitives
have one — the ``catalog_only`` refusals — and the other eighteen do not, including
all six ``jvm.*`` descriptors, which have no catalog surface at all. Before this
group, a person asking "how do I delay a Java method?" was told about
``app.exception`` and nothing else, and had no way to learn that mayhem knows the
answer is a JVMTI agent it does not ship. This group is the surface for the
descriptors; the refusals stay where they are, because a fault refusal belongs
next to the fault.

It reads nothing and writes nothing
-----------------------------------
There is no ``--apply``, no ``--force``, no store, no database, and no engine. The
whole group is a projection of :mod:`mayhem.domain.lowlevel_report`, which is
pure. That is not a limitation to apologise for — it is the point. Plan 04 has no
mechanism, so the only honest thing this surface can do is explain, and a command
that could inject would have to ship before it could be correct.

The caveat is not optional
--------------------------
Every rendered explanation ends with :data:`mayhem.domain.lowlevel_report.
LOWLEVEL_NOT_ATTACHED_NOTICE`, which says in one sentence that nothing was
attached. ``--json`` carries the same sentence as a ``notice`` key on every
record, because a JSON consumer that renders a subset of the fields must still be
able to find the caveat. :func:`primitives_payload` and :func:`explain_payload`
build the payloads so the two renderers cannot drift on which fields exist, and
``tests/unit/test_lowlevel_surface.py`` asserts the notice is reachable in both.

Invocations that resolve against this command::

    mayhem lowlevel --help
    mayhem lowlevel primitives
    mayhem lowlevel primitives --family kernel --json
    mayhem lowlevel primitives --injectable
    mayhem lowlevel explain jvm.method_delay
    mayhem lowlevel explain kernel.syscall_latency --json
    mayhem lowlevel explain io.write_delay --json
    mayhem lowlevel admit io.capacity_exhaustion --engine podman --duration 30
    mayhem lowlevel admit kernel.syscall_errno --param syscall=read --param errno=EIO
    mayhem lowlevel admit io.read_delay --active io.read_delay --json

.. warning::

   **This group is not registered.** ``cli/command_registry.py`` and
   ``cli/app.py`` are outside this lane's ownership, so the group is exported and
   tested directly through ``CliRunner`` and the integration pass has to add the
   row. See the Phase 3 entry in ``docs/v1.1.0/04_EBPF_KERNEL_IO_JVM.md``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli import style
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.lowlevel import SubstrateSurface
    from mayhem.domain.lowlevel_admission import AdmissionReport
    from mayhem.domain.lowlevel_report import PrimitiveExplanation

__all__ = [
    "admit",
    "explain",
    "explain_payload",
    "lowlevel",
    "parse_params",
    "primitives",
    "primitives_payload",
    "render_admission_lines",
    "render_primitive_lines",
    "render_summary_lines",
]


#: Version of the payload structure. Bumped when a field's *meaning* changes,
#: never when one is added — the payload is additive.
LOWLEVEL_SCHEMA_VERSION = "1.0"

lowlevel = make_group(
    "lowlevel",
    "Explain the eBPF, IO, JVM and clock primitives plan 04 declares, and why they are refused.",
)


# ── projections: one payload, two renderers ──────────────────────────────────


def primitives_payload(
    explanations: Sequence[PrimitiveExplanation],
) -> dict[str, Any]:
    """The listing structure, shared by ``--json`` and the rendered lines.

    Carries the notice at the top *and* on every record. The duplication is
    deliberate and cheap: a consumer that keeps one record must still be able to
    find the caveat without having read the listing's header, and a caveat that
    only exists at the top of a document is a caveat that a per-record renderer
    drops.
    """
    summary: dict[str, Any] = {
        "total": len(explanations),
        "injectable": sum(1 for e in explanations if e.injectable),
        "declared_not_applied": sum(
            1 for e in explanations if e.mechanism_state.value == "declared_not_applied"
        ),
        "unachievable": sum(
            1 for e in explanations if e.mechanism_state.value == "unachievable"
        ),
    }
    by_disposition: dict[str, int] = {}
    for explanation in explanations:
        by_disposition[explanation.disposition.value] = (
            by_disposition.get(explanation.disposition.value, 0) + 1
        )
    summary["by_disposition"] = dict(sorted(by_disposition.items()))
    return {
        "schema_version": LOWLEVEL_SCHEMA_VERSION,
        "summary": summary,
        "notice": explanations[0].notice if explanations else _EMPTY_NOTICE,
        "primitives": [explanation.to_payload() for explanation in explanations],
    }


_EMPTY_NOTICE: str = (
    "no low-level primitive is declared, so there is nothing this build could attach "
    "and nothing to explain"
)


def explain_payload(explanation: PrimitiveExplanation) -> dict[str, Any]:
    """One primitive's structure, so the CLI and any later surface agree."""
    return {
        "schema_version": LOWLEVEL_SCHEMA_VERSION,
        **explanation.to_payload(),
    }


def render_summary_lines(explanations: Sequence[PrimitiveExplanation]) -> list[str]:
    """The listing, one line per primitive plus a header and a caveat."""
    if not explanations:
        return [f"no low-level primitive matches the filter; {_EMPTY_NOTICE}"]
    lines = [
        f"{len(explanations)} low-level primitive(s) declared; "
        f"{sum(1 for e in explanations if e.injectable)} injectable on this substrate, "
        f"{sum(1 for e in explanations if not e.injectable)} refused",
    ]
    for explanation in explanations:
        mechanism = explanation.mechanism or explanation.carried_by or "-"
        lines.append(
            f"{explanation.primitive_id:<34} {explanation.family:<6} "
            f"risk={explanation.risk:<8} {explanation.disposition.value:<24} "
            f"mechanism={mechanism} applied="
            f"{str(explanation.mechanism_applied).lower()}"
        )
    lines.append(f"notice: {explanations[0].notice}")
    return lines


def render_primitive_lines(explanation: PrimitiveExplanation) -> list[str]:
    """One primitive in full, using the domain's own vocabulary.

    The words come from
    :func:`mayhem.domain.lowlevel_report.describe_primitive` and the fields it
    summarises, so a renderer cannot introduce a fourth reading of "refused".
    This module holds no disposition vocabulary of its own.
    """
    from mayhem.domain.lowlevel_report import describe_explanation

    lines = describe_explanation(explanation).split("\n")
    verdict_index = next(
        (i for i, line in enumerate(lines) if line.startswith("  verdict:")), None
    )
    if verdict_index is None:  # pragma: no cover - defensive: the renderer owns the shape
        return lines
    lines[verdict_index] = style.orange(lines[verdict_index])
    return lines


def _fail(ctx: click.Context, exc: Exception) -> None:
    """Emit a refusal and exit with this surface's code.

    Rendered and exited here for the reason ``risk_preview_cmd._fail`` does it:
    the group is invoked directly by its own suite, so the documented exit code
    must be a property of *this* surface rather than of whichever wrapper
    dispatches it.
    """
    if isinstance(exc, InvariantViolationError):
        click.echo(style.orange(str(exc)), err=True)
    else:  # pragma: no cover - defensive: only invariant refusals reach here
        click.echo(style.orange(str(exc)), err=True)
    ctx.exit(int(ExitCode.VALIDATION_ERROR))


def _family(value: str) -> str | None:
    """The family filter, or ``None`` for "every family".

    Validated against the declared families rather than against an arbitrary
    string, so a typo is a usage error rather than a listing of nothing — which
    would look like "this build has no kernel primitives", a false and alarming
    finding.
    """
    from mayhem.domain.lowlevel import PrimitiveFamily

    known = {family.value for family in PrimitiveFamily}
    if value not in known:
        raise click.BadParameter(
            f"unknown family {value!r}; choose one of {', '.join(sorted(known))}"
        )
    return value


@lowlevel.command("primitives")
@click.option(
    "--family",
    "family_opt",
    default=None,
    help="Only primitives in this plan-04 family (kernel, io, jvm, clock).",
)
@click.option(
    "--injectable/--blocked",
    "only_injectable",
    default=None,
    help="Only primitives this substrate can inject, or only the ones it cannot.",
)
@click.option(
    "--disposition",
    "disposition_opt",
    default=None,
    help="Only primitives with this disposition.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the payload as JSON.")
@click.pass_context
def primitives(
    ctx: click.Context,
    family_opt: str | None,
    only_injectable: bool | None,
    disposition_opt: str | None,
    as_json: bool,
) -> None:
    """List every declared primitive with its disposition and its mechanism.

    Read-only. Exits ``0`` for a listing whose entries are all refusals, because
    a listing that exits non-zero for "nothing here is injectable" would train an
    operator to ignore the exit code; the refusals are in the output.
    """
    from mayhem.domain.lowlevel_report import (
        PrimitiveDisposition,
        explain_primitives,
    )

    if disposition_opt is not None and disposition_opt not in {
        member.value for member in PrimitiveDisposition
    }:
        raise click.BadParameter(
            f"unknown disposition {disposition_opt!r}; choose one of "
            + ", ".join(sorted(member.value for member in PrimitiveDisposition))
        )
    family = _family(family_opt) if family_opt else None
    surface = _surface()
    selected = [
        explanation
        for explanation in explain_primitives(surface=surface)
        if (family is None or explanation.family == family)
        and (only_injectable is None or explanation.injectable is only_injectable)
        and (
            disposition_opt is None or explanation.disposition.value == disposition_opt
        )
    ]
    if as_json:
        click.echo(json.dumps(primitives_payload(selected), indent=2, sort_keys=True))
        return
    for line in render_summary_lines(selected):
        click.echo(line)


@lowlevel.command("explain")
@click.argument("primitive_id")
@click.option("--json", "as_json", is_flag=True, help="Emit the payload as JSON.")
@click.pass_context
def explain(ctx: click.Context, primitive_id: str, as_json: bool) -> None:
    """Explain one primitive in full, including why it will not run.

    Refuses with exit code 4 when no such primitive is declared — an unknown id
    is a usage problem, and answering it with an empty report would let a caller
    believe mayhem had checked a primitive that does not exist.
    """
    from mayhem.domain.lowlevel_report import explain_primitive

    try:
        explanation = explain_primitive(primitive_id, surface=_surface())
    except InvariantViolationError as exc:
        _fail(ctx, exc)
        return
    if as_json:
        click.echo(json.dumps(explain_payload(explanation), indent=2, sort_keys=True))
        return
    for line in render_primitive_lines(explanation):
        click.echo(line)


def _surface() -> SubstrateSurface:
    """The substrate this invocation describes.

    :data:`~mayhem.domain.lowlevel.CURRENT_SUBSTRATE` for now, and there is no
    ``--surface`` flag on purpose: a flag that let a caller claim a substrate
    could inject a primitive would let them read "injectable" out of an output
    produced on a host that cannot do it. The one day mayhem probes a real cell,
    this becomes a parameter read from the probe — not a flag.
    """
    from mayhem.domain.lowlevel import CURRENT_SUBSTRATE

    return CURRENT_SUBSTRATE


# =============================================================================
# Admission: the runnable refusal
# =============================================================================


def parse_params(pairs: tuple[str, ...]) -> dict[str, object]:
    """Turn ``--param name=value`` repetitions into a parameter mapping.

    Each value is parsed as JSON first and falls back to the bare string, so
    ``delay_ms=1500`` arrives as an ``int`` (and is therefore range-checked as a
    number) while ``path=/tmp/x`` arrives as the string it is. Without the JSON
    step every value would be a string, and a magnitude of ``"1500"`` would have
    to be silently coerced — which is exactly the "grammar that repairs instead of
    refusing" failure :func:`mayhem.domain.lowlevel.resolve_params` refuses.

    Raises:
        click.BadParameter: On a pair with no ``=``, an empty name, or a value that
            is not valid JSON and not a plain string.
    """
    params: dict[str, object] = {}
    for pair in pairs:
        name, separator, raw = pair.partition("=")
        if not separator or not name.strip():
            raise click.BadParameter(
                f"--param {pair!r} is not name=value; the value is parsed as JSON so a "
                "magnitude is checked as a number rather than coerced from a string"
            )
        try:
            params[name.strip()] = json.loads(raw)
        except json.JSONDecodeError:
            params[name.strip()] = raw
    return params


def render_admission_lines(report: AdmissionReport) -> list[str]:
    """The admission report as printable lines, refusals marked.

    Every check is printed, passing ones included. A refusal list that shows only
    the failures reads like "the other five things were fine", which is not the
    same claim as "the other five things were checked".
    """
    lines = [report.refusal_reason, ""]
    for check in report.checks:
        rendered = check.describe()
        lines.append(f"  {rendered}: {check.detail}" if check.refuses else f"  {rendered}")
    lines.append(
        f"  applied={'true' if report.applied else 'false'} "
        f"(applied_primitive={report.applied_primitive or 'none'})"
    )
    from mayhem.domain.lowlevel_admission import declared_unbound_ports

    lines.append(f"  unbound ports: {', '.join(declared_unbound_ports())}")
    return lines


@lowlevel.command("admit")
@click.argument("primitive_id")
@click.option(
    "--engine",
    "engine_opt",
    type=click.Choice(["docker", "podman", "kubernetes"], case_sensitive=False),
    default="docker",
    show_default=True,
    help="The engine the injection would run on.",
)
@click.option(
    "--duration",
    "duration_s",
    default=30.0,
    show_default=True,
    help="Requested window in seconds, bounded by the primitive's own maximum.",
)
@click.option(
    "--param",
    "param_pairs",
    multiple=True,
    metavar="NAME=VALUE",
    help="A parameter for the request. Repeatable; values are parsed as JSON.",
)
@click.option(
    "--active",
    "active_primitives",
    multiple=True,
    metavar="PRIMITIVE",
    help="A primitive already live in this drill. Repeatable; drives the collision check.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the report as JSON.")
@click.pass_context
def admit(
    ctx: click.Context,
    primitive_id: str,
    engine_opt: str,
    duration_s: float,
    param_pairs: tuple[str, ...],
    active_primitives: tuple[str, ...],
    as_json: bool,
) -> None:
    """Decide whether a low-level injection may be attempted, and refuse loudly.

    **This command never injects anything.** It runs the admission gate over a
    request and reports the verdict. In this build the gate refuses every low-level
    request, because the mechanism port is unbound: mayhem ships no eBPF loader,
    FUSE shim, device-mapper target or JVM agent. That refusal is the output, and
    it is the honest one — there is no ``--force``, no ``--apply`` and no path
    through this command that touches the kernel, a mount or a JVM.

    Exits ``5`` (``ExitCode.SAFETY_REFUSAL``) on a refusal, which is the code every
    other mayhem safety gate uses, so a script does not have to learn a new number
    to learn that nothing happened.
    """
    from mayhem.domain.lowlevel_admission import (
        LowLevelRefusedError,
        LowLevelRequest,
    )
    from mayhem.domain.lowlevel_admission import admit as admit_request

    try:
        request = LowLevelRequest(
            primitive_id=primitive_id,
            engine=engine_opt.lower(),
            duration_s=duration_s,
            params=parse_params(param_pairs),
            active_primitives=tuple(active_primitives),
            request_id=f"cli:{primitive_id}",
        )
    except InvariantViolationError as exc:
        _fail(ctx, exc)
        return
    try:
        report = admit_request(request)
    except LowLevelRefusedError as exc:
        # A refusal carries the whole report, so the refusal text a caller reads is
        # the report's own — never a private string invented by this command. Under
        # ``--json`` the payload is the *only* thing emitted, so a consumer
        # parsing stderr is not handed prose in the middle of its JSON.
        if as_json:
            click.echo(json.dumps(exc.report.to_payload(), indent=2, sort_keys=True), err=True)
        else:
            for line in render_admission_lines(exc.report):
                click.echo(style.orange(line) if line.startswith("  ") else line, err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    if as_json:
        click.echo(json.dumps(report.to_payload(), indent=2, sort_keys=True))
        return
    for line in render_admission_lines(report):
        click.echo(line)
