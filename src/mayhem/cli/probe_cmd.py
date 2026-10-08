"""``mayhem probe`` — the probe-builder and authoring surface
(docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md, Phase 3, UX half).

Phase 1 wrote down what a probe *is*
(:mod:`mayhem.domain.probes`), Phase 2 runs it
(:mod:`mayhem.controller.probe_service`,
:mod:`mayhem.controller.probe_collector`), and Phase 3 shipped the bounded
read-only connectors (:mod:`mayhem.controller.probe_integrations`). None of those
is reachable by a person. This module is the button: five sub-commands that let an
author build a probe definition, author a stop condition against it, read the
tolerance reference, see the connector catalogue with its rollout order, and — the
one with teeth — ask **what would this run not be able to see?**

Five commitments shape it.

**The surface is a group and it is not registered.** ``mayhem probe`` is a Click
group with five sub-commands and is deliberately **absent** from
:data:`mayhem.cli.command_registry.COMMANDS`, which this work item does not own.
``tests/unit/test_probe_cmd.py`` therefore invokes the group directly through
``CliRunner``, which is the shape ``tests/unit/test_stop_surface.py`` uses for the
same reason. The ledger in the plan's STATUS records the one-line registration
that is owed.

**"What cannot this run see?" is a first-class answer, not an absence.**
``mayhem probe uncover`` names the probe families with no bound connector and
prints the word ``UNAVAILABLE`` for each. The refusal is
:func:`mayhem.controller.probe_service.refuses_probe`, the same word the engine
prints, so an operator reading the CLI and an operator reading a run report are
reading the same vocabulary. This is the load-bearing surface for the whole plan:
**no probe data must never render as healthy**, and the surface that would render
it as healthy is the one that says ``UNAVAILABLE`` by name.

**Nothing here connects to anything.** Every sub-command is a pure function of its
flags over shipped data. No store, no network, no cluster, no vendor. A command
that could reach a real system from a CLI would make "we have not run this against
a live cell" indistinguishable from "we ran it and it passed", which is exactly
the claim this module refuses to leave available.

**The tolerance reference prints the absence too.** ``mayhem probe tolerances``
lists the four mechanisms ``ToleranceKind`` carries and states that
``categorical`` is **deliberately absent**, naming the missing field on
:class:`~mayhem.domain.observations.ObservationResult`. A reference that listed
only what exists would let a reader assume the gap was an oversight.

**Refusals are the output, and nothing is written on the way to one.**
``build`` and ``condition`` construct through the domain's own validators, so a
definition without its locator, a plan whose warm-up has no budget, or a threshold
with two bounds all fail here with the rule id the run would fail with.

Invocations that resolve against this group::

    mayhem probe catalogue
    mayhem probe connectors
    mayhem probe tolerances
    mayhem probe build --id http.api --family http --endpoint https://api/latency \\
        --unit ms --stages during-fault --cadence 5
    mayhem probe condition --metric http.api --op lte --value 250 --for-samples 2
    mayhem probe uncover --families prometheus,logs,redis --bound prometheus,loki
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, NoReturn

import click
from pydantic import ValidationError

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.output import echo_machine
from mayhem.controller.probe_integrations import (
    MAX_CONNECTOR_BYTES,
    MAX_CONNECTOR_TIMEOUT_S,
    ROLLOUT_TIER_ORDER,
    ConnectorId,
    default_connectors,
)
from mayhem.controller.probe_service import ProbeAvailability, refuses_probe
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.observations import CriterionOperator
from mayhem.domain.probes import (
    LifecycleStage,
    ProbeDefinition,
    ProbeFamily,
    ProbePin,
    ProbeValueKind,
    required_locator,
)
from mayhem.domain.steady_state import AbsoluteExpect
from mayhem.domain.stop_conditions import Condition, FiresWhen, Threshold, ToleranceKind

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

__all__ = [
    "CATEGORICAL_ABSENT_REASON",
    "TOLERANCE_REFERENCE",
    "build_condition",
    "build_definition",
    "catalogue_payload",
    "connectors_payload",
    "family_rows",
    "probe",
    "tolerances_payload",
    "uncover_payload",
]


#: Why ``categorical`` is not in :data:`~mayhem.domain.stop_conditions.ToleranceKind`.
#: Printed by ``mayhem probe tolerances`` and stated here so the absence has one
#: spelling. It mirrors ``probes.categorical_unsupported`` in
#: :mod:`mayhem.domain.probes`, which is the enforceable form of the same fact.
CATEGORICAL_ABSENT_REASON = (
    "ObservationResult carries value: float | None and no label, enum or string field, so "
    "there is nothing for a categorical comparison to compare. Declaring a categorical "
    "probe is refused with probes.categorical_unsupported, which names this gap; the "
    "refusal is lifted in the same commit that adds the field."
)

#: The tolerance reference, one row per mechanism
#: :data:`~mayhem.domain.stop_conditions.ToleranceKind` carries. ``operator`` is the
#: bucket percentile bounds and time-to-recovery land in, which is why it is listed
#: rather than being its own kind.
TOLERANCE_REFERENCE: tuple[dict[str, str], ...] = (
    {
        "kind": ToleranceKind.ABSOLUTE.value,
        "carries": "AbsoluteExpect (eq / lte / gte)",
        "compares": "the reading against a fixed bound, in the probe's declared unit",
        "baseline": "no",
        "notes": "a bound on both ends has no single governing bound, so hysteresis is refused",
    },
    {
        "kind": ToleranceKind.RATIO.value,
        "carries": "Tolerance against a captured baseline",
        "compares": "relative *deviation*, never magnitude, so an inverted signal fails",
        "baseline": "required",
        "notes": "no baseline makes the bound unmeasurable: not-met, never healthy",
    },
    {
        "kind": ToleranceKind.PERCENTAGE.value,
        "carries": "percent",
        "compares": "|delta_pct| from a baseline, reusing the steady-state change maths",
        "baseline": "required",
        "notes": "reuses the verdict core's comparison rather than restating it",
    },
    {
        "kind": ToleranceKind.OPERATOR.value,
        "carries": "a whole SloCriterion",
        "compares": "the criterion's operator table — percentile and recovery land here",
        "baseline": "no",
        "notes": "the bucket for an SLO criterion rather than a new comparison mechanism",
    },
)


# =============================================================================
# Payloads: pure functions of their inputs, shared by text and machine output
# =============================================================================


def family_rows(catalog: Any = None) -> tuple[dict[str, Any], ...]:
    """One row per probe family: its locator, its rollout tier, its connectors.

    ``tier`` is ``"declared-only"`` for a family no shipped connector serves —
    redis, kafka, grpc, sql and the rest. That word matters: the family *exists* as
    a definition and is refused nothing, but mayhem ships no read path for it, so
    a probe of that family is ``UNAVAILABLE`` until somebody binds a port. The
    catalogue therefore never implies coverage it does not have.
    """
    catalogue = default_connectors() if catalog is None else catalog
    rows: list[dict[str, Any]] = []
    for family in ProbeFamily:
        connectors = catalogue.for_family(family)
        rows.append(
            {
                "family": family.value,
                "locators": list(locators_for(family)),
                "tier": connectors[0].tier.value if connectors else "declared-only",
                "connectors": [connector.connector_id.value for connector in connectors],
                "served": bool(connectors),
                "value_kinds": [kind.value for kind in ProbeValueKind],
            }
        )
    return tuple(rows)


def locators_for(family: ProbeFamily) -> tuple[str, ...]:
    """Which locator field makes a definition *that* family.

    A delegation, not a copy: :func:`mayhem.domain.probes.required_locator` is the
    domain's own answer, so this surface cannot document a requirement the domain
    does not have. A copy here would be a second table that could disagree with the
    first, and its symptom would be a flag that builds a definition the domain then
    refuses.
    """
    return required_locator(family)


def catalogue_payload(catalog: Any = None) -> dict[str, Any]:
    """The whole catalogue: families, tiers, and the families mayhem cannot read."""
    catalogue = default_connectors() if catalog is None else catalog
    families = family_rows(catalogue)
    return {
        "families": list(families),
        "declared_only": [row["family"] for row in families if not row["served"]],
        "served": [row["family"] for row in families if row["served"]],
        "lifecycle": [stage.value for stage in LifecycleStage],
        "notes": (
            "A family marked declared-only has no shipped connector. A probe of that "
            "family is UNAVAILABLE until a port is bound, and UNAVAILABLE is not "
            "evidence of health."
        ),
    }


def connectors_payload(catalog: Any = None) -> dict[str, Any]:
    """Every shipped connector, its bounds, and the rollout order they ship in."""
    catalogue = default_connectors() if catalog is None else catalog
    return {
        "connectors": [connector.to_dict() for connector in catalogue.connectors],
        "rollout": [
            {
                "tier": tier.value,
                "connectors": [c.connector_id.value for c in catalogue.for_tier(tier)],
            }
            for tier in ROLLOUT_TIER_ORDER
        ],
        "ambiguous_families": [family.value for family in catalogue.ambiguous_families()],
        "bounds": {
            "max_timeout_s": MAX_CONNECTOR_TIMEOUT_S,
            "max_bytes": MAX_CONNECTOR_BYTES,
            "redaction_required": True,
        },
    }


def tolerances_payload() -> dict[str, Any]:
    """The tolerance reference, plus the mechanism that is deliberately absent."""
    return {
        "tolerances": [dict(row) for row in TOLERANCE_REFERENCE],
        "kinds": [kind.value for kind in ToleranceKind],
        "absent": {
            "kind": "categorical",
            "reason": CATEGORICAL_ABSENT_REASON,
            "refusal": "probes.categorical_unsupported",
        },
    }


def uncover_payload(
    families: Sequence[ProbeFamily],
    *,
    bound: Sequence[ConnectorId] = (),
    catalog: Any = None,
) -> dict[str, Any]:
    """What a run with these probes and these bound connectors **cannot see**.

    The plan's central question, answered as data. A family with no connector at
    all, and a family whose only connectors are unbound, are *different findings*
    and are reported as different rows:

    * ``unavailable_reason: "no shipped connector"`` — mayhem has no read path
      for this family, so binding anything will not help;
    * ``unavailable_reason: "connector declared but not bound"`` — the read path
      exists and this run did not attach to it, which is a wiring fault rather
      than a gap in mayhem;
    * ``available`` — a bound connector serves it.

    Every unavailable row carries the word
    :data:`~mayhem.controller.probe_service.ProbeAvailability.UNAVAILABLE` and the
    same refusal verdict the engine would reach, read from
    :func:`~mayhem.controller.probe_service.refuses_probe` rather than restated.
    """
    catalogue = default_connectors() if catalog is None else catalog
    bound_ids = set(bound)
    rows: list[dict[str, Any]] = []
    for family in families:
        connectors = catalogue.for_family(family)
        if not connectors:
            availability = ProbeAvailability.UNAVAILABLE
            reason = "no shipped connector serves this family"
            serving: list[str] = []
        else:
            serving = [c.connector_id.value for c in connectors if c.connector_id in bound_ids]
            if serving:
                availability = ProbeAvailability.AVAILABLE
                reason = "a bound connector serves this family"
            else:
                availability = ProbeAvailability.UNAVAILABLE
                reason = "connector declared but not bound"
        rows.append(
            {
                "family": family.value,
                "availability": availability.value,
                "refuses": refuses_probe(availability),
                "unavailable_reason": None if availability.value == "available" else reason,
                "bound_connectors": serving,
                "declared_connectors": [c.connector_id.value for c in connectors],
            }
        )
    unavailable = [row["family"] for row in rows if row["refuses"]]
    return {
        "families": rows,
        "unavailable": unavailable,
        "verdict_bearing": not unavailable,
        "summary": (
            "every requested family has a bound connector, so this run's observations "
            "may support a verdict"
            if not unavailable
            else f"{len(unavailable)} of {len(rows)} requested family(ies) are UNAVAILABLE "
            f"({', '.join(unavailable)}); those runs observed nothing there, which is a "
            "statement about mayhem's wiring and not about the system"
        ),
    }


# =============================================================================
# Builders: the two things an author writes, constructed through the domain
# =============================================================================


def build_definition(
    *,
    probe_id: str,
    family: ProbeFamily,
    version: str = "1.0",
    unit: str,
    locator: str = "",
    stages: Sequence[LifecycleStage] = (),
    cadence: float = 5.0,
    window: float = 10.0,
    warmup: float = 0.0,
    cooldown: float = 0.0,
    description: str = "",
) -> dict[str, Any]:
    """Build a :class:`~mayhem.domain.probes.ProbeDefinition` and render its pin.

    One ``locator`` argument rather than one per field, resolved through the
    family's own required locator, because the alternative is a CLI with a
    ``--endpoint``/``--query``/``--target``/``--path``/``--command``/``--steps``
    sextet where five of the six are always wrong for any given family — and a
    flag that is wrong for most invocations is a flag that gets ignored.

    Returns the definition as JSON plus the :class:`~mayhem.domain.probes.ProbePin`
    a plan must carry. The pin is printed because it is the thing the author has
    to copy: without it the definition cannot be bound to a catalogue, and
    ``probes.unpinned_probe`` is what they would meet later.

    Raises:
        InvariantViolationError: Whatever the domain refuses — no locator for the
            family, a non-absolute http endpoint, ``warm-up`` with no ``--warmup``
            budget, and the rest. The rule id is rendered so it matches what a run
            would report.
    """
    locator_fields = required_locator(family)
    payload: dict[str, Any] = {
        "id": probe_id,
        "family": family,
        "version": version,
        "unit": unit,
        "stages": tuple(stages),
        "cadence": cadence,
        "window": window,
        "warmup": warmup,
        "cooldown": cooldown,
        "description": description,
    }
    if not locator.strip():
        raise InvariantViolationError(
            "probes.probe_without_locator",
            f"a {family.value} probe is defined by its "
            f"{locator_fields[0]!r} and none was given: "
            f"mayhem probe build --locator. With neither an endpoint nor a query it "
            "resolves to nothing, and a probe that resolves to nothing is "
            "indistinguishable from a system that is fine.",
        )
    first = locator_fields[0]
    payload[first] = locator
    if first == "steps":
        payload[first] = tuple(part.strip() for part in locator.split(">") if part.strip())
    definition = ProbeDefinition(**payload)
    pin = ProbePin.of(definition)
    return {
        "definition": definition.model_dump(mode="json"),
        "pin": pin.model_dump(mode="json"),
        "pin_summary": pin.describe,
        "graded_stages": [stage.value for stage in definition.graded_stages],
        "excluded_stages": [stage.value for stage in definition.excluded_stages],
    }


def build_condition(
    *,
    metric: str,
    op: CriterionOperator,
    value: float,
    fires_when: FiresWhen = FiresWhen.BROKEN,
    name: str = "",
    for_samples: int = 1,
    debounce: float = 0.0,
    cooldown: float = 0.0,
    hysteresis: float | None = None,
    hysteresis_absolute: float | None = None,
    max_duration: float | None = None,
) -> dict[str, Any]:
    """Build a leaf :class:`~mayhem.domain.stop_conditions.Condition` and render it.

    The authoring guide as a function: every control the domain exposes is a flag
    here, so an author discovers the whole surface by reading ``--help`` rather
    than by reading the domain module. ``--hysteresis`` and
    ``--hysteresis-absolute`` are separate flags because the domain keeps them
    separate — one is a fraction of the bound, one is an absolute dead band — and
    a single flag that guessed which was meant would make a silent decision about
    the size of a dead band.

    Raises:
        InvariantViolationError: Whatever the domain refuses — a value-control set
            where it cannot mean anything, a ``fires-when met`` condition with a
            duration limit that can never be met, and the rest.
    """
    expect = AbsoluteExpect(**_expect_field(op, value))
    threshold = Threshold(fires_when=fires_when, expect=expect)
    # The two hysteresis forms stay separate keys rather than one optional
    # number: the domain keeps them apart because a fraction of the bound and an
    # absolute dead band are different sizes, and collapsing them would make the
    # surface silently decide the size of a dead band.
    dead_band: dict[str, Any] = {}
    if hysteresis is not None:
        dead_band["hysteresis"] = hysteresis
    if hysteresis_absolute is not None:
        dead_band["hysteresis_absolute"] = hysteresis_absolute
    condition = Condition.metric(
        metric,
        threshold,
        name=name or f"{metric}:{op.value}{value:g}",
        for_samples=for_samples,
        debounce=debounce,
        cooldown=cooldown,
        max_duration=max_duration,
        **dead_band,
    )
    return {
        "condition": condition.model_dump(mode="json"),
        "summary": (
            f"{fires_when.value} when {metric} {op.value} {value:g} for "
            f"{for_samples} consecutive sample(s)"
            + (f", debounced {debounce:g}s" if debounce else "")
            + (f", cooldown {cooldown:g}s" if cooldown else "")
            + (f", window {max_duration:g}s" if max_duration is not None else "")
            + (
                f", hysteresis {hysteresis:.0%}"
                if hysteresis is not None
                else (f", dead band {hysteresis_absolute:g}" if hysteresis_absolute else "")
            )
        ),
        "supported_by": "mayhem.domain.stop_conditions.Condition.evaluate",
    }


def _expect_field(op: CriterionOperator, value: float) -> dict[str, float]:
    """The :class:`~mayhem.domain.steady_state.AbsoluteExpect` field an operator maps to."""
    fields: dict[CriterionOperator, str] = {
        CriterionOperator.LTE: "lte",
        CriterionOperator.GTE: "gte",
        CriterionOperator.EQ: "eq",
    }
    if op not in fields:
        raise InvariantViolationError(
            "stop_conditions.unsupported_operator",
            f"operator {op.value!r} has no absolute bound: a stop condition authored "
            "from this surface compares with eq, lte or gte. Percentile and "
            "time-to-recovery bounds belong in an SloCriterion, which is the "
            "'operator' tolerance kind rather than a flag here.",
        )
    return {fields[op]: value}


# =============================================================================
# The surface
# =============================================================================


@contextmanager
def _authored(what: str) -> Iterator[None]:
    """Render a construction refusal as a CLI error, keeping its rule id.

    Two exception types reach here and both are the *author's* mistake rather than
    a crash: :class:`~mayhem.domain.errors.InvariantViolationError` when a domain
    validator refuses (a missing locator, a warm-up with no budget, two bounds on
    one threshold), and ``pydantic.ValidationError`` when a field constraint
    refuses (an id that is not an identifier, a version that is not
    ``major.minor``).

    Both are caught and rendered rather than allowed to escape, for two reasons.
    **A traceback is not a refusal**: a CLI that dumps a pydantic stack when a
    ``--id`` is malformed teaches the reader that the tool is broken when in fact
    it caught the mistake. And this group is deliberately **unregistered**, so
    :func:`mayhem.cli.app.main`'s ``MayhemCliError`` handler is not on the path —
    the error has to render itself or it renders as silence, and a surface that
    says nothing when an author gets it wrong is the failure this whole plan
    argues against. The same :class:`~mayhem.cli.errors.MayhemCliError` is raised
    as the cause, so registering the group later changes nothing about the
    structured content.

    The rule id survives into the message, so the author sees the identifier a run
    would report rather than prose they have to translate.
    """
    try:
        yield
    except InvariantViolationError as exc:
        _render(f"{what}: {_rule_message(exc)}", details={"rule": exc.rule})
    except ValidationError as exc:
        _render(
            f"{what}: {_first_validation_error(exc)}",
            details={"field_errors": exc.error_count()},
        )


def _render(message: str, *, details: dict[str, Any]) -> NoReturn:
    """Print a refusal and exit with the validation code.

    Deliberately one line plus its details, and deliberately on stderr: this is
    the failure output, not a result.
    """
    click.echo(f"{style.danger('error:')} {message}", err=True)
    for key in sorted(details):
        click.echo(f"  {key}: {details[key]}", err=True)
    click.echo(
        style.cyan(
            "A refusal here is the same refusal a run reports: nothing was collected "
            "and nothing was graded."
        ),
        err=True,
    )
    raise SystemExit(ExitCode.VALIDATION_ERROR)


def _rule_message(exc: InvariantViolationError) -> str:
    """The refusal's message without the ``[rule]`` prefix its constructor adds."""
    text = exc.args[0] if exc.args else str(exc)
    return text.split("] ", 1)[-1] if text.startswith("[") else text


def _first_validation_error(exc: ValidationError) -> str:
    """The first field error, rendered as one line rather than as a table."""
    first = exc.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "(definition)"
    return f"{location}: {first.get('msg', 'invalid')}"


@click.group(name="probe")
def probe() -> None:
    """Probes, tolerances and stop conditions: build them, and see what they cannot see."""


@probe.command(name="catalogue")
def catalogue_command() -> None:
    """List every probe family, its locator, and whether mayhem can read it."""
    payload = catalogue_payload()
    if echo_machine(payload):
        return
    click.echo(style.info("Probe families"))
    for row in payload["families"]:
        mark = style.ok("*") if row["served"] else style.warn("!")
        connectors = ", ".join(row["connectors"]) or "-"
        click.echo(
            f"  {mark} {row['family']:<15} locator={'|'.join(row['locators']):<20} "
            f"tier={row['tier']:<26} connectors={connectors}"
        )
    click.echo("")
    click.echo(style.info(f"served: {', '.join(payload['served']) or '(none)'}"))
    click.echo(style.warn(f"declared only: {', '.join(payload['declared_only']) or '(none)'}"))
    click.echo("")
    click.echo(style.cyan(payload["notes"]))


@probe.command(name="connectors")
def connectors_command() -> None:
    """List the shipped read-only connectors, their bounds, and the rollout order."""
    catalogue = default_connectors()
    payload = connectors_payload(catalogue)
    if echo_machine(payload):
        return
    click.echo(style.info("Signal connectors (read-only, bounded, redacted)"))
    for connector in catalogue.connectors:
        click.echo(f"  {connector.describe()}")
    click.echo("")
    for tier in payload["rollout"]:
        click.echo(style.cyan(f"{tier['tier']}: ") + ", ".join(tier["connectors"]))
    if payload["ambiguous_families"]:
        click.echo("")
        click.echo(
            style.warn(
                "families with more than one shipped connector (bind one): "
                + ", ".join(payload["ambiguous_families"])
            )
        )


@probe.command(name="tolerances")
def tolerances_command() -> None:
    """Print the tolerance-type reference, including the one that is absent."""
    payload = tolerances_payload()
    if echo_machine(payload):
        return
    click.echo(style.info("Tolerance types"))
    for row in payload["tolerances"]:
        click.echo(f"  {row['kind']:<12} carries {row['carries']}")
        click.echo(f"  {'':<12} compares {row['compares']}")
        click.echo(f"  {'':<12} baseline: {row['baseline']}  ({row['notes']})")
    click.echo("")
    absent = payload["absent"]
    click.echo(style.warn(f"{absent['kind']}: ABSENT by decision."))
    click.echo(style.cyan(absent["reason"]))


@probe.command(name="build")
@click.option("--id", "probe_id", required=True, help="Probe id; conditions reference it.")
@click.option(
    "--family",
    required=True,
    type=click.Choice([family.value for family in ProbeFamily]),
    help="Probe family.",
)
@click.option("--version", "version", default="1.0", show_default=True, help="Definition version.")
@click.option("--unit", required=True, help="The unit every reading must be in.")
@click.option("--locator", default="", help="Endpoint, query, target, path, command or steps.")
@click.option(
    "--stages",
    default="",
    help="Comma-separated lifecycle stages, e.g. pre-baseline,warm-up,during-fault.",
)
@click.option(
    "--cadence", default=5.0, show_default=True, type=float, help="Seconds between samples."
)
@click.option(
    "--window", default=10.0, show_default=True, type=float, help="Observation window, seconds."
)
@click.option(
    "--warmup", default=0.0, show_default=True, type=float, help="Warm-up budget, seconds."
)
@click.option(
    "--cooldown", default=0.0, show_default=True, type=float, help="Cooldown budget, seconds."
)
@click.option("--description", default="", help="Prose. Excluded from the pin fingerprint.")
def build_command(
    probe_id: str,
    family: str,
    version: str,
    unit: str,
    locator: str,
    stages: str,
    cadence: float,
    window: float,
    warmup: float,
    cooldown: float,
    description: str,
) -> None:
    """Build a probe definition and print the pin a plan must carry."""
    with _authored(f"probe {probe_id}"):
        payload = build_definition(
            probe_id=probe_id,
            family=ProbeFamily(family),
            version=version,
            unit=unit,
            locator=locator,
            stages=_stages_from(stages),
            cadence=cadence,
            window=window,
            warmup=warmup,
            cooldown=cooldown,
            description=description,
        )
    if echo_machine(payload):
        return
    click.echo(style.info(f"probe {probe_id} ({family})"))
    for stage in payload["graded_stages"]:
        click.echo(f"  graded:  {stage}")
    for stage in payload["excluded_stages"]:
        click.echo(f"  settling (recorded, not graded): {stage}")
    click.echo("")
    click.echo(style.cyan("pin: ") + payload["pin_summary"])
    click.echo(
        style.info("A plan that does not carry this pin is refused with probes.unpinned_probe.")
    )


@probe.command(name="condition")
@click.option("--metric", required=True, help="A probe id, as printed by `probe build`.")
@click.option(
    "--op",
    required=True,
    type=click.Choice([op.value for op in CriterionOperator]),
    help="Comparison operator.",
)
@click.option("--value", required=True, type=float, help="The bound.")
@click.option(
    "--fires-when",
    "fires_when",
    default=FiresWhen.BROKEN.value,
    show_default=True,
    type=click.Choice([when.value for when in FiresWhen]),
    help="Whether the bound firing is the failure or the recovery.",
)
@click.option("--name", default="", help="Condition name; defaults to a derived one.")
@click.option("--for-samples", "for_samples", default=1, show_default=True, type=int)
@click.option("--debounce", default=0.0, show_default=True, type=float)
@click.option("--cooldown", default=0.0, show_default=True, type=float)
@click.option("--max-duration", "max_duration", default=None, type=float)
@click.option("--hysteresis", default=None, type=float, help="Fraction of the bound, in (0, 1).")
@click.option(
    "--hysteresis-absolute",
    "hysteresis_absolute",
    default=None,
    type=float,
    help="Absolute dead band, in the probe's unit.",
)
def condition_command(
    metric: str,
    op: str,
    value: float,
    fires_when: str,
    name: str,
    for_samples: int,
    debounce: float,
    cooldown: float,
    max_duration: float | None,
    hysteresis: float | None,
    hysteresis_absolute: float | None,
) -> None:
    """Author a stop condition against a probe and print it."""
    with _authored(f"a condition on {metric}"):
        payload = build_condition(
            metric=metric,
            op=CriterionOperator(op),
            value=value,
            fires_when=FiresWhen(fires_when),
            name=name,
            for_samples=for_samples,
            debounce=debounce,
            cooldown=cooldown,
            hysteresis=hysteresis,
            hysteresis_absolute=hysteresis_absolute,
            max_duration=max_duration,
        )
    if echo_machine(payload):
        return
    click.echo(style.info(f"condition {payload['summary']}"))
    click.echo(
        style.info(
            "Every firing cites the samples that produced it; a stop without citations is refused."
        )
    )
    click.echo(
        style.warn(
            "A condition whose probes produced no usable reading resolves to nothing, and "
            "resolving to nothing is refused rather than reported as clear."
        )
    )


@probe.command(name="uncover")
@click.option(
    "--families",
    required=True,
    help="Comma-separated probe families the plan declares.",
)
@click.option(
    "--bound",
    default="",
    help="Comma-separated connector ids this run binds. Everything else is UNAVAILABLE.",
)
def uncover_command(families: str, bound: str) -> None:
    """Report which declared families this run cannot see, and why."""
    payload = uncover_payload(
        _families_from(families),
        bound=_connector_ids_from(bound),
    )
    if echo_machine(payload):
        return
    click.echo(style.info("What this run cannot see"))
    for row in payload["families"]:
        if row["availability"] == ProbeAvailability.AVAILABLE.value:
            click.echo(
                f"  {style.ok('available')}      {row['family']:<15} "
                f"via {', '.join(row['bound_connectors'])}"
            )
            continue
        click.echo(
            f"  {style.warn('UNAVAILABLE')} {row['family']:<15} "
            f"{row['unavailable_reason']} "
            f"(declared: {', '.join(row['declared_connectors']) or 'none'})"
        )
    click.echo("")
    click.echo(payload["summary"])
    if payload["unavailable"]:
        click.echo("")
        click.echo(
            style.warn(
                "A run in this state may not report a passing verdict: there is no "
                "observation behind one. That is a fact about mayhem's wiring, not "
                "about the system under test."
            )
        )
    raise SystemExit(ExitCode.SUCCESS)


# =============================================================================
# Internals
# =============================================================================


def _stages_from(text: str) -> tuple[LifecycleStage, ...]:
    """Parse the ``--stages`` flag. A bad stage names itself and the valid set."""
    if not text.strip():
        return ()
    names = [part.strip() for part in text.split(",") if part.strip()]
    known = {stage.value: stage for stage in LifecycleStage}
    unknown = [name for name in names if name not in known]
    if unknown:
        raise MayhemCliError(
            code="usage_error",
            message=(
                f"unknown lifecycle stage(s) {', '.join(unknown)}; choose from {', '.join(known)}"
            ),
        )
    return tuple(known[name] for name in names)


def _families_from(text: str) -> tuple[ProbeFamily, ...]:
    """Parse the ``--families`` flag, preserving catalogue order for the report."""
    names = {part.strip() for part in text.split(",") if part.strip()}
    unknown = names - {family.value for family in ProbeFamily}
    if unknown:
        raise MayhemCliError(
            code="usage_error",
            message=(
                f"unknown probe family/families {', '.join(sorted(unknown))}; "
                f"choose from {', '.join(f.value for f in ProbeFamily)}"
            ),
        )
    return tuple(family for family in ProbeFamily if family.value in names)


def _connector_ids_from(text: str) -> tuple[ConnectorId, ...]:
    """Parse the ``--bound`` flag. Unknown ids are refused rather than dropped."""
    if not text.strip():
        return ()
    known = {connector.value: connector for connector in ConnectorId}
    ids: list[ConnectorId] = []
    for part in (piece.strip() for piece in text.split(",")):
        if not part:
            continue
        if part not in known:
            raise MayhemCliError(
                code="usage_error",
                message=f"unknown connector id {part!r}; choose from {', '.join(known)}",
            )
        ids.append(known[part])
    return tuple(ids)
