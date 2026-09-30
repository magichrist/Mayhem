"""Journey programs: versioned, per-step-asserted, and honest about coverage.

Why this file exists
--------------------
The capability under test is plan 22's gap 51 — *business metrics as
resilience criteria* — and the failure mode of a synthetic journey is not that
it crashes. It is that it goes green. A step that asserts nothing produces a
result whatever the system did, so the journey reports "checkout passed" having
checked only that a socket closed, and that green tick is exactly the artefact
a reviewer later cites as proof the flow is healthy. So the tests are grouped as:

* **the program.** Structure, citation handles, and the version/digest pin that
  makes "same journey" decidable.
* **the step assertions.** The four criterion kinds, the single-basis rule, the
  finite-bound rule, and the business statement.
* **the negative controls.** A step that asserts nothing, a duplicate citation
  handle, a forward dependency, a non-finite bound, a business assertion with
  no sentence — each refused at *construction*, so none of them can exist to be
  reported on.
* **catalog presence is not coverage.** Writing a journey registers untested
  cells and nothing more; the only way to leave ``unknown`` is executed
  evidence, which this phase does not have.

The last test re-states the domain law locally: this module may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI, but that check needs an
extra dependency, so the guard also lives here.
"""

from __future__ import annotations

import ast
import math
from typing import TYPE_CHECKING, Any

import pytest

import mayhem.domain.journeys as journeys_module
from mayhem.domain.coverage import CellState
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.journeys import (
    CANONICAL_CHECKOUT_LADDER,
    PLAN_BUSINESS_METRICS,
    AssertionBasis,
    AssertionComparator,
    AssertionKind,
    JourneyPin,
    JourneyProgram,
    JourneyStage,
    JourneyStep,
    StepAssertion,
    authored_cells,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

# ── fixtures ────────────────────────────────────────────────────────────────────


def _latency(
    criterion_id: str = "checkout.latency.p95",
    *,
    threshold: float | None = 800.0,
    metric: str = "p95_latency_ms",
) -> StepAssertion:
    return StepAssertion(
        criterion_id=criterion_id,
        kind=AssertionKind.LATENCY,
        metric=metric,
        comparator=AssertionComparator.LTE,
        unit="ms",
        threshold=threshold,
    )


def _success(criterion_id: str = "checkout.success") -> StepAssertion:
    return StepAssertion(
        criterion_id=criterion_id,
        kind=AssertionKind.SUCCESS,
        metric="step_completion_ratio",
        comparator=AssertionComparator.GTE,
        unit="ratio",
        threshold=1.0,
    )


def _business(
    criterion_id: str = "checkout.success_rate",
    *,
    metric: str = "checkout_success_rate",
    description: str = "at least 97% of attempted checkouts complete",
) -> StepAssertion:
    return StepAssertion(
        criterion_id=criterion_id,
        kind=AssertionKind.BUSINESS_CORRECTNESS,
        metric=metric,
        comparator=AssertionComparator.GTE,
        unit="ratio",
        baseline=0.97,
        tolerance_pct=2.0,
        description=description,
    )


def _step(
    name: str,
    stage: JourneyStage,
    *,
    service: str | None = None,
    assertions: Sequence[StepAssertion] | None = None,
    depends_on: Sequence[str] = (),
) -> JourneyStep:
    return JourneyStep(
        name=name,
        stage=stage,
        service=service or f"{name}-service",
        assertions=tuple(assertions if assertions is not None else (_success(f"{name}.success"),)),
        depends_on=tuple(depends_on),
    )


def _ladder_program(version: str = "1.0.0") -> JourneyProgram:
    """The plan's reference journey: signup → login → cart → checkout → payment → order."""
    stages = (
        ("signup", JourneyStage.SIGNUP),
        ("login", JourneyStage.LOGIN),
        ("cart", JourneyStage.CART),
        ("checkout", JourneyStage.CHECKOUT),
        ("payment", JourneyStage.PAYMENT),
        ("order", JourneyStage.ORDER),
    )
    steps: list[JourneyStep] = []
    previous = ""
    for name, stage in stages:
        steps.append(
            _step(
                name,
                stage,
                assertions=(
                    _success(f"{name}.success"),
                    _latency(f"{name}.latency.p95"),
                    _business(f"{name}.business"),
                ),
                depends_on=(previous,) if previous else (),
            )
        )
        previous = name
    return JourneyProgram(
        name="checkout-journey",
        version=version,
        title="synthetic checkout",
        steps=tuple(steps),
    )


# ── the ladder ──────────────────────────────────────────────────────────────────


def test_canonical_ladder_is_the_six_business_steps_in_order() -> None:
    assert CANONICAL_CHECKOUT_LADDER == (
        JourneyStage.SIGNUP,
        JourneyStage.LOGIN,
        JourneyStage.CART,
        JourneyStage.CHECKOUT,
        JourneyStage.PAYMENT,
        JourneyStage.ORDER,
    )


def test_a_ladder_program_says_so_and_threads_its_dependencies() -> None:
    program = _ladder_program()

    assert program.covers_checkout_ladder
    assert tuple(step.name for step in program.steps) == (
        "signup",
        "login",
        "cart",
        "checkout",
        "payment",
        "order",
    )
    assert program.steps[1].depends_on == ("signup",)
    assert program.steps[-1].depends_on == ("payment",)


def test_a_program_missing_a_stage_does_not_claim_the_ladder() -> None:
    partial = JourneyProgram(
        name="signup-journey",
        version="1",
        steps=(_step("signup", JourneyStage.SIGNUP),),
    )

    assert not partial.covers_checkout_ladder


def test_all_six_stages_out_of_order_is_not_the_ladder() -> None:
    steps = (
        _step("order", JourneyStage.ORDER),
        _step("signup", JourneyStage.SIGNUP),
        _step("login", JourneyStage.LOGIN),
        _step("cart", JourneyStage.CART),
        _step("checkout", JourneyStage.CHECKOUT),
        _step("payment", JourneyStage.PAYMENT),
    )
    shuffled = JourneyProgram(name="reordered-journey", version="1", steps=steps)

    # Every stage is present, but "order before signup" is not the reference
    # journey, and reporting it as one would make `order` look like something
    # that happened before `signup`.
    assert {step.stage for step in shuffled.steps} == set(CANONICAL_CHECKOUT_LADDER)
    assert not shuffled.covers_checkout_ladder


# ── business metrics as first-class criteria ───────────────────────────────────


def test_a_step_can_assert_all_four_criterion_kinds() -> None:
    step = _step(
        "payment",
        JourneyStage.PAYMENT,
        service="payments-service",
        assertions=(
            _success("payment.success"),
            _latency("payment.latency.p95"),
            StepAssertion(
                criterion_id="payment.error_rate",
                kind=AssertionKind.ERROR_RATE,
                metric="payment_error_rate",
                comparator=AssertionComparator.LTE,
                unit="ratio",
                threshold=0.01,
            ),
            _business("payment.success_rate", metric="payment_success_rate"),
        ),
    )
    program = JourneyProgram(name="payment-journey", version="1", steps=(step,))

    assert {assertion.kind for assertion in step.assertions} == set(AssertionKind)
    assert program.business_metrics == ("payment_success_rate",)


def test_business_correctness_requires_the_business_sentence() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _business("checkout.success_rate", description="   ")

    assert excinfo.value.rule == "journey.business_assertion_undescribed"
    assert "nobody can act on" in str(excinfo.value)


def test_a_non_business_assertion_needs_no_description() -> None:
    assertion = _latency()

    assert assertion.description == ""
    assert assertion.kind is AssertionKind.LATENCY


def test_business_assertions_report_which_plan_kpis_they_cite() -> None:
    program = JourneyProgram(
        name="commerce-journey",
        version="1",
        steps=(
            _step(
                "checkout",
                JourneyStage.CHECKOUT,
                assertions=(
                    _business("checkout.rate", metric="checkout_success_rate"),
                    _business("checkout.throughput", metric="orders_per_minute"),
                    _business("checkout.queue", metric="queue_lag"),
                ),
            ),
        ),
    )

    assert set(program.business_metrics) <= PLAN_BUSINESS_METRICS
    assert all(
        assertion.cites_plan_metric
        for step in program.steps
        for assertion in step.assertions
        if assertion.kind is AssertionKind.BUSINESS_CORRECTNESS
    )


def test_an_unlisted_metric_is_allowed_and_not_claimed_as_a_plan_kpi() -> None:
    assertion = _business("checkout.odd", metric="cart_abandonment_ratio")

    assert not assertion.cites_plan_metric


# ── one basis, one finite bound ─────────────────────────────────────────────────


def test_an_assertion_records_which_single_basis_it_is_judged_against() -> None:
    assert _latency().basis is AssertionBasis.THRESHOLD
    assert _business().basis is AssertionBasis.BASELINE_TOLERANCE


def test_an_assertion_may_not_set_both_a_threshold_and_a_baseline() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        StepAssertion(
            criterion_id="checkout.latency.p95",
            kind=AssertionKind.LATENCY,
            metric="p95_latency_ms",
            unit="ms",
            threshold=800.0,
            baseline=600.0,
            tolerance_pct=10.0,
        )

    assert excinfo.value.rule == "journey.assertion_mixes_bases"
    assert "silently ignored" in str(excinfo.value)


def test_an_assertion_declaring_no_bound_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        StepAssertion(
            criterion_id="checkout.latency.p95",
            kind=AssertionKind.LATENCY,
            metric="p95_latency_ms",
            unit="ms",
        )

    assert excinfo.value.rule == "journey.assertion_declares_no_bound"
    assert "accept every measurement" in str(excinfo.value)


def test_a_baseline_without_a_tolerance_is_not_a_bound() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        StepAssertion(
            criterion_id="checkout.success_rate",
            kind=AssertionKind.BUSINESS_CORRECTNESS,
            metric="checkout_success_rate",
            comparator=AssertionComparator.GTE,
            unit="ratio",
            baseline=0.97,
            description="97% of checkouts complete",
        )

    assert excinfo.value.rule == "journey.baseline_without_tolerance"


def test_a_tolerance_without_a_baseline_is_not_a_bound() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        StepAssertion(
            criterion_id="checkout.success_rate",
            kind=AssertionKind.BUSINESS_CORRECTNESS,
            metric="checkout_success_rate",
            comparator=AssertionComparator.GTE,
            unit="ratio",
            tolerance_pct=2.0,
            description="97% of checkouts complete",
        )

    assert excinfo.value.rule == "journey.tolerance_without_baseline"


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_a_non_finite_bound_cannot_judge_anything_so_it_is_refused(bad: float) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _latency(threshold=bad)

    assert excinfo.value.rule == "journey.assertion_bound_not_finite"


def test_a_non_finite_baseline_is_refused_too() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        StepAssertion(
            criterion_id="checkout.success_rate",
            kind=AssertionKind.BUSINESS_CORRECTNESS,
            metric="checkout_success_rate",
            comparator=AssertionComparator.GTE,
            unit="ratio",
            baseline=math.inf,
            tolerance_pct=2.0,
            description="97% of checkouts complete",
        )

    assert excinfo.value.rule == "journey.assertion_bound_not_finite"


# ── negative controls: a step that asserts nothing cannot be written ───────────


def test_a_step_that_asserts_nothing_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _step("cart", JourneyStage.CART, assertions=())

    assert excinfo.value.rule == "journey.step_asserts_nothing"
    assert "a passing journey is" in str(excinfo.value)


def test_a_program_with_no_steps_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        JourneyProgram(name="empty-journey", version="1", steps=())

    assert excinfo.value.rule == "journey.program_has_no_steps"
    assert "having walked nowhere" in str(excinfo.value)


def test_two_steps_may_not_share_a_name() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        JourneyProgram(
            name="dupe-journey",
            version="1",
            steps=(
                _step("checkout", JourneyStage.CHECKOUT),
                _step("checkout", JourneyStage.SIGNUP),
            ),
        )

    assert excinfo.value.rule == "journey.duplicate_step"


def test_a_criterion_id_may_not_be_declared_twice_inside_one_step() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _step(
            "checkout",
            JourneyStage.CHECKOUT,
            assertions=(
                _latency("checkout.latency"),
                _latency("checkout.latency", threshold=900.0),
            ),
        )

    assert excinfo.value.rule == "journey.duplicate_criterion_id"
    assert "unciteable" in str(excinfo.value)


def test_a_criterion_id_is_unique_across_the_whole_program() -> None:
    """Two steps may not both own ``checkout.latency.p95``.

    The id is the handle a finding quotes, so it has to resolve to exactly one
    assertion in the program. Per-step uniqueness alone would let the same
    handle mean two different thresholds.
    """
    with pytest.raises(InvariantViolationError) as excinfo:
        JourneyProgram(
            name="dupe-criteria-journey",
            version="1",
            steps=(
                _step("cart", JourneyStage.CART, assertions=(_latency("shared.criterion"),)),
                _step(
                    "checkout",
                    JourneyStage.CHECKOUT,
                    assertions=(_latency("shared.criterion", threshold=1200.0),),
                ),
            ),
        )

    assert excinfo.value.rule == "journey.duplicate_criterion_id"
    assert "resolve to one assertion" in str(excinfo.value)


def test_criterion_ids_are_the_programs_citation_index() -> None:
    program = JourneyProgram(
        name="checkout-journey",
        version="1",
        steps=(
            _step("checkout", JourneyStage.CHECKOUT, assertions=(_success("c.ok"), _latency())),
        ),
    )

    assert program.criterion_ids == ("c.ok", "checkout.latency.p95")


# ── dependencies ────────────────────────────────────────────────────────────────


def test_a_step_may_depend_on_a_step_authored_before_it() -> None:
    program = JourneyProgram(
        name="dependency-journey",
        version="1",
        steps=(
            _step("login", JourneyStage.LOGIN),
            _step("cart", JourneyStage.CART, depends_on=("login",)),
        ),
    )

    assert program.steps[1].depends_on == ("login",)


def test_a_forward_dependency_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        JourneyProgram(
            name="forward-journey",
            version="1",
            steps=(
                _step("cart", JourneyStage.CART, depends_on=("payment",)),
                _step("payment", JourneyStage.PAYMENT),
            ),
        )

    assert excinfo.value.rule == "journey.unresolved_dependency"
    assert "declared later" in str(excinfo.value)


def test_a_dangling_dependency_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        JourneyProgram(
            name="dangling-journey",
            version="1",
            steps=(_step("cart", JourneyStage.CART, depends_on=("nonexistent-step",)),),
        )

    assert excinfo.value.rule == "journey.unresolved_dependency"
    assert "not declared anywhere" in str(excinfo.value)


def test_a_repeated_dependency_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _step("cart", JourneyStage.CART, depends_on=("login", "login"))

    assert excinfo.value.rule == "journey.duplicate_dependency"


# ── version pinning ─────────────────────────────────────────────────────────────


def test_a_program_digest_is_stable_for_identical_programs() -> None:
    assert _ladder_program().digest() == _ladder_program().digest()
    assert _ladder_program().pin.digest == _ladder_program().digest()


def test_a_version_bump_changes_the_pin() -> None:
    v1 = _ladder_program("1.0.0")
    v2 = _ladder_program("1.0.1")

    assert v1.digest() != v2.digest()
    assert v1.pin.version == "1.0.0"
    assert v2.pin.version == "1.0.1"
    assert v1.pin.label != v2.pin.label


def test_editing_a_threshold_without_bumping_the_version_still_changes_the_digest() -> None:
    original = JourneyProgram(
        name="checkout-journey",
        version="1.0.0",
        steps=(_step("checkout", JourneyStage.CHECKOUT, assertions=(_latency(),)),),
    )
    edited = JourneyProgram(
        name="checkout-journey",
        version="1.0.0",
        steps=(_step("checkout", JourneyStage.CHECKOUT, assertions=(_latency(threshold=1500.0),)),),
    )

    # Same name, same version, different program: the digest is what tells a
    # comparison that the thing it is about changed underneath it.
    assert original.digest() != edited.digest()


def test_a_pin_carries_a_sha256_digest_and_a_short_label() -> None:
    pin = _ladder_program().pin

    assert len(pin.digest) == 64
    assert all(character in "0123456789abcdef" for character in pin.digest)
    assert pin.label == f"checkout-journey@1.0.0#{pin.digest[:12]}"


def test_a_pin_rejects_a_digest_that_is_not_a_sha256() -> None:
    with pytest.raises(ValueError, match=r"string_pattern_mismatch|^$"):
        JourneyPin(name="checkout-journey", version="1.0.0", digest="not-a-digest")


def test_an_unsupported_schema_version_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        JourneyProgram(
            schema_version="9.9",
            name="checkout-journey",
            version="1.0.0",
            steps=(_step("checkout", JourneyStage.CHECKOUT),),
        )

    assert excinfo.value.rule == "journey.unsupported_schema"


def test_a_program_is_frozen() -> None:
    program = _ladder_program()

    with pytest.raises(ValueError, match=r"frozen|immutable"):
        program.version = "2.0.0"


# ── catalog presence is not coverage ────────────────────────────────────────────


def test_authoring_a_journey_registers_untested_cells_and_nothing_more() -> None:
    """The negative control: a written journey is not a covered journey."""
    program = _ladder_program()

    cells = authored_cells(program)

    assert len(cells) == len(program.steps)
    assert {cell.state for cell in cells} == {CellState.UNKNOWN}
    assert all(cell.state is not CellState.PASSED for cell in cells)


def test_each_step_maps_onto_its_own_service_x_probe_x_context_x_band_cell() -> None:
    program = JourneyProgram(
        name="checkout-journey",
        version="2.1.0",
        steps=(
            _step("cart", JourneyStage.CART, service="cart-service"),
            _step("checkout", JourneyStage.CHECKOUT, service="checkout-service"),
        ),
    )

    assert tuple((cell.target, cell.parameter_band) for cell in program.cells) == (
        ("cart-service", "2.1.0#cart"),
        ("checkout-service", "2.1.0#checkout"),
    )
    assert {cell.execution_context for cell in program.cells} == {"journey:checkout-journey"}
    assert {cell.fault_kind for cell in program.cells} == {"synthetic.journey"}


def test_repinning_a_journey_lands_on_a_different_cell() -> None:
    """Old evidence stays addressable instead of being overwritten by a new run."""
    v1 = _ladder_program("1.0.0")
    v2 = _ladder_program("2.0.0")

    v1_keys = {cell.key for cell in v1.cells}
    v2_keys = {cell.key for cell in v2.cells}

    assert v1_keys.isdisjoint(v2_keys)
    assert len(v1_keys) == len(v1.steps)


def test_cells_are_built_on_the_existing_coverage_cell_key() -> None:
    program = _ladder_program()

    # Not a new key shape: the journey dimensions ride in the existing band and
    # context fields, so the coverage store is extended, never forked.
    for cell, step in zip(program.cells, program.steps, strict=True):
        assert cell.key == "\x1f".join(
            (step.service, "synthetic.journey", "journey:checkout-journey", f"1.0.0#{step.name}")
        )


# ── serialization ───────────────────────────────────────────────────────────────


def test_a_program_round_trips_through_its_reloadable_dump() -> None:
    program = _ladder_program()

    assert JourneyProgram.model_validate(program.model_dump(mode="json")) == program


def test_a_program_report_payload_carries_its_citation_facts() -> None:
    program = _ladder_program()
    payload: dict[str, Any] = program.to_dict()

    assert payload["pin"] == program.pin.to_dict()
    assert payload["digest"] == program.digest()
    assert payload["covers_checkout_ladder"] is True
    assert payload["criterion_ids"] == list(program.criterion_ids)
    assert payload["business_metrics"] == ["checkout_success_rate"]


def test_a_step_dict_carries_its_derived_assertion_facts() -> None:
    step = _step("checkout", JourneyStage.CHECKOUT, assertions=(_business(),))
    payload: dict[str, Any] = step.to_dict()

    assert payload["assertions"][0]["basis"] == "baseline_tolerance"
    assert payload["assertions"][0]["cites_plan_metric"] is True
    assert payload["stage"] == "checkout"


# ── the domain law, restated where the module lives ────────────────────────────


_FORBIDDEN_STDLIB = frozenset({"asyncio", "socket", "subprocess", "sqlite3", "pathlib", "os"})
_FORBIDDEN_LAYERS = ("mayhem.toolkit", "mayhem.agents", "mayhem.controller", "mayhem.infra")


def test_journeys_imports_nothing_the_domain_may_not_import() -> None:
    source = open(journeys_module.__file__, encoding="utf-8").read()  # noqa: SIM115, PTH123
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    assert not imported & _FORBIDDEN_STDLIB
    assert not [name for name in sorted(imported) if name.startswith(_FORBIDDEN_LAYERS)]
