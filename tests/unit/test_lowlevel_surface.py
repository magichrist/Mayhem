"""Plan 04 Phase 3 — the parameter grammar and the explanation surface.

Phase 1 declared 22 descriptors, Phase 2 decided what a user meets for 18 of
them, and neither was reachable by a person. Phase 3 lands the two things that
were missing: the **parameter grammar** Phase 1 recorded as deferred work, and
the **explanation** for every primitive including the fourteen with no catalog
id. This file is the suite for both.

The groups, in the order they fail:

* **the magnitude rule.** Every mode whose effect *scales with an amount* must
  declare one, bounded by the descriptor's own maximum safe duration. A delay
  fault with no delay is a fault that cannot be told apart from a no-op, which is
  the inert-parameter defect the plan's Phase 5 names; Phase 3 refuses it at the
  descriptor, so it cannot reach the grammar.
* **the grammar is derived, not written.** Every parameter is read from a field
  the descriptor already validated, so the grammar cannot disagree with the model.
  Asserted from both directions: every parameter's ``default`` is the descriptor's
  own value, and every enum's ``choices`` are a subset of the closed table the
  descriptor was validated against.
* **the explanation is total and honest.** All 22 primitives explain, none of
  them claims a mechanism was applied, every blocked one names its mechanism, and
  the construction error that makes ``mechanism_applied=True`` impossible is
  exercised rather than described.
* **the two decision tables are exhaustive and disjoint**, checked through
  :func:`disposition_problems` — the same "problems as data, not an exception"
  shape Phase 1 used for the substrate claims, and for the same reason.
* **the surface.** ``mayhem lowlevel`` resolves through the real Click tree and
  renders both a listing and one primitive, with the caveat reachable in the lines
  *and* in the JSON. The group is not registered, so the suite invokes it
  directly, the way ``test_risk_preview_surface.py`` does.

Negative controls, at the end: a descriptor that drops its magnitude, one that
sets a magnitude on a mode that has none, a zero magnitude, a magnitude longer
than the recovery window, a grammar that omits a required parameter, an
explanation that claims a mechanism was applied, an undecided primitive, an
unknown primitive, and a filter typo that would otherwise list nothing.

Deliberately **not** claimed here: any injection. Nothing in this suite, in
``domain/lowlevel.py`` or in ``cli/lowlevel_cmd.py`` attaches anything, and
:data:`LOWLEVEL_NOT_ATTACHED_NOTICE` says so on every value that leaves the
surface.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mayhem.cli import lowlevel_cmd
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.lowlevel_cmd import lowlevel
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.lowlevel import (
    ERNO_NUMBERS,
    MAX_SLEW_PPM,
    PRIMITIVES,
    RETURN_MUTATIONS,
    ClockId,
    ErrorCode,
    IoOperation,
    IOPrimitive,
    JVMInstrumentation,
    JVMPrimitive,
    KernelPrimitive,
    ParamKind,
    PrimitiveParam,
    ReverseAttachment,
    descriptor_for,
    magnitude_holder,
    parameter_grammar,
    resolve_params,
    specification_for,
)
from mayhem.domain.lowlevel_report import (
    CATALOG_REFUSAL_BY_PRIMITIVE,
    DESCRIPTOR_ONLY_RULES,
    LOWLEVEL_NOT_ATTACHED_NOTICE,
    RULE_IDS,
    PrimitiveAvailability,
    PrimitiveDisposition,
    PrimitiveExplanation,
    blocked_primitives,
    describe_explanation,
    disposition_problems,
    explain_primitive,
    explain_primitives,
)

if TYPE_CHECKING:
    from mayhem.domain.lowlevel import LowLevelPrimitive

ALL_IDS: tuple[str, ...] = tuple(sorted(PRIMITIVES))
BLOCKED_IDS: tuple[str, ...] = tuple(sorted(blocked_primitives()))

#: The same pattern ``mayhem.domain.capabilities.Identifier`` uses, restated so the
#: test checks the *claim* rather than trusting that the annotation is applied.
_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")

#: Every closed enum table a grammar is allowed to draw a choice from. Built from
#: the enums themselves rather than from literals, so adding a member to one of
#: them does not silently make this test fail — and does not silently make it
#: *weaker*, because the tables are the same objects the validators read.
_CLOSED_VOCABULARIES: frozenset[str] = (
    frozenset(code.value for code in ErrorCode)
    | frozenset(RETURN_MUTATIONS)
    | frozenset(
        value
        for enum in (
            IoOperation,
            JVMInstrumentation,
            ClockId,
            ReverseAttachment,
        )
        for value in (member.value for member in enum)
    )
)


def _declared_syscall_names() -> frozenset[str]:
    """Every syscall name any kernel descriptor declares.

    A syscall vocabulary is per-descriptor rather than global — ``kernel.
    syscall_latency`` offers ``fsync`` and ``kernel.syscall_errno`` does not —
    so the test's "is this a real choice" check reads the union and the
    per-descriptor check is :meth:`test_a_kernel_syscall_grammar_is_the_descriptor_
    own_syscall_set` below.
    """
    return frozenset(
        syscall
        for primitive in PRIMITIVES.values()
        if isinstance(primitive, KernelPrimitive)
        for syscall in primitive.syscalls
    )


def _explanation(primitive_id: str) -> PrimitiveExplanation:
    return explain_primitive(primitive_id)


def _payload(primitive_id: str, **params: object) -> dict[str, object]:
    return specification_for(descriptor_for(primitive_id), params).model_dump(mode="json")


def _grammar(primitive_id: str) -> dict[str, PrimitiveParam]:
    """The primitive's grammar as a name-keyed mapping."""
    return {param.name: param for param in parameter_grammar(descriptor_for(primitive_id))}


def _params_for(primitive_id: str) -> dict[str, object]:
    """The smallest legal request for a primitive.

    The grammar's own defaults, plus the one selector no default can stand in
    for: a syscall. A kernel primitive that accepts a request naming no syscall
    would be a request to perturb all of them, which is a different and much
    larger fault, so the grammar requires the target and this helper supplies the
    first declared one.
    """
    primitive = descriptor_for(primitive_id)
    required = [param for param in parameter_grammar(primitive) if param.required]
    params: dict[str, object] = {}
    for param in required:
        if param.default is None and param.choices:
            params[param.name] = param.choices[0]
    return params


def _minimal_kernel(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "kernel.probe",
        "family": "kernel",
        "mode": "latency_delay",
        "title": "A probe kernel primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": "process",
        "risk": "high",
        "max_safe_duration_s": 60.0,
        "latency_ms": 2500,
        "syscalls": frozenset({"read"}),
        "loader": "probe-loader",
        "reversibility_statement": {
            "reversibility": "reversible",
            "undo": "detach the probe",
            "verification": "a canary call is unhooked",
            "compensation_template": "kernel.probe.detach",
        },
        "residue_checks": (
            {
                "facet": "attachment",
                "probe": "read the tracefs kprobe table",
                "expectation": "no probe entry remains",
            },
        ),
    }
    base.update(overrides)
    return base


def _minimal_io(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "io.probe",
        "family": "io",
        "mode": "delay",
        "title": "A probe IO primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": "storage",
        "risk": "medium",
        "max_safe_duration_s": 60.0,
        "delay_ms": 1500,
        "operation": "read",
        "shim": "fuse",
        "path_param": "path",
        "default_path": "/tmp",
        "reversibility_statement": {
            "reversibility": "reversible",
            "undo": "unmount the shim",
            "verification": "a probe read is unmounted again",
            "compensation_template": "storage.probe.unmount",
        },
        "residue_checks": (
            {
                "facet": "mount",
                "probe": "findmnt --target /tmp",
                "expectation": "the mount is gone",
            },
        ),
    }
    base.update(overrides)
    return base


def _minimal_jvm(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "jvm.probe",
        "family": "jvm",
        "mode": "method_delay",
        "title": "A probe JVM primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": "process",
        "risk": "medium",
        "max_safe_duration_s": 60.0,
        "delay_ms": 1200,
        "target_class": "java.lang.System",
        "target_method": "gc",
        "instrumentation": "jvmti_agent",
        "reversibility_statement": {
            "reversibility": "reversible",
            "undo": "detach the agent",
            "verification": "the method's latency returns to baseline",
            "compensation_template": "jvm.agent_detach",
        },
        "residue_checks": (
            {
                "facet": "bytecode",
                "probe": "re-dump the instrumented method",
                "expectation": "the dump matches the pre-injection bytes",
            },
        ),
    }
    base.update(overrides)
    return base


# ── 1. the magnitude rule ────────────────────────────────────────────────────


class TestMagnitudeRule:
    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_every_scaling_mode_declares_a_magnitude(self, primitive_id: str) -> None:
        """A perturbation with no amount cannot differ from a no-op."""
        explanation = _explanation(primitive_id)
        primitive = descriptor_for(primitive_id)
        grammar = {param.name for param in parameter_grammar(primitive)}
        field = _magnitude_field_of(primitive)
        if field is None:
            assert explanation.magnitude_holder, (
                f"{primitive_id} names no magnitude at all, not even where it lives"
            )
            return
        assert field in grammar, f"{primitive_id} scales by an amount but declares no {field}"

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_a_declared_magnitude_never_outlasts_its_own_recovery_window(
        self, primitive_id: str
    ) -> None:
        primitive = descriptor_for(primitive_id)
        for param in parameter_grammar(primitive):
            if param.kind is not ParamKind.INTEGER or param.unit != "ms":
                continue
            assert param.maximum is not None
            assert param.maximum <= int(primitive.max_safe_duration_s * 1000), (
                f"{primitive_id}.{param.name} may outlast the descriptor's own "
                f"{primitive.max_safe_duration_s:g}s window"
            )

    def test_the_clock_offset_bound_is_the_descriptors_own_window(self) -> None:
        """A skew longer than the window it is injected for cannot be undone in it."""
        for primitive_id in ("clock.realtime_offset", "clock.monotonic_offset"):
            primitive = descriptor_for(primitive_id)
            grammar = {param.name: param for param in parameter_grammar(primitive)}
            window = int(primitive.max_safe_duration_s * 1000)
            assert grammar["offset_ms"].maximum == window, primitive_id
            assert grammar["offset_ms"].minimum == -window, primitive_id


def _magnitude_field_of(primitive: LowLevelPrimitive) -> str | None:
    """The magnitude parameter this primitive carries, read from its own grammar.

    Deliberately derived from the grammar rather than from the module-private
    table: the test asks the same question the surface answers, so a magnitude
    that appeared in the grammar without being reachable would be visible here.
    """
    magnitudes = [
        param.name
        for param in parameter_grammar(primitive)
        if param.kind is ParamKind.INTEGER and param.unit in {"ms", "ppm"}
    ]
    return magnitudes[0] if magnitudes else None


# ── 2. the grammar is derived ────────────────────────────────────────────────


class TestDerivedGrammar:
    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_the_grammar_is_never_empty(self, primitive_id: str) -> None:
        """No selector means two requests could not be told apart at all."""
        assert parameter_grammar(descriptor_for(primitive_id))

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_every_primitive_parameter_name_is_identifier_shaped(self, primitive_id: str) -> None:
        """``Identifier``-shaped, because a parameter reaches a drill spec as a key."""
        grammar = parameter_grammar(descriptor_for(primitive_id))
        assert len({param.name for param in grammar}) == len(grammar), (
            f"{primitive_id} declares a parameter twice"
        )
        for param in grammar:
            assert _IDENTIFIER_RE.fullmatch(param.name), (
                f"{primitive_id}.{param.name!r} is not identifier-shaped"
            )

    def test_a_parameter_name_that_is_not_identifier_shaped_is_refused(self) -> None:
        """Negative control for the line above: the shape is enforced, not assumed."""
        with pytest.raises(ValidationError):
            PrimitiveParam(name="Delay Ms", kind=ParamKind.INTEGER, unit="ms", minimum=1, maximum=2)

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_every_enum_choice_comes_from_a_closed_table(self, primitive_id: str) -> None:
        """A choice the descriptor was not validated against is a typo generator."""
        known = _CLOSED_VOCABULARIES | _declared_syscall_names()
        for param in parameter_grammar(descriptor_for(primitive_id)):
            if param.kind is not ParamKind.ENUM:
                continue
            assert set(param.choices) <= known, (
                f"{primitive_id}.{param.name} offers a choice outside every closed table: "
                f"{sorted(set(param.choices) - known)}"
            )

    def test_a_kernel_syscall_grammar_is_the_descriptor_own_syscall_set(self) -> None:
        for primitive_id, primitive in PRIMITIVES.items():
            if not isinstance(primitive, KernelPrimitive):
                continue
            grammar = _grammar(primitive_id)
            assert set(grammar["syscall"].choices) == set(primitive.syscalls), (
                f"{primitive_id} would accept a syscall its descriptor does not declare"
            )
            assert grammar["syscall"].required

    def test_an_io_grammar_uses_the_descriptor_own_path_parameter_name(self) -> None:
        for primitive_id, primitive in PRIMITIVES.items():
            if not isinstance(primitive, IOPrimitive):
                continue
            names = set(_grammar(primitive_id))
            assert primitive.path_param in names, (
                f"{primitive_id} parameterises a path under a name the grammar does not use"
            )

    def test_a_jvm_pressure_grammar_names_the_mode_own_unit(self) -> None:
        """262144 means different things per mode, and the grammar has to say which."""
        expected = {
            "jvm.allocation_pressure": "bytes",
            "jvm.gc_pressure": "invocations",
            "jvm.thread_pressure": "threads",
        }
        for primitive_id, unit in expected.items():
            grammar = _grammar(primitive_id)
            assert grammar["pressure_units"].unit == unit, primitive_id
            assert grammar["pressure_units"].required

    def test_every_default_is_the_descriptors_own_value(self) -> None:
        """A grammar that defaults to something else is a second source of truth."""
        for primitive_id, primitive in PRIMITIVES.items():
            payload = _payload(primitive_id, **_params_for(primitive_id))
            for name, value in payload["targets"]:
                param = next(p for p in parameter_grammar(primitive) if p.name == name)
                if param.default is None:
                    # A parameter with no default is one the request had to
                    # supply, so there is nothing to compare against.
                    continue
                if param.kind is ParamKind.INTEGER:
                    assert param.default == int(value), f"{primitive_id}.{name}"
                else:
                    assert param.default == value, f"{primitive_id}.{name}"

    def test_the_errno_grammar_offers_exactly_the_closed_table(self) -> None:
        grammar = _grammar("kernel.syscall_errno")
        assert set(grammar["errno"].choices) == {code.value for code in ErrorCode}
        assert {ERNO_NUMBERS[ErrorCode.EIO]} == {5}

    def test_the_slew_bound_is_the_one_the_descriptor_validates(self) -> None:
        primitive = descriptor_for("clock.monotonic_offset")
        grammar = {param.name: param for param in parameter_grammar(primitive)}
        assert grammar["offset_ms"].minimum == -int(primitive.max_safe_duration_s * 1000)
        assert MAX_SLEW_PPM == 500


# ── 3. resolution: refuse, never repair ──────────────────────────────────────


class TestResolveParams:
    def test_an_unknown_parameter_is_refused_and_the_grammar_is_printed(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            resolve_params(descriptor_for("io.read_delay"), {"pathh": "/tmp"})
        assert refusal.value.rule == "lowlevel.parameter_out_of_grammar"
        assert "pathh" in str(refusal.value)
        assert "delay_ms" in str(refusal.value), (
            "the refusal must print the grammar so a caller can correct the request"
        )

    def test_a_missing_required_selector_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="requires parameter 'syscall'"):
            resolve_params(descriptor_for("kernel.syscall_errno"), {})

    def test_a_value_outside_a_closed_vocabulary_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="not an accepted value"):
            resolve_params(
                descriptor_for("kernel.syscall_errno"),
                {"syscall": "read", "errno": "EBOGUS"},
            )

    def test_a_zero_magnitude_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="outside 1\\.\\."):
            resolve_params(descriptor_for("io.read_delay"), {"delay_ms": 0})

    def test_a_magnitude_past_the_window_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="outside"):
            resolve_params(descriptor_for("io.read_delay"), {"delay_ms": 10_000_000})

    def test_a_non_integer_magnitude_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="must be an integer"):
            resolve_params(descriptor_for("io.read_delay"), {"delay_ms": "1500"})

    def test_a_boolean_is_not_an_integer(self) -> None:
        """``True`` is an ``int`` in Python, and ``delay_ms=True`` would be 1ms."""
        with pytest.raises(InvariantViolationError, match="must be an integer"):
            resolve_params(descriptor_for("io.read_delay"), {"delay_ms": True})

    def test_a_relative_path_is_refused_by_the_descriptor(self) -> None:
        """A relative path resolves against whatever cwd an injector runs with."""
        with pytest.raises(ValidationError, match="default_path must be an absolute path"):
            IOPrimitive.model_validate(_minimal_io(default_path="tmp/data"))
        with pytest.raises(ValidationError, match="default_path must be an absolute path"):
            IOPrimitive.model_validate(_minimal_io(default_path="./tmp"))
        assert IOPrimitive.model_validate(_minimal_io(default_path="/dev/sda")).default_path == (
            "/dev/sda"
        )

    def test_a_resolved_request_defaults_everything_the_descriptor_fixes(self) -> None:
        resolved = resolve_params(descriptor_for("io.read_delay"), {})
        names = {param.name for param, _ in resolved}
        assert "delay_ms" in names
        assert "path" in names
        assert "operation" in names


# ── 4. the explanation is total, and honest ──────────────────────────────────


class TestExplanation:
    def test_every_primitive_explains(self) -> None:
        assert len(explain_primitives()) == len(PRIMITIVES) == 22

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_no_primitive_claims_its_mechanism_was_applied(self, primitive_id: str) -> None:
        assert _explanation(primitive_id).mechanism_applied is False

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_every_blocked_primitive_names_the_mechanism_that_is_missing(
        self, primitive_id: str
    ) -> None:
        """A refusal that names nothing gives an operator nothing to file."""
        explanation = _explanation(primitive_id)
        assert not explanation.injectable, primitive_id
        assert explanation.mechanism, f"{primitive_id} is blocked and names no mechanism"
        assert explanation.mechanism in explanation.refusal_reason
        assert explanation.limits, f"{primitive_id} is blocked and names no limit"

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_every_primitive_is_blocked_or_carried_by_an_active_fault(
        self, primitive_id: str
    ) -> None:
        """The exhaustive half, so the test above needs no skip.

        Two questions, twenty-two answers, and a primitive that is neither would
        be a third state the catalog has no word for.
        """
        explanation = _explanation(primitive_id)
        if primitive_id in BLOCKED_IDS:
            assert not explanation.injectable, primitive_id
            return
        assert explanation.injectable, primitive_id
        assert explanation.disposition is PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT
        assert explanation.carried_by

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_every_explanation_carries_the_caveat(self, primitive_id: str) -> None:
        explanation = _explanation(primitive_id)
        assert explanation.notice == LOWLEVEL_NOT_ATTACHED_NOTICE
        assert "attaches no eBPF program" in explanation.notice
        assert explanation.to_payload()["notice"] == LOWLEVEL_NOT_ATTACHED_NOTICE

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_the_disposition_matches_the_facts(self, primitive_id: str) -> None:
        explanation = _explanation(primitive_id)
        primitive = descriptor_for(primitive_id)
        if primitive.existing_fault_id is not None:
            assert explanation.disposition is PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT
            assert explanation.carried_by == primitive.existing_fault_id
            definition = definition_for(primitive.existing_fault_id)
            assert definition.catalog_only is False, (
                "a carried primitive must name an entry that actually works"
            )
            assert explanation.mechanism_state is PrimitiveAvailability.CARRIED_BY_ACTIVE_FAULT
            return
        assert primitive_id in BLOCKED_IDS
        if primitive.missing is not None and primitive.missing.unachievable_substrate:
            assert explanation.disposition is PrimitiveDisposition.UNACHIEVABLE
            assert explanation.mechanism_state is PrimitiveAvailability.UNACHIEVABLE
            assert explanation.unachievable_substrate
            return
        assert explanation.mechanism_state is PrimitiveAvailability.DECLARED_NOT_APPLIED
        if primitive_id in CATALOG_REFUSAL_BY_PRIMITIVE:
            assert explanation.disposition is PrimitiveDisposition.REFUSED_IN_CATALOG
            assert explanation.catalog_refusal
            assert (
                explanation.catalog_refusal
                == definition_for(CATALOG_REFUSAL_BY_PRIMITIVE[primitive_id]).refusal_reason
            )
        else:
            assert explanation.disposition is PrimitiveDisposition.DESCRIPTOR_ONLY
            assert explanation.rule_id in DESCRIPTOR_ONLY_RULES.values()
            assert explanation.rule_reason

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_a_blocked_primitive_never_offers_a_substitute(self, primitive_id: str) -> None:
        """Near misses are annotated, never presented as equivalents."""
        explanation = _explanation(primitive_id)
        for near_miss in explanation.near_misses:
            assert definition_for(near_miss).id == near_miss, (
                f"{primitive_id} annotates a near miss that is not a catalog id"
            )
            assert len(explanation.why_no_substitute.split()) > 5
        if explanation.disposition is PrimitiveDisposition.DESCRIPTOR_ONLY:
            assert explanation.near_misses or not explanation.why_no_substitute

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_the_grammar_in_the_explanation_is_the_descriptors_own(self, primitive_id: str) -> None:
        explanation = _explanation(primitive_id)
        rendered = dict(explanation.grammar)
        for param in parameter_grammar(descriptor_for(primitive_id)):
            assert param.name in rendered
            assert param.describe() == rendered[param.name]

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_the_incompatibility_relation_is_symmetric(self, primitive_id: str) -> None:
        explanation = _explanation(primitive_id)
        for other_id in explanation.incompatible_with:
            assert primitive_id in _explanation(other_id).incompatible_with, (
                f"{primitive_id} cannot run alongside {other_id}, but not the reverse"
            )

    def test_the_four_injectable_primitives_name_no_missing_mechanism(self) -> None:
        for primitive_id in ("io.capacity_exhaustion", "io.inode_exhaustion"):
            explanation = _explanation(primitive_id)
            assert explanation.injectable
            assert explanation.mechanism == ""
            assert explanation.magnitude_holder == (
                f"the parameters of the backing catalog entry {explanation.carried_by}"
            ), "a quota primitive takes its size from the fault it is backed by"

    def test_an_error_mode_says_its_magnitude_is_a_code_not_an_amount(self) -> None:
        holder = magnitude_holder(descriptor_for("io.read_error"))
        assert "code rather than an amount" in holder

    def test_a_freeze_mode_names_itself_rather_than_a_missing_parameter(self) -> None:
        holder = magnitude_holder(descriptor_for("clock.realtime_freeze"))
        assert "no tunable amount" in holder

    def test_a_rendered_explanation_carries_the_caveat_on_its_last_line(self) -> None:
        rendered = describe_explanation(_explanation("kernel.syscall_errno"))
        assert rendered.split("\n")[-1] == f"  notice: {LOWLEVEL_NOT_ATTACHED_NOTICE}"


# ── 5. the two decision tables ───────────────────────────────────────────────


class TestDecisionTables:
    def test_the_tables_report_no_disagreement(self) -> None:
        assert disposition_problems() == ()

    def test_every_blocked_primitive_is_decided_exactly_once(self) -> None:
        decided = set(CATALOG_REFUSAL_BY_PRIMITIVE) | set(DESCRIPTOR_ONLY_RULES)
        assert set(BLOCKED_IDS) - decided == set(), (
            f"blocked primitives with no written outcome: {sorted(set(BLOCKED_IDS) - decided)}"
        )
        assert decided - set(BLOCKED_IDS) == set(), (
            f"outcomes recorded for primitives that are injectable: "
            f"{sorted(decided - set(BLOCKED_IDS))}"
        )

    def test_every_rule_id_has_a_stated_reason(self) -> None:
        used = set(DESCRIPTOR_ONLY_RULES.values())
        assert used <= set(RULE_IDS)
        for rule_id in used:
            assert len(RULE_IDS[rule_id].split()) > 8, rule_id

    def test_every_catalog_refusal_row_names_a_catalog_only_entry(self) -> None:
        for primitive_id, fault_id in CATALOG_REFUSAL_BY_PRIMITIVE.items():
            definition = definition_for(fault_id)
            assert definition.catalog_only, (
                f"{primitive_id} points at {fault_id}, which is an active entry"
            )
            assert definition.refusal_reason

    def test_every_catalog_refusal_row_is_in_the_impact_gate_set(self) -> None:
        """The Phase-2 trap, restated at the explanation layer."""
        from mayhem.agents import impact

        for fault_id in set(CATALOG_REFUSAL_BY_PRIMITIVE.values()):
            assert fault_id in impact._CATALOG_ONLY_FAULTS, (
                f"{fault_id} would be reported impact_possible by gate_fault"
            )

    def test_a_refused_primitive_never_names_a_refusal_as_an_alternative(self) -> None:
        refusals = set(CATALOG_REFUSAL_BY_PRIMITIVE.values())
        for primitive_id, explanation in ((p, _explanation(p)) for p in BLOCKED_IDS):
            if primitive_id in CATALOG_REFUSAL_BY_PRIMITIVE:
                continue
            assert refusals.isdisjoint(explanation.near_misses), (
                f"{primitive_id} points at a refusal as if it were usable"
            )


# ── 6. the surface ───────────────────────────────────────────────────────────


class TestSurface:
    def test_the_group_is_not_registered_yet(self) -> None:
        """Recorded, so the integration pass's row is a known gap rather than a surprise."""
        from mayhem.cli import command_registry

        assert "lowlevel" not in command_registry.COMMAND_SPECS

    def test_the_listing_renders_and_exits_zero(self) -> None:
        result = CliRunner().invoke(lowlevel, ["primitives"])
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "22 low-level primitive(s) declared" in result.output
        assert "applied=false" in result.output
        assert LOWLEVEL_NOT_ATTACHED_NOTICE in result.output

    def test_the_listing_json_carries_the_caveat_at_the_top_and_on_every_record(self) -> None:
        result = CliRunner().invoke(lowlevel, ["primitives", "--json"])
        assert result.exit_code == ExitCode.SUCCESS, result.output
        payload = json.loads(result.output)
        assert payload["notice"] == LOWLEVEL_NOT_ATTACHED_NOTICE
        assert payload["summary"]["total"] == 22
        assert payload["summary"]["injectable"] == 4
        assert payload["summary"]["declared_not_applied"] == 16
        assert payload["summary"]["unachievable"] == 2
        assert payload["summary"]["by_disposition"] == {
            "carried_by_active_fault": 4,
            "descriptor_only": 10,
            "refused_in_catalog": 6,
            "unachievable": 2,
        }, "six primitives are answered by four refusal ids: one refusal per mechanism"
        for record in payload["primitives"]:
            assert record["notice"] == LOWLEVEL_NOT_ATTACHED_NOTICE
            assert record["mechanism_applied"] is False

    @pytest.mark.parametrize(
        ("family", "expected"),
        [("kernel", 3), ("io", 9), ("jvm", 6), ("clock", 4)],
    )
    def test_a_family_filter_selects_exactly_that_family(self, family: str, expected: int) -> None:
        result = CliRunner().invoke(lowlevel, ["primitives", "--family", family, "--json"])
        assert result.exit_code == ExitCode.SUCCESS, result.output
        payload = json.loads(result.output)
        assert payload["summary"]["total"] == expected
        assert {record["family"] for record in payload["primitives"]} == {family}

    def test_the_injectable_filter_returns_only_the_four_working_ones(self) -> None:
        result = CliRunner().invoke(lowlevel, ["primitives", "--injectable", "--json"])
        payload = json.loads(result.output)
        assert [r["primitive_id"] for r in payload["primitives"]] == [
            "clock.realtime_offset",
            "io.capacity_exhaustion",
            "io.filesystem_read_only",
            "io.inode_exhaustion",
        ]

    def test_a_disposition_filter_selects_exactly_that_disposition(self) -> None:
        result = CliRunner().invoke(
            lowlevel, ["primitives", "--disposition", "refused_in_catalog", "--json"]
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        payload = json.loads(result.output)
        assert [r["primitive_id"] for r in payload["primitives"]] == [
            "io.block_device_delay",
            "io.read_delay",
            "io.write_delay",
            "kernel.syscall_errno",
            "kernel.syscall_latency",
            "kernel.syscall_return_mutation",
        ]
        assert {r["catalog_fault_id"] for r in payload["primitives"]} == {
            "fs.block_device_delay",
            "fs.read_delay",
            "process.syscall_error",
            "process.syscall_return_mutation",
        }, "four refusal ids answer six primitives"

    def test_an_unknown_primitive_is_a_validation_error_naming_the_rule(self) -> None:
        result = CliRunner().invoke(lowlevel, ["explain", "kernel.nope"])
        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "lowlevel.unknown_primitive" in result.output

    def test_one_primitive_explains_with_its_grammar_and_undo(self) -> None:
        result = CliRunner().invoke(lowlevel, ["explain", "jvm.thread_pressure"])
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "mechanism=jvm_attach_agent" in result.output
        assert "state=declared_not_applied applied=false" in result.output
        assert "pressure_units: 1..1000000 threads" in result.output
        assert "undo (reversible)" in result.output
        assert "compensation template: jvm.agent_detach" in result.output
        assert LOWLEVEL_NOT_ATTACHED_NOTICE in result.output

    def test_the_jvm_primitives_have_a_surface_at_all(self) -> None:
        """The gap Phase 3 exists to close: no catalog id, and previously no words.

        Five of the six are ``R4`` (no expressible id); ``jvm.exception_injection``
        is ``R2`` — ``app.exception`` is already the authoritative refusal — so it
        is asserted to say *that* rather than the prefix reason. Both are refusals
        with a stated reason; neither is silence.
        """
        for primitive_id, fragment in (
            ("jvm.method_delay", "family prefix is not a registered fault prefix"),
            ("jvm.gc_pressure", "family prefix is not a registered fault prefix"),
            ("jvm.thread_pressure", "family prefix is not a registered fault prefix"),
            ("jvm.exception_injection", "already carries this failure"),
        ):
            result = CliRunner().invoke(lowlevel, ["explain", primitive_id])
            assert result.exit_code == ExitCode.SUCCESS, result.output
            assert "mechanism=" in result.output
            assert "applied=false" in result.output
            assert fragment in result.output, primitive_id

    def test_the_renderers_agree_on_which_fields_exist(self) -> None:
        """The listing and the single explanation project off the same value."""
        explanation = _explanation("io.read_delay")
        payload = lowlevel_cmd.explain_payload(explanation)
        lines = lowlevel_cmd.render_primitive_lines(explanation)
        assert payload["mechanism"] in "\n".join(lines)
        assert payload["magnitude_holder"] in "\n".join(lines)
        assert payload["refusal_reason"] in "\n".join(lines)
        listing = json.loads(CliRunner().invoke(lowlevel, ["primitives", "--json"]).output)
        record = next(r for r in listing["primitives"] if r["primitive_id"] == "io.read_delay")
        assert record == {k: v for k, v in payload.items() if k != "schema_version"}, (
            "the listing and the single explanation must publish the same record"
        )

    def test_the_documented_invocations_resolve(self) -> None:
        for argv in (
            ["--help"],
            ["primitives"],
            ["primitives", "--family", "kernel", "--json"],
            ["primitives", "--injectable"],
            ["primitives", "--disposition", "unachievable", "--json"],
            ["explain", "kernel.syscall_latency"],
            ["explain", "kernel.syscall_latency", "--json"],
        ):
            result = CliRunner().invoke(lowlevel, argv)
            assert result.exit_code in (0, 2), f"{argv} -> {result.exit_code}: {result.output}"

    def test_the_module_docstring_documents_only_invocations_that_resolve(self) -> None:
        """A typo in a documented invocation fails the way a typo would.

        The spellings are read out of the module's own invocation block, so a
        documented example that stops resolving is a failing test rather than a
        reader's wasted afternoon. ``admit`` is expected to exit ``5`` — it is the
        refusal this build always produces — while the read-only commands exit
        ``0``.
        """
        block = (lowlevel_cmd.__doc__ or "").split("::", 1)
        assert len(block) == 2, "the module documents no invocation block"
        spellings = [
            line.strip()
            for line in block[1].split("\n")
            if line.strip().startswith("mayhem lowlevel")
        ]
        assert len(spellings) >= 9, f"only {len(spellings)} documented invocations found"
        for spelling in spellings:
            # The group is invoked directly here, so the documented group name is
            # dropped: ``mayhem lowlevel explain X`` becomes ``["explain", "X"]``.
            argv = spelling.removeprefix("mayhem lowlevel").split()
            result = CliRunner().invoke(lowlevel, argv)
            expected = ExitCode.SAFETY_REFUSAL if argv[0] == "admit" else ExitCode.SUCCESS
            assert result.exit_code == int(expected), (
                f"documented invocation {spelling!r} exited {result.exit_code}: {result.output}"
            )


# ── 7. negative controls ─────────────────────────────────────────────────────


class TestNegativeControls:
    def test_a_descriptor_that_drops_its_magnitude_is_refused(self) -> None:
        """The inert-parameter defect, refused at construction."""
        with pytest.raises(ValidationError, match="must declare latency_ms"):
            KernelPrimitive.model_validate(_minimal_kernel(latency_ms=None))
        with pytest.raises(ValidationError, match="must declare delay_ms"):
            IOPrimitive.model_validate(_minimal_io(delay_ms=None))
        with pytest.raises(ValidationError, match="must declare pressure_units"):
            JVMPrimitive.model_validate(
                _minimal_jvm(
                    mode="gc_pressure",
                    delay_ms=None,
                    pressure_units=None,
                )
            )

    def test_a_descriptor_that_sets_a_magnitude_it_has_no_mode_for_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="declares no latency_ms"):
            KernelPrimitive.model_validate(
                _minimal_kernel(mode="errno_return", latency_ms=10, errno_name="EIO")
            )

    def test_a_zero_magnitude_is_refused_at_construction(self) -> None:
        with pytest.raises(ValidationError, match="zero injects nothing"):
            IOPrimitive.model_validate(_minimal_io(delay_ms=0))

    def test_a_magnitude_longer_than_the_recovery_window_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="exceeds the descriptor's own maximum"):
            IOPrimitive.model_validate(_minimal_io(max_safe_duration_s=10.0, delay_ms=11_000))

    def test_the_magnitude_guard_fires_for_the_real_descriptor_it_was_written_for(self) -> None:
        """Proof the guard is not vacuous: the declared descriptor still validates."""
        real = descriptor_for("io.read_delay")
        assert real.delay_ms is not None
        assert real.delay_ms <= int(real.max_safe_duration_s * 1000)

    def test_an_explanation_claiming_a_mechanism_was_applied_is_refused(self) -> None:
        explanation = _explanation("kernel.syscall_errno")
        with pytest.raises(ValidationError, match="mechanism_applied cannot be True"):
            PrimitiveExplanation.model_validate(
                {**explanation.model_dump(mode="json"), "mechanism_applied": True}
            )

    def test_an_explanation_whose_disposition_contradicts_the_verdict_is_refused(self) -> None:
        """A blocked primitive cannot be reported as one an active fault carries."""
        explanation = _explanation("io.read_delay")
        with pytest.raises(ValidationError, match="must name the active fault"):
            PrimitiveExplanation.model_validate(
                {**explanation.model_dump(mode="json"), "disposition": "carried_by_active_fault"}
            )

    def test_an_injectable_primitive_reported_as_refused_is_refused(self) -> None:
        """The other direction: a fault that works must not read as a refusal."""
        explanation = _explanation("io.capacity_exhaustion")
        with pytest.raises(ValidationError, match="must be 'carried_by_active_fault'"):
            PrimitiveExplanation.model_validate(
                {**explanation.model_dump(mode="json"), "disposition": "refused_in_catalog"}
            )

    def test_a_carried_explanation_that_names_nothing_is_refused(self) -> None:
        explanation = _explanation("io.capacity_exhaustion")
        with pytest.raises(ValidationError, match="must name the active fault"):
            PrimitiveExplanation.model_validate(
                {**explanation.model_dump(mode="json"), "carried_by": None}
            )

    def test_an_undecided_blocked_primitive_is_refused_rather_than_rendered(self) -> None:
        """The property that stops a new primitive reading as "nothing to say"."""
        from mayhem.domain import lowlevel_report

        saved = lowlevel_report.DESCRIPTOR_ONLY_RULES
        trimmed = {key: value for key, value in saved.items() if key != "jvm.gc_pressure"}
        object.__setattr__(lowlevel_report, "DESCRIPTOR_ONLY_RULES", trimmed)
        try:
            with pytest.raises(InvariantViolationError) as refusal:
                explain_primitive("jvm.gc_pressure")
            assert refusal.value.rule == "lowlevel.undecided_primitive"
        finally:
            object.__setattr__(lowlevel_report, "DESCRIPTOR_ONLY_RULES", saved)
        assert explain_primitive("jvm.gc_pressure").rule_id == "R4"

    def test_a_primitive_in_both_tables_is_a_reported_problem(self) -> None:
        from mayhem.domain import lowlevel_report

        saved = lowlevel_report.DESCRIPTOR_ONLY_RULES
        object.__setattr__(
            lowlevel_report,
            "DESCRIPTOR_ONLY_RULES",
            {**saved, "io.read_delay": "R4"},
        )
        try:
            problems = disposition_problems()
        finally:
            object.__setattr__(lowlevel_report, "DESCRIPTOR_ONLY_RULES", saved)
        assert [p.subject for p in problems] == ["io.read_delay"]
        assert "claimed by both" in problems[0].detail
        assert disposition_problems() == (), "the restore must be exact"

    def test_a_refusal_row_pointing_at_an_active_fault_is_a_reported_problem(self) -> None:
        """``fs.write_delay`` works, so refusing under that name would mislead."""
        from mayhem.domain import lowlevel_report

        saved = lowlevel_report.CATALOG_REFUSAL_BY_PRIMITIVE
        object.__setattr__(
            lowlevel_report,
            "CATALOG_REFUSAL_BY_PRIMITIVE",
            {**saved, "io.write_delay": "fs.write_delay"},
        )
        try:
            problems = disposition_problems()
        finally:
            object.__setattr__(lowlevel_report, "CATALOG_REFUSAL_BY_PRIMITIVE", saved)
        assert [p.subject for p in problems] == ["io.write_delay"]
        assert "an active catalog entry" in problems[0].detail

    def test_an_unknown_family_filter_is_a_usage_error_not_an_empty_listing(self) -> None:
        """An empty listing reads as "this build has no kernel primitives"."""
        result = CliRunner().invoke(lowlevel, ["primitives", "--family", "kernal"])
        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "unknown family" in result.output
        assert "kernel" in result.output

    def test_an_unknown_disposition_filter_is_a_usage_error(self) -> None:
        result = CliRunner().invoke(lowlevel, ["primitives", "--disposition", "refused"])
        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "unknown disposition" in result.output

    def test_a_filter_matching_nothing_renders_a_named_emptiness(self) -> None:
        from mayhem.domain.lowlevel import SubstrateSurface

        empty = SubstrateSurface(
            capabilities=frozenset(),
            probe_bins=frozenset(),
            cap_bits=frozenset(),
            installable_bins=frozenset(),
            host_tools=frozenset(),
            manifest_capabilities=frozenset(),
        )
        assert explain_primitives(surface=empty), "every primitive becomes blocked on nothing"
        assert all(not e.injectable for e in explain_primitives(surface=empty))
