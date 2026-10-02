"""Plan 04 Phase 2 — the catalog-only outcome for the low-level primitives.

What this file checks
---------------------
Phase 1 declared 22 primitive descriptors in ``domain/lowlevel.py`` and found
that **18 of them cannot be injected** by mayhem's current substrate, each naming
its ``MissingMechanism``. Phase 2 turns that into the honest catalog outcome:
four ``catalog_only`` refusals, and a written reason for each of the other
fourteen.

The groups here, in the order they fail:

* **the selection rule.** ``test_every_non_injectable_primitive_has_a_written_outcome``
  is the load-bearing one. Every blocked primitive is either covered by a new
  refusal or carries a rule id (``R2``-``R5``) explaining why no id was added —
  and each rule id is then *checked against the facts that justify it*, so a
  justification that stops being true fails rather than silently rotting. A
  nineteenth blocked primitive fails the test demanding a decision.
* **the five-registry contract.** For each new id: a catalog definition that is
  ``catalog_only`` with a refusal and no maturity claim; **no** executor routing
  (no override, reported ``catalog.unsupported`` on every engine); **no**
  compensation template, with ``compensated()`` refusing by rule id; **no** impact
  ``REQUIREMENTS`` row and no engine-fault row; and the deriving suites that sweep
  from ``CATALOG`` — the planner refuses it, the explanation reports it as
  catalog-only, and it is deliberately *outside* the active non-k8s set whose
  executor/template contract would demand a mechanism it does not have.
* **the refusal names a real mechanism.** The phrase each refusal must contain is
  keyed by the descriptor's own ``MissingMechanism.mechanism`` string, so the
  catalog text is checked against the domain declaration rather than against a
  literal copied into this test. Rename the mechanism in ``lowlevel.py`` and this
  fails.
* **the impact-gate trap.** ``gate_fault`` reports ``impact_possible=True`` for a
  ``catalog_only`` id missing from ``impact._CATALOG_ONLY_FAULTS`` — it falls
  through to "no in-image tooling required". The negative control removes an id
  from that set and *observes* the contradiction rather than trusting the comment.

Negative controls, at the end: an executable entry carrying a ``refusal_reason``
is refused by ``validate_catalog``; a refusal that names no mechanism fails the
predicate this file enforces; and a new ``FaultCategory`` cannot be constructed
without all three total-map entries, because ``_define`` indexes all three.

Deliberately **not** enforced here: whether a ``refusal_reason`` names a
mechanism is checked test-side, not by ``validate_catalog``. The validator only
knows a refusal must be non-blank, and it cannot know a mechanism vocabulary —
``FaultDefinition`` has no field to hold one and ``domain/faults.py`` is outside
this lane's ownership.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

from mayhem.agents import impact
from mayhem.agents.executors import _FAULT_EXECUTOR_OVERRIDES, executor_for
from mayhem.controller.catalog_report import (
    _executor_name,
    execution_status,
    explain_catalog_fault,
)
from mayhem.controller.compensation import compensated, template_for
from mayhem.controller.planner import PlanningError, plan_drill
from mayhem.domain import catalog as catalog_module
from mayhem.domain.catalog import CATALOG, definition_for, validate_catalog
from mayhem.domain.errors import InvariantViolationError, SchemaValidationError
from mayhem.domain.experiments import (
    DrillConfig,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
    PlannedFault,
)
from mayhem.domain.faults import FaultCategory, MaturityLevel
from mayhem.domain.lowlevel import (
    CURRENT_SUBSTRATE,
    PRIMITIVES,
    ClockPrimitive,
    MissingMechanism,
    descriptor_for,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind, ServiceNode, TopologyGraph

# ── the selection rule, as data ─────────────────────────────────────────────

#: The Phase 2 refusals: catalog id -> the descriptor ids it answers for.
#:
#: One refusal per *mechanism*, not per primitive. ``process.syscall_error``
#: covers the syscall-latency primitive too because both name
#: ``ebpf_kprobe_loader``, and two refusals for one loader is one refusal to keep
#: in step. ``fs.read_delay`` covers ``io.write_delay`` for the same reason — the
#: id ``fs.write_delay`` is already an *active* entry, so there is no name left.
COVERED_BY_CATALOG: dict[str, tuple[str, ...]] = {
    "process.syscall_error": ("kernel.syscall_errno", "kernel.syscall_latency"),
    "process.syscall_return_mutation": ("kernel.syscall_return_mutation",),
    "fs.read_delay": ("io.read_delay", "io.write_delay"),
    "fs.block_device_delay": ("io.block_device_delay",),
}

#: Blocked primitives that get no id, and the rule that says why.
#:
#: * ``R2`` — the catalog already holds the authoritative refusal, named by
#:   ``MissingMechanism.anchor_fault_id``.
#: * ``R3`` — ``NOT_STEPPABLE``: a ``catalog_only`` entry is a promotion ticket
#:   and this one can never be promoted on Linux.
#: * ``R4`` — no expressible id: the family prefix is absent from
#:   ``_PREFIX_TO_CATEGORY``, and this lane adds neither a prefix nor a category.
#: * ``R5`` — the catalog has no honest shape. ``R5a``: the id a user would type
#:   is taken by an active entry with a different mechanism. ``R5b``: the
#:   descriptor's risk rung has no row for its scope.
DESCRIPTOR_ONLY: dict[str, str] = {
    "io.read_error": "R2",
    "io.permission_error": "R2",
    "jvm.exception_injection": "R2",
    "clock.realtime_freeze": "R2",
    "clock.monotonic_offset": "R3",
    "clock.monotonic_freeze": "R3",
    "jvm.method_delay": "R4",
    "jvm.return_value_mutation": "R4",
    "jvm.allocation_pressure": "R4",
    "jvm.gc_pressure": "R4",
    "jvm.thread_pressure": "R4",
    "io.write_delay": "R5a",
    "io.torn_write": "R5b",
}

NEW_IDS: tuple[str, ...] = tuple(COVERED_BY_CATALOG)

#: The human phrase each refusal must contain, keyed by the descriptor's own
#: ``MissingMechanism.mechanism``. Keying on the mechanism is the point: the
#: catalog text is checked against the domain declaration, so renaming a
#: mechanism in ``lowlevel.py`` fails here instead of quietly leaving a refusal
#: naming something mayhem no longer needs.
MECHANISM_PHRASE: dict[str, str] = {
    "ebpf_kprobe_loader": "ebpf kprobe loader",
    "ebpf_return_value_rewrite": "return-value rewrite",
    "fuse_delay_shim": "fuse delay shim",
    "device_mapper_delay_target": "device-mapper delay target",
}

#: Every catalog-only refusal must name something that has to be built or
#: provisioned. The bar is deliberately low and concrete: a mechanism class, a
#: device, a daemon, a capability row or a loader — any artefact whose absence is
#: the reason. "not supported", "coming soon" and "unimplemented" do not pass,
#: because a refusal that names nothing gives an operator nothing to file.
_ARTEFACTS = (
    "loader",
    "shim",
    "daemon",
    "target",
    "device",
    "agent",
    "injection",
    "hook",
    "preload",
    "instrumentation",
    "control plane",
    "capability-bit",
    "probe-bin",
)

#: A refused id may only cite faults that exist. ``test_refusal_points_at_a_fault_
#: that_exists`` in ``test_catalog_only_refusals.py`` enforces that catalog-wide;
#: the pattern is repeated here so a reader of *this* file sees the guarantee.
_DOTTED_REF = re.compile(r"\b([a-z]+\.[a-z_0-9]+)\b")

NON_K8S_ACTIVE_KINDS = frozenset(
    {
        NodeKind.SERVICE,
        NodeKind.CONTAINER,
        NodeKind.HOST,
        NodeKind.PROCESS,
        NodeKind.EXTERNAL_DEPENDENCY,
    }
)


def _refusal(fault_id: str) -> str:
    return definition_for(fault_id).refusal_reason or ""


def _missing(primitive_id: str) -> MissingMechanism:
    """The named missing mechanism, or a failure that says which id has none."""
    missing = descriptor_for(primitive_id).missing
    assert missing is not None, f"{primitive_id} declares no missing mechanism"
    return missing


def _blocked_primitives() -> set[str]:
    return {
        primitive.id
        for primitive in PRIMITIVES.values()
        if not primitive.substrate_verdict(CURRENT_SUBSTRATE)
    }


def _names_a_mechanism(reason: str) -> bool:
    """True when *reason* names a mechanism rather than merely declining."""
    if not reason.startswith("catalog.unsupported: "):
        return False
    body = reason.split(":", 1)[1].lower()
    return any(word in body for word in _ARTEFACTS)


def _topology_with_one_service() -> TopologyGraph:
    """A one-node graph, so the planner gets as far as the fault's own refusal.

    ``plan_drill`` validates container names against the topology *before* it
    compiles a fault, so an empty graph would fail on the container and never
    reach the refusal this file is about.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="svc-1", name="testcase-api", container_name="testcase-api"),
        ),
        edges=(),
    )


def _drill_spec(fault_id: str) -> DrillSpec:
    return DrillSpec(
        kind="drill",
        name="lowlevel-refusal",
        config=DrillConfig(),
        containers={
            "testcase-api": DrillContainer(
                faults=(DrillFault(fault=fault_id, duration="3s"),)
            )
        },
        execution=(ExecutionStep(parallel=("testcase-api",)),),
    )


# ── 1. the selection rule ───────────────────────────────────────────────────


class TestSelectionRule:
    def test_phase_one_found_exactly_eighteen_blocked_primitives(self) -> None:
        assert len(_blocked_primitives()) == 18

    def test_every_non_injectable_primitive_has_a_written_outcome(self) -> None:
        """The rule as an exhaustive statement, so a new primitive must be decided."""
        blocked = _blocked_primitives()
        accounted = {
            primitive_id
            for primitive_ids in COVERED_BY_CATALOG.values()
            for primitive_id in primitive_ids
        } | set(DESCRIPTOR_ONLY)
        assert blocked - accounted == set(), (
            "these blocked primitives have neither a refusal nor a written reason: "
            f"{sorted(blocked - accounted)}"
        )
        assert accounted - blocked == set(), (
            f"these outcomes name primitives that are not blocked: "
            f"{sorted(accounted - blocked)}"
        )

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_a_refusal_only_covers_primitives_sharing_one_mechanism(self, fault_id: str) -> None:
        """One refusal per mechanism — the property that keeps refusals from drifting."""
        mechanisms = {_missing(pid).mechanism for pid in COVERED_BY_CATALOG[fault_id]}
        assert len(mechanisms) == 1, (
            f"{fault_id} would carry {len(mechanisms)} different mechanisms' refusals: "
            f"{sorted(mechanisms)}"
        )

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_a_refusal_covers_only_primitives_that_cannot_be_injected(
        self, fault_id: str
    ) -> None:
        blocked = _blocked_primitives()
        for primitive_id in COVERED_BY_CATALOG[fault_id]:
            assert primitive_id in blocked

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_a_refusal_id_is_not_also_a_descriptor_id(self, fault_id: str) -> None:
        """A fault id and a primitive id in one place is one claim in two registries."""
        assert fault_id not in PRIMITIVES
        assert fault_id not in COVERED_BY_CATALOG[fault_id]

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_a_refusal_reuses_an_existing_category_under_a_registered_prefix(
        self, fault_id: str
    ) -> None:
        """No new ``FaultCategory`` and no new prefix."""
        definition = definition_for(fault_id)
        assert definition.category is FaultCategory.from_fault_id(fault_id)
        assert definition.category in frozenset(FaultCategory)

    def test_phase_one_is_still_untouched_by_phase_two(self) -> None:
        """Phase 2 adds refusals; it does not promote or edit a descriptor."""
        assert len(PRIMITIVES) == 22
        injectable = sorted(
            pid
            for pid, primitive in PRIMITIVES.items()
            if primitive.substrate_verdict(CURRENT_SUBSTRATE)
        )
        assert injectable == [
            "clock.realtime_offset",
            "io.capacity_exhaustion",
            "io.filesystem_read_only",
            "io.inode_exhaustion",
        ], "a refusal must not make a primitive injectable, nor the reverse"
        for primitive_ids in COVERED_BY_CATALOG.values():
            for primitive_id in primitive_ids:
                assert descriptor_for(primitive_id).existing_fault_id is None, (
                    f"{primitive_id} names an active fault, so it is not a refusal candidate"
                )


class TestDescriptorOnlyJustifications:
    """Each rule id must still be true, or the decision must be revisited."""

    @pytest.mark.parametrize(
        "primitive_id", [p for p, rule in DESCRIPTOR_ONLY.items() if rule == "R2"]
    )
    def test_r2_the_catalog_already_holds_the_authoritative_refusal(
        self, primitive_id: str
    ) -> None:
        anchor_id = _missing(primitive_id).anchor_fault_id
        assert anchor_id is not None, f"{primitive_id} lost its anchor"
        anchor = definition_for(anchor_id)
        assert anchor.catalog_only
        assert (anchor.refusal_reason or "").startswith("catalog.unsupported")
        assert anchor_id not in NEW_IDS, (
            f"{anchor_id} is the authoritative refusal for {primitive_id} and was "
            "duplicated by this phase"
        )

    @pytest.mark.parametrize(
        "primitive_id", [p for p, rule in DESCRIPTOR_ONLY.items() if rule == "R3"]
    )
    def test_r3_a_not_steppable_primitive_is_never_promotable(self, primitive_id: str) -> None:
        missing = _missing(primitive_id)
        assert missing.code.value == "not_steppable"
        assert missing.unachievable_substrate is True

    @pytest.mark.parametrize(
        "primitive_id", [p for p, rule in DESCRIPTOR_ONLY.items() if rule == "R4"]
    )
    def test_r4_the_family_prefix_is_not_a_registered_fault_prefix(
        self, primitive_id: str
    ) -> None:
        family = primitive_id.split(".", 1)[0]
        for candidate in (primitive_id, f"{family}.probe"):
            with pytest.raises(SchemaValidationError):
                FaultCategory.from_fault_id(candidate)

    def test_r5a_the_name_a_user_would_type_is_an_active_different_mechanism(self) -> None:
        occupant = definition_for("fs.write_delay")
        assert occupant.catalog_only is False
        assert template_for("fs.write_delay") is not None
        assert _missing("io.write_delay").mechanism == "fuse_delay_shim"
        assert _missing("io.read_delay").mechanism == "fuse_delay_shim", (
            "if these two mechanisms diverge, io.write_delay may deserve its own refusal"
        )

    def test_r5b_the_descriptor_risk_rung_has_no_catalog_row_for_its_scope(self) -> None:
        """A CRITICAL, container-scoped primitive cannot be published honestly."""
        torn = descriptor_for("io.torn_write")
        assert torn.risk is RiskLevel.CRITICAL
        assert torn.category is FaultCategory.STORAGE
        assert "fs.torn_write" not in {d.id for d in CATALOG}
        critical_scopes = [
            d.applicable_node_kinds for d in CATALOG if d.risk is RiskLevel.CRITICAL
        ]
        assert critical_scopes, "the catalog no longer has a CRITICAL rung to compare against"
        assert all(
            scopes <= frozenset({NodeKind.POD, NodeKind.K8S_NODE}) for scopes in critical_scopes
        ), (
            "the catalog reserves the critical rung for pod/node faults; io.torn_write is "
            "container-scoped, so publishing it would either understate the risk or "
            "misfile the scope"
        )


# ── 2. the five-registry contract ───────────────────────────────────────────


class TestFiveRegistryContract:
    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_1_catalog_definition_is_a_refusal_not_a_mechanism(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        assert definition.catalog_only is True
        assert definition.refusal_reason
        assert definition.maturity is MaturityLevel.EXPERIMENTAL
        assert definition.verification_date is None
        assert definition.params_schema == ()
        assert definition.failure_domain is not None
        assert definition.target_kinds
        assert definition.target_kind in definition.target_kinds
        assert definition.engine_lanes
        assert definition.verification_method is not None
        assert definition.reversibility is not None
        assert definition.observable_effect.strip()
        assert definition.compensation_evidence
        assert definition.max_duration_s > 0.0
        if definition.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            assert definition.max_duration_s <= 600.0

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_1b_required_caps_name_why_the_gate_cannot_evaluate_the_demand(
        self, fault_id: str
    ) -> None:
        """The catalog names the capability the mechanism would need, even unused."""
        assert definition_for(fault_id).required_caps

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_2_no_executor_routing_claims_the_fault(self, fault_id: str) -> None:
        assert fault_id not in _FAULT_EXECUTOR_OVERRIDES, (
            "a refusal must not gain an explicit executor override: that is how a "
            "refused fault starts looking routable"
        )
        definition = definition_for(fault_id)
        for engine in ("docker", "podman", "kubernetes"):
            assert execution_status(definition, engine) == "catalog-only"
            assert _executor_name(definition, engine) == "catalog.unsupported"

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_2b_prefix_dispatch_is_never_reached_for_a_refusal(self, fault_id: str) -> None:
        """``executor_for`` may resolve ``process.*`` by prefix; nothing routes there.

        Both routing-contract suites exclude ``catalog_only`` ids, so this is the
        only place that records *why* it is safe for a refused ``process.*`` id to
        sit under a prefix another executor owns.
        """
        assert definition_for(fault_id).catalog_only
        resolved = executor_for(fault_id)
        assert resolved is None or resolved.prefixes  # a registered class, never a refusal shim
        assert _executor_name(definition_for(fault_id), "docker") == "catalog.unsupported"

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_3_no_compensation_template_and_compensated_refuses_by_rule(
        self, fault_id: str
    ) -> None:
        assert template_for(fault_id) is None
        planned = PlannedFault(fault_id=fault_id, targets=(), duration=5.0, params={})
        with pytest.raises(InvariantViolationError) as excinfo:
            compensated(planned, ())
        assert excinfo.value.rule == "plan_uncompensated_fault"

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_4_impact_gate_has_no_requirements_row(self, fault_id: str) -> None:
        """A REQUIREMENTS row would gate a fault that has no tooling to probe."""
        assert fault_id not in impact.REQUIREMENTS
        assert fault_id not in impact._ENGINE_FAULTS

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_5_the_planner_refuses_with_the_refusal_text(self, fault_id: str) -> None:
        with pytest.raises(PlanningError) as excinfo:
            plan_drill(
                "run-lowlevel-refusal",
                _drill_spec(fault_id),
                _topology_with_one_service(),
                config_snapshot_id="cfg",
                topology_snapshot_id="topo",
                environment_fingerprint="fp",
            )
        assert _refusal(fault_id) in str(excinfo.value)

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_5b_the_explanation_surfaces_the_refusal(self, fault_id: str) -> None:
        for engine in ("docker", "podman"):
            explanation = explain_catalog_fault(fault_id, engine=engine)
            assert explanation["status"] == "catalog-only"
            assert explanation["executor"] == "catalog.unsupported"
            assert explanation["refusal"] == _refusal(fault_id)

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_5c_deriving_suites_derive_it_as_catalog_only(self, fault_id: str) -> None:
        """The derived sets the catalog-sweeping suites compute from ``CATALOG``."""
        derived_catalog_only = tuple(d.id for d in CATALOG if d.catalog_only)
        derived_active_non_k8s = tuple(
            d.id
            for d in CATALOG
            if d.applicable_node_kinds & NON_K8S_ACTIVE_KINDS and not d.catalog_only
        )
        derived_k8s_only = tuple(
            d.id for d in CATALOG if d.applicable_node_kinds <= {NodeKind.POD, NodeKind.K8S_NODE}
        )
        assert fault_id in derived_catalog_only
        assert fault_id not in derived_active_non_k8s, (
            "a refusal swept into the active non-k8s set would be held to an executor "
            "and a compensation template it cannot have"
        )
        assert fault_id not in derived_k8s_only

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_validate_catalog_accepts_the_new_entries(self, fault_id: str) -> None:
        validate_catalog((definition_for(fault_id),))
        validate_catalog(CATALOG)


# ── 3. the refusal names a real mechanism ───────────────────────────────────


class TestRefusalNamesAMechanism:
    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_refusal_names_the_descriptor_mechanism(self, fault_id: str) -> None:
        reason = _refusal(fault_id).lower()
        for primitive_id in COVERED_BY_CATALOG[fault_id]:
            mechanism = _missing(primitive_id).mechanism
            assert mechanism in MECHANISM_PHRASE, (
                f"{primitive_id} names mechanism {mechanism!r}, which this file has no "
                "phrase for; the refusal's wording is unverified"
            )
            assert MECHANISM_PHRASE[mechanism] in reason, (
                f"{fault_id} does not name {mechanism!r} — the refusal answering "
                f"{primitive_id} must name the mechanism that is missing"
            )

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_refusal_passes_the_names_a_mechanism_predicate(self, fault_id: str) -> None:
        assert _names_a_mechanism(_refusal(fault_id))

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_refusal_cites_only_faults_that_exist(self, fault_id: str) -> None:
        """A refusal naming a renamed or removed fault is worse than none."""
        cited = {
            ref
            for ref in _DOTTED_REF.findall(_refusal(fault_id))
            if ref != "catalog.unsupported"
        }
        assert cited, f"{fault_id} points at nothing, so a reader has no next step"
        for ref in cited:
            assert definition_for(ref).id == ref

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_refusal_offers_no_substitute_fault(self, fault_id: str) -> None:
        """The plan's rule: the refusal is the deliverable, not a weaker stand-in.

        The descriptor side already forbids a substitute by construction —
        ``MissingMechanism`` has no substitute field, only ``near_misses`` with a
        written reason each. This is the catalog half: the refusal's job is to
        name the mechanism and point at what exists, and the ids it points at are
        cited as *different* failures, never as equivalents.
        """
        cited = {
            ref
            for ref in _DOTTED_REF.findall(_refusal(fault_id))
            if ref != "catalog.unsupported"
        }
        assert not cited & set(COVERED_BY_CATALOG[fault_id]), (
            "a refusal must not point at another refusal as if it were usable"
        )
        for primitive_id in COVERED_BY_CATALOG[fault_id]:
            missing = _missing(primitive_id)
            assert missing.near_misses, f"{primitive_id} names no near miss to annotate"
            assert len(missing.why_no_substitute.split()) > 5, (
                "why_no_substitute has to say why the near misses are not the same fault"
            )


# ── 4. the impact-gate trap ─────────────────────────────────────────────────


class TestImpactGateTrap:
    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_gate_reports_the_refusal_as_inert_and_probed(self, fault_id: str) -> None:
        verdict = impact.gate_fault(fault_id, "some-container", "podman")
        assert verdict.probed is True
        assert verdict.impact_possible is False
        assert "catalog-only" in verdict.note

    def test_every_container_lane_catalog_only_id_is_in_the_gate_set(self) -> None:
        """The set, not just these four: the trap applies to every refusal."""
        uncovered = sorted(
            d.id
            for d in CATALOG
            if d.catalog_only
            and not d.id.startswith("k8s.")
            and d.id not in impact._CATALOG_ONLY_FAULTS
        )
        assert uncovered == [], (
            "these catalog-only ids would be reported impact-possible by gate_fault"
        )

    def test_negative_control_removing_an_id_makes_the_gate_claim_impact(self) -> None:
        """Observed, not assumed: without the table entry the gate contradicts itself."""
        fault_id = "process.syscall_error"
        assert fault_id in impact._CATALOG_ONLY_FAULTS
        original = impact._CATALOG_ONLY_FAULTS
        try:
            impact._CATALOG_ONLY_FAULTS = original - {fault_id}
            verdict = impact.gate_fault(fault_id, "some-container", "podman")
        finally:
            impact._CATALOG_ONLY_FAULTS = original
        assert verdict.probed is False
        assert verdict.impact_possible is True, (
            "this is the silent contradiction: a fault that cannot be injected is "
            "reported as able to take effect"
        )
        assert verdict.note == "no in-image tooling required"

    @pytest.mark.parametrize("fault_id", NEW_IDS)
    def test_scan_plan_gates_a_refusal_without_probing_a_container(
        self, fault_id: str
    ) -> None:
        plan = _plan_carrying_only(fault_id)
        verdicts, engine_probed = impact.scan_plan_faults(
            plan,  # type: ignore[arg-type] - see _plan_carrying_only
            TopologyGraph(nodes=(), edges=()),
            "podman",
        )
        assert engine_probed is False
        assert len(verdicts) == 1
        assert verdicts[0].fault_id == fault_id
        assert verdicts[0].impact_possible is False
        assert verdicts[0].probed is True


def _plan_carrying_only(fault_id: str) -> SimpleNamespace:
    """The smallest thing ``scan_plan_faults`` reads: ``plan.steps[*].fault``.

    A real ``ExecutionPlan`` cannot be built here — ``plan_drill`` refuses a
    ``catalog_only`` fault before it emits one, which is the point — and the plan
    constructor's own required fields are not what this test is about.
    """
    fault = PlannedFault(fault_id=fault_id, targets=(), duration=5.0, params={})
    return SimpleNamespace(steps=(SimpleNamespace(fault=fault),))


# ── 5. negative controls ────────────────────────────────────────────────────


class TestNegativeControls:
    def test_an_executable_entry_carrying_a_refusal_reason_is_refused(self) -> None:
        executable = CATALOG[0]
        assert executable.catalog_only is False
        forged = executable.model_copy(
            update={
                "catalog_only": False,
                "refusal_reason": "catalog.unsupported: not built yet",
            }
        )
        with pytest.raises(SchemaValidationError, match="executable entry cannot carry"):
            validate_catalog((forged,))

    def test_a_catalog_only_entry_without_a_refusal_reason_is_refused(self) -> None:
        forged = definition_for("fs.read_delay").model_copy(
            update={"catalog_only": True, "refusal_reason": None}
        )
        with pytest.raises(SchemaValidationError, match="requires refusal_reason"):
            validate_catalog((forged,))

    @pytest.mark.parametrize(
        "reason",
        (
            pytest.param("catalog.unsupported: this fault is not supported yet", id="no-artefact"),
            pytest.param("catalog.unsupported: see the roadmap", id="pointer-only"),
            pytest.param("this needs an ebpf kprobe loader", id="no-stable-refusal-code"),
        ),
    )
    def test_a_refusal_reason_naming_no_mechanism_is_refused(self, reason: str) -> None:
        assert not _names_a_mechanism(reason)

    def test_a_new_fault_category_cannot_be_constructed(self) -> None:
        """The three TOTAL maps are the reason Phase 1 added no category.

        ``_define`` indexes all three, so a ``FaultCategory`` missing from any one
        is an import-time ``KeyError`` that breaks ``import mayhem`` for the whole
        package. Two directions are shown: a category name no map knows, and a
        real category with one map's row removed.
        """
        with pytest.raises(KeyError):
            catalog_module._FAILURE_DOMAIN_BY_CATEGORY[cast("FaultCategory", "kernel")]
        with pytest.raises(KeyError):
            catalog_module._VERIFICATION_BY_CATEGORY[cast("FaultCategory", "kernel")]
        with pytest.raises(KeyError):
            catalog_module._EFFECT_BY_CATEGORY[cast("FaultCategory", "kernel")]

        effects = catalog_module._EFFECT_BY_CATEGORY
        saved = effects.pop(FaultCategory.K8S)
        try:
            with pytest.raises(KeyError):
                catalog_module._define(
                    id="k8s.probe",
                    category=FaultCategory.K8S,
                    risk=RiskLevel.LOW,
                    applicable_node_kinds=frozenset({NodeKind.POD}),
                    max_duration_s=60.0,
                    params_schema=(),
                )
        finally:
            effects[FaultCategory.K8S] = saved

    def test_all_three_category_maps_cover_every_category_today(self) -> None:
        assert set(catalog_module._FAILURE_DOMAIN_BY_CATEGORY) == set(FaultCategory)
        assert set(catalog_module._VERIFICATION_BY_CATEGORY) == set(FaultCategory)
        assert set(catalog_module._EFFECT_BY_CATEGORY) == set(FaultCategory)

    def test_a_descriptor_may_not_claim_a_category_outside_its_family(self) -> None:
        """The Phase 1 guard, restated: category reuse is enforced, not documented."""
        primitive = descriptor_for("clock.realtime_freeze")
        forged = {**primitive.model_dump(), "category": FaultCategory.STORAGE}
        with pytest.raises(ValidationError, match="primitives reuse category"):
            ClockPrimitive.model_validate(forged)
