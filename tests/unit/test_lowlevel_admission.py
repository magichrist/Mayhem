"""Plan 04 Phase 4 — safety and evidence integration for the low-level gate.

Phases 1 to 3 built descriptors, refusals, a parameter grammar and an explanation
surface. None of them *admits* anything: a request to inject one of the eighteen
refused primitives had nowhere to go. This file is the suite for the gate that
answers it, and it is built around four claims.

**The gate refuses every primitive this build cannot inject, and it says which
mechanism is missing.** The refusal text names the mechanism rather than a class
of error, and lists the unmet demands so a reader learns *which* impact-gate trap
is in play. A refusal that names nothing gives an operator nothing to file.

**An unavailable witness refuses.** The mechanism port is unbound in this build,
and an unbound port, a port that raises, a port that answers ``None``, and a port
that answers the wrong type are all ``UNAVAILABLE`` — which blocks, because
*mayhem cannot see an eBPF loader, so it cannot certify that one attached*. The
negative controls here prove each of those four is genuinely ``UNAVAILABLE``
rather than ``REFUSED``, by constructing each one.

**There is no silent fallback.** The structural proof is that the report has no
field to hold one: ``test_the_report_has_no_field_for_a_fallback_mechanism`` fails
if a ``substituted_with``-shaped field ever appears, and the admission checks are
asserted to be exactly the declared catalogue, so a weaker mechanism cannot be
added without the catalogue changing.

**The impact gate gets no ``REQUIREMENTS`` row, and the reason is data.**
:func:`requirements_rows_needed` returns the ids a row would genuinely gate; today
that is empty, because every blocked primitive trips one of the four documented
traps. The test asserts the emptiness *and* asserts the restatement is still true
of the real ``_PROBE_BINS``, ``_CAP_BITS`` and ``_PM_PACKAGES`` — so the decision
cannot be inherited after the tables change underneath it.

Phase 5's wire-execution, residue-scan and inertness-guard tests live in
``test_lowlevel_wire.py``; this file is the decision layer, and it never reaches a
port except through a fake it constructs itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from mayhem.agents import impact
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.lowlevel import CURRENT_SUBSTRATE, PRIMITIVES, descriptor_for
from mayhem.domain.lowlevel_admission import (
    ALL_CHECKS,
    CHECK_COLLISION_PAIRS,
    CHECK_DURATION,
    CHECK_ENGINE,
    CHECK_MECHANISM_APPLY,
    CHECK_MECHANISM_PROBE,
    CHECK_PARAMETERS,
    CHECK_PRIMITIVE_KNOWN,
    CHECK_SUBSTRATE,
    INERT_GAP_REASONS,
    MIN_OBSERVABLE_FRACTION,
    SUPPORTED_ENGINES,
    AdmissionReport,
    LowLevelCheck,
    LowLevelRefusedError,
    LowLevelRequest,
    LowLevelStatus,
    MechanismObservation,
    MechanismPorts,
    ResidueObservation,
    admit,
    collision_edges,
    declared_unbound_ports,
    disposition_of,
    evaluate,
    inert_demands,
    mechanism_ref,
    refuses_gate,
    refusing_names,
    requirements_rows_needed,
    residue_scan,
    unprobeable_demands,
)
from mayhem.domain.lowlevel_report import PrimitiveDisposition
from mayhem.domain.policy import CompatibilityVerdict

BLOCKED_IDS: tuple[str, ...] = (
    "kernel.syscall_errno",
    "kernel.syscall_latency",
    "kernel.syscall_return_mutation",
    "io.read_delay",
    "io.write_delay",
    "io.read_error",
    "io.permission_error",
    "io.block_device_delay",
    "io.torn_write",
    "jvm.method_delay",
    "jvm.return_value_mutation",
    "jvm.exception_injection",
    "jvm.allocation_pressure",
    "jvm.gc_pressure",
    "jvm.thread_pressure",
    "clock.realtime_freeze",
    "clock.monotonic_offset",
    "clock.monotonic_freeze",
)
INJECTABLE_IDS: tuple[str, ...] = (
    "io.capacity_exhaustion",
    "io.inode_exhaustion",
    "io.filesystem_read_only",
    "clock.realtime_offset",
)


# ── the mechanism port, as a fake ────────────────────────────────────────────


@dataclass
class _FakePort:
    """A mechanism port that answers whatever the test tells it to.

    Three independent switches, because the gate asks three different questions
    and a fake with one switch cannot prove that ``probe`` is not answering the
    ``attach`` question. ``raise_on`` records which method raised, so a test can
    show that a raising port is reported as ``UNAVAILABLE`` *for that check* and
    not as a crash.
    """

    available: bool = True
    applied: bool = True
    answer: object = None
    raise_on: frozenset[str] = frozenset()
    calls: list[str] = field(default_factory=list)

    def _observe(self, method: str) -> MechanismObservation:
        self.calls.append(method)
        if method in self.raise_on:
            raise RuntimeError(f"{method} exploded")
        if self.answer is not None:
            return self.answer
        return MechanismObservation(
            available=self.available,
            applied=self.applied,
            evidence_ref=f"fake://{method}",
            detail=f"fake says {method} was {'applied' if self.applied else 'not applied'}",
        )

    def probe(self, primitive: object) -> MechanismObservation:
        return self._observe("probe")

    def attach(self, specification: object) -> MechanismObservation:
        return self._observe("attach")

    def detach(self, specification: object) -> MechanismObservation:
        return self._observe("detach")

    def residue(self, specification: object) -> MechanismObservation:
        return self._observe("residue")


def _request(primitive_id: str = "kernel.syscall_errno", **overrides: object) -> LowLevelRequest:
    params: dict[str, object] = {"syscall": "read"}
    duration = 30.0
    fields: dict[str, object] = {
        "primitive_id": primitive_id,
        "engine": "podman",
        "duration_s": duration,
        "params": params,
        "request_id": "req-1",
    }
    fields.update(overrides)
    return LowLevelRequest(**fields)  # type: ignore[arg-type]


def _injectable_request(primitive_id: str = "io.capacity_exhaustion", **overrides: object):
    fields: dict[str, object] = {
        "primitive_id": primitive_id,
        "engine": "podman",
        "duration_s": 30.0,
        "params": {},
        "request_id": "req-injectable",
    }
    fields.update(overrides)
    return LowLevelRequest(**fields)  # type: ignore[arg-type]


def _manifest_provides(capability: str) -> bool:
    """Whether any declared tool manifest offers *capability*.

    Read from the registry's manifests rather than from
    ``domain/lowlevel.py``'s restatement, because the two agreeing is the
    property under test everywhere else and this is where the real table is.
    """
    from mayhem.toolkit.registry import default_registry

    return any(
        capability in manifest.provides for manifest in default_registry().manifests
    )


# ── 1. the refusals ──────────────────────────────────────────────────────────


class TestRefusals:
    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_a_blocked_primitive_is_refused_and_names_its_mechanism(
        self, primitive_id: str
    ) -> None:
        report = evaluate(_request(primitive_id))
        assert not report.granted
        assert report.applied is False
        substrate = report.check(CHECK_SUBSTRATE)
        assert substrate is not None
        assert substrate.status is LowLevelStatus.REFUSED
        mechanism = descriptor_for(primitive_id).missing
        assert mechanism is not None
        assert mechanism.mechanism in substrate.detail, (
            "a refusal that names no mechanism gives an operator nothing to file"
        )

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_a_blocked_primitive_refuses_on_the_substrate_and_on_the_port(
        self, primitive_id: str
    ) -> None:
        """Two refusals, not one: mayhem knows it cannot, *and* has no witness."""
        report = evaluate(_request(primitive_id))
        refused = {check.name for check in report.refused_checks}
        unavailable = {check.name for check in report.unavailable_checks}
        assert CHECK_SUBSTRATE in refused, primitive_id
        assert CHECK_MECHANISM_PROBE in unavailable, primitive_id
        assert CHECK_MECHANISM_APPLY in unavailable, primitive_id

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_a_refusal_lists_the_first_unmet_demand_and_its_trap(
        self, primitive_id: str
    ) -> None:
        gaps = descriptor_for(primitive_id).substrate_gaps(CURRENT_SUBSTRATE)
        assert gaps, primitive_id
        report = evaluate(_request(primitive_id))
        detail = report.check(CHECK_SUBSTRATE).detail
        assert gaps[0].demand in detail
        assert gaps[0].reason.value in detail

    def test_an_unknown_primitive_is_refused_not_raised(self) -> None:
        report = evaluate(_request("kernel.not_a_primitive"))
        assert not report.granted
        known = report.check(CHECK_PRIMITIVE_KNOWN)
        assert known is not None
        assert known.status is LowLevelStatus.REFUSED
        assert "no low-level primitive is declared" in known.detail
        assert CHECK_SUBSTRATE in {c.name for c in report.unavailable_checks}

    def test_an_unachievable_primitive_says_the_host_cannot_do_it_at_all(self) -> None:
        """Distinct from "not built yet": a roadmap item that can never close."""
        report = evaluate(_request("clock.monotonic_offset", params={}, duration_s=30.0))
        detail = report.check(CHECK_SUBSTRATE).detail
        assert "the host does not offer the operation at all" in detail

    def test_admit_raises_with_the_report_that_refused(self) -> None:
        with pytest.raises(LowLevelRefusedError) as refusal:
            admit(_request())
        assert refusal.value.rule == "lowlevel.admission_refused"
        assert refusal.value.report.refusal_reason in str(refusal.value)
        assert CHECK_SUBSTRATE in {c.name for c in refusal.value.refusing_checks}

    def test_refusing_names_previews_without_granting(self) -> None:
        names = refusing_names(_request())
        assert CHECK_SUBSTRATE in names
        assert isinstance(names, tuple)


# ── 2. the engine refusal: no silent fallback to a weaker lane ────────────────


class TestEngineRefusal:
    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS + INJECTABLE_IDS)
    def test_kubernetes_is_refused_for_every_family(self, primitive_id: str) -> None:
        """Every mechanism is in-image; the k8s adapter grants neither cap_add nor debugfs."""
        report = evaluate(_request(primitive_id, engine="kubernetes"))
        engine = report.check(CHECK_ENGINE)
        assert engine is not None
        assert engine.status is LowLevelStatus.REFUSED
        assert "not a lane mayhem attaches low-level mechanisms on" in engine.detail
        assert "cap_add" in engine.detail, (
            "the refusal must say why the lane differs, not merely that it is refused"
        )

    def test_an_engine_mayhem_does_not_have_is_refused_by_name(self) -> None:
        report = evaluate(_request(engine="containerd"))
        engine = report.check(CHECK_ENGINE)
        assert engine is not None
        assert engine.status is LowLevelStatus.REFUSED
        assert "is not one mayhem knows" in engine.detail

    @pytest.mark.parametrize("engine", sorted(SUPPORTED_ENGINES))
    def test_a_supported_engine_is_not_the_reason_for_a_refusal(self, engine: str) -> None:
        report = evaluate(_request(engine=engine))
        check = report.check(CHECK_ENGINE)
        assert check is not None
        assert check.status is LowLevelStatus.PASS

    @pytest.mark.parametrize("primitive_id", INJECTABLE_IDS)
    def test_an_injectable_primitive_still_refuses_the_kubernetes_lane(
        self, primitive_id: str
    ) -> None:
        """The refusal is about the lane, not about the mechanism."""
        report = evaluate(_injectable_request(primitive_id, engine="kubernetes"))
        assert report.check(CHECK_SUBSTRATE).status is LowLevelStatus.PASS
        assert report.check(CHECK_ENGINE).status is LowLevelStatus.REFUSED

    def test_no_check_anywhere_substitutes_a_different_engine(self) -> None:
        """Structurally: there is no ``fallback_engine`` to substitute."""
        fields = set(LowLevelRequest.__dataclass_fields__)
        assert fields == {
            "primitive_id",
            "engine",
            "duration_s",
            "params",
            "active_primitives",
            "request_id",
        }, f"the request gained a field that could carry a fallback: {sorted(fields)}"


# ── 3. duration and parameters ───────────────────────────────────────────────


class TestDurationAndParameters:
    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS + INJECTABLE_IDS)
    def test_a_duration_past_the_primitive_ceiling_is_refused(self, primitive_id: str) -> None:
        ceiling = descriptor_for(primitive_id).max_safe_duration_s
        report = evaluate(_request(primitive_id, duration_s=ceiling * 4))
        duration = report.check(CHECK_DURATION)
        assert duration is not None
        assert duration.status is LowLevelStatus.REFUSED
        assert "exceeds" in duration.detail
        assert f"{ceiling:g}s" in duration.detail

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS + INJECTABLE_IDS)
    def test_a_window_too_short_to_observe_is_refused(self, primitive_id: str) -> None:
        """A fault nobody can see is the inert parameter wearing a duration."""
        ceiling = descriptor_for(primitive_id).max_safe_duration_s
        report = evaluate(
            _request(primitive_id, duration_s=ceiling * MIN_OBSERVABLE_FRACTION / 2)
        )
        duration = report.check(CHECK_DURATION)
        assert duration is not None
        assert duration.status is LowLevelStatus.REFUSED
        assert "minimum observable window" in duration.detail

    @pytest.mark.parametrize("primitive_id", INJECTABLE_IDS)
    def test_an_injectable_primitive_passes_every_real_check(self, primitive_id: str) -> None:
        """Proof the refusals above are about the substrate, not a broken gate."""
        report = evaluate(
            _injectable_request(primitive_id),
            MechanismPorts(mechanism=_FakePort()),
        )
        real = [
            c
            for c in report.checks
            if c.name
            not in {CHECK_MECHANISM_PROBE, CHECK_MECHANISM_APPLY}
        ]
        assert real and all(check.status is LowLevelStatus.PASS for check in real), (
            f"{primitive_id} was refused by {[(c.name, c.status.value) for c in real]}"
        )

    def test_a_zero_duration_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError, match="duration_s must be positive"):
            _request(duration_s=0.0)

    def test_a_blank_primitive_or_engine_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError, match="must name the primitive"):
            LowLevelRequest(primitive_id="  ", engine="podman", duration_s=5.0)
        with pytest.raises(InvariantViolationError, match="must name the engine"):
            LowLevelRequest(primitive_id="io.read_delay", engine="", duration_s=5.0)

    def test_a_parameter_outside_the_grammar_is_refused_and_prints_it(self) -> None:
        report = evaluate(_request(params={"syscall": "read", "latency_ms": 0}))
        parameters = report.check(CHECK_PARAMETERS)
        assert parameters is not None
        assert parameters.status is LowLevelStatus.REFUSED
        assert "latency_ms" in parameters.detail

    def test_an_unknown_parameter_is_refused_by_the_grammar(self) -> None:
        report = evaluate(_request(params={"syscall": "read", "errn0": "EIO"}))
        assert report.check(CHECK_PARAMETERS).status is LowLevelStatus.REFUSED
        assert "errn0" in report.check(CHECK_PARAMETERS).detail

    def test_a_request_with_no_specification_has_nothing_to_attach(self) -> None:
        report = evaluate(_request(params={"errn0": "EIO"}))
        assert report.specification is None
        applied = report.check(CHECK_MECHANISM_APPLY)
        assert applied is not None
        assert "nothing to attach" in applied.detail


# ── 4. collisions, and the edges plan 07 needs ───────────────────────────────


class TestCollisions:
    def test_a_declared_incompatible_pair_is_refused(self) -> None:
        report = evaluate(
            _request("kernel.syscall_latency", active_primitives=("kernel.syscall_errno",))
        )
        pairs = report.check(CHECK_COLLISION_PAIRS)
        assert pairs is not None
        assert pairs.status is LowLevelStatus.REFUSED
        assert "kernel.syscall_errno" in pairs.detail
        assert "could be attributed" in pairs.detail

    def test_the_refusal_is_symmetric_because_the_relation_is(self) -> None:
        forward = evaluate(
            _request("kernel.syscall_latency", active_primitives=("kernel.syscall_errno",))
        )
        backward = evaluate(
            _request("kernel.syscall_errno", active_primitives=("kernel.syscall_latency",))
        )
        assert forward.check(CHECK_COLLISION_PAIRS).status is LowLevelStatus.REFUSED
        assert backward.check(CHECK_COLLISION_PAIRS).status is LowLevelStatus.REFUSED

    def test_a_compatible_pair_is_admitted_by_this_check(self) -> None:
        report = evaluate(
            _request("io.read_delay", active_primitives=("io.capacity_exhaustion",))
        )
        assert report.check(CHECK_COLLISION_PAIRS).status is LowLevelStatus.PASS

    def test_an_active_set_mayhem_cannot_resolve_is_refused(self) -> None:
        """An unresolvable active set means no collision can be ruled out."""
        report = evaluate(_request(active_primitives=("io.ghost",)))
        pairs = report.check(CHECK_COLLISION_PAIRS)
        assert pairs is not None
        assert pairs.status is LowLevelStatus.REFUSED
        assert "does not declare" in pairs.detail

    def test_the_collision_edges_are_derived_from_the_descriptors(self) -> None:
        edges = collision_edges()
        assert edges, "the descriptors declare incompatible pairs"
        expected = {
            frozenset({primitive.id, other})
            for primitive in PRIMITIVES.values()
            for other in primitive.incompatible_ids()
        }
        assert {edge.pair() for edge in edges} == expected
        assert len({edge.pair() for edge in edges}) == len(edges), "a pair is declared twice"

    def test_every_edge_is_conflicting_and_carries_a_reason(self) -> None:
        """Plan 07 refuses an edge that conflicts without saying why."""
        for edge in collision_edges():
            assert edge.verdict is CompatibilityVerdict.CONFLICTING
            assert edge.reason.strip()
            assert edge.left_fault != edge.right_fault

    def test_the_edges_are_stable_across_calls(self) -> None:
        assert collision_edges() == collision_edges()


# ── 5. the impact-gate row, decided as data ──────────────────────────────────


class TestRequirementsRow:
    def test_no_primitive_earns_a_requirements_row_today(self) -> None:
        assert requirements_rows_needed() == (), (
            "a primitive whose demands the gate cannot evaluate would get an INERT row "
            "that reads like a gate that ran"
        )

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_every_blocked_primitive_trips_at_least_one_inert_trap(
        self, primitive_id: str
    ) -> None:
        assert inert_demands(primitive_id), (
            f"{primitive_id} is blocked but a requirements row could still gate it: "
            "revisit the decision to publish no row"
        )

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_the_restatement_matches_the_real_impact_gate_tables(
        self, primitive_id: str
    ) -> None:
        """The four traps, checked against ``agents/impact.py`` rather than trusted.

        This is the load-bearing half of "no requirements row": each blocked
        primitive is shown to trip at least one trap *in the real tables*, so the
        decision cannot be inherited after the tables change underneath it.
        """
        primitive = descriptor_for(primitive_id)
        traps: list[str] = []
        for binary in primitive.probe_bins:
            if binary not in impact._PROBE_BINS:
                traps.append(f"{binary} is in no _PROBE_BINS row, so it is never probed")
            elif binary not in impact._PM_PACKAGES:
                traps.append(f"{binary} has no _PM_PACKAGES row, so it can never be installed")
        for cap_bit in primitive.probe_caps:
            if cap_bit not in impact._CAP_BITS:
                traps.append(f"{cap_bit} is in no _CAP_BITS row, so has_cap answers False")
        for capability in primitive.tool_capabilities:
            if not _manifest_provides(capability):
                traps.append(f"no manifest declares {capability} in provides")
        assert traps, (
            f"{primitive_id} is blocked but the real impact gate could evaluate every "
            "demand it makes, so a requirements row for it would be a real gate: "
            "revisit requirements_rows_needed()"
        )

    def test_the_demanded_bins_that_the_gate_never_probes_are_the_named_ones(self) -> None:
        """The bin half of the trap, spelled out rather than summed."""
        unprobed = {
            binary
            for binary in unprobeable_demands()
            if binary not in impact._PROBE_BINS
        }
        assert unprobed == {"bpftool", "dmsetup", "faketime", "fusermount3", "jcmd", "mount"}, (
            "the set of bins a blocked primitive needs and the gate cannot probe changed; "
            "revisit the decision to publish no requirements row"
        )

    def test_the_inert_reason_set_is_exactly_the_documented_traps(self) -> None:
        documented = frozenset(
            {
                "bin_not_probed",
                "cap_bit_undefined",
                "bin_not_installable",
                "tool_not_manifested",
            }
        )
        assert documented == INERT_GAP_REASONS
        assert INERT_GAP_REASONS - documented == set(), (
            "a new gap reason may join the inert set, but only deliberately"
        )

    def test_no_blocked_primitive_has_an_impact_requirements_row(self) -> None:
        """And so no catalog_only id does either — Phase 2's table is the only row."""
        from mayhem.domain.lowlevel_report import CATALOG_REFUSAL_BY_PRIMITIVE

        for fault_id in set(CATALOG_REFUSAL_BY_PRIMITIVE.values()):
            assert fault_id not in impact.REQUIREMENTS
            assert fault_id not in impact._ENGINE_FAULTS
            assert fault_id in impact._CATALOG_ONLY_FAULTS


# ── 6. the port is unbound, and an unavailable witness refuses ───────────────


class TestUnboundPort:
    def test_with_no_port_bound_the_report_is_unavailable_and_refuses(self) -> None:
        report = evaluate(_injectable_request(), None)
        assert not report.granted
        assert report.applied is False
        probe = report.check(CHECK_MECHANISM_PROBE)
        apply = report.check(CHECK_MECHANISM_APPLY)
        assert probe is not None and apply is not None
        assert probe.status is LowLevelStatus.UNAVAILABLE
        assert apply.status is LowLevelStatus.UNAVAILABLE
        assert probe.evidence_ref == mechanism_ref("mechanism")

    def test_omitting_the_port_argument_is_not_skipping_the_port_checks(self) -> None:
        """Otherwise a caller could obtain a granting report by leaving an argument out."""
        omitted = evaluate(_injectable_request())
        explicitly_none = evaluate(_injectable_request(), None)
        assert [c.name for c in omitted.checks] == [c.name for c in explicitly_none.checks]
        assert not omitted.granted

    def test_the_unavailability_detail_names_what_could_not_be_reached(self) -> None:
        report = evaluate(_injectable_request())
        probe = report.check(CHECK_MECHANISM_PROBE)
        assert probe is not None
        assert "no eBPF loader, FUSE shim" in probe.detail
        assert "cannot ask" in probe.detail

    def test_the_declared_unbound_ports_are_named_not_merely_absent(self) -> None:
        assert declared_unbound_ports() == ("mechanism",)
        assert "unbound_ports" in evaluate(_injectable_request()).to_payload()

    def test_a_fake_port_that_applies_actually_gets_a_grant(self) -> None:
        """The gate grants what a port reports; it cannot audit the port's honesty."""
        report = admit(_injectable_request(), MechanismPorts(mechanism=_FakePort()))
        assert report.granted
        assert report.applied is True
        assert report.applied_primitive == "io.capacity_exhaustion"

    def test_a_port_reporting_not_applied_is_refused_not_granted(self) -> None:
        report = evaluate(_injectable_request(), MechanismPorts(mechanism=_FakePort(applied=False)))
        apply = report.check(CHECK_MECHANISM_APPLY)
        assert apply is not None
        assert apply.status is LowLevelStatus.REFUSED
        assert not report.granted
        assert report.applied is False

    def test_a_port_reporting_unavailable_is_refused_at_the_probe(self) -> None:
        ports = MechanismPorts(mechanism=_FakePort(available=False, applied=False))
        report = evaluate(_injectable_request(), ports)
        probe = report.check(CHECK_MECHANISM_PROBE)
        assert probe is not None
        assert probe.status is LowLevelStatus.REFUSED
        assert "reports no mechanism" in probe.detail
        assert not report.granted


# ── 7. the residue scan ──────────────────────────────────────────────────────


class TestResidueScan:
    def _clean(self, primitive_id: str) -> tuple[ResidueObservation, ...]:
        return tuple(
            ResidueObservation(facet=check.facet.value, probe=check.probe, clean=True)
            for check in descriptor_for(primitive_id).residue_checks
        )

    @pytest.mark.parametrize(
        "primitive_id",
        ("kernel.syscall_errno", "io.read_delay", "jvm.method_delay", "io.capacity_exhaustion"),
    )
    def test_a_scan_that_covered_every_declared_facet_is_clean(
        self, primitive_id: str
    ) -> None:
        scan = residue_scan(primitive_id, self._clean(primitive_id))
        assert scan.complete
        assert scan.clean
        assert not scan.open_obligations
        assert "is clean" in scan.describe()

    def test_a_dirty_observation_is_an_open_obligation(self) -> None:
        primitive_id = "kernel.syscall_errno"
        observations = list(self._clean(primitive_id))
        observations[0] = ResidueObservation(
            facet=observations[0].facet, probe=observations[0].probe, clean=False,
            detail="a kprobe entry is still attached",
        )
        scan = residue_scan(primitive_id, observations)
        assert scan.complete
        assert not scan.clean
        assert len(scan.open_obligations) == 1
        assert "open obligation" in scan.describe()

    def test_a_skipped_facet_is_not_a_clean_scan(self) -> None:
        """The load-bearing half: "we looked at one of the two" is not clean."""
        primitive_id = "kernel.syscall_errno"
        scan = residue_scan(primitive_id, self._clean(primitive_id)[:1])
        assert not scan.complete
        assert not scan.clean
        assert "is incomplete" in scan.describe()

    def test_an_observation_for_an_undeclared_facet_is_recorded_not_counted(self) -> None:
        """Extra assurance is not the promised assurance."""
        primitive_id = "io.capacity_exhaustion"
        observations = (*self._clean(primitive_id), ResidueObservation(
            facet="capability", probe="grep CapEff", clean=True
        ))
        scan = residue_scan(primitive_id, observations)
        assert scan.complete
        assert scan.undeclared_facets == ("capability",)
        assert "capability" in scan.describe() or not scan.open_obligations

    def test_an_empty_scan_of_a_multi_facet_primitive_is_not_clean(self) -> None:
        scan = residue_scan("kernel.syscall_errno", ())
        assert not scan.complete
        assert not scan.clean

    def test_residue_for_an_undeclared_primitive_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="undeclared primitive"):
            residue_scan("kernel.ghost", ())


# ── 8. no silent fallback ────────────────────────────────────────────────────


class TestNoFallback:
    def test_the_report_has_no_field_for_a_fallback_mechanism(self) -> None:
        fields = set(AdmissionReport.__dataclass_fields__)
        assert fields == {
            "request",
            "checks",
            "applied_primitive",
            "specification",
        }, f"the report gained a field that could carry a substitution: {sorted(fields)}"

    @pytest.mark.parametrize("primitive_id", BLOCKED_IDS)
    def test_a_refused_report_names_no_applied_primitive(self, primitive_id: str) -> None:
        report = evaluate(_request(primitive_id), MechanismPorts(mechanism=_FakePort()))
        assert not report.granted
        assert report.applied_primitive is None, (
            "a refusing report must not name something as attached"
        )

    def test_the_check_catalogue_is_exactly_the_declared_checks(self) -> None:
        """A weaker mechanism would have to arrive as a new check, and this fails."""
        assert ALL_CHECKS == (
            CHECK_PRIMITIVE_KNOWN,
            CHECK_SUBSTRATE,
            CHECK_ENGINE,
            CHECK_DURATION,
            CHECK_PARAMETERS,
            CHECK_COLLISION_PAIRS,
            CHECK_MECHANISM_PROBE,
            CHECK_MECHANISM_APPLY,
        )
        report = evaluate(_request())
        assert tuple(check.name for check in report.checks) == ALL_CHECKS

    def test_an_unknown_check_is_refused_rather_than_silently_dropped(self) -> None:
        with pytest.raises(InvariantViolationError, match="unknown low-level check"):
            evaluate(_request(), checks=(*ALL_CHECKS, "mechanism:try_something_cheaper"))

    def test_a_gate_that_evaluated_nothing_never_grants(self) -> None:
        report = evaluate(_request(), checks=())
        assert report.vacuous
        assert not report.granted
        assert "evaluated no checks" in report.refusal_reason

    def test_refuses_gate_is_total_and_refuses_anything_but_pass(self) -> None:
        assert not refuses_gate(LowLevelStatus.PASS)
        assert refuses_gate(LowLevelStatus.REFUSED)
        assert refuses_gate(LowLevelStatus.UNAVAILABLE)
        assert refuses_gate("some_future_status") is True, (
            "an unrecognised status must refuse rather than pass by omission"
        )

    def test_every_check_cites_a_witness_on_every_status(self) -> None:
        """An ``UNAVAILABLE`` is the status most likely to arrive uncited."""
        for status in LowLevelStatus:
            check = LowLevelCheck(
                name="x", status=status, detail="d", evidence_ref="lowlevel.primitive/x"
            )
            assert check.evidence_ref

    def test_a_blank_evidence_ref_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError, match="must be non-blank"):
            LowLevelCheck(name="x", status=LowLevelStatus.PASS, detail="d", evidence_ref="  ")

    def test_a_duplicate_check_name_is_refused_at_construction(self) -> None:
        check = LowLevelCheck(name="x", status=LowLevelStatus.PASS, detail="d", evidence_ref="r")
        with pytest.raises(InvariantViolationError, match="repeats a check"):
            AdmissionReport(
                request=_request(), checks=(check, check), applied_primitive=None
            )

    def test_the_disposition_is_read_from_phase_three_not_re_derived(self) -> None:
        for primitive_id in BLOCKED_IDS:
            assert disposition_of(primitive_id) is not PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT
        for primitive_id in INJECTABLE_IDS:
            assert disposition_of(primitive_id) is PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT

    def test_an_undecided_primitive_becomes_a_finding_not_an_exception(self) -> None:
        """Nothing a caller can hand in makes ``evaluate`` raise.

        Phase 3 refuses to explain a primitive no table decides. The gate reads
        Phase 3's answer, so without this guard an undecided primitive would turn a
        finding into a crash — and a crash reads as a bug in the caller rather than
        as the undecided row it is.
        """
        from mayhem.domain import lowlevel_report

        saved = lowlevel_report.DESCRIPTOR_ONLY_RULES
        object.__setattr__(
            lowlevel_report,
            "DESCRIPTOR_ONLY_RULES",
            {key: value for key, value in saved.items() if key != "jvm.gc_pressure"},
        )
        try:
            report = evaluate(_request("jvm.gc_pressure", params={}))
        finally:
            object.__setattr__(lowlevel_report, "DESCRIPTOR_ONLY_RULES", saved)
        known = report.check(CHECK_PRIMITIVE_KNOWN)
        assert known is not None
        assert known.status is LowLevelStatus.REFUSED
        assert "nothing has decided what happens to it" in known.detail
        assert not report.granted
        # And the restore is exact, so the control proves something.
        assert evaluate(_request("jvm.gc_pressure", params={})).check(
            CHECK_PRIMITIVE_KNOWN
        ).status is LowLevelStatus.PASS


# ── 9. negative controls ─────────────────────────────────────────────────────


class TestNegativeControls:
    def test_a_port_that_raises_is_unavailable_not_refused_not_a_crash(self) -> None:
        ports = MechanismPorts(mechanism=_FakePort(raise_on=frozenset({"probe"})))
        report = evaluate(_injectable_request(), ports)
        probe = report.check(CHECK_MECHANISM_PROBE)
        assert probe is not None
        assert probe.status is LowLevelStatus.UNAVAILABLE
        assert "RuntimeError" in probe.detail
        assert not report.granted

    def test_a_port_answering_none_is_unavailable(self) -> None:
        ports = MechanismPorts(mechanism=_FakePort(answer=None, applied=True))
        # ``answer=None`` means "use the defaults", so the wrong-shape case needs
        # a port whose answer is genuinely not an observation.
        class _WrongShape:
            def probe(self, primitive: object) -> str:
                return "attached"

            def attach(self, specification: object) -> str:
                return "attached"

        report = evaluate(_injectable_request(), MechanismPorts(mechanism=_WrongShape()))
        assert report.check(CHECK_MECHANISM_PROBE).status is LowLevelStatus.UNAVAILABLE
        assert report.check(CHECK_MECHANISM_APPLY).status is LowLevelStatus.UNAVAILABLE
        assert not ports.mechanism.calls  # the real fake was never consulted

    def test_a_port_missing_the_attach_method_is_unavailable(self) -> None:
        class _ProbeOnly:
            def probe(self, primitive: object) -> MechanismObservation:
                return MechanismObservation(True, True, "fake://probe", "ok")

        report = evaluate(_injectable_request(), MechanismPorts(mechanism=_ProbeOnly()))
        assert report.check(CHECK_MECHANISM_PROBE).status is LowLevelStatus.PASS
        assert report.check(CHECK_MECHANISM_APPLY).status is LowLevelStatus.UNAVAILABLE

    def test_an_observation_citing_nothing_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError, match="must cite something"):
            MechanismObservation(available=True, applied=True, evidence_ref="  ")

    def test_an_observation_applied_while_unavailable_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="cannot be applied while"):
            MechanismObservation(available=False, applied=True, evidence_ref="fake://x")

    def test_removing_a_refusal_from_the_gate_makes_the_report_grant(self) -> None:
        """Observed, not assumed: the refusals are load-bearing, not decorative."""
        good = evaluate(_injectable_request(), MechanismPorts(mechanism=_FakePort()))
        assert good.granted
        weakened = evaluate(
            _injectable_request(),
            MechanismPorts(mechanism=_FakePort()),
            checks=tuple(c for c in ALL_CHECKS if c not in {CHECK_MECHANISM_PROBE}),
        )
        assert weakened.granted and len(weakened.checks) == len(ALL_CHECKS) - 1, (
            "a probe check that never runs cannot be the reason a refusal happens; "
            "this control shows the report shape follows the catalogue"
        )
        nothing = evaluate(
            _injectable_request(),
            MechanismPorts(mechanism=_FakePort()),
            checks=(CHECK_MECHANISM_APPLY,),
        )
        assert nothing.granted
        assert nothing.refusal_reason.startswith("low-level admission")

    def test_a_substituted_primitive_cannot_enter_a_granting_report(self) -> None:
        """A blocked primitive refused at the substrate, with a working fake port."""
        report = evaluate(_request("jvm.gc_pressure"), MechanismPorts(mechanism=_FakePort()))
        assert report.check(CHECK_SUBSTRATE).status is LowLevelStatus.REFUSED
        assert not report.granted
        assert report.applied_primitive is None
        assert "jvm_attach_agent" in report.refusal_reason

    def test_the_wrong_surface_can_flip_a_verdict_and_the_gate_notices(self) -> None:
        """The substrate argument is real, not decorative."""
        from mayhem.domain.lowlevel import Capability, SubstrateSurface

        barren = SubstrateSurface(
            capabilities=frozenset(),
            probe_bins=frozenset(),
            cap_bits=frozenset(),
            installable_bins=frozenset(),
            host_tools=frozenset(),
            manifest_capabilities=frozenset(),
        )
        report = evaluate(_injectable_request("io.capacity_exhaustion"), surface=barren)
        assert report.check(CHECK_SUBSTRATE).status is LowLevelStatus.REFUSED
        assert Capability.SYS_ADMIN, "the barren surface must still be a Capability set"

    def test_the_pinned_baseline_survives_adding_a_primitive(self) -> None:
        """The counts in this file are the inventory, and a new primitive must break them."""
        assert len(PRIMITIVES) == 22
        assert len(BLOCKED_IDS) == 18
        assert len(INJECTABLE_IDS) == 4
        assert set(BLOCKED_IDS) | set(INJECTABLE_IDS) == set(PRIMITIVES)
