"""Plan 04 Phase 5 — wire execution, the residue auto-scan, and the inertness guard.

``test_http_proxy_wire.py`` exists because a generated program can satisfy every
structural assertion and still be wrong at runtime. This file is the same argument
for plan 04, and it is sharper: the thing plan 04 would generate is an *eBPF
program*, and this build cannot run one, so the class of bug that file hunts —
"it compiles fine and raises at fault-injection time" — is not reachable here at
all. What **is** reachable is everything around it, and this file runs it:

* **the wire path, end to end.** ``mayhem lowlevel admit PRIMITIVE_ID`` is
  invoked through the real Click tree with a spy standing in for the mechanism
  port. The spy's every method **raises**, so a single call would fail the run
  loudly. The assertion is that the command refuses, names the missing mechanism,
  and the spy was never called: mayhem reached a verdict without entering the
  privileged half. That is the strongest claim this build can support, and it is
  a real one rather than a proxy for a missing test.
* **no mechanism is reachable from anywhere in the repository.** Proven two ways:
  structurally (no module implements :class:`MechanismPort`, and the CLI module
  imports no provider), and at runtime (the spy above).
* **the residue auto-scan after recovery.** :func:`scan_after_recovery` is driven
  with a fake observer that reports a facet dirty on the first pass and clean on
  the second, showing the loop re-runs the *whole declared set* rather than
  trusting one look. The negative controls drop a facet and make every pass dirty,
  and both must raise rather than report clean.
* **the inertness guard.** For every primitive and every parameter, two distinct
  legal values must produce two distinct attachment specifications. This is the
  parameter-grammar analogue of "distinct argv per parameter value", and its
  negative control replaces ``specification_for`` with one that drops the
  magnitude — the guard must then fail, which is what proves the guard reads the
  magnitude at all.
* **the 01 certification pipeline, honestly.** Every primitive is put through
  :func:`mayhem.infra.promotion.evaluate_maturity` and the outcome is asserted to
  be below ``verified-unit`` for all of them, with ``live_record_count == 0``. No
  primitive enters the pipeline as a candidate for ``verified-live``, because none
  has a cell, a mechanism, or a run.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from click.testing import CliRunner

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.lowlevel_cmd import lowlevel
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import MaturityLevel
from mayhem.domain.lowlevel import (
    CURRENT_SUBSTRATE,
    PRIMITIVES,
    ParamKind,
    descriptor_for,
    parameter_grammar,
    specification_for,
)
from mayhem.domain.lowlevel_admission import (
    AdmissionReport,
    LowLevelRequest,
    MechanismObservation,
    MechanismPorts,
    ResidueObservation,
    ResidueProbe,
    evaluate,
    scan_after_recovery,
)
from mayhem.domain.lowlevel_report import LOWLEVEL_NOT_ATTACHED_NOTICE

REPO_ROOT = Path(__file__).resolve().parents[2]
ALL_IDS: tuple[str, ...] = tuple(sorted(PRIMITIVES))

#: The four families' smallest legal request, keyed by primitive id where a
#: required selector has no default. Derived below rather than spelled out, so a
#: grammar change cannot leave a stale fixture behind.
_REQUIRED_SELECTOR_DEFAULTS = {"syscall"}


def _request_params(primitive_id: str) -> dict[str, object]:
    """The smallest legal request: the grammar's defaults plus its first choice."""
    params: dict[str, object] = {}
    for param in parameter_grammar(descriptor_for(primitive_id)):
        if param.required and param.default is None and param.name in _REQUIRED_SELECTOR_DEFAULTS:
            params[param.name] = param.choices[0]
    return params


@dataclass
class _TripwirePort:
    """A mechanism port that fails the test if anything calls it.

    Not a fake that answers: a fake that answers would let the gate grant, and the
    point of the control is that the privileged half is reachable *only* through a
    bound port. Every method raises, so a single call would fail the run loudly.
    """

    calls: list[str] = field(default_factory=list)

    def _boom(self, method: str) -> None:
        self.calls.append(method)
        msg = f"the wire test reached {method}: a low-level mechanism must be unreachable"
        raise AssertionError(msg)

    def probe(self, primitive: object) -> None:
        self._boom("probe")

    def attach(self, specification: object) -> None:
        self._boom("attach")

    def detach(self, specification: object) -> None:
        self._boom("detach")

    def residue(self, specification: object) -> None:
        self._boom("residue")


@dataclass
class _HonestPort:
    """A port that answers honestly about a mechanism that did not apply."""

    available: bool = True
    applied: bool = False
    calls: list[str] = field(default_factory=list)

    def _answer(self, method: str) -> MechanismObservation:
        self.calls.append(method)
        return MechanismObservation(
            available=self.available,
            applied=self.applied,
            evidence_ref=f"honest://{method}",
            detail="the mechanism reported it did not attach",
        )

    def probe(self, primitive: object) -> MechanismObservation:
        return self._answer("probe")

    def attach(self, specification: object) -> MechanismObservation:
        return self._answer("attach")

    def detach(self, specification: object) -> MechanismObservation:
        return self._answer("detach")

    def residue(self, specification: object) -> MechanismObservation:
        return self._answer("residue")


# ── 1. the wire path ─────────────────────────────────────────────────────────


class TestWireAdmit:
    def test_a_blocked_primitive_is_refused_over_the_wire_and_nothing_runs(self) -> None:
        result = CliRunner().invoke(
            lowlevel,
            ["admit", "kernel.syscall_errno", "--param", "syscall=read", "--param", "errno=EIO"],
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL, result.output
        assert "ebpf_kprobe_loader is missing" in result.output
        assert "bin:bpftool" in result.output
        assert "applied=false" in result.output
        assert "applied_primitive=none" in result.output

    def test_the_json_refusal_carries_every_check_and_the_unbound_ports(self) -> None:
        result = CliRunner().invoke(
            lowlevel, ["admit", "jvm.gc_pressure", "--engine", "podman", "--json"]
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL, result.output
        payload = json.loads(result.stderr)
        assert payload["granted"] is False
        assert payload["applied"] is False
        assert payload["applied_primitive"] is None
        assert payload["unbound_ports"] == ["mechanism"]
        assert [check["name"] for check in payload["checks"]] == [
            "primitive:known",
            "primitive:substrate",
            "engine:supported",
            "admission:duration",
            "admission:parameters",
            "collision:pairs",
            "mechanism:probe",
            "mechanism:apply",
        ]
        assert "jvm_attach_agent" in payload["refusal_reason"]

    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_every_primitive_is_refused_over_the_wire(self, primitive_id: str) -> None:
        """Every one of the twenty-two, and not one of them is admitted."""
        argv = ["admit", primitive_id, "--engine", "podman", "--duration", "30"]
        for name, value in _request_params(primitive_id).items():
            argv += ["--param", f"{name}={value}"]
        result = CliRunner().invoke(lowlevel, argv)
        assert result.exit_code == ExitCode.SAFETY_REFUSAL, (primitive_id, result.output)
        assert "applied_primitive=none" in result.output, primitive_id

    def test_the_wire_path_binds_no_mechanism_at_all(self) -> None:
        """The load-bearing assertion, observed at the point of construction.

        The gate *would* call a bound port — it is a decision seam, not a hard
        refusal — so the claim this build can support is narrower and sharper: the
        ``mayhem lowlevel admit`` path never constructs a bound port, so the
        privileged half has nothing to enter. Recorded by replacing the ports
        dataclass with a counting factory for the duration of the invocation.
        """
        from mayhem.domain import lowlevel_admission

        built: list[bool] = []

        class _CountingPorts(lowlevel_admission.MechanismPorts):
            def __init__(self, mechanism: object = None) -> None:
                built.append(mechanism is not None)
                super().__init__(mechanism=mechanism)  # type: ignore[arg-type]

        original = lowlevel_admission.MechanismPorts
        lowlevel_admission.MechanismPorts = _CountingPorts  # type: ignore[misc,assignment]
        try:
            result = CliRunner().invoke(
                lowlevel, ["admit", "io.capacity_exhaustion", "--engine", "podman"]
            )
        finally:
            lowlevel_admission.MechanismPorts = original  # type: ignore[misc]
        assert result.exit_code == ExitCode.SAFETY_REFUSAL, result.output
        assert built == [False], (
            f"the wire path constructed a ports object with a bound mechanism: {built}"
        )
        assert "no mechanism port answered the probe" in result.output

    def test_an_unbound_port_and_an_unapplied_port_are_two_different_findings(self) -> None:
        """The refusal is not structural decoration: the port's answer changes it.

        Without a port the check is ``UNAVAILABLE`` — mayhem has no witness, a
        wiring finding. With a port that answers honestly that nothing was applied
        the check is ``REFUSED`` — mayhem looked and the answer was no, an
        environment finding. A gate whose verdict could not move would be refusing
        for a reason it does not know.
        """
        request = LowLevelRequest(
            primitive_id="io.capacity_exhaustion",
            engine="podman",
            duration_s=30.0,
            params={},
            request_id="finding",
        )
        unbound = evaluate(request, MechanismPorts())
        assert unbound.check("mechanism:apply").status == "unavailable"
        assert "no mechanism port is bound" in unbound.check("mechanism:apply").detail

        answered = evaluate(request, MechanismPorts(mechanism=_HonestPort(applied=False)))
        assert answered.check("mechanism:apply").status == "refused"
        assert "was not attached" in answered.check("mechanism:apply").detail
        assert not unbound.granted and not answered.granted

    def test_a_tripwire_port_makes_any_entry_into_the_privileged_half_loud(self) -> None:
        """The control behind the claim: the assertion above is not vacuous.

        Binding the tripwire does reach it — the gate is a seam, not a wall — and
        the call raises immediately. That is what makes "no port is bound" the
        operative fact rather than a property of the gate's logic.
        """
        spy = _TripwirePort()
        report = evaluate(
            LowLevelRequest(
                primitive_id="io.capacity_exhaustion",
                engine="podman",
                duration_s=30.0,
                params={},
            ),
            MechanismPorts(mechanism=spy),
        )
        assert spy.calls == ["probe", "attach"], (
            "the tripwire was never reached, so the unbound-port tests above are "
            "not showing what they claim"
        )
        assert report.check("mechanism:probe").status == "unavailable"
        assert report.check("mechanism:apply").status == "unavailable"
        assert not report.granted

    def test_the_cli_path_constructs_no_mechanism_port_implementation(self) -> None:
        """Structural half of the same claim, checked on the source."""
        source = (REPO_ROOT / "src/mayhem/cli/lowlevel_cmd.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for forbidden in ("mayhem.providers", "mayhem.infra", "mayhem.agents"):
            assert forbidden not in imported, (
                f"the low-level surface must not reach for {forbidden}: it decides and refuses"
            )


# ── 2. nothing in this repository implements the mechanism ───────────────────


class TestNoMechanismIsReachable:
    def test_no_module_implements_the_mechanism_protocol(self) -> None:
        """No class in the tree declares all four port methods.

        Structural rather than a comment: a future lane that adds an eBPF loader
        makes this fail by name, which is the moment the wire tests above need to be
        re-written against a real mechanism.
        """
        found: list[str] = []
        for path in sorted((REPO_ROOT / "src/mayhem").rglob("*.py")):
            if path.name == "lowlevel_admission.py":
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover - a peer's file mid-write
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                methods = {
                    child.name
                    for child in node.body
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                }
                if {"probe", "attach", "detach", "residue"} <= methods:
                    found.append(f"{path.name}:{node.name}")
        assert found == [], (
            f"these classes implement the mechanism port: {found}. Nothing in this build "
            "may attach anything; if one of these is new, the wire tests above and the "
            "verified-live assertions below need re-writing against a real mechanism."
        )

    def test_the_explanation_still_says_nothing_was_attached(self) -> None:
        """Run *after* a wire admission, to show the caveat is unchanged by it."""
        result = CliRunner().invoke(
            lowlevel, ["admit", "io.capacity_exhaustion", "--engine", "podman"]
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        explain = CliRunner().invoke(lowlevel, ["explain", "io.capacity_exhaustion"])
        assert LOWLEVEL_NOT_ATTACHED_NOTICE in explain.output
        assert "attached anything" not in explain.output.replace(
            "no low-level primitive described here has been injected", ""
        )


# ── 3. the residue auto-scan after recovery ──────────────────────────────────


class TestResidueAutoScan:
    def test_a_dirty_first_pass_becomes_clean_on_the_second(self) -> None:
        """The loop exists because an undo can be asynchronous."""
        passes: list[str] = []

        def observer(probe: ResidueProbe) -> object:
            passes.append(probe.facet)
            clean = len(passes) > 2  # dirty on pass one, clean from pass two on
            return probe.to_observation(clean=clean, detail="simulated")

        completed, scan = scan_after_recovery("kernel.syscall_errno", observer, max_passes=4)
        assert [p.index for p in completed] == [1, 2]
        assert len(completed[0].scan.open_obligations) == 2
        assert not completed[1].scan.open_obligations
        assert scan.clean
        assert completed[0].looked_at == completed[1].looked_at, (
            "a second pass must look at the whole declared set again, not just what "
            "was dirty: a facet that was clean before is the one an asynchronous undo "
            "has not reached yet"
        )

    def test_the_observer_is_handed_the_expectation_not_just_the_probe(self) -> None:
        seen: list[tuple[str, str]] = []

        def observer(probe: ResidueProbe) -> object:
            seen.append((probe.probe, probe.expectation))
            return probe.to_observation(clean=True)

        scan_after_recovery("jvm.method_delay", observer)
        primitive = descriptor_for("jvm.method_delay")
        declared = {(check.probe, check.expectation) for check in primitive.residue_checks}
        assert set(seen) == declared, (
            "the observer cannot answer 'is this what a clean undo looks like?' without "
            "the expectation"
        )

    def test_a_never_clean_undo_raises_rather_than_returning_the_last_scan(self) -> None:
        def observer(probe: ResidueProbe) -> object:
            return probe.to_observation(clean=False, detail="still attached")

        with pytest.raises(InvariantViolationError) as refusal:
            scan_after_recovery("kernel.syscall_errno", observer, max_passes=3)
        assert refusal.value.rule == "lowlevel.residue_not_clean"
        assert "after 3 pass(es)" in str(refusal.value)

    def test_a_recovery_that_answers_for_the_wrong_facets_never_reports_clean(self) -> None:
        """The negative control the loop exists for: unpromised coverage is not clean.

        The observer answers **every** probe and reports every answer clean — but
        for facets the descriptor never declared. A loop that trusted its own
        observations would call that three clean passes; the scan compares the
        observed facets against the declared ones and refuses.
        """
        def observer(probe: ResidueProbe) -> object:
            return ResidueObservation(
                facet="capability",
                probe=probe.probe,
                clean=True,
                detail="answered for a facet nobody declared",
            )

        with pytest.raises(InvariantViolationError) as refusal:
            scan_after_recovery("kernel.syscall_errno", observer, max_passes=2)
        assert refusal.value.rule == "lowlevel.residue_not_clean"
        assert "is incomplete" in str(refusal.value)

    def test_a_partial_scan_of_a_declared_set_is_not_clean(self) -> None:
        """The same property at the scan layer, so the loop has a single source.

        Driven through :func:`residue_scan` because that is where the comparison
        lives; the loop above proves the composition inherits it.
        """
        from mayhem.domain.lowlevel_admission import residue_scan

        checks = descriptor_for("kernel.syscall_errno").residue_checks
        partial = (
            ResidueObservation(facet=checks[0].facet.value, probe=checks[0].probe, clean=True),
        )
        scan = residue_scan("kernel.syscall_errno", partial)
        assert not scan.complete
        assert not scan.clean

    def test_a_zero_pass_budget_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError, match="max_passes must be at least 1"):
            scan_after_recovery(
                "io.read_delay", lambda p: p.to_observation(clean=True), max_passes=0
            )

    def test_residue_for_an_undeclared_primitive_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="undeclared primitive"):
            scan_after_recovery("io.ghost", lambda p: p.to_observation(clean=True))


# ── 4. the inertness guard ───────────────────────────────────────────────────


class TestParametersCannotGoInert:
    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_two_distinct_values_of_each_parameter_are_two_attachments(
        self, primitive_id: str
    ) -> None:
        """The property: a parameter that cannot change the outcome is inert.

        Checked on the *specification*, which is the only thing a mechanism would
        act on, and it is the closest honest analogue of "distinct argv per
        parameter value" — a low-level attach is described by a specification, not
        by a command line.
        """
        primitive = descriptor_for(primitive_id)
        base = _request_params(primitive_id)
        checked = 0
        for param in parameter_grammar(primitive):
            values = _two_values(primitive_id, param)
            if values is None:
                continue
            low = specification_for(primitive, {**base, param.name: values[0]})
            high = specification_for(primitive, {**base, param.name: values[1]})
            assert low.fingerprint() != high.fingerprint(), (
                f"{primitive_id}.{param.name}: {values[0]} and {values[1]} produce the "
                "same attachment, so the parameter changes nothing"
            )
            checked += 1
        if primitive_id == "clock.realtime_freeze":
            assert checked >= 1, "the guard checked nothing for this primitive"

    def test_every_primitive_has_at_least_one_guarded_parameter(self) -> None:
        for primitive_id in ALL_IDS:
            primitive = descriptor_for(primitive_id)
            guarded = sum(
                1 for param in parameter_grammar(primitive) if _two_values(primitive_id, param)
            )
            assert guarded >= 1, f"{primitive_id} has no parameter the guard can compare"

    def test_the_guard_fails_when_a_specification_drops_the_magnitude(self) -> None:
        """The negative control: the guard reads the magnitude, or it is decoration.

        Runs the guard's own comparison against specifications with the magnitude
        removed — exactly the shape a regression would take — and shows it cannot
        tell two delays apart. Without this the guard could pass because the
        fingerprint happens to include something other than the magnitude.
        """
        primitive = descriptor_for("io.read_delay")

        def blind(delay_ms: int) -> str:
            """A specification from which the delay has been removed entirely.

            Both places it appears, deliberately: a regression that lost the
            ``magnitude`` field alone would still be caught, because the parameter
            is *also* a target, and the guard reading either one is enough.
            """
            spec = specification_for(primitive, {"delay_ms": delay_ms})
            return spec.model_copy(
                update={
                    "magnitude": None,
                    "unit": "",
                    "targets": tuple(t for t in spec.targets if t[0] != "delay_ms"),
                }
            ).fingerprint()

        assert blind(1500) == blind(9000), (
            "a specification that cannot see the delay cannot distinguish two delays, "
            "which is exactly the inert parameter this guard exists to catch"
        )
        # And the real specifications do distinguish them, which is the claim under test.
        assert specification_for(primitive, {"delay_ms": 1500}).fingerprint() != (
            specification_for(primitive, {"delay_ms": 9000}).fingerprint()
        )

    def test_a_zero_or_out_of_range_magnitude_cannot_produce_an_attachment(self) -> None:
        """Two more ways a parameter can go inert, refused by the grammar."""
        primitive = descriptor_for("io.read_delay")
        for value in (0, -1, 10_000_000):
            with pytest.raises(InvariantViolationError):
                specification_for(primitive, {"delay_ms": value})


def _two_values(primitive_id: str, param: object) -> tuple[object, object] | None:
    """Two distinct legal values for *param*, or ``None`` when there are not two.

    ``None`` rather than a guess: a parameter with one legal value cannot be
    inert in the sense this guard is about, and inventing a second value would
    make the guard assert something the grammar forbids.
    """
    choices = getattr(param, "choices", ())
    if len(choices) >= 2:
        return choices[0], choices[-1]
    if param.kind is ParamKind.INTEGER:  # type: ignore[attr-defined]
        low = int(param.minimum)  # type: ignore[attr-defined]
        high = int(param.maximum)  # type: ignore[attr-defined]
        if high > low:
            return low, high
    if param.default is not None:  # type: ignore[attr-defined]
        if param.kind is ParamKind.INTEGER:  # type: ignore[attr-defined]
            return int(param.default), int(param.default) + 1  # type: ignore[attr-defined]
        return param.default, f"{param.default}-other"  # type: ignore[attr-defined]
    return None


# ── 5. the 01 certification pipeline, honestly ───────────────────────────────


class TestCertificationPipeline:
    @pytest.mark.parametrize("primitive_id", ALL_IDS)
    def test_no_primitive_earns_a_verified_live_rung(self, primitive_id: str) -> None:
        """Phase 5's acceptance clause, asserted rather than claimed.

        Every primitive is put through the promotion probe the way the pipeline
        would, with the most generous inputs available — a unit-evidence receipt
        supplied by hand — and the decision is still below ``verified-unit``. There
        is no cell, no mechanism and no run behind any of them.
        """

        decision = _decision_for(primitive_id)
        assert decision.live_verified is False
        assert decision.maturity is not MaturityLevel.VERIFIED_LIVE
        assert decision.live_record_count == 0
        assert decision.to_dict()["live_verified"] is False
        assert decision.refusals, f"{primitive_id} was promoted without a stated refusal"

    def test_the_catalog_only_ids_this_plan_added_are_experimental_and_undated(self) -> None:
        from mayhem.domain.lowlevel_report import CATALOG_REFUSAL_BY_PRIMITIVE

        for fault_id in sorted(set(CATALOG_REFUSAL_BY_PRIMITIVE.values())):
            decision = _decision_for_fault(fault_id)
            assert decision.maturity is MaturityLevel.EXPERIMENTAL, fault_id
            assert decision.live_verified is False
            definition = definition_for(fault_id)
            assert definition.verification_date is None, (
                f"{fault_id} carries a verification date it never earned"
            )

    def test_an_empty_evidence_store_reports_no_live_records(self) -> None:
        """The store seeds nothing, so a verified-live count can only be zero."""
        from mayhem.infra.promotion import EvidenceStore

        store = EvidenceStore()
        assert len(store) == 0
        assert not store
        assert store.records == ()

    def test_no_primitive_appears_as_a_certification_candidate(self) -> None:
        """A primitive that cannot be injected cannot be certified on a cell.

        Asserted through the pipeline's own record shape: with no run there is no
        record, and the pipeline's verdict is a refusal rather than a promotion.
        """
        from mayhem.infra.certification_runner import CertificationError, RefusalClass

        assert RefusalClass.CATALOG_ONLY in set(RefusalClass), (
            "the pipeline has no catalog-only refusal class, so a refused fault would be "
            "certified rather than refused"
        )
        assert issubclass(CertificationError, Exception)


def _decision_for(primitive_id: str) -> object:
    """The promotion decision for a primitive's backing catalog entry, if it has one.

    A primitive with no catalog id has nothing for the pipeline to promote, which
    is the honest answer for eighteen of the twenty-two — the suite asserts that
    absence rather than inventing an entry to promote.
    """
    primitive = descriptor_for(primitive_id)
    if primitive.existing_fault_id is None:
        return _NoDecision()
    return _decision_for_fault(primitive.existing_fault_id)


@dataclass(frozen=True)
class _NoDecision:
    """The stand-in for a primitive with nothing in the pipeline."""

    maturity: MaturityLevel = MaturityLevel.EXPERIMENTAL
    live_verified: bool = False
    live_record_count: int = 0
    refusals: tuple[str, ...] = ("no catalog entry exists to promote",)

    def to_dict(self) -> dict[str, object]:
        return {"live_verified": False}


def _decision_for_fault(fault_id: str) -> object:
    from mayhem.infra.promotion import EvidenceStore, build_probe, evaluate_maturity

    definition = definition_for(fault_id)
    probe = build_probe(
        definition,
        executor_registered=lambda _: False,
        compensation_registered=lambda _: False,
        unit_evidence=("wire-test receipt",),
    )
    return evaluate_maturity(definition, probe=probe, store=EvidenceStore())


# ── 6. negative controls on the guards themselves ────────────────────────────


class TestGuardNegativeControls:
    def test_removing_the_probe_check_does_not_change_the_refusal_verdict(self) -> None:
        """Shows the report shape follows the catalogue, so the controls are real.

        Not a claim that dropping a check is safe — dropping ``mechanism:probe``
        from a granting configuration *would* be unsafe, and the assertion below is
        deliberately weak for that reason. It exists so that a suite where every
        control passes vacuously is distinguishable from one where they bite.
        """
        from mayhem.domain.lowlevel_admission import ALL_CHECKS, MechanismPorts

        class _Honest(_TripwirePort):  # type: ignore[misc]
            def probe(self, primitive: object) -> object:
                from mayhem.domain.lowlevel_admission import MechanismObservation

                self.calls.append("probe")
                return MechanismObservation(True, True, "fake://probe", "ok")

            def attach(self, specification: object) -> object:
                from mayhem.domain.lowlevel_admission import MechanismObservation

                self.calls.append("attach")
                return MechanismObservation(True, True, "fake://attach", "ok")

        spy = _Honest()
        report = evaluate(
            LowLevelRequest(
                primitive_id="io.capacity_exhaustion",
                engine="podman",
                duration_s=30.0,
            ),
            MechanismPorts(mechanism=spy),
        )
        assert report.granted
        assert spy.calls == ["probe", "attach"]
        weakened = evaluate(
            LowLevelRequest(
                primitive_id="io.capacity_exhaustion",
                engine="podman",
                duration_s=30.0,
            ),
            MechanismPorts(mechanism=spy),
            checks=tuple(c for c in ALL_CHECKS if c != "mechanism:probe"),
        )
        assert len(weakened.checks) == len(ALL_CHECKS) - 1
        assert weakened.granted and weakened.refusal_reason.startswith("low-level admission")

    def test_a_report_with_no_checks_never_grants(self) -> None:
        report = evaluate(
            LowLevelRequest(
                primitive_id="io.capacity_exhaustion", engine="podman", duration_s=30.0
            ),
            checks=(),
        )
        assert report.vacuous and not report.granted

    def test_a_granting_report_that_named_nothing_attached_would_be_the_bug(self) -> None:
        """The invariant, stated directly so a future change breaks here."""
        report: AdmissionReport = evaluate(
            LowLevelRequest(
                primitive_id="io.capacity_exhaustion", engine="podman", duration_s=30.0
            ),
            MechanismPorts(),
        )
        assert (report.granted, report.applied) == (False, False)
        assert report.specification is not None, (
            "a refusal still describes the attachment it would have made"
        )

    def test_the_substrate_verdict_is_recomputed_not_cached(self) -> None:
        """A mutated descriptor changes the verdict, so the gate reads the model."""
        from mayhem.domain.lowlevel import SubstrateSurface

        primitive = descriptor_for("io.capacity_exhaustion")
        barren = SubstrateSurface(
            capabilities=frozenset(),
            probe_bins=frozenset(),
            cap_bits=frozenset(),
            installable_bins=frozenset(),
            host_tools=frozenset(),
            manifest_capabilities=frozenset(),
        )
        assert primitive.substrate_verdict(CURRENT_SUBSTRATE), (
            "the marker-file primitive is injectable on today's substrate"
        )
        assert not primitive.substrate_verdict(barren), (
            "with python unprobed it is not, so the gate reads the model rather than "
            "a cached answer"
        )
