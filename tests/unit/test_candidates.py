"""Candidate generation + gates tests (ADR-M5-2, M5 Phase 5.3).

Acceptance: generator output is valid; every executable candidate passed all
three gates; rejected candidates carry a reason.
"""

from __future__ import annotations

import pytest

from mayhem.domain.candidates import (
    CandidateDecision,
    CandidateGate,
    ExperimentCandidate,
)
from mayhem.domain.risks import RiskLevel
from mayhem.infra.candidate_gates import (
    CandidateGatePipeline,
    FeasibilityGate,
    ResourceConflictGate,
    SafetyGate,
)
from mayhem.infra.candidate_generator import (
    CandidateLandscape,
    SeededCandidateGenerator,
)


class TestExperimentCandidate:
    def test_id_is_stable_for_same_fields(self) -> None:
        a = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",), seed_hint=1)
        b = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",), seed_hint=1)
        assert a.id == b.id
        assert a.id.startswith("cand-")

    def test_id_differs_for_different_target(self) -> None:
        a = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",), seed_hint=1)
        c = ExperimentCandidate(target="api-1", fault_kinds=("net.delay",), seed_hint=1)
        assert a.id != c.id

    def test_frozen(self) -> None:
        cand = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",))
        with pytest.raises(AttributeError):
            cand.target = "api-1"  # type: ignore[misc]

    def test_primary_fault(self) -> None:
        assert ExperimentCandidate(target="t", fault_kinds=("a", "b")).primary_fault == "a"
        assert ExperimentCandidate(target="t", fault_kinds=()).primary_fault == ""


class TestGenerator:
    def _gen(self, **kwargs: object) -> SeededCandidateGenerator:
        landscape = CandidateLandscape(**kwargs)  # type: ignore[arg-type]
        return SeededCandidateGenerator(landscape=landscape, seed=7)

    def test_deterministic_given_seed(self) -> None:
        g1 = self._gen(
            targets=("web-1", "api-1"),
            fault_kinds=("net.delay", "cpu.spike"),
            parameter_bands=("50ms", "250ms"),
        )
        g2 = self._gen(
            targets=("web-1", "api-1"),
            fault_kinds=("net.delay", "cpu.spike"),
            parameter_bands=("50ms", "250ms"),
        )
        out1 = g1.generate()
        out2 = g2.generate()
        assert [c.id for c in out1] == [c.id for c in out2]
        assert len(out1) == len(out2)

    def test_output_is_valid_candidates(self) -> None:
        var = self._gen(targets=("web-1",), fault_kinds=("net.delay",))
        for cand in var.generate():
            assert isinstance(cand, ExperimentCandidate)
            assert cand.target == "web-1"
            assert cand.fault_kinds == ("net.delay",)
            assert cand.seed_hint == 7
            assert cand.id.startswith("cand-")

    def test_landscape_cross_product(self) -> None:
        gen = self._gen(
            targets=("a", "b"),
            fault_kinds=("x", "y"),
            execution_contexts=("container", "host"),
            parameter_bands=("p1", "p2"),
        )
        out = gen.generate()
        # 2 targets * 2 faults * 2 contexts * 2 bands = 16
        assert len(out) == 16
        # every band present
        assert {c.params.get("band") for c in out} == {"p1", "p2"}

    def test_limit_bounds_output(self) -> None:
        gen = self._gen(
            targets=("a", "b", "c"),
            fault_kinds=("x", "y"),
            execution_contexts=("container",),
            parameter_bands=("p1",),
        )
        out = gen.generate(limit=4)
        assert len(out) == 4

    def test_risk_ceiling_excludes_hot_faults(self) -> None:
        # "node.reboot" maps to CRITICAL; ceiling of MEDIUM must drop it.
        gen = SeededCandidateGenerator(
            landscape=CandidateLandscape(
                targets=("host-1",),
                fault_kinds=("net.delay", "node.reboot", "cpu.spike"),
                risk_ceiling=RiskLevel.MEDIUM,
            ),
            seed=1,
        )
        out = gen.generate()
        kinds = {c.primary_fault for c in out}
        assert kinds == {"net.delay", "cpu.spike"}  # node.reboot excluded
        assert "node.reboot" not in kinds

    def test_empty_landscape_yields_nothing(self) -> None:
        gen = self._gen(targets=(), fault_kinds=())
        assert gen.generate() == ()


class TestGates:
    def test_safety_rejects_forbidden_fault_with_reason(self) -> None:
        gate = SafetyGate(forbidden_faults=("node.reboot",))
        cand = ExperimentCandidate(target="host-1", fault_kinds=("node.reboot",))
        reason = gate.check(cand)
        assert reason is not None
        assert "node.reboot" in reason

    def test_feasibility_rejects_unsupported_with_reason(self) -> None:
        gate = FeasibilityGate(supported=("net.delay",), unsupported=("fs.fill",))
        cand = ExperimentCandidate(target="db-1", fault_kinds=("fs.fill",))
        reason = gate.check(cand)
        assert reason is not None
        assert "UNSUPPORTED" in reason

    def test_feasibility_rejects_unknown_fault(self) -> None:
        gate = FeasibilityGate(supported=("net.delay",))
        cand = ExperimentCandidate(target="db-1", fault_kinds=("mem.leak",))
        reason = gate.check(cand)
        assert reason is not None
        assert "not in the supported" in reason

    def test_feasibility_passes_supported(self) -> None:
        gate = FeasibilityGate(supported=("net.delay",))
        cand = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",))
        assert gate.check(cand) is None

    def test_resource_conflict_rejects_busy_target(self) -> None:
        gate = ResourceConflictGate(busy_targets=("web-1",))
        cand = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",))
        reason = gate.check(cand)
        assert reason is not None
        assert "resource conflict" in reason


class TestGatePipeline:
    def test_executable_candidate_passed_all_three_gates(self) -> None:
        """Acceptance: every executable candidate passed all three gates."""
        pipeline = CandidateGatePipeline(
            safety=SafetyGate(),
            feasibility=FeasibilityGate(supported=("net.delay", "cpu.spike")),
            resource_conflict=ResourceConflictGate(),
        )
        cand = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",))
        decision = pipeline.gate(cand)
        assert decision.accepted is True
        assert decision.gate is None

    def test_rejected_candidate_carries_reason(self) -> None:
        """Acceptance: rejected candidates carry a reason."""
        pipeline = CandidateGatePipeline(
            feasibility=FeasibilityGate(supported=("net.delay",)),
        )
        cand = ExperimentCandidate(target="db-1", fault_kinds=("fs.fill",))
        decision = pipeline.gate(cand)
        assert decision.rejected is True
        assert decision.gate is CandidateGate.FEASIBILITY
        assert decision.reason != ""
        assert "fs.fill" in decision.reason

    def test_safety_rejects_before_feasibility(self) -> None:
        """Gate order: Safety runs first."""
        pipeline = CandidateGatePipeline(
            safety=SafetyGate(forbidden_faults=("node.reboot",)),
            feasibility=FeasibilityGate(supported=("node.reboot",)),
        )
        cand = ExperimentCandidate(target="host-1", fault_kinds=("node.reboot",))
        decision = pipeline.gate(cand)
        assert decision.gate is CandidateGate.SAFETY

    def test_resource_conflict_rejects_last(self) -> None:
        pipeline = CandidateGatePipeline(
            feasibility=FeasibilityGate(supported=("net.delay",)),
            resource_conflict=ResourceConflictGate(busy_targets=("web-1",)),
        )
        cand = ExperimentCandidate(target="web-1", fault_kinds=("net.delay",))
        decision = pipeline.gate(cand)
        assert decision.gate is CandidateGate.RESOURCE_CONFLICT

    def test_gate_many(self) -> None:
        pipeline = CandidateGatePipeline(
            feasibility=FeasibilityGate(supported=("net.delay",)),
        )
        good = ExperimentCandidate(target="a", fault_kinds=("net.delay",))
        bad = ExperimentCandidate(target="b", fault_kinds=("fs.fill",))
        decisions = pipeline.gate_many((good, bad))
        assert decisions[0].accepted is True
        assert decisions[1].rejected is True
        assert decisions[1].gate is CandidateGate.FEASIBILITY

    def test_generator_plus_pipeline_integration(self) -> None:
        gen = SeededCandidateGenerator(
            landscape=CandidateLandscape(
                targets=("web-1", "api-1", "db-1"),
                fault_kinds=("net.delay", "fs.fill", "cpu.spike"),
            ),
            seed=3,
        )
        pipeline = CandidateGatePipeline(
            feasibility=FeasibilityGate(supported=("net.delay", "cpu.spike")),
        )
        decisions: tuple[CandidateDecision, ...] = pipeline.gate_many(gen.generate())
        executable = [d for d in decisions if d.accepted]
        rejected = [d for d in decisions if d.rejected]
        assert len(executable) > 0
        # every accepted candidate used a supported fault kind
        for d in executable:
            assert d.candidate.primary_fault in ("net.delay", "cpu.spike")
        # every rejected candidate has a reason
        for d in rejected:
            assert d.reason != ""
            assert d.gate is not None
