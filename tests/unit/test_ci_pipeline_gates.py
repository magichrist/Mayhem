"""Fixture pull requests, fixture releases, and the negative controls that prove
the gates notice (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 5).

Phases 2 and 4 tested the engine's units. This file tests the two things a person
actually meets:

* **check evaluation on fixture pull requests** — whole-plan evaluations through
  the real compile → proof → policy path, over a matrix of plans that each trip a
  different check. Not unit tests of the projection: the whole engine, run over
  a plan file, because a projection that agrees with the gate in isolation and
  disagrees when the plan has six fault steps is exactly the failure Phase 2 was
  built to prevent.
* **gate tests on fixture releases**, including the plan's own worked example —
  v2.4 → v2.5 crossing a 20% latency tolerance. The chain under test is the real
  one: plan 22's :func:`~mayhem.domain.comparison.compare` grades two fixture
  runs, the grade becomes a
  :class:`~mayhem.controller.check_gate.ResilienceSuite`, and the suite decides a
  :func:`~mayhem.controller.check_gate.release_gate`. A gate that reads "the
  regression check passed" from a run whose comparison was *insufficient* is a
  gate that opened on a question nobody answered, so the ungraded case is a
  first-class fixture rather than an afterthought.

Then the negative controls, which are the point of the file. Each one breaks a
property **on purpose** and asserts the break is observable:

* an unreachable control plane reported as ``PASS`` is refused *structurally*, and
  the control monkeypatches the engine's own short-circuit away to show the guard
  is load-bearing rather than incidental;
* a merged plan that differs from the checked plan invalidates every approval, and
  the control shows that with ``PlanMerge.changed`` stubbed to ``False`` the same
  merge leaves the approvals standing — so the assertion is not resting on the
  comparison happening to be unequal;
* a coverage number cannot be printed without its denominator, and the control
  shows the gate line is emitted with a landscape attached;
* the release gate cannot be constructed into an allow without evidence, and the
  control shows that deleting the enforcement does let it be constructed — which
  is the strongest statement available that the enforcement is what stopped it.

Nothing here reaches a control plane: no network, no forge, no runner. Every case
is a pure function over fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller import check_gate as cg
from mayhem.controller.check_gate import (
    GATE_ALLOW,
    GATE_BLOCK,
    RULE_ALLOW_WITHOUT_EVIDENCE,
    ChangeKind,
    ChatOpsCommand,
    CoverageSurface,
    ReleaseGateDecision,
    ReleaseGateRequest,
    ResilienceSuite,
    evaluate_pr_checks,
    release_gate,
)
from mayhem.controller.safety import SafetyContext
from mayhem.domain.certification import CertificationRecord, CertificationState, MatrixCell
from mayhem.domain.comparison import (
    ComparisonMetric,
    MetricKind,
    RunPin,
    RunReport,
    RunSample,
    compare,
)
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
)
from mayhem.domain.identity import (
    RoleGrant as _RoleGrant,
)
from mayhem.domain.journeys import JourneyPin
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.pipeline import (
    ChangeLink,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    PipelinePins,
    PlanApproval,
    PlanMerge,
    gates_release,
)
from mayhem.domain.quota import DamageQuota
from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityVerdict,
    RuntimeAdapter,
    VerdictResult,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.topology.providers.base import PartialGraph

FP = "f" * 64
OTHER_FP = "e" * 64
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=2)
GIT_SHA = "a1b2c3d"

JOURNEY = JourneyPin(name="checkout-journey", version="1.0.0", digest="a" * 64)


# ── fixtures: topology, plans, context ─────────────────────────────────────────


@dataclass(frozen=True)
class Fixture:
    """One pull request, described well enough to be evaluated.

    A dataclass rather than a set of keyword arguments because the matrix below
    is *about* which axis moves: a reader should be able to see that
    ``over_blast`` and ``over_budget`` differ in one field and nothing else.
    """

    name: str
    faults: tuple[str, ...] = ("proc.pause", "net.latency")
    durations: tuple[float, ...] = (10.0, 10.0)
    compensate: bool = True
    nodes: int = 3
    budget: BlastRadiusBudget = field(default=None)  # type: ignore[assignment]

    def plan(self) -> ExecutionPlan:
        selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
        steps = []
        for index, (fault_id, duration) in enumerate(zip(self.faults, self.durations, strict=True)):
            steps.append(
                PlannedStep(
                    id=f"s{index}",
                    seq=index,
                    raw_action=InjectFault(
                        fault=fault_id, selectors=(selector,), duration=duration
                    ),
                    fault=PlannedFault(
                        fault_id=fault_id,
                        targets=(
                            ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),
                        ),
                        duration=duration,
                        undo_ops=(UndoOp(op="tc.del_qdisc"),) if self.compensate else (),
                        verify_probes=(
                            (VerifyProbe(probe="tc.qdisc_absent"),) if self.compensate else ()
                        ),
                    ),
                )
            )
        return ExecutionPlan(
            run_id=f"r-{self.name}",
            kind=ExperimentKind.DETERMINISTIC,
            steps=tuple(steps),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint=FP,
        )

    def graph(self) -> TopologyGraph:
        return TopologyGraph(
            nodes=(
                ServiceNode(id="n-a", name="a"),
                ServiceNode(id="n-b", name="b"),
                ServiceNode(id="n-c", name="c"),
                HostNode(id="h-local", name="local", transport="local"),
            )[: self.nodes + 1],
            edges=(Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
        )

    def safety(self, *, fingerprint: str = FP, quota: DamageQuota | None = None) -> SafetyContext:
        return SafetyContext(
            policy=PolicyCfg(),
            budget=self.budget or _permissive(),
            fingerprint=fingerprint,
            damage_quota=quota or DamageQuota(),
        )


def _permissive(**overrides: Any) -> BlastRadiusBudget:
    fields: dict[str, Any] = {
        "max_services_pct": 100.0,
        "max_hosts": 2**31 - 1,
        "max_concurrent_faults": 2**31 - 1,
        "max_duration_per_fault_s": float("inf"),
        "forbidden_fault_pairs": frozenset(),
    }
    fields.update(overrides)
    return BlastRadiusBudget(**fields)


class _Adapter(RuntimeAdapter):
    blocking = False

    @property
    def id(self) -> str:
        return "fake-adapter"

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            engine=self.id, supported=frozenset(), alternatives=frozenset(), version=None
        )

    def evaluate(self, reqs: Any) -> VerdictResult:
        verdict = CapabilityVerdict.UNSUPPORTED if self.blocking else CapabilityVerdict.SUPPORTED
        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts={"namespace": verdict.value},
            blocking=self.blocking,
        )

    def ps(self) -> list[dict[str, Any]]:
        return []

    def inspect(self, container_id: str) -> tuple[Any, None]:
        from mayhem.domain.identity import RuntimeIdentity

        return RuntimeIdentity(runtime="fake", host_id="h", runtime_id=container_id), None

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        return ""

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        return None

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(self, project: str, services: Any = None) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self) -> PartialGraph:
        return PartialGraph(source=self.id)


class _BlockingAdapter(_Adapter):
    blocking = True


def _pin(**overrides: Any) -> RunPin:
    fields: dict[str, Any] = {
        "run_id": "run-v25-0001",
        "experiment": "checkout-resilience",
        "release": "v2.5",
        "environment": "staging",
        "plan_version": "plan-7",
        "policy_version": "policy-7",
        "catalog_version": "catalog-2026.09",
        "agent_version": "agent-2.0.0",
        "runtime_version": "runtime-2.1.0",
        "evidence_digest": "0" * 64,
        "journey": JOURNEY,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _link(**overrides: Any) -> ChangeLink:
    fields: dict[str, Any] = {
        "git_sha": GIT_SHA,
        "change_ticket": "CH-1421",
        "deployment_id": "deploy-9931",
        "pins": PipelinePins.from_run(_pin()),
        "linked_at": NOW,
    }
    fields.update(overrides)
    return ChangeLink(**fields)


def _evaluate(fixture: Fixture, **overrides: Any) -> cg.CheckReport:
    fields: dict[str, Any] = {
        "plan": fixture.plan(),
        "graph": fixture.graph(),
        "safety": fixture.safety(),
        "change": _link(),
        "cited_run": _pin(),
        "adapter": _Adapter(),
    }
    fields.update(overrides)
    return evaluate_pr_checks(cg.CheckInputs(**fields))


# ── fixture pull requests ──────────────────────────────────────────────────────


class TestFixturePullRequests:
    def test_a_clean_pull_request_passes_every_check(self) -> None:
        report = _evaluate(Fixture(name="clean"))
        assert [check.outcome for check in report.checks] == [CheckOutcome.PASS] * 6
        assert report.proven
        assert report.blocking == ()
        assert report.plan_digest

    def test_every_check_cites_something_it_was_read_from(self) -> None:
        report = _evaluate(Fixture(name="clean"))
        for check in report.checks:
            assert check.evidence_refs, check.name

    def test_an_unresolvable_fault_id_fails_only_syntax(self) -> None:
        """A well-formed id for a fault the catalog does not have.

        The category prefix has to be real, or the *plan* refuses first, at
        :func:`~mayhem.domain.faults.FaultCategory.from_fault_id`. Both refusals
        exist at different layers and the fixture is chosen to reach the one under
        test.
        """
        unknown = next(
            f"{prefix}.no_such_fault"
            for prefix in ("proc", "net", "disk")
            if not any(d.id == f"{prefix}.no_such_fault" for d in _catalog())
        )
        report = _evaluate(Fixture(name="bogus", faults=(unknown,), durations=(10.0,)))
        outcomes = {check.scope: check.outcome for check in report.checks}
        assert outcomes[CheckScope.SYNTAX] is CheckOutcome.FAIL
        assert unknown in report.check(cg.CHECK_NAME[CheckScope.SYNTAX]).detail

    def test_an_unknown_category_prefix_is_refused_by_the_plan_before_any_check_runs(
        self,
    ) -> None:
        """The layer below the syntax check, asserted so it stays below it."""
        from mayhem.domain.errors import SchemaValidationError

        with pytest.raises(SchemaValidationError):
            Fixture(name="bad-prefix", faults=("no.such.fault",), durations=(10.0,)).plan()

    def test_a_catalog_only_fault_is_refused_twice_and_says_two_different_things(
        self,
    ) -> None:
        """Two facts, both true, and a reviewer needs both.

        "the fault this build refuses to run" (syntax) and "the fault nothing
        certified" (compatibility) are not the same sentence.
        """
        from mayhem.domain.catalog import definition_for

        catalog_only = next(
            definition.id for definition in _catalog() if definition.catalog_only
        )
        report = _evaluate(
            Fixture(name="catalog-only", faults=(catalog_only,), durations=(10.0,))
        )
        syntax = report.check(cg.CHECK_NAME[CheckScope.SYNTAX])
        compat = report.check(cg.CHECK_NAME[CheckScope.FAULT_COMPATIBILITY])
        assert syntax.outcome is CheckOutcome.FAIL
        assert compat.outcome is CheckOutcome.FAIL
        assert "catalog-only" in syntax.detail
        assert "catalog-only" in compat.detail
        assert definition_for(catalog_only).catalog_only

    def test_a_plan_with_no_compensation_fails_the_safety_policy_check(self) -> None:
        report = _evaluate(Fixture(name="no-compensation", compensate=False))
        outcomes = {check.scope: check.outcome for check in report.checks}
        assert outcomes[CheckScope.SAFETY_POLICY] is CheckOutcome.FAIL
        assert "compensation" in report.check(cg.CHECK_NAME[CheckScope.SAFETY_POLICY]).detail

    def test_a_blocking_adapter_fails_only_fault_compatibility(self) -> None:
        report = _evaluate(Fixture(name="no-capability"), adapter=_BlockingAdapter())
        outcomes = {check.scope: check.outcome for check in report.checks}
        assert outcomes[CheckScope.FAULT_COMPATIBILITY] is CheckOutcome.FAIL
        assert outcomes[CheckScope.SYNTAX] is CheckOutcome.PASS

    def test_a_tight_blast_budget_fails_blast_radius(self) -> None:
        tight = _permissive(max_services_pct=1.0)
        report = _evaluate(Fixture(name="over-blast", budget=tight))
        outcomes = {check.scope: check.outcome for check in report.checks}
        assert outcomes[CheckScope.BLAST_RADIUS] is CheckOutcome.FAIL

    def test_an_exhausted_damage_quota_fails_the_damage_budget_check(self) -> None:
        """A per-fault ceiling the plan's own fault durations exceed.

        The quota rides on the :class:`SafetyContext` rather than as a check
        input, because that is where the gate reads it — a quota with no path to
        the engine would make this test prove nothing.
        """
        fixture = Fixture(name="no-budget")
        tight = DamageQuota(per_fault_ceiling_s=1.0)
        report = _evaluate(fixture, safety=fixture.safety(quota=tight))
        outcomes = {check.scope: check.outcome for check in report.checks}
        assert outcomes[CheckScope.DAMAGE_BUDGET] is CheckOutcome.FAIL

    def test_a_plan_with_no_fault_step_fails_the_syntax_check(self) -> None:
        empty = Fixture(name="wait-only")
        plan = ExecutionPlan(
            run_id="r-wait",
            kind=ExperimentKind.DETERMINISTIC,
            steps=(PlannedStep(id="s-wait", seq=0, raw_action=Wait(duration=5.0)),),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint=FP,
        )
        report = _evaluate(empty, plan=plan)
        assert report.check(cg.CHECK_NAME[CheckScope.SYNTAX]).outcome is CheckOutcome.FAIL

    def test_an_uncertified_fault_is_a_warning_not_a_failure(self) -> None:
        """Red on every PR until the whole catalog is certified is a red nobody reads."""
        report = _evaluate(Fixture(name="uncertified"))
        compat = report.check(cg.CHECK_NAME[CheckScope.FAULT_COMPATIBILITY])
        assert compat.outcome is CheckOutcome.PASS
        assert compat.finding is not None
        assert compat.finding.code == "check.fault-compatibility.uncertified"
        assert compat.finding.blocks is False

    def test_a_certified_fault_reports_no_warning(self) -> None:
        records = {
            fault_id: [_certified(fault_id)] for fault_id in ("proc.pause", "net.latency")
        }
        report = _evaluate(Fixture(name="certified"), certifications=records)
        compat = report.check(cg.CHECK_NAME[CheckScope.FAULT_COMPATIBILITY])
        assert compat.finding is None
        assert "2 of 2" in compat.detail

    def test_every_report_names_one_check_per_declared_scope_in_order(self) -> None:
        report = _evaluate(Fixture(name="clean"))
        assert [check.name for check in report.checks] == [
            cg.CHECK_NAME[scope] for scope in cg.CHECK_ORDER
        ]

    def test_two_evaluations_of_one_fixture_are_identical(self) -> None:
        """Determinism: the same PR twice is the same report, plan digest included."""
        fixture = Fixture(name="determinism")
        assert _evaluate(fixture).plan_digest == _evaluate(fixture).plan_digest
        assert _evaluate(fixture).evidence_refs == _evaluate(fixture).evidence_refs


def _catalog() -> list[Any]:
    from mayhem.domain.catalog import CATALOG

    return list(CATALOG)


def _certified(fault_id: str) -> CertificationRecord:
    from mayhem.domain.capabilities import Capability
    from mayhem.domain.certification import (
        BUNDLE_DIGEST_RE,
        REQUIRED_EVIDENCE_DIGESTS,
        Arch,
        EvidenceBundleRef,
        certify,
    )
    from mayhem.domain.faults import EngineLane

    assert BUNDLE_DIGEST_RE  # the shape the bundle ref below relies on
    pending = CertificationRecord(
        fault_id=fault_id,
        cell=MatrixCell(
            engine=EngineLane.PODMAN,
            engine_version="5.0",
            os_distro="debian12",
            kernel_version="6.1.0",
            arch=Arch.AMD64,
            capabilities=frozenset({Capability.NET_ADMIN}),
        ),
        injector_version="injector-1",
        expires_at=LATER,
        state=CertificationState.PENDING,
    )
    bundle = EvidenceBundleRef(
        bundle_hash="9" * 64,
        mayhem_version="1.1.0",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, "1" * 64),
    )
    return certify(
        pending,
        at=NOW,
        expires_at=LATER,
        evidence=(bundle,),
        outcome="injected effect observed, undo restored the baseline",
        injector_version="injector-1",
    ).model_copy(update={"state": CertificationState.CERTIFIED})


# ── the coverage check on a fixture PR ─────────────────────────────────────────


POSTGRES_CELL = CoverageCell(
    target="checkout", fault_kind="postgres_failure",
    execution_context="container", parameter_band="default",
)
TIMEOUT_CELL = CoverageCell(
    target="checkout", fault_kind="http_timeout",
    execution_context="container", parameter_band="default",
)


class TestCoverageOnAPullRequest:
    def _surface(self, **overrides: Any) -> CoverageSurface:
        fields: dict[str, Any] = {
            "service": "checkout",
            "cells": (POSTGRES_CELL, TIMEOUT_CELL),
        }
        fields.update(overrides)
        return CoverageSurface(**fields)

    def test_a_gap_is_a_warning_naming_the_gap(self) -> None:
        """The plan's own words: "checkout has no experiment covering PostgreSQL failure"."""
        check = cg.coverage_check(self._surface(covered=frozenset({TIMEOUT_CELL.key})))
        assert check.outcome is CheckOutcome.PASS
        assert check.finding is not None
        assert check.finding.code == "coverage.gap"
        assert "postgres_failure" in check.finding.message
        assert "1 of 2" in check.finding.message

    def test_lost_coverage_is_an_error_and_fails(self) -> None:
        check = cg.coverage_check(
            self._surface(covered=frozenset(), lost=(TIMEOUT_CELL,))
        )
        assert check.outcome is CheckOutcome.FAIL
        assert check.finding.severity.value == "error"

    def test_full_coverage_passes_with_no_finding(self) -> None:
        check = cg.coverage_check(
            self._surface(covered=frozenset({POSTGRES_CELL.key, TIMEOUT_CELL.key}))
        )
        assert check.outcome is CheckOutcome.PASS
        assert check.finding is None

    def test_a_coverage_number_cannot_be_computed_without_a_landscape(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            CoverageSurface(service="checkout", cells=())
        assert excinfo.value.rule == cg.RULE_COVERAGE_EMPTY_DENOMINATOR

    def test_a_cell_outside_the_landscape_cannot_be_counted(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            self._surface(covered=frozenset({"checkout/ghost/cell/default"}))
        assert excinfo.value.rule == cg.RULE_COVERAGE_UNKNOWN_KEY

    def test_the_summary_line_reads_n_of_m(self) -> None:
        assert "1 of 2" in self._surface(covered=frozenset({TIMEOUT_CELL.key})).describe()

    def test_negative_control_a_bare_fraction_is_representable_so_the_message_must_carry_it(
        self,
    ) -> None:
        """The control.

        ``CoverageSurface`` does expose ``fraction``, so nothing stops a renderer
        printing ``0.5``. What stops it is that ``describe()`` — the only string
        the summary calls — has no way to express a fraction. Asserting that the
        fraction exists while the sentence does not contain it is how a future
        renderer is caught before it reaches a pull request.
        """
        surface = self._surface(covered=frozenset({TIMEOUT_CELL.key}))
        assert surface.fraction == 0.5
        assert "%" not in surface.describe()
        assert surface.evidence_ref.endswith("1of2")


# ── fixture releases: the v2.4 → v2.5 tolerance regression ─────────────────────

LATENCY = ComparisonMetric(
    name="p95_latency_ms", kind=MetricKind.LATENCY, unit="ms", tolerance_pct=20.0
)
ERROR_RATE = ComparisonMetric(
    name="checkout_error_rate", kind=MetricKind.ERROR_RATE, unit="ratio", tolerance_pct=5.0
)
METRICS = (LATENCY, ERROR_RATE)


def _sample(metric: str, value: float) -> RunSample:
    return RunSample(metric=metric, value=value, samples=10)


def _v24(**metric_overrides: float) -> RunReport:
    """The baseline run: same pins as the candidate, one release behind.

    Only ``release`` and ``run_id`` move. The catalog, agent and runtime axes are
    held constant because
    :func:`~mayhem.domain.comparison.equivalent_pins` requires them to match —
    a v2.4 run on an older catalog is not comparable to a v2.5 run on the
    current one, and the comparison refuses rather than guessing which of the two
    differences explains the latency. That refusal is its own fixture below.
    """
    values = {"p95_latency_ms": 200.0, "checkout_error_rate": 0.02, **metric_overrides}
    return RunReport(
        pin=_pin(run_id="run-v24-0001", release="v2.4", evidence_digest="0" * 64),
        metrics=tuple(_sample(name, value) for name, value in values.items()),
    )


def _v25(**metric_overrides: float) -> RunReport:
    values = {"p95_latency_ms": 200.0, "checkout_error_rate": 0.02, **metric_overrides}
    return RunReport(
        pin=_pin(),
        metrics=tuple(_sample(name, value) for name, value in values.items()),
    )


def _suite_from(comparison: Any, *, name: str = "resilience.post-deploy") -> ResilienceSuite:
    """Plan 22's grade, as the release gate reads it.

    The mapping is the interesting part and it is deliberately one-way and total:
    a regression is a ``FAIL``, an ungraded or incomparable comparison is
    ``UNKNOWN`` with the reason attached, and anything else that scored is a
    ``PASS`` citing the two runs it compared. There is no branch here that
    produces a pass from a comparison that did not score — that is the property
    :meth:`TestReleaseGateOnFixtureReleases.test_an_ungraded_comparison_never_passes`
    exists to pin.
    """
    if comparison.regressed:
        return ResilienceSuite(
            name=name,
            outcome=CheckOutcome.FAIL,
            evidence_refs=(
                f"comparison/{comparison.baseline.label}",
                f"comparison/{comparison.candidate.label}",
            ),
            run=comparison.candidate,
            detail="; ".join(comparison.reasons),
        )
    if comparison.scored:
        return ResilienceSuite(
            name=name,
            outcome=CheckOutcome.PASS,
            evidence_refs=(
                f"comparison/{comparison.baseline.label}",
                f"comparison/{comparison.candidate.label}",
            ),
            run=comparison.candidate,
            detail=f"comparison graded {comparison.outcome.value}",
        )
    return ResilienceSuite(
        name=name,
        outcome=CheckOutcome.UNKNOWN,
        detail="; ".join(comparison.reasons) or f"comparison was {comparison.outcome.value}",
    )


def _passing_verdict(**overrides: Any) -> Any:
    """A pipeline verdict that gates, so the suites decide the release."""
    from mayhem.domain.pipeline import PipelineVerdict, PRCheck

    check = PRCheck(
        name=cg.CHECK_NAME[CheckScope.BLAST_RADIUS],
        scope=CheckScope.BLAST_RADIUS,
        outcome=CheckOutcome.PASS,
        evidence_refs=("check_blast_radius/staging",),
        detail="2 of 2 proof lines pass",
        observed_at=NOW,
    )
    fields: dict[str, Any] = {
        "outcome": "pass",
        "change": _link(),
        "evidence_refs": ("check_blast_radius/staging",),
        "checks": (check,),
        "cited_run": _pin(),
        "decided_at": NOW,
    }
    fields.update(overrides)
    return PipelineVerdict(**fields)


class TestReleaseGateOnFixtureReleases:
    def _request(
        self, kind: ChangeKind = ChangeKind.DEPLOYMENT, **overrides: Any
    ) -> ReleaseGateRequest:
        fields: dict[str, Any] = {
            "change": _link(),
            "kind": kind,
            "subject": "checkout v2.5",
        }
        fields.update(overrides)
        return ReleaseGateRequest(**fields)

    def test_the_plans_worked_example_a_tolerance_crossing_blocks_the_release(self) -> None:
        """v2.4 → v2.5 with a 30% latency rise against a 20% tolerance.

        This is the fixture the plan names. Everything upstream of the gate
        (equivalent pins, a graded comparison, a ``FAIL`` suite with a cited run)
        is real; the gate blocks because the comparison says the release made
        checkout slower.
        """
        comparison = compare(_v24(), _v25(p95_latency_ms=260.0), METRICS)
        assert comparison.regressed
        decision = release_gate(
            _passing_verdict(), self._request(), suites=[_suite_from(comparison)]
        )
        assert decision.decision == GATE_BLOCK
        assert decision.opens_release is False
        assert any("reported fail" in reason for reason in decision.reasons)

    def test_a_move_inside_the_tolerance_opens_the_release(self) -> None:
        comparison = compare(_v24(), _v25(p95_latency_ms=230.0), METRICS)
        assert not comparison.regressed
        assert comparison.scored
        decision = release_gate(
            _passing_verdict(), self._request(), suites=[_suite_from(comparison)]
        )
        assert decision.decision == GATE_ALLOW
        assert decision.opens_release is True
        assert decision.reasons == ()

    def test_an_ungraded_comparison_never_passes(self) -> None:
        """Insufficient data is unknown, and unknown blocks.

        The most dangerous shape in this file: a comparison that could not be
        graded is *not* a pass, and the suite it becomes is ``UNKNOWN`` with the
        reason attached rather than a ``PASS`` with a shrug.
        """
        comparison = compare(_v24(), _v25(), ())  # no declared metrics
        assert not comparison.scored
        suite = _suite_from(comparison)
        assert suite.outcome is CheckOutcome.UNKNOWN
        decision = release_gate(_passing_verdict(), self._request(), suites=[suite])
        assert decision.decision == GATE_BLOCK
        assert any("did not conclude" in reason for reason in decision.reasons)

    def test_an_incomparable_comparison_blocks(self) -> None:
        """Different pins: the comparison is refused, so nothing was established."""
        drifted = _v25(p95_latency_ms=260.0).model_copy(
            update={"pin": _pin(catalog_version="catalog-2026.10")}
        )
        incomparable = compare(_v24(), drifted, METRICS)
        assert not incomparable.scored
        decision = release_gate(
            _passing_verdict(), self._request(), suites=[_suite_from(incomparable)]
        )
        assert decision.decision == GATE_BLOCK

    @pytest.mark.parametrize(
        "kind",
        [ChangeKind.DEPLOYMENT, ChangeKind.DEPENDENCY, ChangeKind.INFRASTRUCTURE],
    )
    def test_each_trigger_owes_its_own_suite(self, kind: ChangeKind) -> None:
        """Three triggers, three different suites, read from one table."""
        request = self._request(kind)
        assert request.required_suites == cg.required_suites_for(kind)
        decision = release_gate(_passing_verdict(), request, suites=[])
        assert decision.decision == GATE_BLOCK
        assert any("did not report" in reason for reason in decision.reasons)

    def test_a_missing_suite_blocks_even_when_the_verdict_passes(self) -> None:
        decision = release_gate(_passing_verdict(), self._request(), suites=[])
        assert decision.decision == GATE_BLOCK
        assert "resilience.post-deploy" in " ".join(decision.reasons)

    def test_a_gate_that_allows_carries_its_evidence(self) -> None:
        comparison = compare(_v24(), _v25(p95_latency_ms=230.0), METRICS)
        decision = release_gate(
            _passing_verdict(), self._request(), suites=[_suite_from(comparison)]
        )
        assert decision.evidence_refs
        assert any(ref.startswith("comparison/") for ref in decision.evidence_refs)

    def test_a_blocking_pipeline_is_reported_separately_from_a_missing_suite(self) -> None:
        """Two diagnoses, two sentences.

        A gate that conflates "the pipeline never passed" with "the suite did not
        report" tells an operator to re-run a suite when the pipeline is the
        problem.
        """
        from mayhem.domain.pipeline import PipelineVerdict

        failing = PipelineVerdict(
            outcome="fail",
            change=_link(),
            evidence_refs=("check_blast_radius/staging",),
            checks=(),
            reasons=("the plan changed under the check",),
            decided_at=NOW,
        )
        decision = release_gate(failing, self._request(), suites=[])
        assert decision.decision == GATE_BLOCK
        assert decision.gate_reasons
        assert any("did not report" in reason for reason in decision.reasons)
        assert "the plan changed under the check" in decision.reasons

    def test_a_merge_that_moved_the_plan_invalidates_the_approvals(self) -> None:
        """The negative control the plan names, at the gate.

        The approvals were granted against the plan that was checked; the merge
        landed a different one. Every approval is invalidated, not just the ones
        whose digest happens to match.
        """
        comparison = compare(_v24(), _v25(p95_latency_ms=230.0), METRICS)
        approvals = (
            PlanApproval(approver="u-oncall", plan_digest="a" * 64, approved_at=NOW),
            PlanApproval(approver="u-sre", plan_digest="b" * 64, approved_at=NOW),
        )
        merge = PlanMerge(
            checked_plan_digest="a" * 64,
            merged_plan_digest="c" * 64,
            approvals=approvals,
            merged_at=LATER,
        )
        decision = release_gate(
            _passing_verdict(),
            self._request(merge=merge),
            suites=[_suite_from(comparison)],
        )
        assert decision.decision == GATE_BLOCK
        assert any("invalidated" in reason for reason in decision.reasons)
        assert gates_release(_passing_verdict(), merge) is False

    def test_an_unmerged_plan_leaves_the_approvals_standing(self) -> None:
        comparison = compare(_v24(), _v25(p95_latency_ms=230.0), METRICS)
        approvals = (PlanApproval(approver="u-oncall", plan_digest="a" * 64, approved_at=NOW),)
        merge = PlanMerge(
            checked_plan_digest="a" * 64, merged_plan_digest="a" * 64, approvals=approvals
        )
        decision = release_gate(
            _passing_verdict(),
            self._request(merge=merge),
            suites=[_suite_from(comparison)],
        )
        assert decision.decision == GATE_ALLOW

    def test_an_unpinned_change_link_cannot_back_the_gate(self) -> None:
        comparison = compare(_v24(), _v25(p95_latency_ms=230.0), METRICS)
        unpinned = _link(pins=PipelinePins(plan_version="plan-7"))
        decision = release_gate(
            _passing_verdict(change=unpinned),
            self._request(change=unpinned),
            suites=[_suite_from(comparison)],
        )
        assert decision.decision == GATE_BLOCK
        assert any("unpinned" in reason for reason in decision.reasons)


# ── negative controls ──────────────────────────────────────────────────────────


class TestNegativeControls:
    def test_negative_control_an_unreachable_plane_cannot_be_made_to_pass(self) -> None:
        """Control: the unreachable branch is short-circuited, and it matters.

        First the property: with an unreachable control plane every check is
        ``UNKNOWN`` and no gate ran at all. Then the mutation: stub
        :func:`~mayhem.controller.check_gate._unreachable_report` to return a
        report of *passing* checks. It succeeds — which proves the all-``UNKNOWN``
        answer comes from that short-circuit and not from some other property of
        the inputs, and that a regression which removed it would be invisible
        without this second half.
        """
        from mayhem.domain.pipeline import PRCheck

        inputs = cg.CheckInputs(
            plan=Fixture(name="unreachable").plan(),
            graph=Fixture(name="unreachable").graph(),
            safety=Fixture(name="unreachable").safety(),
            change=_link(),
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail="the api host did not resolve",
        )
        report = evaluate_pr_checks(inputs)
        assert {check.outcome for check in report.checks} == {CheckOutcome.UNKNOWN}
        assert report.compilation is None
        assert report.plan_digest == ""

        original = cg._unreachable_report
        try:
            cg._unreachable_report = lambda _inputs: cg.CheckReport(  # type: ignore[assignment]
                checks=(
                    PRCheck(
                        name=cg.CHECK_NAME[scope],
                        scope=scope,
                        outcome=CheckOutcome.PASS,
                        evidence_refs=("gate-output/fabricated",),
                        detail="looks fine",
                        observed_at=NOW,
                    )
                    for scope in cg.CHECK_ORDER
                ),
                change=inputs.change,
                cited_run=inputs.cited_run,
                plan_digest="e" * 64,
                control_plane=ControlPlaneReach.UNREACHABLE,
            )
            mutated = evaluate_pr_checks(inputs)
        finally:
            cg._unreachable_report = original  # type: ignore[assignment]

        assert all(check.is_pass for check in mutated.checks), (
            "with the short-circuit replaced, all-passing checks must be "
            "constructible — otherwise the UNKNOWN assertion above proves nothing"
        )

    def test_negative_control_a_pr_check_cannot_be_constructed_as_a_passing_unknown(
        self,
    ) -> None:
        """Control: the structural guard, not the engine's good intentions.

        An unreachable plane reporting ``PASS`` is refused by :class:`PRCheck`
        itself, so no engine bug can produce one. Proven by constructing it.
        """
        with pytest.raises(InvariantViolationError) as excinfo:
            cg.PRCheck(
                name="syntax",
                scope=CheckScope.SYNTAX,
                outcome=CheckOutcome.PASS,
                control_plane=ControlPlaneReach.UNREACHABLE,
                evidence_refs=("gate-output/fabricated",),
                detail="the network was down",
            )
        assert excinfo.value.rule == "pipeline.unreachable_check_concluded"

    def test_negative_control_stubbing_the_merge_comparison_restores_the_approvals(
        self,
    ) -> None:
        """Control: the digests really are what invalidates the approvals.

        Two merges, otherwise identical, and the only difference between them is
        which digest the approval was granted against. With both approvals bound
        to the merged plan, the real :attr:`PlanMerge.changed` says the plan
        moved and invalidates them anyway — a plan that changed invalidates
        *every* approval, not just the mismatched ones, which is the rule Phase 1
        states and this assertion pins. Stub :attr:`PlanMerge.changed` to
        ``False`` and the same merge invalidates nothing and the gate opens.

        Without the stub the assertion could be resting on the approval digests
        rather than on the comparison, and the invalidation test above would
        still pass. That is the whole reason the control exists.
        """
        suite = _suite_from(compare(_v24(), _v25(p95_latency_ms=230.0), METRICS))
        merged_digest = "c" * 64
        approvals = (
            PlanApproval(approver="u-oncall", plan_digest=merged_digest, approved_at=NOW),
            PlanApproval(approver="u-sre", plan_digest=merged_digest, approved_at=NOW),
        )
        merge = PlanMerge(
            checked_plan_digest="a" * 64,
            merged_plan_digest=merged_digest,
            approvals=approvals,
            merged_at=LATER,
        )
        request = ReleaseGateRequest(
            change=_link(), kind=ChangeKind.DEPLOYMENT, subject="checkout v2.5", merge=merge
        )

        # The real rule: the plan moved, so both approvals are invalidated even
        # though their digests match what merged.
        assert merge.changed is True
        assert len(merge.invalidated) == 2
        assert release_gate(_passing_verdict(), request, suites=[suite]).decision == GATE_BLOCK

        original = PlanMerge.changed
        try:
            PlanMerge.changed = property(lambda self: False)  # type: ignore[assignment]
            assert merge.invalidated == ()
            assert merge.approvals_stand is True
            decision = release_gate(_passing_verdict(), request, suites=[suite])
        finally:
            PlanMerge.changed = original  # type: ignore[assignment]
        assert decision.decision == GATE_ALLOW, (
            "with the comparison stubbed, the approvals must stand and the gate must "
            "open — otherwise the invalidation assertion above proves nothing"
        )

    def test_negative_control_removing_the_validation_lets_an_evidence_free_allow(
        self,
    ) -> None:
        """Control: the refusal is an enforcement, not a convention.

        ``ReleaseGateDecision`` refuses to *be* an allow without evidence, and
        refuses again while any required suite has not passed. The control takes
        pydantic's own escape hatch — :meth:`ReleaseGateDecision.model_construct`,
        which skips every validator — and builds exactly the decision the
        constructor refuses.

        This is the strongest statement available from inside the test: not that
        the caller was careful, but that with the validation removed there is
        nothing left standing between an empty evidence set and an open release.
        """
        request = ReleaseGateRequest(
            change=_link(), kind=ChangeKind.DEPLOYMENT, subject="checkout v2.5"
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            ReleaseGateDecision(
                kind=ChangeKind.DEPLOYMENT,
                subject="checkout v2.5",
                decision=GATE_ALLOW,
                evidence_refs=(),
            )
        assert excinfo.value.rule == RULE_ALLOW_WITHOUT_EVIDENCE

        with pytest.raises(InvariantViolationError) as suite_excinfo:
            ReleaseGateDecision(
                kind=request.kind,
                subject=request.subject,
                decision=GATE_ALLOW,
                evidence_refs=("evidence/1",),
                required_suites=request.required_suites,
                suites=(),
            )
        assert suite_excinfo.value.rule == RULE_ALLOW_WITHOUT_EVIDENCE

        unvalidated = ReleaseGateDecision.model_construct(
            kind=request.kind,
            subject=request.subject,
            decision=GATE_ALLOW,
            evidence_refs=(),
            required_suites=request.required_suites,
            suites=(),
            reasons=(),
        )
        assert unvalidated.opens_release is True, (
            "with validation skipped, an evidence-free allow must be constructible — "
            "otherwise the refusal above is not what stopped it"
        )

    def test_a_gate_that_allows_needs_both_evidence_and_a_passing_suite(self) -> None:
        """The positive half: the legitimate allow, with both halves satisfied."""
        request = ReleaseGateRequest(
            change=_link(), kind=ChangeKind.DEPLOYMENT, subject="checkout v2.5"
        )
        suite = _suite_from(compare(_v24(), _v25(p95_latency_ms=230.0), METRICS))
        decision = ReleaseGateDecision(
            kind=request.kind,
            subject=request.subject,
            decision=GATE_ALLOW,
            evidence_refs=(*suite.evidence_refs, "check_blast_radius/staging"),
            required_suites=request.required_suites,
            suites=(suite,),
            verdict_digest="a" * 64,
        )
        assert decision.opens_release is True

    def test_negative_control_a_block_without_a_reason_cannot_be_built(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ReleaseGateDecision(
                kind=ChangeKind.DEPLOYMENT,
                subject="checkout v2.5",
                decision=GATE_BLOCK,
            )
        assert excinfo.value.rule == cg.RULE_BLOCK_WITHOUT_REASON

    def test_negative_control_a_resilience_pass_with_no_run_cannot_be_built(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ResilienceSuite(
                name="resilience.post-deploy",
                outcome=CheckOutcome.PASS,
                evidence_refs=("evidence/1",),
            )
        assert excinfo.value.rule == cg.RULE_SUITE_WITHOUT_RUN

    def test_negative_control_an_unknown_suite_must_explain_itself(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ResilienceSuite(name="resilience.post-deploy", outcome=CheckOutcome.UNKNOWN)
        assert excinfo.value.rule == cg.RULE_SUITE_UNKNOWN_UNEXPLAINED


# ── ChatOps authorization, end to end from a channel binding ───────────────────


STAGING = EnvironmentScope(environment="staging", project="checkout")
OPERATOR = Principal(principal_id="sa-ops-bot", kind=PrincipalKind.SERVICE_ACCOUNT)
PERSON = Principal(principal_id="u-oncall", kind=PrincipalKind.HUMAN)


class _RecordingValidator:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, request: Any) -> Any:
        self.calls.append(request)
        return _passing_verdict()


class _RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    def send(self, receipt: Any) -> None:
        self.sent.append(receipt)


class TestChatOpsAuthorizationEndToEnd:
    def _bot(self, *grants: RoleGrant) -> Any:
        from mayhem.controller.chatops import ChannelBinding, ChatOpsBot

        bot = ChatOpsBot(principals={"U-OPS": OPERATOR, "U-HUMAN": PERSON}, grants=list(grants))
        bot.bind(ChannelBinding(channel_id="C-OPS", scope=STAGING))
        return bot

    def test_an_authorized_run_reaches_validation_once(self) -> None:
        grant = _RoleGrant(
            role=Role.EXECUTE, scope=STAGING, principal=OPERATOR, granted_at=NOW
        )
        validator, transport = _RecordingValidator(), _RecordingTransport()
        outcome, _ = self._bot(grant).dispatch(
            _chat_message("mayhem run run-ci-0001"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome.value == "dispatched"
        assert len(validator.calls) == 1
        assert len(transport.sent) == 1

    def test_an_unauthorized_approve_never_reaches_validation(self) -> None:
        """The ordering, through the bot rather than through the seam."""
        grant = _RoleGrant(
            role=Role.EXECUTE, scope=STAGING, principal=OPERATOR, granted_at=NOW
        )
        validator, transport = _RecordingValidator(), _RecordingTransport()
        outcome, detail = self._bot(grant).dispatch(
            _chat_message("mayhem approve run-ci-0001"),
            transport=transport,
            validate=validator,
            now=NOW,
        )
        assert outcome.value == "refused"
        assert validator.calls == []
        assert "approve" in detail

    def test_every_chatops_command_is_gated_by_the_engines_own_table(self) -> None:
        """The matrix is data, so this iterates rather than restates it."""
        validator = _RecordingValidator()
        for command, role in cg.CHATOPS_REQUIRED_ROLE.items():
            grant = _RoleGrant(role=role, scope=STAGING, principal=OPERATOR, granted_at=NOW)
            outcome, _ = self._bot(grant).dispatch(
                _chat_message(f"mayhem {command.value} run-ci-0001"),
                transport=_RecordingTransport(),
                validate=validator,
                now=NOW,
            )
            assert outcome.value == "dispatched", command
        assert len(validator.calls) == len(ChatOpsCommand)


def _chat_message(text: str) -> Any:
    from mayhem.controller.chatops import ChatMessage

    return ChatMessage(channel_id="C-OPS", author_id="U-OPS", text=text)
