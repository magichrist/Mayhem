"""The check-evaluation and release-gating engine — plan 16 Phase 2 (gaps 43, 46, 47, 103).

Why this file exists
--------------------
Phase 1 built the vocabulary; this phase is the thing that produces it, and every
failure mode it can have is a *silent* one. A check that re-implements a gate
agrees with the real gate on the happy path and drifts on the first rule it
forgot. A release gate that treats "no evidence" as "no problem" opens a release
on the strength of a suite nobody ran. A ChatOps path that validates first and
authorizes second lets an unauthorized approver reach the same code a CLI
operator reaches. A coverage warning that prints "12%" without its denominator is
indistinguishable from a coverage number.

So the tests are grouped as:

* **the engine reads the real gate.** Not by re-deriving the gate's answer, but
  by running ``validate_plan`` and asserting the check agrees with the proof the
  compiler built from it — over a matrix of refusals (blast, damage, capability,
  environment, compensation), one case per check scope, plus the agreement
  property that ``compiler_refusals <= what the checks report``.
* **release gates fail closed.** Every branch that blocks is exercised: no
  evidence, an unknown suite, a failing suite, a merged plan that moved, an
  unpinned run. And the decision object refuses to be *constructed* into an allow
  without evidence, which is the property a test cannot reach any other way.
* **coverage numbers carry their denominator.** Asserted on the rendered message
  and on the serialised payload, not on an internal field.
* **ChatOps authorization.** The requester is bound, an unauthorized principal is
  refused, and the refusal happens *before* the injected validator is called —
  with a fake transport and a recording validator, no Slack client.
* **the negative controls the plan names.** Unreachable control plane reports
  unknown and never pass; an unpinned run cannot gate; a merged plan that differs
  from the checked plan invalidates every approval; a catalog-only or uncertified
  fault is never reported as runtime-certified; a gate cannot allow without
  evidence.
* **the honest-reporting rule.** Every runtime state the check vocabulary may
  print is a state the certification module defines, asserted against that module
  rather than a copy of it.

The last two tests restate two laws where they are enforced: this module may not
re-implement a gate (``OBLIGATION_FOR_RULE`` covers every rule ``RULE_CHECK``
claims), and nothing here reads a clock or a store.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller import check_gate
from mayhem.controller import check_gate as cg
from mayhem.controller.policy_gate import RULE_BUNDLE_DENY
from mayhem.controller.safety import SafetyContext, validate_plan
from mayhem.controller.safety_proof import OBLIGATION_FOR_RULE
from mayhem.domain.certification import (
    BUNDLE_DIGEST_RE,
    REQUIRED_EVIDENCE_DIGESTS,
    CertificationRecord,
    CertificationState,
    MatrixCell,
    certify,
)
from mayhem.domain.comparison import RunPin
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
    Role,
    RoleGrant,
    TeamMembership,
)
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.pipeline import (
    REQUIRED_PINS,
    ChangeLink,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    FindingSeverity,
    PipelinePins,
    PipelineVerdict,
    PlanApproval,
    PlanMerge,
    PRCheck,
)
from mayhem.domain.quota import DamageQuota
from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityVerdict,
    RuntimeAdapter,
    VerdictResult,
)
from mayhem.domain.safety_proof import ProofVerdict
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

# ── fixtures ───────────────────────────────────────────────────────────────────

FP = "f" * 64
OTHER_FP = "e" * 64
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
RUN_DIGEST = "0" * 64
BUNDLE_DIGEST = "9" * 64
CELL_FP = "checkout-failure@service"

CHECKOUT_POSTGRES = CoverageCell(
    target="checkout",
    fault_kind="postgres_failure",
    execution_context="container",
    parameter_band="default",
)
CHECKOUT_TIMEOUT = CoverageCell(
    target="checkout",
    fault_kind="http_timeout",
    execution_context="container",
    parameter_band="default",
)
PAYMENT_DNS = CoverageCell(
    target="payment",
    fault_kind="dns_failure",
    execution_context="kubernetes",
    parameter_band="default",
)


def _graph() -> TopologyGraph:
    """Three independent services on one host, plus one dependency edge."""
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _permissive(**overrides: Any) -> BlastRadiusBudget:
    """Per-step limits no test trips by accident unless it means to."""
    fields: dict[str, Any] = {
        "max_services_pct": 100.0,
        "max_hosts": 2**31 - 1,
        "max_concurrent_faults": 2**31 - 1,
        "max_duration_per_fault_s": float("inf"),
        "forbidden_fault_pairs": frozenset(),
    }
    fields.update(overrides)
    return BlastRadiusBudget(**fields)


def _ctx(
    budget: BlastRadiusBudget | None = None,
    *,
    fingerprint: str = FP,
    quota: DamageQuota | None = None,
) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=budget or _permissive(),
        fingerprint=fingerprint,
        damage_quota=quota or DamageQuota(),
    )


def _plan(
    fault_ids: tuple[str, ...] = ("proc.pause", "net.latency"),
    durations: tuple[float, ...] = (10.0, 10.0),
    *,
    fingerprint: str = FP,
    compensate: bool = True,
) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    steps: list[PlannedStep] = []
    for index, (fault_id, duration) in enumerate(zip(fault_ids, durations, strict=True)):
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
                    undo_ops=(UndoOp(op="tc.del_qdisc"),) if compensate else (),
                    verify_probes=(
                        (VerifyProbe(probe="tc.qdisc_absent"),) if compensate else ()
                    ),
                ),
            )
        )
    return ExecutionPlan(
        run_id="r-check",
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=fingerprint,
    )


def _no_fault_plan() -> ExecutionPlan:
    return ExecutionPlan(
        run_id="r-empty",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(PlannedStep(id="s-wait", seq=0, raw_action=Wait(duration=5.0)),),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


class _Adapter(RuntimeAdapter):
    """A fake runtime that answers capability questions on demand."""

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
        verdict = (
            CapabilityVerdict.UNSUPPORTED if self.blocking else CapabilityVerdict.SUPPORTED
        )
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
        "evidence_digest": RUN_DIGEST,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _link(**overrides: Any) -> ChangeLink:
    fields: dict[str, Any] = {
        "git_sha": "a1b2c3d",
        "change_ticket": "CH-1421",
        "pins": PipelinePins.from_run(_pin()),
        "linked_at": NOW,
    }
    fields.update(overrides)
    return ChangeLink(**fields)


def _inputs(**overrides: Any) -> cg.CheckInputs:
    fields: dict[str, Any] = {
        "plan": _plan(),
        "graph": _graph(),
        "safety": _ctx(),
        "change": _link(),
        "cited_run": _pin(),
        "adapter": _Adapter(),
    }
    fields.update(overrides)
    return cg.CheckInputs(**fields)


def _matrix_cell() -> MatrixCell:
    from mayhem.domain.capabilities import Capability
    from mayhem.domain.certification import Arch
    from mayhem.domain.faults import EngineLane

    return MatrixCell(
        engine=EngineLane.PODMAN,
        engine_version="5.0",
        os_distro="debian12",
        kernel_version="6.1.0",
        arch=Arch.AMD64,
        capabilities=frozenset({Capability.NET_ADMIN}),
    )


def _bundle_ref() -> Any:
    from mayhem.domain.certification import EvidenceBundleRef

    return EvidenceBundleRef(
        bundle_hash=BUNDLE_DIGEST,
        mayhem_version="1.1.0",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, "1" * 64),
    )


def _pending_record(fault_id: str = "proc.pause") -> CertificationRecord:
    return CertificationRecord(
        fault_id=fault_id,
        cell=_matrix_cell(),
        injector_version="injector-1",
        expires_at=NOW + timedelta(days=30),
        state=CertificationState.PENDING,
    )


def _certified_record(
    fault_id: str = "proc.pause",
    *,
    state: CertificationState = CertificationState.CERTIFIED,
) -> CertificationRecord:
    return certify(
        _pending_record(fault_id),
        at=NOW,
        expires_at=NOW + timedelta(days=30),
        evidence=(_bundle_ref(),),
        outcome="injected effect observed, undo restored the baseline",
        injector_version="injector-1",
    ).model_copy(update={"state": state})


def _surface(**overrides: Any) -> cg.CoverageSurface:
    fields: dict[str, Any] = {
        "service": "checkout",
        "cells": (CHECKOUT_POSTGRES, CHECKOUT_TIMEOUT),
    }
    fields.update(overrides)
    return cg.CoverageSurface(**fields)


def _clean_report(**overrides: Any) -> cg.CheckReport:
    return cg.evaluate_pr_checks(_inputs(**overrides))


# ── the attribution tables are complete ────────────────────────────────────────


def test_every_rule_the_proof_compiler_can_blame_has_an_exactly_one_check() -> None:
    """A rule no check reports is a refusal nobody sees. Total by construction."""
    table_keys = set(cg.RULE_CHECK)
    for rule in OBLIGATION_FOR_RULE:
        assert rule in table_keys, f"{rule} is blamed by the compiler but no check reports it"
    # Plus three plan-contract lines that carry no rule of their own.
    assert set(OBLIGATION_FOR_RULE.values()) <= set(cg.OBLIGATION_CHECK)


def test_an_unknown_rule_id_is_routed_rather_than_dropped() -> None:
    """A bundle authors its own rule ids, so 'which check' cannot be enumerated."""
    assert cg.check_for_rule("checkout.blocklist_v3") is cg.DEFAULT_RULE_CHECK
    assert cg.DEFAULT_RULE_CHECK is CheckScope.SAFETY_POLICY


def test_every_named_obligation_belongs_to_a_check() -> None:
    from mayhem.domain.safety_proof import REQUIRED_OBLIGATIONS

    assert set(cg.OBLIGATION_CHECK) == set(REQUIRED_OBLIGATIONS)


def test_a_check_is_named_once_and_its_name_is_unique_in_a_report() -> None:
    report = _clean_report()
    names = [check.name for check in report.checks]
    assert len(set(names)) == len(names)
    assert names == [cg.CHECK_NAME[scope] for scope in cg.CHECK_ORDER]


def test_the_rendering_tables_have_no_syntax_scope_of_their_own() -> None:
    """``syntax`` is not a gate scope, so it owns no obligation and no rule."""
    assert CheckScope.SYNTAX not in cg.OBLIGATION_CHECK.values()
    assert CheckScope.SYNTAX not in cg.RULE_CHECK.values()


# ── per-check evaluation ───────────────────────────────────────────────────────


def test_a_clean_plan_passes_every_check_and_proves_a_safety_case() -> None:
    report = _clean_report()

    assert [check.outcome for check in report.checks] == [CheckOutcome.PASS] * 6
    assert report.proven
    assert report.compilation is not None
    assert report.compilation.proof.verdict is ProofVerdict.PASS
    assert report.void_reason == ""
    assert report.blocking == ()


def test_a_passing_check_cites_the_gate_output_it_was_read_from() -> None:
    """Citations name the gate that produced them, not the check that read it."""
    report = _clean_report()

    for check in report.checks:
        assert check.evidence_refs, check.name
        for ref in check.evidence_refs:
            assert ref.strip(), check.name
    blast = report.check("blast-radius")
    assert blast is not None
    assert any("check_blast_radius" in ref for ref in blast.evidence_refs)
    syntax = report.check("syntax")
    assert syntax is not None
    assert syntax.evidence_refs == (f"plan-digest/{report.plan_digest}",)


def test_a_blast_radius_breach_is_reported_on_the_blast_radius_check_alone() -> None:
    report = cg.evaluate_pr_checks(
        _inputs(safety=_ctx(_permissive(max_concurrent_faults=1)))
    )

    blast = report.check("blast-radius")
    assert blast is not None
    assert blast.outcome is CheckOutcome.FAIL
    assert blast.finding is not None
    assert blast.finding.severity is FindingSeverity.ERROR
    assert "max_concurrent_faults" in blast.detail
    # The scopes that own their own lines still pass: attribution is per-line,
    # and blaming every check for the proof's global verdict is what makes a
    # reader stop trusting the one that matters.
    for other in ("target", "safety-policy", "damage-budget"):
        check = report.check(other)
        assert check is not None and check.is_pass, other
    assert not report.proven


def test_a_damage_budget_breach_is_reported_on_the_damage_budget_check() -> None:
    report = cg.evaluate_pr_checks(
        _inputs(safety=_ctx(_permissive(max_duration_per_fault_s=5.0)))
    )

    budget = report.check("damage-budget")
    assert budget is not None
    assert budget.outcome is CheckOutcome.FAIL
    assert "damage" in budget.detail.lower() or "max_duration" in budget.detail


def test_an_unsupported_capability_is_reported_on_fault_compatibility_alone() -> None:
    report = cg.evaluate_pr_checks(_inputs(adapter=_BlockingAdapter()))

    compat = report.check("fault-compatibility")
    assert compat is not None
    assert compat.outcome is CheckOutcome.FAIL
    assert compat.finding is not None
    assert compat.finding.severity is FindingSeverity.ERROR
    assert report.check("blast-radius") is not None
    assert report.check("blast-radius").is_pass  # type: ignore[union-attr]


def test_a_missing_capability_adapter_does_not_pass_vacuously() -> None:
    """``validate_plan`` skips the capability check without one, so the line is
    VOID — and a check that reported it as pass would be claiming a check nobody
    ran."""
    report = cg.evaluate_pr_checks(_inputs(adapter=None))

    compat = report.check("fault-compatibility")
    assert compat is not None
    assert compat.outcome is CheckOutcome.FAIL
    assert "capability_requirements" in compat.detail
    assert not report.proven


def test_an_environment_fingerprint_mismatch_is_reported_on_the_target_check() -> None:
    report = cg.evaluate_pr_checks(_inputs(safety=_ctx(fingerprint=OTHER_FP)))

    target = report.check("target")
    assert target is not None
    assert target.outcome is CheckOutcome.FAIL
    assert "fingerprint" in target.detail.lower()


def test_a_plan_without_compensation_is_reported_on_safety_policy() -> None:
    """``compensation``/``recovery_path``/``stop_conditions`` have no Phase-2 row
    of their own, so safety-policy is where they surface. Hiding them would be
    the exact failure the engine exists to prevent."""
    report = cg.evaluate_pr_checks(_inputs(plan=_plan(compensate=False)))

    policy = report.check("safety-policy")
    assert policy is not None
    assert policy.outcome is CheckOutcome.FAIL
    assert "compensation" in policy.detail
    assert "recovery_path" in policy.detail


def test_a_plan_with_no_fault_step_is_refused_rather_than_vacuously_passing() -> None:
    report = cg.evaluate_pr_checks(_inputs(plan=_no_fault_plan()))

    syntax = report.check("syntax")
    assert syntax is not None
    assert syntax.outcome is CheckOutcome.FAIL
    assert "no fault step" in syntax.detail
    assert not report.proven
    assert "max_concurrent_faults" in report.void_reason


def test_a_check_agrees_with_the_proof_it_was_read_from() -> None:
    """The engine cannot be stricter or kinder than the path it reads.

    The comparison is against the *real* gate rather than a hand-written
    expectation list: the engine must report at least every refusal
    ``validate_plan`` makes, and the refusal set it publishes must be a superset
    of the compiler's. Over a matrix, not a single case — an engine that quietly
    re-derived "what the gate would say" would agree on the happy path.
    """
    cases: list[cg.CheckInputs] = [
        _inputs(),
        _inputs(plan=_plan(compensate=False)),
        _inputs(safety=_ctx(_permissive(max_concurrent_faults=1))),
        _inputs(safety=_ctx(_permissive(max_services_pct=0.5))),
        _inputs(
            safety=_ctx(
                _permissive(
                    forbidden_fault_pairs=frozenset({frozenset({"proc.pause", "net.latency"})})
                )
            )
        ),
        _inputs(adapter=_BlockingAdapter()),
        _inputs(adapter=None),
        _inputs(safety=_ctx(fingerprint=OTHER_FP)),
        _inputs(plan=_plan(fingerprint=OTHER_FP)),
        _inputs(plan=_no_fault_plan()),
    ]
    for inputs in cases:
        report = cg.evaluate_pr_checks(inputs)
        compilation = report.compilation
        assert compilation is not None
        refused_by_gate = _gate_refusals(inputs)
        # validate_plan's own refusals are inside the compiler's set.
        assert refused_by_gate <= set(compilation.compiler_refusals)
        # And every one of them lands on a check that failed.
        failed = {check.scope for check in report.checks if not check.is_pass}
        for rule in refused_by_gate:
            assert cg.check_for_rule(rule) in failed, (
                f"{rule} was refused by validate_plan but no check failed"
            )
        # And a clean compile means a clean pipeline: no scope invented a
        # problem the gate did not find.
        if not compilation.compiler_refusals and compilation.proof.verdict is ProofVerdict.PASS:
            assert report.blocking == (), [c.detail for c in report.blocking]


def _probe(safety: SafetyContext) -> SafetyContext:
    """A throwaway context so the agreement check does not pollute the caller's."""
    from dataclasses import replace

    return replace(safety, decisions=[], warnings=[])


def _gate_refusals(inputs: cg.CheckInputs) -> set[str]:
    """Rule ids the real ``validate_plan`` refuses on, run on a throwaway context."""
    from mayhem.controller.safety import SafetyRefusedError

    try:
        validate_plan(inputs.plan, inputs.graph, _probe(inputs.safety))
    except SafetyRefusedError as exc:
        return {exc.decision.rule_id} if exc.decision is not None else {exc.reason_code}
    except Exception:
        return set()
    return set()


def test_the_checks_cannot_reach_the_gate_without_running_it() -> None:
    """Six checks, one compilation: no scope calls a gate a second time."""
    report = _clean_report()
    assert report.compilation is not None
    assert report.compilation.gate_refusals == ()
    assert len(report.compilation.proof.obligations) == 9


def test_a_check_with_no_cited_gate_output_cannot_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """No fabricated reference. Strip every blast-radius line out of the
    attribution table and the check must *fail* on the missing citation rather
    than pass on a synthesised ``gate-output/...`` string, which would read as
    cited while leading nowhere."""
    stripped = {
        name: owning
        for name, owning in cg.OBLIGATION_CHECK.items()
        if owning is not CheckScope.BLAST_RADIUS
    }
    monkeypatch.setattr(cg, "OBLIGATION_CHECK", stripped)

    report = _clean_report()
    blast = report.check("blast-radius")

    assert blast is not None
    assert blast.outcome is CheckOutcome.FAIL
    assert blast.evidence_refs == ()
    assert blast.finding is not None
    assert blast.finding.severity is FindingSeverity.ERROR
    assert "no evidence behind it and cannot pass" in blast.detail


def test_a_coverage_surface_is_still_reported_over_an_unreachable_plane() -> None:
    """The surface was read before the plane went away, so reporting it is
    honest — and a *lost* cell is a fact, not a guess, even while everything
    else is unknown."""
    report = cg.evaluate_pr_checks(
        _inputs(
            coverage=(_surface(lost=(CHECKOUT_POSTGRES,)),),
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail="connection refused",
        )
    )

    gate_checks = report.by_scope(CheckScope.BLAST_RADIUS)
    assert gate_checks and gate_checks[0].outcome is CheckOutcome.UNKNOWN
    lost = report.check("coverage:checkout")
    assert lost is not None
    assert lost.outcome is CheckOutcome.FAIL
    assert report.compilation is None


def test_evaluating_a_pr_does_not_touch_the_callers_safety_record() -> None:
    """The compiler probes on clones; a PR evaluation must not append preview
    decisions to the record a real run is judged by."""
    safety = _ctx()
    before = list(safety.decisions)

    cg.evaluate_pr_checks(_inputs(safety=safety))

    assert safety.decisions == before


# ── negative control: an unreachable control plane is UNKNOWN, never PASS ─────


def test_an_unreachable_control_plane_reports_unknown_and_never_concludes() -> None:
    report = cg.evaluate_pr_checks(
        _inputs(
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail="control plane at mayhem.internal:8443 did not answer in 30s",
        )
    )

    assert report.control_plane is ControlPlaneReach.UNREACHABLE
    assert report.compilation is None
    assert report.blocking == report.checks
    for check in report.checks:
        assert check.outcome is CheckOutcome.UNKNOWN, check.name
        assert not check.is_pass
        assert not check.conclusive
        assert check.control_plane is ControlPlaneReach.UNREACHABLE
        assert "did not answer in 30s" in check.detail
        assert "unknown, never pass" in check.detail


def test_an_unreachable_control_plane_ran_no_gate() -> None:
    """The short-circuit is structural: a half-reachable plane cannot make a
    check pass by answering the cheap half of the path."""
    report = cg.evaluate_pr_checks(
        _inputs(
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail="connection refused",
        )
    )

    assert report.compilation is None
    assert report.void_reason == ""
    assert not report.proven
    assert report.evidence_refs == ()


def test_an_unreachable_control_plane_yields_no_verdict_rather_than_a_forged_one() -> None:
    """Unknown checks carry no evidence, so there is nothing to cite and no
    verdict to build. Inventing a reference to get one is the forgery Phase 1
    refuses, and this module refuses to route around it."""
    report = cg.evaluate_pr_checks(
        _inputs(
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail="connection refused",
        )
    )

    with pytest.raises(InvariantViolationError) as excinfo:
        report.verdict()

    assert excinfo.value.rule == "pipeline.verdict_without_evidence"


def test_an_unreachable_control_plane_must_say_why() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _inputs(
            control_plane=ControlPlaneReach.UNREACHABLE,
            control_plane_detail="   ",
        )

    assert excinfo.value.rule == cg.RULE_UNKNOWN_UNEXPLAINED


def test_the_engine_cannot_construct_a_conclusion_over_an_unreachable_plane() -> None:
    """Belt and braces: even asked directly, ``PRCheck`` refuses."""
    with pytest.raises(InvariantViolationError) as excinfo:
        PRCheck(
            name="safety-policy",
            scope=CheckScope.SAFETY_POLICY,
            outcome=CheckOutcome.PASS,
            control_plane=ControlPlaneReach.UNREACHABLE,
            detail="connection refused",
        )

    assert excinfo.value.rule == "pipeline.unreachable_check_concluded"


# ── negative control: an unpinned run cannot gate a release ────────────────────


@pytest.mark.parametrize("blanked", REQUIRED_PINS)
def test_an_unpinned_link_blocks_the_release_gate_however_green_the_pipeline_is(
    blanked: str,
) -> None:
    pins = {axis: f"{axis}-v1" for axis in REQUIRED_PINS}
    pins[blanked] = ""
    report = _clean_report()
    verdict = report.verdict()

    unpinned = _verdict_for(report, change=_link(pins=PipelinePins(**pins)))
    assert unpinned.outcome.value == "pass"
    decision = cg.release_gate(
        unpinned,
        cg.ReleaseGateRequest(
            change=_link(pins=PipelinePins(**pins)),
            kind=cg.ChangeKind.DEPLOYMENT,
            subject="dpl-77",
        ),
        suites=(_passing_suite(),),
    )

    assert not decision.opens_release
    assert decision.decision == cg.GATE_BLOCK
    assert any(blanked in reason for reason in decision.reasons)
    assert any("cannot back a release-gate decision" in reason for reason in decision.reasons)
    assert verdict.outcome.value == "pass"  # the pipeline itself was green


def _verdict_for(report: cg.CheckReport, *, change: ChangeLink) -> PipelineVerdict:
    """The same checks, graded against a different change link."""
    return PipelineVerdict.decide(
        change,
        report.checks,
        cited_run=report.cited_run,
        decided_at=NOW,
    )


# ── negative control: a merged plan that moved invalidates approvals ───────────


def test_a_merged_plan_differing_from_the_checked_one_blocks_the_release() -> None:
    """Including the approvals whose digest happens to match the merged plan: an
    approval granted against a plan nobody ran approves nothing."""
    report = _clean_report()
    verdict = report.verdict()
    merge = PlanMerge(
        checked_plan_digest="a" * 64,
        merged_plan_digest="b" * 64,
        approvals=(
            PlanApproval(approver="ana", plan_digest="a" * 64, approved_at=NOW),
            PlanApproval(approver="bo", plan_digest="b" * 64, approved_at=NOW),
        ),
        merged_at=NOW + timedelta(minutes=5),
    )

    decision = cg.release_gate(
        verdict,
        cg.ReleaseGateRequest(
            change=_link(),
            kind=cg.ChangeKind.INFRASTRUCTURE,
            subject="cluster-eu-1 node-pool",
            merge=merge,
        ),
        suites=(_passing_suite(),),
    )

    assert not decision.opens_release
    assert decision.decision == cg.GATE_BLOCK
    assert any("approves nothing" in reason for reason in decision.reasons)
    assert any(reason in decision.gate_reasons for reason in decision.reasons)


def test_an_unchanged_merge_leaves_the_approvals_standing() -> None:
    report = _clean_report()
    verdict = report.verdict()
    merge = PlanMerge(
        checked_plan_digest="a" * 64,
        merged_plan_digest="a" * 64,
        approvals=(PlanApproval(approver="ana", plan_digest="a" * 64, approved_at=NOW),),
        merged_at=NOW,
    )

    decision = cg.release_gate(
        verdict,
        cg.ReleaseGateRequest(
            change=_link(),
            kind=cg.ChangeKind.DEPENDENCY,
            subject="postgres 15 -> 16",
            merge=merge,
        ),
        suites=(_passing_suite("resilience.dependency-failure"),),
    )

    assert decision.opens_release


# ── coverage: the number carries its denominator ───────────────────────────────


def test_a_coverage_gap_is_reported_with_the_denominator_on_the_same_surface() -> None:
    surface = _surface()
    check = cg.coverage_check(surface)

    assert check.outcome is CheckOutcome.PASS
    assert check.finding is not None
    assert check.finding.severity is FindingSeverity.WARNING
    assert not check.finding.blocks
    assert check.finding.cell == CHECKOUT_POSTGRES
    assert "checkout has no experiment covering postgres_failure" in check.finding.message
    assert "0 of 2" in check.finding.message
    assert f"{surface.denominator}" in check.finding.message
    assert "denominator" not in check.finding.message  # stated as a count, not a word
    assert "0 of 2" in check.detail


def test_the_denominator_travels_with_the_coverage_payload() -> None:
    payload = _surface().to_dict()

    assert payload["denominator"] == 2
    assert payload["covered"] == 0
    assert "0 of 2" in payload["statement"]
    assert payload["fraction"] == 0.0


def test_partial_coverage_states_the_denominator_too() -> None:
    surface = _surface(covered=frozenset({CHECKOUT_POSTGRES.key}))
    check = cg.coverage_check(surface)

    assert surface.numerator == 1
    assert surface.fraction == 0.5
    assert check.finding is not None
    assert "1 of 2" in check.finding.message
    assert check.detail.startswith("1 of 2 declared cells uncovered")
    assert check.detail.endswith("(checkout: 1 of 2 declared resilience cells covered)")


def test_full_coverage_is_a_clean_pass_with_its_denominator_in_the_detail() -> None:
    surface = _surface(covered=frozenset({CHECKOUT_POSTGRES.key, CHECKOUT_TIMEOUT.key}))
    check = cg.coverage_check(surface)

    assert check.is_pass
    assert check.finding is None
    assert "2 of 2" in check.detail


def test_a_coverage_landscape_with_no_denominator_is_refused() -> None:
    """'None of nothing covered' is how an untested service reports 100%."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _surface(cells=())

    assert excinfo.value.rule == cg.RULE_COVERAGE_EMPTY_DENOMINATOR
    assert "denominator" in str(excinfo.value)


def test_a_coverage_key_outside_the_landscape_is_refused() -> None:
    """Counting a cell the landscape does not contain would push the numerator
    past the denominator — the one arithmetic a coverage report must never do."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _surface(covered=frozenset({PAYMENT_DNS.key}))

    assert excinfo.value.rule == cg.RULE_COVERAGE_UNKNOWN_KEY


def test_a_repeated_cell_is_refused_because_a_cell_has_one_place_in_the_ratio() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _surface(cells=(CHECKOUT_POSTGRES, CHECKOUT_POSTGRES))

    assert excinfo.value.rule == cg.RULE_COVERAGE_UNKNOWN_KEY


def test_lost_coverage_is_an_error_because_a_regression_is_not_a_known_gap() -> None:
    surface = _surface(
        covered=frozenset({CHECKOUT_POSTGRES.key, CHECKOUT_TIMEOUT.key}),
        lost=(CHECKOUT_TIMEOUT,),
    )
    check = cg.coverage_check(surface)

    assert check.outcome is CheckOutcome.FAIL
    assert check.finding is not None
    assert check.finding.severity is FindingSeverity.ERROR
    assert check.finding.code == "coverage.lost"
    assert "lost coverage" in check.finding.message
    assert "2 of 2" in check.finding.message


def test_coverage_surfaces_join_the_report_with_unique_names() -> None:
    report = cg.evaluate_pr_checks(
        _inputs(coverage=(_surface(), _surface(service="payment", cells=(PAYMENT_DNS,))))
    )

    names = [check.name for check in report.checks if check.scope is CheckScope.COVERAGE]
    assert names == ["coverage:checkout", "coverage:payment"]
    assert len(set(names)) == len(names)


def test_a_coverage_gap_does_not_fail_the_pipeline() -> None:
    report = cg.evaluate_pr_checks(_inputs(coverage=(_surface(),)))
    verdict = report.verdict()

    assert verdict.outcome.value == "pass"
    coverage = report.check("coverage:checkout")
    assert coverage is not None and coverage.is_pass
    assert coverage.finding is not None and not coverage.finding.blocks


def test_a_lost_coverage_cell_does_fail_the_pipeline() -> None:
    report = cg.evaluate_pr_checks(
        _inputs(coverage=(_surface(lost=(CHECKOUT_POSTGRES,)),))
    )
    verdict = report.verdict()

    blocking = report.blocking
    assert verdict.outcome.value == "fail"
    assert [check.name for check in blocking] == ["coverage:checkout"]
    assert blocking[0].finding is not None
    assert blocking[0].finding.code == "coverage.lost"
    assert "lost coverage" in verdict.reasons[0]


# ── certification states a check may report ────────────────────────────────────


def test_every_reportable_state_is_a_state_the_record_store_holds() -> None:
    """Asserted against the certification module, not a copy of it."""
    recorded = {state.value for state in CertificationState}

    assert cg.REPORTABLE_STATES - {"unverified"} == recorded
    assert cg.REPORTABLE_STATES - recorded == {"unverified"}


def test_a_catalog_only_fault_is_never_reported_as_runtime_certified() -> None:
    from mayhem.domain.catalog import definition_for

    catalog_only = next(
        definition for definition in _catalog_only_definitions()
    )
    assert catalog_only.catalog_only

    # Even handed a live record, a catalog-only fault cannot claim it.
    claim = cg.claim_for_fault(catalog_only, (_certified_record(catalog_only.id),))

    assert claim.state is cg.RuntimeFaultState.UNVERIFIED
    assert claim.live is False
    assert claim.catalog_only
    assert claim.runtime_certified is False
    assert definition_for(catalog_only.id).id == catalog_only.id


def _catalog_only_definitions() -> tuple[Any, ...]:
    from mayhem.domain.catalog import CATALOG

    found = tuple(definition for definition in CATALOG if definition.catalog_only)
    assert found, "the catalog-only refusal path is untested if this is empty"
    return found


@pytest.mark.parametrize(
    ("state", "live"),
    [
        (cg.RuntimeFaultState.CERTIFIED, False),
        (cg.RuntimeFaultState.EXPIRING, False),
        (cg.RuntimeFaultState.UNVERIFIED, True),
        (cg.RuntimeFaultState.PENDING, True),
    ],
)
def test_a_live_claim_cannot_be_constructed_outside_a_record_state(
    state: cg.RuntimeFaultState,
    live: bool,
) -> None:
    """The state and the flag are one statement; a disagreement is malformed."""
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.FaultClaim(
            fault_id="proc.pause",
            state=state,
            live=live,
            evidence_refs=("certification:proc.pause@cell",),
        )

    assert excinfo.value.rule == cg.RULE_CLAIM_WITHOUT_RECORD
    assert "cannot disagree" in str(excinfo.value)


def test_a_catalog_only_fault_cannot_be_given_a_live_claim() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.FaultClaim(
            fault_id="proc.pause",
            state=cg.RuntimeFaultState.CERTIFIED,
            live=True,
            catalog_only=True,
            evidence_refs=("certification:proc.pause@cell",),
        )

    assert excinfo.value.rule == cg.RULE_CLAIM_WITHOUT_RECORD


def test_a_live_claim_with_no_evidence_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.FaultClaim(fault_id="proc.pause", state=cg.RuntimeFaultState.CERTIFIED, live=True)

    assert excinfo.value.rule == cg.RULE_CLAIM_WITHOUT_RECORD
    assert "badge" in str(excinfo.value)


def test_an_expiring_record_still_counts_as_a_current_claim_and_is_named_as_expiring() -> None:
    from mayhem.domain.catalog import definition_for

    claim = cg.claim_for_fault(
        definition_for("proc.pause"),
        (_certified_record("proc.pause", state=CertificationState.EXPIRING),),
    )

    assert claim.state is cg.RuntimeFaultState.EXPIRING
    assert claim.live is True
    assert claim.runtime_certified is True
    assert claim.evidence_refs


def test_a_lapsed_record_is_reported_as_lapsed_not_as_never_verified() -> None:
    from mayhem.domain.catalog import definition_for

    lapsed = _certified_record("proc.pause").model_copy(
        update={"state": CertificationState.STALE, "reason": "expired at the deadline"}
    )
    claim = cg.claim_for_fault(definition_for("proc.pause"), (lapsed,))

    assert claim.state is cg.RuntimeFaultState.STALE
    assert claim.live is False
    assert claim.runtime_certified is False


def test_no_record_at_all_is_unverified_which_is_not_the_same_as_stale() -> None:
    from mayhem.domain.catalog import definition_for

    claim = cg.claim_for_fault(definition_for("proc.pause"), ())

    assert claim.state is cg.RuntimeFaultState.UNVERIFIED
    assert not claim.state.record_backed
    assert claim.state is not cg.RuntimeFaultState.STALE


def test_an_uncertified_fault_is_a_warning_on_a_passing_check() -> None:
    """A check red on every PR until the whole catalog is certified is a check
    people learn to ignore. The lie is reported the other way round."""
    report = cg.evaluate_pr_checks(_inputs(certifications={"proc.pause": (), "net.latency": ()}))

    compat = report.check("fault-compatibility")
    assert compat is not None
    assert compat.is_pass
    assert compat.finding is not None
    assert compat.finding.severity is FindingSeverity.WARNING
    assert compat.finding.code == "check.fault-compatibility.uncertified"
    assert "unverified" in compat.finding.message
    assert "2 of 2" in compat.finding.message


def test_a_certified_fault_clears_the_warning() -> None:
    report = cg.evaluate_pr_checks(
        _inputs(
            certifications={
                "proc.pause": (_certified_record("proc.pause"),),
                "net.latency": (_certified_record("net.latency"),),
            }
        )
    )

    compat = report.check("fault-compatibility")
    assert compat is not None
    assert compat.is_pass
    assert compat.finding is None
    assert "2 of 2 planned faults hold a live certification record" in compat.detail


def test_a_catalog_only_fault_in_a_plan_fails_the_compatibility_check() -> None:
    catalog_only = _catalog_only_definitions()[0]
    report = cg.evaluate_pr_checks(
        _inputs(
            plan=_plan(fault_ids=(catalog_only.id,), durations=(10.0,)),
        )
    )

    compat = report.check("fault-compatibility")
    assert compat is not None
    assert compat.outcome is CheckOutcome.FAIL
    assert compat.finding is not None
    assert compat.finding.severity is FindingSeverity.ERROR
    assert "catalog-only" in compat.finding.message
    syntax = report.check("syntax")
    assert syntax is not None and syntax.outcome is CheckOutcome.FAIL


def test_a_certification_record_requires_sha256_evidence_to_exist() -> None:
    """The states a check may print are only as trustworthy as the store behind
    them; a record with a non-digest bundle hash cannot be constructed."""
    from mayhem.domain.certification import EvidenceBundleRef

    assert BUNDLE_DIGEST_RE.fullmatch(_bundle_ref().bundle_hash)
    with pytest.raises(ValueError, match="64 lowercase hex characters"):
        EvidenceBundleRef(
            bundle_hash="z" * 64,
            mayhem_version="1.1.0",
            digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, "1" * 64),
        )


# ── release gates ──────────────────────────────────────────────────────────────


def _passing_suite(name: str = "resilience.post-deploy") -> cg.ResilienceSuite:
    return cg.ResilienceSuite(
        name=name,
        outcome=CheckOutcome.PASS,
        evidence_refs=("bundle:sha-abc",),
        run=_pin(),
    )


def _gate(**overrides: Any) -> cg.ReleaseGateRequest:
    fields: dict[str, Any] = {
        "change": _link(),
        "kind": cg.ChangeKind.DEPLOYMENT,
        "subject": "dpl-77",
    }
    fields.update(overrides)
    return cg.ReleaseGateRequest(**fields)


@pytest.mark.parametrize(
    ("kind", "suite"),
    [
        (cg.ChangeKind.DEPLOYMENT, "resilience.post-deploy"),
        (cg.ChangeKind.DEPENDENCY, "resilience.dependency-failure"),
        (cg.ChangeKind.INFRASTRUCTURE, "resilience.infrastructure-drift"),
    ],
)
def test_each_trigger_owes_its_own_resilience_suite(kind: cg.ChangeKind, suite: str) -> None:
    """Gap 103: suites are attached to deployments, dependency changes, and
    infrastructure changes — three triggers, three different suites."""
    assert cg.required_suites_for(kind) == (suite,)

    verdict = _clean_report().verdict()
    decision = cg.release_gate(verdict, _gate(kind=kind))

    assert not decision.opens_release
    assert any(suite in reason for reason in decision.reasons)
    assert decision.required_suites == (suite,)

    with_suite = cg.release_gate(verdict, _gate(kind=kind), suites=(_passing_suite(suite),))
    assert with_suite.opens_release
    assert f"run/{_pin().label}" in with_suite.evidence_refs


def test_a_gate_with_no_evidence_blocks_rather_than_allowing() -> None:
    verdict = _clean_report().verdict()

    decision = cg.release_gate(verdict, _gate())

    assert decision.decision == cg.GATE_BLOCK
    assert not decision.opens_release
    assert decision.reasons
    assert any("no evidence" in reason for reason in decision.reasons)


def test_an_unknown_suite_blocks_and_names_why_it_did_not_conclude() -> None:
    verdict = _clean_report().verdict()
    suite = cg.ResilienceSuite(
        name="resilience.post-deploy",
        outcome=CheckOutcome.UNKNOWN,
        detail="the runner queue was empty; nothing was executed",
    )

    decision = cg.release_gate(verdict, _gate(), suites=(suite,))

    assert not decision.opens_release
    assert any("did not conclude" in reason for reason in decision.reasons)
    assert any("runner queue was empty" in reason for reason in decision.reasons)


def test_a_failing_suite_fails_the_pipeline() -> None:
    """Plan 16's acceptance criterion, decided by Phase 1's types."""
    verdict = _clean_report().verdict()
    suite = cg.ResilienceSuite(
        name="resilience.post-deploy",
        outcome=CheckOutcome.FAIL,
        evidence_refs=("bundle:sha-abc",),
        run=_pin(),
        detail="p99 checkout latency rose 340% against a 10% tolerance",
    )

    decision = cg.release_gate(verdict, _gate(), suites=(suite,))

    assert not decision.opens_release
    assert any("340%" in reason for reason in decision.reasons)


def test_an_unknown_check_in_the_pipeline_blocks_the_gate() -> None:
    """An unknown check is not a soft pass, so it is not a soft block."""
    verdict = PipelineVerdict.decide(
        _link(),
        (
            _clean_report().checks[0],
            PRCheck(
                name="safety-policy",
                scope=CheckScope.SAFETY_POLICY,
                outcome=CheckOutcome.UNKNOWN,
                control_plane=ControlPlaneReach.UNREACHABLE,
                detail="control plane did not answer in 30s",
            ),
        ),
        cited_run=_pin(),
        decided_at=NOW,
    )

    decision = cg.release_gate(verdict, _gate(), suites=(_passing_suite(),))

    assert not decision.opens_release
    assert any("reported unknown" in reason for reason in decision.reasons)


def test_a_suite_that_passes_with_no_evidence_cannot_be_built() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ResilienceSuite(name="resilience.post-deploy", outcome=CheckOutcome.PASS)

    assert excinfo.value.rule == cg.RULE_SUITE_WITHOUT_EVIDENCE


def test_a_suite_that_passes_with_no_run_cannot_be_built() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ResilienceSuite(
            name="resilience.post-deploy",
            outcome=CheckOutcome.PASS,
            evidence_refs=("bundle:sha-abc",),
        )

    assert excinfo.value.rule == cg.RULE_SUITE_WITHOUT_RUN
    assert "cannot be compared across a release" in str(excinfo.value)


def test_an_unknown_suite_must_say_why() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ResilienceSuite(
            name="resilience.post-deploy", outcome=CheckOutcome.UNKNOWN, detail="  "
        )

    assert excinfo.value.rule == cg.RULE_SUITE_UNKNOWN_UNEXPLAINED


def test_a_gate_cannot_be_constructed_into_an_allow_without_evidence() -> None:
    """The property a runtime test cannot otherwise reach: 'allow' is not a value
    this object can hold with nothing behind it."""
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ReleaseGateDecision(
            kind=cg.ChangeKind.DEPLOYMENT,
            subject="dpl-77",
            decision=cg.GATE_ALLOW,
            required_suites=("resilience.post-deploy",),
            suites=(_passing_suite(),),
        )

    assert excinfo.value.rule == cg.RULE_ALLOW_WITHOUT_EVIDENCE
    assert "not a decision, it is a default" in str(excinfo.value)


def test_a_gate_cannot_be_constructed_into_an_allow_with_a_suite_that_did_not_run() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ReleaseGateDecision(
            kind=cg.ChangeKind.DEPLOYMENT,
            subject="dpl-77",
            decision=cg.GATE_ALLOW,
            evidence_refs=("bundle:sha-abc",),
            required_suites=("resilience.post-deploy",),
            suites=(),
        )

    assert excinfo.value.rule == cg.RULE_ALLOW_WITHOUT_EVIDENCE


def test_a_gate_cannot_be_constructed_into_an_allow_while_naming_reasons() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ReleaseGateDecision(
            kind=cg.ChangeKind.DEPLOYMENT,
            subject="dpl-77",
            decision=cg.GATE_ALLOW,
            evidence_refs=("bundle:sha-abc",),
            reasons=("something was wrong",),
            required_suites=(),
        )

    assert excinfo.value.rule == cg.RULE_ALLOW_WITHOUT_EVIDENCE


def test_a_gate_cannot_be_constructed_into_a_block_that_says_nothing() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ReleaseGateDecision(
            kind=cg.ChangeKind.DEPLOYMENT,
            subject="dpl-77",
            decision=cg.GATE_BLOCK,
        )

    assert excinfo.value.rule == cg.RULE_BLOCK_WITHOUT_REASON


def test_a_gate_decision_must_be_one_of_two_words() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        cg.ReleaseGateDecision(
            kind=cg.ChangeKind.DEPLOYMENT,
            subject="dpl-77",
            decision="probably",
            reasons=("unclear",),
        )

    assert excinfo.value.rule == cg.RULE_BLOCK_WITHOUT_REASON


def test_a_gate_must_name_the_change_it_is_deciding_about() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _gate(subject="  ")

    assert excinfo.value.rule == cg.RULE_BLOCK_WITHOUT_REASON


def test_a_gate_records_which_part_blocked_and_cites_what_it_read() -> None:
    verdict = _clean_report().verdict()
    merge = PlanMerge(
        checked_plan_digest="a" * 64,
        merged_plan_digest="b" * 64,
        approvals=(PlanApproval(approver="ana", plan_digest="a" * 64, approved_at=NOW),),
        merged_at=NOW,
    )

    decision = cg.release_gate(
        verdict, _gate(merge=merge), suites=(_passing_suite(),)
    )

    payload = decision.to_dict()
    assert payload["decision"] == cg.GATE_BLOCK
    assert payload["opens_release"] is False
    assert payload["verdict_digest"] == verdict.verdict_digest()
    assert payload["suites"][0]["run"] == _pin().label
    assert payload["gate_reasons"]
    assert "bundle:sha-abc" in payload["evidence_refs"]


def test_a_gate_allows_with_cited_evidence_when_everything_passes() -> None:
    verdict = _clean_report().verdict()

    decision = cg.release_gate(verdict, _gate(), suites=(_passing_suite(),))

    assert decision.opens_release
    assert decision.reasons == ()
    assert decision.gate_reasons == ()
    assert "bundle:sha-abc" in decision.evidence_refs
    assert f"run/{_pin().label}" in decision.evidence_refs
    assert verdict.evidence_refs[0] in decision.evidence_refs


def test_a_suite_joins_a_verdict_as_a_resilience_check() -> None:
    suite = _passing_suite()
    check = suite.as_check()

    assert check.scope is CheckScope.RESILIENCE
    assert check.is_pass
    assert check.evidence_refs == ("bundle:sha-abc",)

    verdict = PipelineVerdict.decide(
        _link(), (check,), cited_run=_pin(), decided_at=NOW
    )
    assert verdict.resilient

    failing = cg.ResilienceSuite(
        name="resilience.post-deploy",
        outcome=CheckOutcome.FAIL,
        detail="checkout error rate doubled",
    ).as_check()
    assert not failing.is_pass
    assert failing.finding is not None
    assert failing.finding.severity is FindingSeverity.ERROR


def test_a_gate_can_demand_more_than_the_default_suite_list() -> None:
    verdict = _clean_report().verdict()
    request = _gate(suites=("resilience.post-deploy", "resilience.soak"))

    decision = cg.release_gate(verdict, request, suites=(_passing_suite(),))

    assert not decision.opens_release
    assert any("resilience.soak" in reason for reason in decision.reasons)


# ── ChatOps authorization ──────────────────────────────────────────────────────


def _principal(principal_id: str = "u-ana") -> Principal:
    return Principal(principal_id=principal_id, display_name="Ana")


def _scope() -> EnvironmentScope:
    return EnvironmentScope(environment="staging", project="checkout")


def _grant(role: Role, principal: Principal, *, scope: EnvironmentScope | None = None) -> RoleGrant:
    return RoleGrant(
        role=role,
        scope=scope or _scope(),
        principal=principal,
        granted_at=NOW,
    )


class _RecordingTransport:
    """The three-line fake that stands in for a Slack client."""

    def __init__(self) -> None:
        self.sent: list[cg.ChatOpsReceipt] = []

    def send(self, receipt: cg.ChatOpsReceipt) -> None:
        self.sent.append(receipt)


class _RecordingValidator:
    """Stands in for the CLI validation entry point and records what it saw."""

    def __init__(self, verdict: PipelineVerdict) -> None:
        self._verdict = verdict
        self.calls: list[cg.ChatOpsRequest] = []

    def __call__(self, request: cg.ChatOpsRequest) -> PipelineVerdict:
        self.calls.append(request)
        return self._verdict


def _request(
    principal: Principal,
    command: cg.ChatOpsCommand = cg.ChatOpsCommand.APPROVE,
) -> cg.ChatOpsRequest:
    return cg.ChatOpsRequest(
        command=command,
        requester=principal,
        environment=_scope(),
        text=f"{command.value} {principal.principal_id}",
        run_id="r-check",
    )


def test_an_authorized_chat_command_dispatches_and_is_bound_to_the_requester() -> None:
    principal = _principal()
    transport = _RecordingTransport()
    validator = _RecordingValidator(_clean_report().verdict())

    receipt = cg.dispatch_chatops(
        _request(principal),
        transport=transport,
        validate=validator,
        grants=(_grant(Role.APPROVE, principal),),
        now=NOW,
    )

    assert receipt.requester == "u-ana"
    assert receipt.command is cg.ChatOpsCommand.APPROVE
    assert receipt.roles == ("approve",)
    assert receipt.verdict_digest
    assert transport.sent == [receipt]
    assert validator.calls == [_request(principal)]


def test_an_unauthorized_principal_is_refused_and_never_reaches_validation() -> None:
    """The security property, in order: refuse at the door, not downstream."""
    intruder = _principal("u-mallory")
    transport = _RecordingTransport()
    validator = _RecordingValidator(_clean_report().verdict())

    with pytest.raises(cg.ChatOpsRefusedError) as excinfo:
        cg.dispatch_chatops(
            _request(intruder),
            transport=transport,
            validate=validator,
            grants=(_grant(Role.APPROVE, _principal("u-ana")),),
            now=NOW,
        )

    assert excinfo.value.rule == cg.RULE_CHATOPS_NOT_AUTHORIZED
    assert excinfo.value.requester == "u-mallory"
    assert excinfo.value.required == "approve"
    assert excinfo.value.held == ()
    assert validator.calls == []
    assert transport.sent == []


@pytest.mark.parametrize(
    ("command", "role"),
    [
        (cg.ChatOpsCommand.RUN, Role.EXECUTE),
        (cg.ChatOpsCommand.APPROVE, Role.APPROVE),
        (cg.ChatOpsCommand.STOP, Role.EMERGENCY_STOP),
    ],
)
def test_every_chat_command_needs_its_own_role(command: cg.ChatOpsCommand, role: Role) -> None:
    """One table, three refusals: holding another command's role is not enough."""
    assert cg.CHATOPS_REQUIRED_ROLE[command] is role
    principal = _principal()
    transport = _RecordingTransport()
    validator = _RecordingValidator(_clean_report().verdict())
    others = tuple(r for r in (Role.EXECUTE, Role.APPROVE, Role.EMERGENCY_STOP) if r is not role)

    with pytest.raises(cg.ChatOpsRefusedError) as excinfo:
        cg.dispatch_chatops(
            _request(principal, command),
            transport=transport,
            validate=validator,
            grants=tuple(_grant(other, principal) for other in others),
            now=NOW,
        )

    assert excinfo.value.rule == cg.RULE_CHATOPS_NOT_AUTHORIZED
    assert excinfo.value.held == tuple(sorted(other.value for other in others))
    assert validator.calls == []


def test_an_empty_grant_set_refuses_everything() -> None:
    """Default-deny: no grants means no roles."""
    principal = _principal()
    validator = _RecordingValidator(_clean_report().verdict())

    with pytest.raises(cg.ChatOpsRefusedError) as excinfo:
        cg.dispatch_chatops(
            _request(principal, cg.ChatOpsCommand.STOP),
            transport=_RecordingTransport(),
            validate=validator,
            now=NOW,
        )

    assert excinfo.value.held == ()
    assert "no roles" in str(excinfo.value)


def test_a_grant_in_another_environment_does_not_authorize_this_one() -> None:
    """RBAC layered on the environment boundary, not a second authorization
    system: ``EnvironmentScope.covers`` is the only rule and it is not re-derived."""
    principal = _principal()
    validator = _RecordingValidator(_clean_report().verdict())

    with pytest.raises(cg.ChatOpsRefusedError):
        cg.dispatch_chatops(
            _request(principal),
            transport=_RecordingTransport(),
            validate=validator,
            grants=(
                _grant(Role.APPROVE, principal, scope=EnvironmentScope(environment="production")),
            ),
            now=NOW,
        )

    assert validator.calls == []


def test_a_team_grant_authorizes_through_an_active_membership() -> None:
    principal = _principal()
    transport = _RecordingTransport()
    validator = _RecordingValidator(_clean_report().verdict())

    receipt = cg.dispatch_chatops(
        _request(principal),
        transport=transport,
        validate=validator,
        grants=(
            RoleGrant(role=Role.APPROVE, scope=_scope(), team_id="t-sre", granted_at=NOW),
        ),
        memberships=(
            TeamMembership(principal=principal, team_id="t-sre", joined_at=NOW),
        ),
        now=NOW,
    )

    assert receipt.requester == "u-ana"
    assert transport.sent == [receipt]


def test_a_disabled_principal_holds_nothing() -> None:
    """The revoked-approver control as a rule rather than a check somebody has to
    remember to add."""
    principal = _principal().model_copy(update={"disabled": True})
    validator = _RecordingValidator(_clean_report().verdict())

    with pytest.raises(cg.ChatOpsRefusedError):
        cg.dispatch_chatops(
            _request(principal),
            transport=_RecordingTransport(),
            validate=validator,
            grants=(_grant(Role.APPROVE, principal),),
            now=NOW,
        )

    assert validator.calls == []


def test_an_authorized_command_is_still_refused_when_the_shared_validation_blocks() -> None:
    """Authorized is necessary, not sufficient: the chat path runs the CLI's own
    verdict and reads its blocking reasons."""
    principal = _principal()
    transport = _RecordingTransport()
    blocked = PipelineVerdict.decide(
        _link(pins=PipelinePins()),
        (_clean_report().checks[0],),
        cited_run=_pin(),
        decided_at=NOW,
    )
    validator = _RecordingValidator(blocked)

    with pytest.raises(cg.ChatOpsRefusedError) as excinfo:
        cg.dispatch_chatops(
            _request(principal),
            transport=transport,
            validate=validator,
            grants=(_grant(Role.APPROVE, principal),),
            now=NOW,
        )

    assert excinfo.value.rule == cg.RULE_CHATOPS_VALIDATION_REFUSED
    assert "cannot back a release-gate decision" in str(excinfo.value)
    assert validator.calls  # the validator ran; only the identity gate short-circuits
    assert transport.sent == []


def test_a_chat_receipt_carries_the_verdicts_evidence_not_a_yes() -> None:
    principal = _principal()
    validator = _RecordingValidator(_clean_report().verdict())

    receipt = cg.dispatch_chatops(
        _request(principal),
        transport=_RecordingTransport(),
        validate=validator,
        grants=(_grant(Role.APPROVE, principal),),
        now=NOW,
    )

    assert receipt.evidence_refs
    assert len(receipt.verdict_digest) == 64
    payload = receipt.to_dict()
    assert payload["requester"] == "u-ana"
    assert payload["roles"] == ["approve"]
    assert payload["evidence_refs"]


def test_the_chat_ops_vocabulary_is_closed() -> None:
    assert set(cg.CHATOPS_REQUIRED_ROLE) == set(cg.ChatOpsCommand)
    with pytest.raises(ValueError, match="not_a_command"):
        cg.ChatOpsCommand("not_a_command")


def test_the_chatops_transport_is_a_seam_and_not_an_implementation() -> None:
    """No Slack client, and no accidental network: the seam is one method."""
    assert hasattr(cg.ChatOpsTransport, "send")
    methods = {
        name
        for name in vars(cg.ChatOpsTransport)
        if not name.startswith("_")
    }
    assert methods == {"send"}


# ── the module's own laws, restated where they live ────────────────────────────


def test_the_module_imports_no_clock_reading_or_io_helper() -> None:
    source = open(check_gate.__file__, encoding="utf-8").read()  # noqa: SIM115, PTH123
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    forbidden = {"time", "socket", "requests", "httpx", "urllib", "subprocess", "sqlite3"}
    assert not {name.split(".")[0] for name in imported} & forbidden


def test_the_module_reads_no_clock_of_its_own() -> None:
    """``now`` is an argument wherever a decision needs one, so replaying a
    decision reproduces it."""
    source = open(check_gate.__file__, encoding="utf-8").read()  # noqa: SIM115, PTH123
    for forbidden in ("utc_now(", "datetime.now(", "time.time("):
        assert forbidden not in source


def test_the_module_does_not_shell_out_to_a_validation_of_its_own() -> None:
    """``dispatch_chatops`` requires a validator; there is no second one."""
    import inspect

    signature = inspect.signature(cg.dispatch_chatops)
    assert signature.parameters["validate"].default is inspect.Parameter.empty
    assert signature.parameters["now"].default is inspect.Parameter.empty
    assert signature.parameters["transport"].default is inspect.Parameter.empty


def test_the_engine_cites_the_policy_gate_it_read_rather_than_reimplementing_it() -> None:
    """The refusal ids it attributes come from the compiler's own vocabulary."""
    assert RULE_BUNDLE_DENY in cg.RULE_CHECK
    for rule in cg.RULE_CHECK:
        assert isinstance(rule, str) and rule
    assert set(cg.RULE_CHECK.values()) <= set(CheckScope)
