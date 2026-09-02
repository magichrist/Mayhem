"""Three-locus execution context tests (ADR-M3-3)."""

from __future__ import annotations

from mayhem.domain.execution_context import ExecutionContext, ExecutionContextSpec
from mayhem.domain.execution_loci import (
    Locus,
    LocusSpec,
    ThreeLocusContext,
)
from mayhem.domain.experiments import PlannedFault


def test_from_single_host() -> None:
    ctx = ThreeLocusContext.from_single(ExecutionContext.HOST)
    assert ctx.target_locus.kind == Locus.LOCAL
    assert ctx.agent_locus.kind == Locus.LOCAL
    assert ctx.tool_locus.kind == Locus.LOCAL
    assert ctx.plan_context == ExecutionContext.HOST


def test_from_single_remote_host() -> None:
    ctx = ThreeLocusContext.from_single(ExecutionContext.REMOTE_HOST)
    assert ctx.target_locus.kind == Locus.REMOTE
    assert ctx.agent_locus.kind == Locus.REMOTE
    assert ctx.tool_locus.kind == Locus.REMOTE


def test_from_single_container() -> None:
    ctx = ThreeLocusContext.from_single(ExecutionContext.CONTAINER)
    assert ctx.target_locus.kind == Locus.CONTAINER
    assert ctx.agent_locus.kind == Locus.CONTAINER
    assert ctx.tool_locus.kind == Locus.CONTAINER


def test_from_single_network_namespace() -> None:
    ctx = ThreeLocusContext.from_single(ExecutionContext.NETWORK_NAMESPACE)
    assert ctx.target_locus.kind == Locus.NETWORK_NAMESPACE
    # agent and tool run locally to manipulate the namespace
    assert ctx.agent_locus.kind == Locus.LOCAL
    assert ctx.tool_locus.kind == Locus.LOCAL


def test_from_single_remote_container() -> None:
    ctx = ThreeLocusContext.from_single(ExecutionContext.REMOTE_CONTAINER)
    assert ctx.target_locus.kind == Locus.CONTAINER
    assert ctx.agent_locus.kind == Locus.REMOTE
    assert ctx.tool_locus.kind == Locus.REMOTE


def test_from_single_matches_plan_context() -> None:
    for ctx in ExecutionContext:
        three = ThreeLocusContext.from_single(ctx)
        assert three.plan_context == ctx


def test_locus_spec_identifier_optional() -> None:
    spec = LocusSpec(kind=Locus.CONTAINER)
    assert spec.identifier is None
    spec2 = LocusSpec(kind=Locus.CONTAINER, identifier="abc")
    assert spec2.identifier == "abc"


def test_plan_context_spec_bridge() -> None:
    spec = ExecutionContextSpec(context=ExecutionContext.NETWORK_NAMESPACE)
    three = spec.to_three_locus()
    assert isinstance(three, ThreeLocusContext)
    assert three.target_locus.kind == Locus.NETWORK_NAMESPACE


def test_plannedfault_optional_loci_field() -> None:
    # A PlannedFault with no loci is fine (backward compatible).
    f = PlannedFault(
        fault_id="f-1",
        targets=(),
        duration=5,
    )
    assert f.execution_loci is None

    # A PlannedFault carrying the three-locus dict round-trips.
    loci: dict[str, object] = {"target": "container:svc-lb", "agent": "local", "tool": "local"}
    f2 = PlannedFault(
        fault_id="f-2",
        targets=(),
        duration=5,
        execution_loci=loci,
    )
    assert f2.execution_loci == loci
