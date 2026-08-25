"""Tests for the execution context model (ADR-0014)."""

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_context import (
    ExecutionContext,
    ExecutionContextSpec,
    infer_context_for_node,
)
from mayhem.domain.topology import NodeKind


class TestExecutionContextEnum:
    def test_all_values_exist(self) -> None:
        assert set(ExecutionContext) == {
            ExecutionContext.HOST,
            ExecutionContext.CONTAINER,
            ExecutionContext.PROCESS,
            ExecutionContext.NETWORK_NAMESPACE,
            ExecutionContext.REMOTE_HOST,
            ExecutionContext.REMOTE_CONTAINER,
        }

    def test_string_round_trip(self) -> None:
        for ctx in ExecutionContext:
            assert ExecutionContext(ctx.value) is ctx


class TestExecutionContextSpec:
    def test_compatible_host_target(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.HOST)
        spec.assert_compatible(frozenset({NodeKind.HOST}))

    def test_compatible_container_target(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.CONTAINER)
        spec.assert_compatible(frozenset({NodeKind.CONTAINER}))

    def test_compatible_service_target(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.CONTAINER)
        spec.assert_compatible(frozenset({NodeKind.SERVICE}))

    def test_incompatible_host_context_on_container(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.HOST)
        with pytest.raises(InvariantViolationError, match="execution_context_incompatible"):
            spec.assert_compatible(frozenset({NodeKind.CONTAINER}))

    def test_incompatible_container_context_on_host(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.CONTAINER)
        with pytest.raises(InvariantViolationError, match="execution_context_incompatible"):
            spec.assert_compatible(frozenset({NodeKind.HOST}))

    def test_process_context_on_container(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.PROCESS)
        spec.assert_compatible(frozenset({NodeKind.CONTAINER}))  # process can run inside container

    def test_process_context_on_host(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.PROCESS)
        spec.assert_compatible(frozenset({NodeKind.HOST}))

    def test_network_namespace_on_host(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.NETWORK_NAMESPACE)
        spec.assert_compatible(frozenset({NodeKind.HOST}))

    def test_network_namespace_on_container(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.NETWORK_NAMESPACE)
        spec.assert_compatible(frozenset({NodeKind.CONTAINER}))

    def test_remote_host_on_external(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.REMOTE_HOST)
        spec.assert_compatible(frozenset({NodeKind.EXTERNAL_DEPENDENCY}))

    def test_remote_container_on_service(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.REMOTE_CONTAINER)
        spec.assert_compatible(frozenset({NodeKind.SERVICE}))

    def test_empty_node_kinds_raises(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.HOST)
        with pytest.raises(InvariantViolationError, match="execution_context_incompatible"):
            spec.assert_compatible(frozenset())

    def test_mixed_kinds_partial_compatible(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.HOST)
        # HOST + CONTAINER — HOST kind is compatible, so no error
        spec.assert_compatible(frozenset({NodeKind.HOST, NodeKind.CONTAINER}))

    def test_frozen(self) -> None:
        spec = ExecutionContextSpec(context=ExecutionContext.HOST)
        with pytest.raises(Exception):
            spec.context = ExecutionContext.CONTAINER  # type: ignore[misc]


class TestInferContextForNode:
    def test_host_inference(self) -> None:
        assert infer_context_for_node(NodeKind.HOST) == ExecutionContext.HOST

    def test_container_inference(self) -> None:
        assert infer_context_for_node(NodeKind.CONTAINER) == ExecutionContext.CONTAINER

    def test_service_inference(self) -> None:
        assert infer_context_for_node(NodeKind.SERVICE) == ExecutionContext.CONTAINER

    def test_process_inference(self) -> None:
        assert infer_context_for_node(NodeKind.PROCESS) == ExecutionContext.PROCESS

    def test_external_inference(self) -> None:
        assert infer_context_for_node(NodeKind.EXTERNAL_DEPENDENCY) == ExecutionContext.REMOTE_HOST
