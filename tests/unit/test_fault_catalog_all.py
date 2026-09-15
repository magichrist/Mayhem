"""Whole-catalog contract tests — every fault in the catalog, parametrized.

Guards the invariant that *all* registered faults stay loadable, validated,
executor-resolvable, and compensatable. Individual features hide regressions
inside one fault's file; this suite locks the complete contract.
"""

from __future__ import annotations

import pytest

from mayhem.agents.executors import (
    NoopExecutor,
    PayloadExecutor,
    ProcPauseExecutor,
    ToolExecutor,
    executor_for,
)
from mayhem.controller.compensation import compensated, template_for
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.faults import FaultCategory, ParamType
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import (
    ContainerNode,
    ExternalDependencyNode,
    HostNode,
    NodeKind,
    ProcessNode,
    ServiceNode,
)

NON_K8S_KINDS = frozenset(
    {
        NodeKind.SERVICE,
        NodeKind.CONTAINER,
        NodeKind.HOST,
        NodeKind.PROCESS,
        NodeKind.EXTERNAL_DEPENDENCY,
    }
)
K8S_ONLY_KINDS = frozenset({NodeKind.POD, NodeKind.K8S_NODE})

ALL_FAULTS = tuple(d.id for d in CATALOG)

# Non-k8s faults: every catalog fault that addresses at least one non-k8s node
# kind. A fault may also target pods (the portable argv families) and still
# belongs in the non-k8s test set — it stays container-portable with an argv
# compensation template.
NON_K8S = tuple(d.id for d in CATALOG if d.applicable_node_kinds & NON_K8S_KINDS)

# K8s-only: faults whose kinds are a subset of {pod, k8s_node} — pure
# kubernetes archetypes that live exclusively in the kubectl pipeline.
K8S = tuple(d.id for d in CATALOG if d.applicable_node_kinds <= K8S_ONLY_KINDS)

# Values that pass the injection grammar where a generic type seed would not
# (``rate`` is a schema param on both; the STRING seed "test" is not a rate).
_TYPE_SEED: dict[ParamType, int | float | str] = {
    ParamType.INTEGER: 1,
    ParamType.DURATION: "5s",
    ParamType.PERCENT: 50.0,
    ParamType.STRING: "test",
    ParamType.BYTES: "8M",
    ParamType.FLOAT: 0.5,
}

_RATE_SEED: dict[str, dict[str, object]] = {
    "net.bandwidth": {"rate": "10mbit"},
    "dependency.rate_limit": {"rate": 100},
}


def auto_params(definition) -> dict[str, object]:
    """Minimal *valid* params: seed required values; let validate_params fill
    non-required defaults itself (schema defaults are copied raw, so seeding
    them only invites double-coercion)."""
    params: dict[str, object] = {}
    for spec in definition.params_schema:
        if not (spec.required and spec.default is None):
            continue
        value: int | float | str
        if spec.type is ParamType.DURATION:
            value = "5s"
        else:
            value = _TYPE_SEED[spec.type]
            if spec.minimum is not None:
                if spec.type is ParamType.INTEGER:
                    value = max(int(spec.minimum), int(value))
                elif spec.type in (ParamType.PERCENT, ParamType.FLOAT):
                    value = max(float(spec.minimum), float(value))
        if spec.maximum is not None and float(value) > float(spec.maximum):
            value = spec.maximum
        params[spec.name] = value
    params.update(_RATE_SEED.get(definition.id, {}))
    return params


def required_names(definition) -> list[str]:
    return [s.name for s in definition.params_schema if s.required]


def nodes_for(definition) -> tuple:
    """One node per applicable kind, mirroring a planned subtree."""
    kinds = set(definition.applicable_node_kinds)
    nodes: list = []
    if NodeKind.SERVICE in kinds:
        nodes.append(ServiceNode(id="svc.t", name="t", container_name="testcase-t"))
    if NodeKind.CONTAINER in kinds:
        nodes.append(
            ContainerNode(
                id="ctr.t",
                name="t",
                engine="fake",
                runtime_identity=RuntimeIdentity(runtime="fake", host_id="h1", runtime_id="cid-t"),
                runtime_metadata=RuntimeMetadata(service="t", name="t"),
                container_name="testcase-t",
                state="running",
            )
        )
    if NodeKind.PROCESS in kinds:
        nodes.append(
            ProcessNode(
                id="proc.t", name="t-proc", pid=1024, host_id="h1", container_name="testcase-t"
            )
        )
    if NodeKind.HOST in kinds:
        nodes.append(HostNode(id="host.t", name="t"))
    if NodeKind.EXTERNAL_DEPENDENCY in kinds:
        nodes.append(ExternalDependencyNode(id="ext.t", name="t", endpoint="172.18.0.9:3306"))
    assert nodes, f"{definition.id}: no node kind factory available"
    return tuple(nodes)


# ── resolution + metadata ────────────────────────────────────────────────────
class TestCatalogResolution:
    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_definition_for_resolves(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        assert definition.id == fault_id

    def test_unknown_fault_raises(self) -> None:
        with pytest.raises(LookupError):
            definition_for("no.such_fault")

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_category_matches_id_prefix(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        assert FaultCategory.from_fault_id(fault_id) is definition.category

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_risk_and_duration_are_defined(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        assert definition.risk in RiskLevel
        assert definition.max_duration_s >= 1
        assert definition.reversible is not None

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_applicable_node_kinds_are_nonempty_and_unique(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        kinds = definition.applicable_node_kinds
        assert kinds
        assert len(set(kinds)) == len(kinds)

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_params_schema_names_are_unique(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        names = [s.name for s in definition.params_schema]
        assert len(set(names)) == len(names)


# ── parameter contracts ──────────────────────────────────────────────────────
class TestParamsContract:
    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_defaults_validate_unless_required_params_exist(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        if required_names(definition):
            with pytest.raises(SchemaValidationError):
                definition.validate_params({})
        else:
            assert definition.validate_params({}) is not None

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_unknown_param_is_rejected(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        with pytest.raises(SchemaValidationError):
            definition.validate_params({"unexpected_key_xyz": 1})

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_auto_valid_params_roundtrip(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        params = auto_params(definition)
        normalized = definition.validate_params(params)
        for name in required_names(definition):
            assert name in normalized

    @pytest.mark.parametrize("fault_id", ALL_FAULTS)
    def test_bounds_are_enforced(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        for spec in definition.params_schema:
            if spec.minimum is None and spec.maximum is None:
                continue
            base = auto_params(definition)
            if spec.minimum is not None:
                base[spec.name] = float(spec.minimum) - max(1.0, abs(float(spec.minimum)) * 0.1)
                with pytest.raises(SchemaValidationError):
                    definition.validate_params(base)
            if spec.maximum is not None:
                base = auto_params(definition)
                base[spec.name] = float(spec.maximum) + 1.0
                with pytest.raises(SchemaValidationError):
                    definition.validate_params(base)

    @pytest.mark.parametrize("fault_id", NON_K8S)
    def test_rate_params_follow_the_rate_grammar(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        if "rate" not in {s.name for s in definition.params_schema}:
            return
        definition.validate_params(auto_params(definition))


# ── executor resolution ──────────────────────────────────────────────────────
class TestExecutorResolution:
    @pytest.mark.parametrize("fault_id", NON_K8S)
    def test_executor_resolves(self, fault_id: str) -> None:
        """Every argv-executable fault must produce an executor. (Execution-time
        routing keys off ``executor_for`` presence, not ``supports``: argv-pair
        faults like cpu.throttle bypass prefix matching via explicit overrides.)
        """
        assert executor_for(fault_id) is not None

    @pytest.mark.parametrize(
        "fault_id",
        NON_K8S,
    )
    def test_executor_is_a_registered_class(self, fault_id: str) -> None:
        executor = executor_for(fault_id)
        assert isinstance(
            executor, (ProcPauseExecutor, PayloadExecutor, ToolExecutor, NoopExecutor)
        )

    @pytest.mark.parametrize("fault_id", K8S)
    def test_k8s_faults_resolve_to_k8s_executor(self, fault_id: str) -> None:
        """k8s faults are kubectl-native; a kubernetes-runtime step resolves
        every fault to the dedicated K8sExecutor (k-plan-3 SP-3.3 executor
        flip). Non-k8s runtimes keep the legacy registry dispatch."""
        from mayhem.agents.executors import K8sExecutor
        from mayhem.domain.identity import RuntimeLabel

        assert isinstance(executor_for(fault_id, runtime=RuntimeLabel.KUBERNETES), K8sExecutor)


# ── compensation contract ────────────────────────────────────────────────────
class TestCompensationContract:
    @pytest.mark.parametrize("fault_id", NON_K8S)
    def test_template_exists_and_fills_undo_verify(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        assert template_for(fault_id) is not None
        planned = PlannedFault(
            fault_id=fault_id,
            targets=(),
            duration=5.0,
            params=auto_params(definition),
        )
        written = compensated(planned, nodes_for(definition))
        assert written.undo_ops
        assert written.verify_probes
        assert written.fault_id == fault_id

    @pytest.mark.parametrize("fault_id", NON_K8S)
    def test_undo_ops_form_a_chain(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        planned = PlannedFault(
            fault_id=fault_id, targets=(), duration=5.0, params=auto_params(definition)
        )
        written = compensated(planned, nodes_for(definition))
        for op in written.undo_ops:
            assert op.op
            assert op.args is not None

    @pytest.mark.parametrize("fault_id", K8S)
    def test_k8s_faults_are_not_generic_template_faults(self, fault_id: str) -> None:
        """k8s compensation lives in the kubectl layer, not the argv templates."""
        assert template_for(fault_id) is None


# ── k8s catalog metadata ─────────────────────────────────────────────────────
class TestK8sCatalog:
    @pytest.mark.parametrize("fault_id", K8S)
    def test_k8s_faults_are_kubernetes_capability_faults(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        from mayhem.domain.faults import Capability

        assert Capability.KUBERNETES_ENGINE in definition.required_caps
        assert definition.category is FaultCategory.K8S
        assert all(
            kind in (NodeKind.POD, NodeKind.K8S_NODE) for kind in definition.applicable_node_kinds
        )
        assert {s.type for s in definition.params_schema} <= {
            ParamType.STRING,
            ParamType.INTEGER,
            ParamType.PERCENT,
            ParamType.DURATION,
            ParamType.FLOAT,
        }
