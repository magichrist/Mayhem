from __future__ import annotations

import pytest

from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import TargetKind
from mayhem.domain.risks import RiskLevel

CONTAINER_IDS = (
    "cpu.burst",
    "mem.freeze",
    "mem.swap_pressure",
    "fs.quota",
    "fs.write_delay",
    "net.corrupt",
    "net.congestion",
    "process.restart_delay",
    "http.upstream_timeout",
    "app.response_5xx",
)
K8S_IDS = (
    "k8s.pod_restart_churn",
    "k8s.sidecar_termination",
    "k8s.workload_stall",
    "k8s.service_5xx",
    "k8s.dns_timeout",
    "k8s.node_disk_pressure",
    "k8s.node_memory_pressure",
    "k8s.node_pid_pressure",
    "k8s.hpa_oscillation",
    "k8s.pdb_over_eviction",
)


def test_expansion_ids_are_executable_and_typed() -> None:
    for fault_id in (*CONTAINER_IDS, *K8S_IDS):
        definition = definition_for(fault_id)
        assert not definition.catalog_only
        assert definition.risk in RiskLevel
        assert definition.max_duration_s > 0
        assert definition.reversibility is not None
        assert definition.observable_effect.strip()
        assert definition.compensation_evidence
        assert definition.required_caps
        assert definition.target_kinds
        assert len({spec.name for spec in definition.params_schema}) == len(
            definition.params_schema
        )
        assert all(spec.type for spec in definition.params_schema)


def test_kubernetes_target_kinds_follow_families() -> None:
    expected = {
        "k8s.pod_restart_churn": {TargetKind.POD},
        "k8s.sidecar_termination": {TargetKind.POD},
        "k8s.workload_stall": {TargetKind.WORKLOAD, TargetKind.POD},
        "k8s.service_5xx": {TargetKind.SERVICE, TargetKind.POD},
        "k8s.dns_timeout": {TargetKind.SERVICE, TargetKind.POD},
        "k8s.node_disk_pressure": {TargetKind.NODE},
        "k8s.node_memory_pressure": {TargetKind.NODE},
        "k8s.node_pid_pressure": {TargetKind.NODE},
        "k8s.hpa_oscillation": {TargetKind.WORKLOAD, TargetKind.HPA},
        "k8s.pdb_over_eviction": {TargetKind.WORKLOAD, TargetKind.POD, TargetKind.PDB},
    }
    for fault_id, kinds in expected.items():
        assert definition_for(fault_id).target_kinds == kinds


def test_expansion_parameters_reject_unknown_and_out_of_range_values() -> None:
    for fault_id in (*CONTAINER_IDS, *K8S_IDS):
        definition = definition_for(fault_id)
        with pytest.raises(SchemaValidationError):
            definition.validate_params({"not_allowed": 1})
        for spec in definition.params_schema:
            if spec.maximum is not None:
                with pytest.raises(SchemaValidationError):
                    definition.validate_params({spec.name: spec.maximum + 1})


def test_evidence_and_compensation_are_declared() -> None:
    from mayhem.controller.compensation import template_for
    from mayhem.controller.k8s_runtime import k8s_contract_for

    for fault_id in CONTAINER_IDS:
        assert template_for(fault_id) is not None
    for fault_id in K8S_IDS:
        contract = k8s_contract_for(fault_id)
        assert contract.evidence
        assert contract.compensation
        assert contract.executor != "k8s.unsupported"
