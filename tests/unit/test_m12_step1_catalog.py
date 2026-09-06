"""Catalog-contract tests for the step-1 net/dependency fault families.

Each archetype must (a) be a defined NETWORK/DEPENDENCY fault whose prefix maps
to that category, (b) be ``reversible``, (c) resolve to the
:class:`ToolExecutor` (prefix ``net`` / ``dependency``), and (d) be
compensatable at plan time via ``controller.compensation.compensated``.
"""

import pytest

from mayhem.agents.executors import ToolExecutor, executor_for
from mayhem.controller.compensation import compensated, template_for
from mayhem.domain.catalog import definition_for
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.faults import FaultCategory
from mayhem.domain.topology import ProcessNode, ServiceNode

NET_FAMILY = ("net.connection_reset", "net.connection_refuse", "net.reorder", "net.duplicate")
DEP_FAMILY = ("dependency.connection_refuse",)
TOOL_OVERRIDE_FAMILY = ("fs.read_only", "process.crash_loop")

_PREFS: dict[str, dict[str, object]] = {
    "net.connection_reset": {"port": 8080, "percent": 30, "delay_ms": 50},
    "net.connection_refuse": {"port": 8080, "percent": 30, "delay_ms": 50},
    "net.reorder": {"port": 8080, "percent": 30, "delay_ms": 50},
    "net.duplicate": {"port": 8080, "percent": 30, "delay_ms": 50},
    "dependency.connection_refuse": {"port": 3306, "percent": 30, "delay_ms": 50},
    "fs.read_only": {"path": "/"},
    "process.crash_loop": {"restarts": 3, "interval": "2s"},
}


def _fault(fault_id: str) -> PlannedFault:
    return PlannedFault(
        fault_id=fault_id,
        targets=(),
        params=_PREFS[fault_id],
        duration=30.0,
    )


def _nodes() -> tuple[ServiceNode, ProcessNode]:
    return (
        ServiceNode(
            id="svc.api",
            name="api",
            container_name="api_cont",
            image="api:latest",
        ),
        ProcessNode(id="p-api", name="api", pid=4242, host_id="h1", container_name=None),
    )


@pytest.mark.parametrize("fault_id", NET_FAMILY + DEP_FAMILY + TOOL_OVERRIDE_FAMILY)
def test_archetype_has_catalog_definition(fault_id: str) -> None:
    defn = definition_for(fault_id)
    if fault_id in NET_FAMILY:
        expected = FaultCategory.NETWORK
    elif fault_id in DEP_FAMILY:
        expected = FaultCategory.DEPENDENCY
    else:
        expected = FaultCategory.STORAGE if fault_id.startswith("fs.") else FaultCategory.PROCESS
    assert defn.category is expected
    assert FaultCategory.from_fault_id(defn.id) is expected
    assert defn.reversible
    assert {k.value for k in defn.applicable_node_kinds} >= {"service", "container"}


@pytest.mark.parametrize("fault_id", NET_FAMILY + DEP_FAMILY + TOOL_OVERRIDE_FAMILY)
def test_archetype_resolves_to_tool_executor(fault_id: str) -> None:
    assert isinstance(executor_for(fault_id), ToolExecutor)


@pytest.mark.parametrize("fault_id", NET_FAMILY + DEP_FAMILY + TOOL_OVERRIDE_FAMILY)
def test_archetype_is_compensatable(fault_id: str) -> None:
    assert template_for(fault_id) is not None
    filled = compensated(_fault(fault_id), _nodes())
    assert filled.undo_ops and filled.verify_probes
