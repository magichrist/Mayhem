"""Comprehensive tests for topology providers, drift detection, and service merge."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pydantic_core
import pytest

from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ExternalDependencyNode,
    HostNode,
    NodeKind,
    PortBinding,
    ProcessNode,
    ServiceNode,
)
from mayhem.topology.providers.base import PartialGraph, TopologyProvider
from mayhem.topology.service import TopologyService

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


class FakeProvider:
    """Deterministic TopologyProvider for testing."""

    def __init__(
        self,
        source: str,
        nodes: tuple = (),
        edges: tuple = (),
        available: bool = True,
        notes: tuple[str, ...] = (),
    ) -> None:
        self._source = source
        self._nodes = nodes
        self._edges = edges
        self._available = available
        self._notes = notes

    @property
    def id(self) -> str:
        return self._source

    def is_available(self) -> bool:
        return self._available

    def discover(self) -> PartialGraph:
        return PartialGraph(
            source=self._source,
            nodes=self._nodes,
            edges=self._edges,
            notes=self._notes,
        )


def _svc(name: str, image: str = "img:latest") -> ServiceNode:
    return ServiceNode(id=f"svc-{name}", name=name, image=image)


def _ctr(
    name: str,
    service: str | None = None,
    engine: str = "docker",
    state: str = "running",
    image: str = "",
    networks: tuple[str, ...] = (),
    container_name: str | None = None,
) -> ContainerNode:
    return ContainerNode(
        id=f"ctr-{name}",
        name=name,
        engine=engine,
        runtime_identity=RuntimeIdentity(
            runtime=engine, host_id=f"h-{engine}-local", runtime_id=f"id-{name}"
        ),
        runtime_metadata=RuntimeMetadata(service=service, name=name, image=image or None),
        state=state,
        image=image,
        networks=networks,
        container_name=container_name,
    )


def _proc(
    name: str, pid: int, container_id: str | None = None, container_name: str | None = None
) -> ProcessNode:
    return ProcessNode(
        id=f"proc-{name}",
        name=name,
        pid=pid,
        host_id="h-docker-local",
        container_id=container_id,
        container_name=container_name,
    )


def _host(name: str = "docker") -> HostNode:
    return HostNode(id=f"h-{name}-local", name=name, transport="local")


def _edge(src: str, dst: str, kind: EdgeKind) -> Edge:
    return Edge(src=src, dst=dst, kind=kind)


# ===========================================================================
# PortBinding model
# ===========================================================================


class TestPortBinding:
    def test_basic_binding(self) -> None:
        pb = PortBinding(host_port=8080, container_port=80)
        assert pb.host_port == 8080
        assert pb.container_port == 80
        assert pb.protocol == "tcp"
        assert pb.host_address == "0.0.0.0"

    def test_udp_protocol(self) -> None:
        pb = PortBinding(host_port=53, container_port=53, protocol="udp")
        assert pb.protocol == "udp"

    def test_frozen(self) -> None:
        pb = PortBinding(host_port=80, container_port=80)
        with pytest.raises(pydantic_core.ValidationError):
            pb.host_port = 90  # type: ignore[misc]

    def test_network_node_kind(self) -> None:
        assert NodeKind.SERVICE == "service"
        assert NodeKind.CONTAINER == "container"
        assert NodeKind.PROCESS == "process"
        assert NodeKind.HOST == "host"
        assert NodeKind.EXTERNAL_DEPENDENCY == "external_dependency"


# ===========================================================================
# EdgeKind extensions
# ===========================================================================


class TestEdgeKinds:
    def test_contained_in_exists(self) -> None:
        assert EdgeKind.CONTAINED_IN == "contained_in"

    def test_listens_on_exists(self) -> None:
        assert EdgeKind.LISTENS_ON == "listens_on"

    def test_attached_to_exists(self) -> None:
        assert EdgeKind.ATTACHED_TO == "attached_to"

    def test_all_kinds_are_string_enum(self) -> None:
        for kind in EdgeKind:
            assert isinstance(kind.value, str)


# ===========================================================================
# ProcessNode extended fields
# ===========================================================================


class TestProcessNode:
    def test_container_id_default_none(self) -> None:
        p = ProcessNode(id="p1", name="test", pid=1, host_id="h1")
        assert p.container_id is None
        assert p.exe == ""
        assert p.user == ""
        assert p.ppid is None

    def test_container_id_set(self) -> None:
        p = ProcessNode(id="p1", name="test", pid=1, host_id="h1", container_id="abc123")
        assert p.container_id == "abc123"

    def test_frozen(self) -> None:
        p = ProcessNode(id="p1", name="test", pid=1, host_id="h1")
        with pytest.raises(pydantic_core.ValidationError):
            p.pid = 2  # type: ignore[misc]


# ===========================================================================
# ContainerNode extended fields
# ===========================================================================


class TestContainerNode:
    def test_image_field(self) -> None:
        c = ContainerNode(
            id="c1",
            name="test",
            engine="docker",
            runtime_identity=RuntimeIdentity(runtime="docker", host_id="h1", runtime_id="abc"),
            image="nginx:latest",
        )
        assert c.image == "nginx:latest"

    def test_networks_field(self) -> None:
        c = ContainerNode(
            id="c1",
            name="test",
            engine="docker",
            runtime_identity=RuntimeIdentity(runtime="docker", host_id="h1", runtime_id="abc"),
            networks=("mynet", "bridge"),
        )
        assert c.networks == ("mynet", "bridge")

    def test_ports_are_port_bindings(self) -> None:
        c = ContainerNode(
            id="c1",
            name="test",
            engine="docker",
            runtime_identity=RuntimeIdentity(runtime="docker", host_id="h1", runtime_id="abc"),
            ports=(PortBinding(host_port=8080, container_port=80),),
        )
        assert c.ports[0].host_port == 8080
        assert c.ports[0].container_port == 80


# ===========================================================================
# ComposeFileProvider
# ===========================================================================


class TestComposeProvider:
    def test_no_self_edges(self) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        result = provider.discover()

        # Service nodes should NOT have self-edges (no src == dst).
        self_edges = [e for e in result.edges if e.src == e.dst]
        assert self_edges == [], f"self-edges found: {self_edges}"

    def test_depends_on_edges(self) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        result = provider.discover()

        depends_edges = [e for e in result.edges if e.kind == EdgeKind.DEPENDS_ON]
        assert len(depends_edges) >= 2  # lb depends on download-1 and download-2

    def test_exposed_ports_are_port_bindings(self) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        result = provider.discover()

        lb_node = next(n for n in result.nodes if n.name == "lb")
        assert isinstance(lb_node, ServiceNode)
        assert len(lb_node.exposed_ports) == 1
        assert isinstance(lb_node.exposed_ports[0], PortBinding)
        assert lb_node.exposed_ports[0].host_port == 8080
        assert lb_node.exposed_ports[0].container_port == 80

    def test_exposed_ports_empty_for_no_host_mapping(self) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        result = provider.discover()

        download_node = next(n for n in result.nodes if n.name == "download-1")
        assert isinstance(download_node, ServiceNode)
        # download-1 only uses 'expose:', no host port mapping.
        assert download_node.exposed_ports == ()

    def test_external_dependencies_not_inferred_without_url_env(self) -> None:
        """No URL-like env vars means no external dependency nodes."""
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        result = provider.discover()

        ext_nodes = [n for n in result.nodes if isinstance(n, ExternalDependencyNode)]
        # The compose file has no DB_HOST env var on the db service, so
        # no external dependency should be inferred.
        assert len(ext_nodes) == 0

    def test_project_name(self) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        assert provider.project_name == "testcase"

    def test_service_names(self) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        names = provider.service_names
        assert "download-1" in names
        assert "download-2" in names
        assert "lb" in names
        assert "db" in names

    def test_unavailable_file(self, tmp_path: Path) -> None:
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider(tmp_path / "nonexistent.yml")
        assert not provider.is_available()

    def test_depends_on_healthcheck_weight(self) -> None:
        """Service depends_on with condition: service_healthy should have weight=2."""
        from mayhem.topology.providers.compose import ComposeFileProvider

        provider = ComposeFileProvider("examples/testCase/docker-compose.yml")
        result = provider.discover()

        # lb depends on download-1 with condition: service_healthy
        lb_to_dl1 = next(
            (e for e in result.edges if e.src == "svc-lb" and e.dst == "svc-download-1"),
            None,
        )
        assert lb_to_dl1 is not None
        assert lb_to_dl1.weight == 2.0  # service_healthy condition


# ===========================================================================
# TopologyService — merge + drift
# ===========================================================================


class TestTopologyService:
    def test_merge_compose_and_runtime(self) -> None:
        service = TopologyService()
        compose = FakeProvider(
            "compose",
            nodes=(_svc("api"), _svc("web")),
            edges=(_edge("svc-web", "svc-api", EdgeKind.DEPENDS_ON),),
        )
        runtime = FakeProvider(
            "docker",
            nodes=(
                _host(),
                _ctr("api-1", service="api"),
                _proc("api", 100, "api-1"),
            ),
            edges=(_edge("ctr-api-1", "h-docker-local", EdgeKind.RUNS_ON),),
        )
        result = service.discover([compose, runtime])
        node_ids = {n.id for n in result.graph.nodes}
        assert "svc-api" in node_ids
        assert "svc-web" in node_ids
        assert "ctr-api-1" in node_ids
        assert "proc-api" in node_ids

    def test_drift_matched_services(self) -> None:
        service = TopologyService()
        compose = FakeProvider(
            "compose",
            nodes=(_svc("api", image="img:v1"),),
            edges=(),
        )
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api", image="img:v1"),),
            edges=(),
        )
        result = service.discover([compose, runtime])
        matched = result.drift_report.get("matched_services", [])
        assert "api" in matched
        # Empty lists are filtered out of drift report.
        assert result.drift_report.get("missing_services", []) == []

    def test_drift_missing_services(self) -> None:
        service = TopologyService()
        compose = FakeProvider(
            "compose",
            nodes=(_svc("api"), _svc("db")),
            edges=(),
        )
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api"),),
            edges=(),
        )
        result = service.discover([compose, runtime])
        missing = result.drift_report.get("missing_services", [])
        assert missing == ["db"]

    def test_drift_image_changed(self) -> None:
        service = TopologyService()
        compose = FakeProvider(
            "compose",
            nodes=(_svc("api", image="img:v1"),),
            edges=(),
        )
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api", image="img:v2"),),
            edges=(),
        )
        result = service.discover([compose, runtime])
        changed = result.drift_report.get("changed_images", [])
        assert len(changed) == 1
        assert changed[0]["expected"] == "img:v1"
        assert changed[0]["actual"] == "img:v2"

    def test_drift_no_false_positives_on_match(self) -> None:
        """Image match should NOT appear in changed_images."""
        service = TopologyService()
        compose = FakeProvider(
            "compose",
            nodes=(_svc("api", image="img:stable"),),
            edges=(),
        )
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api", image="img:stable"),),
            edges=(),
        )
        result = service.discover([compose, runtime])
        # Empty lists are filtered out of drift report.
        assert result.drift_report.get("changed_images", []) == []

    def test_drift_extra_containers(self) -> None:
        service = TopologyService()
        compose = FakeProvider("compose", nodes=(_svc("api"),), edges=())
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("mystery", service="unknown_svc"),),
            edges=(),
        )
        result = service.discover([compose, runtime])
        extra = result.drift_report.get("extra_containers", [])
        assert len(extra) == 1
        assert extra[0]["name"] == "mystery"

    def test_drift_unhealthy_containers(self) -> None:
        service = TopologyService()
        compose = FakeProvider("compose", nodes=(_svc("api"),), edges=())
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api", state="exited"),),
            edges=(),
        )
        result = service.discover([compose, runtime])
        unhealthy = result.drift_report.get("unhealthy", [])
        assert len(unhealthy) == 1
        assert unhealthy[0]["state"] == "exited"

    def test_partial_on_unavailable_provider(self) -> None:
        service = TopologyService()
        compose = FakeProvider("compose", nodes=(_svc("api"),), edges=())
        runtime = FakeProvider("docker", available=False)
        result = service.discover([compose, runtime])
        assert result.partial is True
        assert len(result.errors) == 1
        assert "not available" in result.errors[0]

    def test_partial_on_provider_exception(self) -> None:
        service = TopologyService()
        compose = FakeProvider("compose", nodes=(_svc("api"),), edges=())
        broken = MagicMock(spec=TopologyProvider)
        broken.id = "broken"
        broken.is_available.return_value = True
        broken.discover.side_effect = RuntimeError("explosion")
        result = service.discover([compose, broken])
        assert result.partial is True
        assert any("explosion" in e for e in result.errors)

    def test_notes_appear_in_drift(self) -> None:
        service = TopologyService()
        compose = FakeProvider("compose", nodes=(), edges=(), notes=("inferred dep x",))
        result = service.discover([compose])
        assert "notes" in result.drift_report
        assert "inferred dep x" in result.drift_report["notes"]

    def test_duplicate_node_ids_first_wins(self) -> None:
        service = TopologyService()
        p1 = FakeProvider(
            "a",
            nodes=(ServiceNode(id="dup", name="from_a"),),
            edges=(),
        )
        p2 = FakeProvider(
            "b",
            nodes=(ServiceNode(id="dup", name="from_b"),),
            edges=(),
        )
        result = service.discover([p1, p2])
        node = next(n for n in result.graph.nodes if n.id == "dup")
        assert node.name == "from_a"  # first provider wins

    def test_dangling_edges_filtered(self) -> None:
        service = TopologyService()
        p = FakeProvider(
            "a",
            nodes=(ServiceNode(id="a", name="a"),),
            edges=(Edge(src="a", dst="ghost", kind=EdgeKind.DEPENDS_ON),),
        )
        result = service.discover([p])
        assert len(result.graph.edges) == 0


# ===========================================================================
# Runtime provider — CONTAINED_IN edges
# ===========================================================================


class TestContainedInEdge:
    def test_contained_in_emitted(self) -> None:
        """Container with service_name should produce contained_in edge to service."""
        service = TopologyService()
        compose = FakeProvider(
            "compose",
            nodes=(_svc("api"),),
            edges=(),
        )
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api"),),
            edges=(_edge("ctr-api", "svc-api", EdgeKind.CONTAINED_IN),),
        )
        result = service.discover([compose, runtime])
        contained = [e for e in result.graph.edges if e.kind == EdgeKind.CONTAINED_IN]
        assert len(contained) == 1
        assert contained[0].src == "ctr-api"
        assert contained[0].dst == "svc-api"


# ===========================================================================
# Container name enforcement (ADR-0020)
# ===========================================================================


class TestContainerNameEnforcement:
    def test_container_with_name_no_errors(self) -> None:
        svc = TopologyService()
        compose = FakeProvider("compose", nodes=(_svc("api"),))
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api", container_name="testcase-api"),),
            edges=(_edge("ctr-api", "svc-api", EdgeKind.CONTAINED_IN),),
        )
        result = svc.discover([compose, runtime])
        assert not any("container_name" in e for e in result.errors)

    def test_container_without_name_produces_error(self) -> None:
        svc = TopologyService()
        compose = FakeProvider("compose", nodes=(_svc("api"),))
        runtime = FakeProvider(
            "docker",
            nodes=(_ctr("api", service="api"),),
            edges=(_edge("ctr-api", "svc-api", EdgeKind.CONTAINED_IN),),
        )
        result = svc.discover([compose, runtime])
        assert any("no container_name" in e for e in result.errors)

    def test_service_node_carries_compose_name(self) -> None:
        node = ServiceNode(id="svc-api", name="api", image="img", container_name="testcase-api")
        assert node.container_name == "testcase-api"

    def test_service_node_container_name_optional(self) -> None:
        node = ServiceNode(id="svc-api", name="api", image="img")
        assert node.container_name is None

    def test_proc_with_container_name(self) -> None:
        node = _proc("api", pid=1, container_name="testcase-api")
        assert node.container_name == "testcase-api"

    def test_proc_container_name_optional(self) -> None:
        node = _proc("api", pid=1)
        assert node.container_name is None


# ===========================================================================
# Integration: topology CLI discover (end-to-end)
# ===========================================================================


def _compose_services_running() -> bool:
    """Return True if the examples/testCase compose stack services are reachable."""
    import shutil
    import subprocess

    engine = "podman" if shutil.which("podman") else ("docker" if shutil.which("docker") else None)
    if engine is None:
        return False
    try:
        r = subprocess.run(
            [engine, "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        names = r.stdout
        return "svc-lb" in names or "svc-db" in names
    except Exception:
        return False


class TestTopologyCLI:
    @pytest.mark.skipif(
        not _compose_services_running(),
        reason="examples/testCase compose stack not running",
    )
    def test_discover_with_compose(self) -> None:
        """Integration test: CLI discover with compose + runtime."""
        from click.testing import CliRunner

        from mayhem.cli.topology import discover

        runner = CliRunner()
        result = runner.invoke(
            discover,
            ["--compose", "examples/testCase/docker-compose.yml"],
            standalone_mode=False,
        )
        if result.exit_code != 0 and result.exception:
            raise result.exception

        output = json.loads(result.output)
        graph = output["graph"]
        node_ids = {n["id"] for n in graph["nodes"]}

        # Services from compose
        assert "svc-download-1" in node_ids
        assert "svc-download-2" in node_ids
        assert "svc-lb" in node_ids
        assert "svc-db" in node_ids

        # Containers from runtime
        containers = [nid for nid in node_ids if nid.startswith("ctr-")]
        assert len(containers) >= 4

        # Processes from runtime
        processes = [nid for nid in node_ids if nid.startswith("proc-")]
        assert len(processes) >= 4

        # Host
        hosts = [nid for nid in node_ids if nid.startswith("h-")]
        assert len(hosts) >= 1

        # No self-edges
        self_edges = [e for e in graph["edges"] if e["src"] == e["dst"]]
        assert self_edges == [], f"self-edges: {self_edges}"

        # Has contained_in edges
        contained = [e for e in graph["edges"] if e["kind"] == "contained_in"]
        assert len(contained) >= 4

        # Has runs_on edges
        runs_on = [e for e in graph["edges"] if e["kind"] == "runs_on"]
        assert len(runs_on) >= 8  # container→host + process→container

        # Drift shows matched services, not false missing
        drift = output["drift"]
        assert drift.get("missing_services", []) == []
        matched = drift.get("matched_services", [])
        assert len(matched) >= 4
        assert "lb" in matched
        assert "db" in matched

    def test_discover_ports_are_bindings(self) -> None:
        from click.testing import CliRunner

        from mayhem.cli.topology import discover

        runner = CliRunner()
        result = runner.invoke(
            discover,
            [
                "--compose",
                "examples/testCase/docker-compose.yml",
                "--runtime",
                "docker",
            ],
            standalone_mode=False,
        )
        output = json.loads(result.output)
        lb_node = next(n for n in output["graph"]["nodes"] if n["id"] == "svc-lb")
        ports = lb_node["exposed_ports"]
        assert len(ports) == 1
        assert ports[0]["host_port"] == 8080
        assert ports[0]["container_port"] == 80

    @pytest.mark.skipif(
        not _compose_services_running(),
        reason="examples/testCase compose stack not running",
    )
    def test_drift_comprehensive(self) -> None:
        """Full drift report should have matched, no missing, no image changes."""
        from click.testing import CliRunner

        from mayhem.cli.topology import discover

        runner = CliRunner()
        result = runner.invoke(
            discover,
            ["--compose", "examples/testCase/docker-compose.yml"],
            standalone_mode=False,
        )
        output = json.loads(result.output)
        drift = output["drift"]

        # All services matched
        matched = drift.get("matched_services", [])
        assert len(matched) >= 4

        # No missing services
        assert drift.get("missing_services", []) == []

        # No image changes (same images)
        assert drift.get("changed_images", []) == []
