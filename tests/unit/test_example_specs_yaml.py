"""Tests the YAML files shipped with the repo actually load and plan.

Exercises ``examples/`` and the built-in toolkit manifests so a broken or
drifted example never silently rots: every drill file must parse, every fault
it names must exist in the catalog, every param it sets must be known, and the
testCase drill must compile to a full compensatable plan against the compose
blueprint it ships alongside.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml

from mayhem.controller.planner import plan_drill
from mayhem.domain.catalog import definition_for
from mayhem.domain.experiments import DrillSpec
from mayhem.domain.topology import NodeKind, TopologyGraph
from mayhem.spec import load_drill
from mayhem.topology.providers.compose import ComposeFileProvider

if TYPE_CHECKING:
    from mayhem.domain.experiments import DrillSpec


REPO = Path(__file__).resolve().parents[2]
TESTCASE_DIR = REPO / "examples" / "testCase"
K8S_DIR = REPO / "examples" / "k8s"
MANIFESTS_DIR = REPO / "src" / "mayhem" / "toolkit" / "manifests"

_FIELD_PARAMS = {"duration", "on_failure", "targets", "network_path", "recovery"}


def compose_graph() -> TopologyGraph:
    """Shared compose+runtime graph (identical to the matrix tests')."""
    from tests.conftest import build_compose_runtime_graph

    return build_compose_runtime_graph()


@pytest.fixture(scope="module")
def testcase_spec() -> DrillSpec:
    return load_drill(str(TESTCASE_DIR / "mayhem.yaml"))


# ── drill file loads ─────────────────────────────────────────────────────────
class TestTestCaseDrillLoads:
    def test_loads_and_metadata(self, testcase_spec: DrillSpec) -> None:
        assert testcase_spec.kind == "drill"
        assert testcase_spec.name == "testcase-fault-drill"
        assert "recover" in (testcase_spec.hypothesis or "")

    def test_file_carries_the_v1_api_version(self) -> None:
        raw = yaml.safe_load((TESTCASE_DIR / "mayhem.yaml").read_text(encoding="utf-8"))
        assert raw["apiVersion"] == "mayhem/v1"
        assert raw["kind"] == "drill"

    def test_containers_blocks(self, testcase_spec: DrillSpec) -> None:
        assert set(testcase_spec.containers) == {
            "testcase-api",
            "testcase-lb",
            "testcase-download-1",
        }

    def test_every_catalog_defined_fault_is_registered_(self, testcase_spec: DrillSpec) -> None:
        for container in testcase_spec.containers.values():
            for fault in container.faults:
                definition_for(fault.fault)  # raises LookupError if unknown

    def test_fault_param_keys_are_known_to_definition(self, testcase_spec: DrillSpec) -> None:
        for container in testcase_spec.containers.values():
            for fault in container.faults:
                definition = definition_for(fault.fault)
                known = {s.name for s in definition.params_schema}
                extra = dict(fault.model_extra or {})
                explicit = extra.pop("params", {}) or {}
                for key, _ in {**explicit, **extra}.items():
                    assert key in known, f"{fault.fault}: unknown param {key!r}"

    def test_observability_references_real_containers(self, testcase_spec: DrillSpec) -> None:
        referenced: set[str] = set()
        for source in testcase_spec.observability.sources:
            if source.kind.value == "logs":
                referenced.add(source.container)
            elif source.probe is not None and source.probe.url is not None:
                host = source.probe.url.split("://", 1)[-1].split(":", 1)[0]
                referenced.add(host)
        assert referenced <= set(testcase_spec.containers)


# ── example drill compiles ───────────────────────────────────────────────────
class TestTestCaseDrillPlans:
    def test_plans_against_compose_blueprint(self, testcase_spec: DrillSpec) -> None:
        plan = plan_drill(
            "run-example",
            testcase_spec,
            compose_graph(),
            config_snapshot_id="cs",
            topology_snapshot_id="ts",
            environment_fingerprint="f",
            engine="fake",
            spec_dir=str(TESTCASE_DIR),
        )
        fault_steps = [s for s in plan.steps if s.fault is not None]
        assert len(fault_steps) == sum(
            len(container.faults) for container in testcase_spec.containers.values()
        )
        for step in fault_steps:
            assert step.fault is not None
            assert step.fault.undo_ops
            assert step.fault.verify_probes

    def test_proc_pause_undo_is_signal_cont(self, testcase_spec: DrillSpec) -> None:
        plan = plan_drill(
            "run-example",
            testcase_spec,
            compose_graph(),
            config_snapshot_id="cs",
            topology_snapshot_id="ts",
            environment_fingerprint="f",
            engine="fake",
            spec_dir=str(TESTCASE_DIR),
        )
        pause = [s for s in plan.steps if s.fault and s.fault.fault_id == "proc.pause"]
        assert pause
        for step in pause:
            ops = {op.op for op in step.fault.undo_ops}
            assert "signal.cont" in ops

    def test_net_load_script_resolves_against_spec_dir(self, testcase_spec: DrillSpec) -> None:
        plan = plan_drill(
            "run-example",
            testcase_spec,
            compose_graph(),
            config_snapshot_id="cs",
            topology_snapshot_id="ts",
            environment_fingerprint="f",
            engine="fake",
            spec_dir=str(TESTCASE_DIR),
        )
        load_steps = [s for s in plan.steps if s.fault and s.fault.fault_id == "net.load"]
        assert load_steps
        for step in load_steps:
            assert step.fault.params.get("url") == "http://testcase-api:8080/"


# ── compose blueprint consistency ────────────────────────────────────────────
class TestComposeBlueprint:
    def test_all_services_have_container_names(self) -> None:
        result = ComposeFileProvider(str(TESTCASE_DIR / "docker-compose.yml")).discover()
        assert {getattr(n, "container_name", None) for n in result.nodes} == {
            "testcase-api",
            "testcase-web",
            "testcase-download-1",
            "testcase-download-2",
            "testcase-lb",
            "testcase-db",
        }

    def test_drill_containers_are_all_in_compose(self, testcase_spec: DrillSpec) -> None:
        result = ComposeFileProvider(str(TESTCASE_DIR / "docker-compose.yml")).discover()
        compose_names = {getattr(n, "container_name", None) for n in result.nodes}
        assert set(testcase_spec.containers) <= compose_names

    def test_compose_services_are_service_nodes(self) -> None:
        result = ComposeFileProvider(str(TESTCASE_DIR / "docker-compose.yml")).discover()
        assert all(n.kind is NodeKind.SERVICE for n in result.nodes)

    def test_compose_file_is_wellformed(self) -> None:
        raw = (TESTCASE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
        doc = yaml.safe_load(raw)
        services = doc["services"]
        assert set(services) == {"api", "web", "download-1", "download-2", "lb", "db"}


# ── k8s example ──────────────────────────────────────────────────────────────
class TestK8sExample:
    def test_k8s_drill_loads(self) -> None:
        spec = load_drill(str(K8S_DIR / "mayhem.yaml"))
        assert spec.kind == "drill"
        assert spec.name == "k8s-fault-drill"
        # targets: mode — mixes k8s_node + deployment targets
        assert spec.targets is not None
        assert set(spec.targets) == {"node-group", "testcase-api", "testcase-lb"}
        for target in spec.targets.values():
            for fault in target.faults:
                definition_for(fault.fault)
        assert spec.config.risk_ceiling is not None

    def test_k8s_manifests_parse(self) -> None:
        raw = (K8S_DIR / "kubernetes.yaml").read_text(encoding="utf-8")
        docs = [d for d in yaml.safe_load_all(raw) if d]
        assert len(docs) >= 2
        kinds = [d.get("kind") for d in docs]
        assert "Deployment" in kinds
        assert "Service" in kinds

    def test_k8s_manifests_point_at_expected_apps(self) -> None:
        raw = (K8S_DIR / "kubernetes.yaml").read_text(encoding="utf-8")
        docs = [d for d in yaml.safe_load_all(raw) if d]
        deployments = [d for d in docs if d.get("kind") == "Deployment"]
        assert deployments
        seen = {d["metadata"]["name"] for d in deployments if d.get("metadata", {}).get("name")}
        assert seen  # at least one named deployment


# ── built-in toolkit manifests ───────────────────────────────────────────────
class TestToolkitManifests:
    @pytest.mark.parametrize(
        "manifest_path",
        sorted(str(p) for p in MANIFESTS_DIR.glob("*.yaml")),
        ids=lambda p: Path(p).stem,
    )
    def test_builtin_manifest_parses_and_provides(self, manifest_path: str) -> None:
        from mayhem.toolkit.registry import manifest_from_yaml

        manifest = manifest_from_yaml(Path(manifest_path))
        assert manifest.tool
        assert manifest.provides
        assert manifest.probe_cmd is not None
