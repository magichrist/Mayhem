"""k-plan-3 — kubernetes blueprint topology synthesis, target-selector
transparency, and maniac random rounds (SP-3.6 + target-selector SP-4).

Target-level kubernetes faults are *always* live-resolved at execution time
(ADR-M7-1). The manifest-provider PopNode stays in state "blueprint" so that
the planner compiles them as logical targets without ever guessing which pod
the mutation will land on. These tests pin four invariants:

  1. ``target_selector.select_many`` on a blueprint-only graph returns
     ``None`` (logically pinned); a Running pod with the matching
     workload owner name wins; a terminat-only match raises SelectionError.
  2. ``synthesize_k8s_maniac_spec`` from the manifest-provider graph
     produces a ``targets:`` spec whose pools contain k8s-specific faults
     (``k8s.pod_kill``) and whose execution block is empty.
  3. ``plan_maniac`` on a synthesized k8s spec compiles without
     SelectionError (blueprint → logically pinned), and every PlannedFault
     carries a TargetScope with the correct namespace/name but no pod_uid.
  4. ``draw_maniac_target_rounds`` at level ≥ 3 draws from *all* targets
     (cross-locus dispatch), with the same determinism guarantees as the
     container-level draw.
"""
from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from mayhem.controller.planner import (
    PlanningError,
    plan_maniac,
    synthesize_k8s_maniac_spec,
)
from mayhem.domain.experiments import (
    DrillSpec,
    ExecutionPlan,
    ManiacCfg,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.maniac import (
    ManiacError,
    draw_maniac_target_rounds,
)
from mayhem.domain.target import ResourceKind
from mayhem.topology.providers.k8s_manifest import KubernetesManifestProvider

# ── fixtures ─────────────────────────────────────────────────────────────────

_DOCKER_API = textwrap.dedent("""\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: api
      namespace: mayhem
      labels:
        app: api
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: api
      template:
        metadata:
          labels:
            app: api
        spec:
          containers:
            - name: api
              image: docker.io/library/python:3.13-alpine
              command: ["python", "-m", "http.server", "8080"]
              ports:
                - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: mayhem
spec:
  selector:
    app: api
  ports:
    - port: 8080
      targetPort: 8080
""")

_SINGLE_NODE_MANIFEST = textwrap.dedent("""\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: api
      namespace: mayhem
      labels:
        app: api
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: api
      template:
        metadata:
          labels:
            app: api
        spec:
          containers:
            - name: api
              image: docker.io/library/python:3.13-alpine
              command: ["python", "-m", "http.server", "8080"]
              ports:
                - containerPort: 8080
              resources:
                requests:
                  cpu: 100m
---
apiVersion: v1
kind: Node
metadata:
  name: control-plane
  labels:
    node-role.kubernetes.io/control-plane: ""
spec:
  podCIDR: 10.244.0.0/24
""")


def _temp_manifest(tmp_path: Path, content: str, name: str = "k8s.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _graph_from_manifest(tmp_path: Path, content: str):
    path = _temp_manifest(tmp_path, content)
    provider = KubernetesManifestProvider(path)
    fragment = provider.discover()
    known_ids = {n.id for n in fragment.nodes}
    safe_edges = tuple(e for e in fragment.edges if e.src in known_ids and e.dst in known_ids)
    from mayhem.domain.topology import TopologyGraph
    return TopologyGraph(nodes=fragment.nodes, edges=safe_edges)


def _live_pod(
    *,
    name: str,
    namespace: str,
    owner_kind: str,
    owner_name: str,
    state: str = "running",
    pod_id: str | None = None,
):
    from mayhem.domain.topology import PodNode
    return PodNode(
        id=pod_id or f"k8s::pod/{namespace}/{name}",
        name=name,
        namespace=namespace,
        state=state,
        owner_kind=owner_kind,
        owner_name=owner_name,
        labels={"app": owner_name},
    )


# ── tests: target_selector transparency ──────────────────────────────────────

class TestBlueprintTransparency:
    """Pins target-selector SP-4: blueprint pods are invisible to live picks."""

    def test_select_many_returns_none_for_all_blueprint(self, tmp_path):
        from mayhem.controller.target_selector import select_many
        graph = _graph_from_manifest(tmp_path, _DOCKER_API)
        scope = DrillSpec.model_validate({
            "kind": "drill",
            "name": "t",
            "targets": {"Deployment/mayhem/api": {
                "runtime": "kubernetes",
                "kubernetes": {"kind": "deployment", "namespace": "mayhem", "name": "api"},
                "faults": [{"fault": "k8s.pod_kill"}],
            }},
            "execution": [{"sequential": ["Deployment/mayhem/api"]}],
        }).targets["Deployment/mayhem/api"].to_scope("Deployment/mayhem/api")
        assert scope.runtime == RuntimeLabel.KUBERNETES
        picks = select_many(graph, scope)
        assert picks is None

    def test_select_many_picks_live_pod_matching_workload(self, tmp_path):
        from mayhem.controller.target_selector import select_many
        graph = _graph_from_manifest(tmp_path, _DOCKER_API)
        live = _live_pod(
            name="api-abc",
            namespace="mayhem",
            owner_kind="Deployment",
            owner_name="api",
            state="running",
        )
        graph = type(graph)(nodes=(*graph.nodes, live), edges=graph.edges)
        scope = DrillSpec.model_validate({
            "kind": "drill",
            "name": "t",
            "targets": {"Deployment/mayhem/api": {
                "runtime": "kubernetes",
                "kubernetes": {"kind": "deployment", "namespace": "mayhem", "name": "api"},
                "faults": [{"fault": "k8s.pod_kill"}],
            }},
            "execution": [{"sequential": ["Deployment/mayhem/api"]}],
        }).targets["Deployment/mayhem/api"].to_scope("Deployment/mayhem/api")
        picks = select_many(graph, scope)
        assert picks is not None
        assert len(picks) == 1
        assert picks[0].name == "api-abc"
        assert picks[0].namespace == "mayhem"

    def test_select_many_terminating_only_raises(self, tmp_path):
        from mayhem.controller.target_selector import select_many

        from mayhem.domain.errors import SelectionError
        graph = _graph_from_manifest(tmp_path, _DOCKER_API)
        dead = _live_pod(
            name="api-zzz",
            namespace="mayhem",
            owner_kind="Deployment",
            owner_name="api",
            state="terminating",
        )
        graph = type(graph)(nodes=(*graph.nodes, dead), edges=graph.edges)
        scope = DrillSpec.model_validate({
            "kind": "drill",
            "name": "t",
            "targets": {"Deployment/mayhem/api": {
                "runtime": "kubernetes",
                "kubernetes": {"kind": "deployment", "namespace": "mayhem", "name": "api"},
                "faults": [{"fault": "k8s.pod_kill"}],
            }},
            "execution": [{"sequential": ["Deployment/mayhem/api"]}],
        }).targets["Deployment/mayhem/api"].to_scope("Deployment/mayhem/api")
        with pytest.raises(SelectionError, match="no live pod"):
            select_many(graph, scope)


# ── tests: synthesize_k8s_maniac_spec ────────────────────────────────────────

class TestSynthesizeK8sManiacSpec:
    """Pins SP-3.6: kubernetes blueprint → targets spec with k8s faults."""

    def test_synthesized_targets_map_from_manifest(self, tmp_path):
        graph = _graph_from_manifest(tmp_path, _DOCKER_API)
        spec = synthesize_k8s_maniac_spec(graph)
        assert spec.kind == "drill"
        assert spec.targets is not None
        assert "Deployment/mayhem/api" in spec.targets
        target = spec.targets["Deployment/mayhem/api"]
        assert target.runtime == RuntimeLabel.KUBERNETES
        assert target.kubernetes is not None
        assert target.kubernetes.kind == ResourceKind.DEPLOYMENT
        assert target.kubernetes.namespace == "mayhem"
        assert target.kubernetes.name == "api"
        assert len(spec.execution) == 1  # schema-satisfying placeholder only

    def test_synthesized_pool_includes_k8s_podium_kill(self, tmp_path):
        graph = _graph_from_manifest(tmp_path, _DOCKER_API)
        spec = synthesize_k8s_maniac_spec(graph)
        target = spec.targets["Deployment/mayhem/api"]
        fault_ids = {f.fault for f in target.faults}
        assert "k8s.pod_kill" in fault_ids
        assert "cpu.saturate" in fault_ids or "mem.exhaust" in fault_ids

    def test_synthesized_node_targets(self, tmp_path):
        graph = _graph_from_manifest(tmp_path, _SINGLE_NODE_MANIFEST)
        spec = synthesize_k8s_maniac_spec(graph)
        assert "k8s_node/control-plane" in spec.targets
        node_target = spec.targets["k8s_node/control-plane"]
        assert node_target.runtime == RuntimeLabel.KUBERNETES
        assert node_target.kubernetes is not None
        assert node_target.kubernetes.kind == ResourceKind.K8S_NODE
        assert node_target.kubernetes.name == "control-plane"
        fault_ids = {f.fault for f in node_target.faults}
        assert "k8s.node_drain" in fault_ids


# ── tests: draw_maniac_target_rounds ────────────────────────────────────────

class TestDrawManiacTargetRounds:
    """Pins cross-locus dispatch (level ≥ 3) and determinism."""

    def _spec_with_targets(
        self,
        targets: dict[str, Any] | None = None,
        *,
        maniac: dict[str, Any] | None = None,
    ) -> DrillSpec:
        if targets is None:
            targets = {
                "Deployment/mayhem/api": {
                    "runtime": "kubernetes",
                    "kubernetes": {"kind": "deployment", "namespace": "mayhem", "name": "api"},
                    "faults": [{"fault": "k8s.pod_kill"}],
                },
            }
        return DrillSpec.model_validate({
            "kind": "drill",
            "name": "kmd",
            "targets": targets,
            "execution": [{"sequential": list(targets.keys())}],
            "config": {
                "risk_ceiling": "critical",
                "max_faults": 1,
                "timeout": "30m",
                **({"maniac": maniac} if maniac else {}),
            },
        })

    def test_deterministic_draw(self):
        spec = self._spec_with_targets(maniac={"level": 2, "run_level": 5, "seed": 42})
        d1 = draw_maniac_target_rounds(spec, level=2, run_level=5, seed=42)
        d2 = draw_maniac_target_rounds(spec, level=2, run_level=5, seed=42)
        assert [r.round for r in d1] == [r.round for r in d2]
        assert [r.target for r in d1] == [r.target for r in d2]
        assert [r.fault.fault for r in d1] == [r.fault.fault for r in d2]

    def test_cross_locus_dispatch(self):
        targets = {
            "Deployment/mayhem/api": {
                "runtime": "kubernetes",
                "kubernetes": {"kind": "deployment", "namespace": "mayhem", "name": "api"},
                "faults": [{"fault": "k8s.pod_kill"}],
            },
            "k8s_node/control-plane": {
                "runtime": "kubernetes",
                "kubernetes": {"kind": "k8s_node", "namespace": "", "name": "control-plane"},
                "faults": [{"fault": "k8s.node_drain", "grace_period": 30}],
            },
        }
        spec = self._spec_with_targets(
            targets=targets,
            maniac={"level": 3, "run_level": 100, "seed": 7},
        )
        draws = draw_maniac_target_rounds(spec, level=3, run_level=100, seed=7)
        seen_targets = {d.target for d in draws}
        assert "Deployment/mayhem/api" in seen_targets
        assert "k8s_node/control-plane" in seen_targets

    def test_run_level_enforced(self):
        spec = self._spec_with_targets(maniac={"level": 2, "run_level": 10, "seed": 1})
        draws = draw_maniac_target_rounds(spec, level=2, run_level=10, seed=1)
        assert len(draws) == 10

    def test_empty_targets_raises(self):
        spec = self._spec_with_targets(targets={}, maniac={"level": 2, "run_level": 5, "seed": 1})
        with pytest.raises(ManiacError):
            draw_maniac_target_rounds(spec, level=2, run_level=5, seed=1)


# ── tests: plan_maniac on k8s synthesized spec ──────────────────────────────

class TestPlanManiacK8sSpec:
    """Pins SP-3.6: synthesized k8s spec compiles through plan_maniac."""

    def _compile(
        self,
        tmp_path,
        content: str = _DOCKER_API,
        *,
        maniac: dict[str, Any] | None = None,
        run_level: int = 3,
        seed: int = 1,
        level: int = 2,
    ) -> ExecutionPlan:
        graph = _graph_from_manifest(tmp_path, content)
        spec = synthesize_k8s_maniac_spec(graph)
        cfg = ManiacCfg(level=level, run_level=run_level, seed=seed)
        if maniac:
            cfg = ManiacCfg(**maniac)
        return plan_maniac(
            "r-maniac-1",
            spec,
            graph,
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
            engine="kubernetes",
            maniac=cfg,
        )

    def test_plan_maniac_compiles(self, tmp_path):
        plan = self._compile(tmp_path)
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 3

    def test_planned_faults_have_target_scope(self, tmp_path):
        plan = self._compile(tmp_path, run_level=2, seed=5)
        faults = [s for s in plan.steps if s.fault is not None]
        for fault in faults:
            scope = fault.target
            assert scope is not None
            assert scope.runtime == RuntimeLabel.KUBERNETES
            assert scope.kind == ResourceKind.DEPLOYMENT
            assert scope.namespace == "mayhem"
            assert scope.name == "api"
            assert scope.pod_uid is None

    def test_plan_maniac_with_node_drain(self, tmp_path):
        plan = self._compile(
            tmp_path,
            content=_SINGLE_NODE_MANIFEST,
            maniac={"level": 2, "run_level": 2, "seed": 10},
        )
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 2
        for fault in faults:
            scope = fault.target
            assert scope is not None
            assert scope.kind == ResourceKind.K8S_NODE
            assert scope.name == "control-plane"
            assert scope.namespace == ""


# ── tests: non-k8s target refusal ───────────────────────────────────────────

class TestPlanManiacRefusesHeterogeneousTargets:
    """k-plan-3 SP-3.6: mixed docker + kubernetes targets in a single spec
    are refused at plan_maniac (maniac rounds are kubernetes-scoped only)."""

    def test_mixed_targets_raises(self, tmp_path):
        graph = _graph_from_manifest(tmp_path, _DOCKER_API)
        spec = DrillSpec.model_validate({
            "kind": "drill",
            "name": "mixed",
            "targets": {
                "docker/web": {
                    "runtime": "docker",
                    "faults": [{"fault": "proc.pause"}],
                },
                "Deployment/mayhem/api": {
                    "runtime": "kubernetes",
                    "kubernetes": {"kind": "deployment", "namespace": "mayhem", "name": "api"},
                    "faults": [{"fault": "k8s.pod_kill"}],
                },
            },
            "execution": [{"sequential": ["docker/web", "Deployment/mayhem/api"]}],
            "config": {"risk_ceiling": "critical", "max_faults": 1, "timeout": "30m"},
        })
        with pytest.raises(PlanningError, match="kubernetes-scoped"):
            plan_maniac(
                "r-x",
                spec,
                graph,
                config_snapshot_id="c",
                topology_snapshot_id="t",
                environment_fingerprint="f",
                engine="kubernetes",
                maniac=ManiacCfg(level=2, run_level=3, seed=1),
            )
