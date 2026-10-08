"""v1.1.0 plan 02 Phase 3 — CRDs compile through `plan_drill`, nothing else.

Acceptance: a CR-created run produces the same frozen plan object as a
CLI-created run over the same spec. "CLI-created" here is
:func:`~mayhem.controller.planner.plan_drill` over the
:class:`~mayhem.domain.experiments.DrillSpec` the CLI's YAML parse would
produce; "CR-created" is :func:`~mayhem.controller.k8s_controller.plan_from_cr`
over the same body inside a CR envelope. Same spec + same ids ⇒ equal plans.

Also pinned: the deploy surface parses (CRDs, RBAC, Helm stub values), the
kubectl plugin maps each subcommand onto exactly one 08 API route, and
`drillRef` (which needs a live informer) is refused with a named debt code.

Honesty note: every plan here came from a dict on an empty graph, not a
cluster. No live cluster has been accepted by this phase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mayhem.cli import k8s_plugin
from mayhem.controller import k8s_controller
from mayhem.controller.planner import plan_drill
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillSpec
from mayhem.domain.k8s_adapter import KubernetesAdapter
from mayhem.domain.topology import TopologyGraph

RUN_ID = "run-cr-1"
SNAPSHOTS = {
    "config_snapshot_id": "cfg-1",
    "topology_snapshot_id": "topo-1",
    "environment_fingerprint": "fp-1",
}

DRILL_BODY: dict[str, Any] = {
    "targets": {
        "checkout": {
            "runtime": "kubernetes",
            "kubernetes": {
                "kind": "deployment",
                "namespace": "shop",
                "name": "checkout",
            },
            "faults": [{"fault": "k8s.pod_kill"}],
        }
    },
    "execution": [{"sequential": ["checkout"]}],
}

CR_API = "mayhem.io/v1alpha1"


def _drill_cr(**overrides: Any) -> dict[str, Any]:
    cr: dict[str, Any] = {
        "apiVersion": CR_API,
        "kind": "MayhemDrill",
        "metadata": {"name": "checkout-chaos", "namespace": "shop"},
        "spec": dict(DRILL_BODY),
    }
    cr.update(overrides)
    return cr


def _graph() -> TopologyGraph:
    """An empty plan-time graph: the workload stays logically pinned (k-plan-1)."""
    return TopologyGraph(nodes=(), edges=())


def _cli_plan():
    spec = DrillSpec.model_validate({"kind": "drill", "name": "checkout-chaos", **DRILL_BODY})
    return plan_drill(RUN_ID, spec, _graph(), **SNAPSHOTS)


def _frozen_shape(plan: object) -> tuple[tuple[object, ...], ...]:
    """The deterministic content of a frozen plan: group ids are run-uuids.

    `_plan_target_faults` mints `grp-<uuid>` per compilation, so two
    compilations of one spec are never byte-equal. The shape below is what
    "same frozen plan" means: every fault step's identity, target, params,
    and timing, in order. Timestamps/snapshot ids are asserted separately
    by construction (same call args).
    """
    steps = getattr(plan, "steps", ())
    shape: list[tuple[object, ...]] = []
    for step in steps:
        fault = getattr(step, "fault", None)
        if fault is None:
            shape.append(("wait", getattr(step, "id", "")))
            continue
        target = getattr(fault, "target", None)
        authority = None
        if target is not None:
            authority = (
                getattr(target, "logical_id", ""),
                getattr(target, "runtime", ""),
                getattr(target, "kind", ""),
                dict(getattr(target, "authority", {}) or {}),
            )
        shape.append(
            (
                getattr(step, "seq", 0),
                getattr(fault, "fault_id", ""),
                authority,
                dict(getattr(fault, "params", {}) or {}),
                str(getattr(fault, "duration", "")),
            )
        )
    return tuple(shape)


# ── acceptance: CR plans equal CLI plans ──────────────────────────────────────
class TestCrParity:
    def test_mayhem_drill_compiles_to_the_cli_plan(self) -> None:
        cr_plan = k8s_controller.plan_from_cr(_drill_cr(), _graph(), run_id=RUN_ID, **SNAPSHOTS)
        assert _frozen_shape(cr_plan) == _frozen_shape(_cli_plan())
        assert cr_plan.run_id == RUN_ID

    def test_mayhem_experiment_compiles_its_template_to_the_cli_plan(self) -> None:
        cr = {
            "apiVersion": CR_API,
            "kind": "MayhemExperiment",
            "metadata": {"name": "checkout-chaos"},
            "spec": {"drill": dict(DRILL_BODY)},
        }
        cr_plan = k8s_controller.plan_from_cr(cr, _graph(), run_id=RUN_ID, **SNAPSHOTS)
        assert _frozen_shape(cr_plan) == _frozen_shape(_cli_plan())

    def test_mayhem_run_with_inline_drill_compiles_to_the_cli_plan(self) -> None:
        cr = {
            "apiVersion": CR_API,
            "kind": "MayhemRun",
            "metadata": {"name": "checkout-chaos", "namespace": "shop"},
            "spec": {"drill": dict(DRILL_BODY)},
        }
        cr_plan = k8s_controller.plan_from_cr(cr, _graph(), run_id=RUN_ID, **SNAPSHOTS)
        assert _frozen_shape(cr_plan) == _frozen_shape(_cli_plan())

    def test_the_frozen_steps_carry_the_workload_identity(self) -> None:
        plan = k8s_controller.plan_from_cr(_drill_cr(), _graph(), run_id=RUN_ID, **SNAPSHOTS)
        (step,) = [s for s in plan.steps if s.fault is not None]
        assert step.fault is not None and step.fault.fault_id == "k8s.pod_kill"
        assert step.fault.target is not None
        assert step.fault.target.authority["name"] == "checkout"
        assert step.fault.target.authority["namespace"] == "shop"


# ── the controller has no parallel planner ────────────────────────────────────
class TestSinglePlanner:
    def test_compilation_goes_through_plan_drill_only(self) -> None:
        source = Path(k8s_controller.__file__).read_text(encoding="utf-8")
        assert "plan_drill" in source
        assert "plan_maniac" not in source

    def test_a_drill_ref_is_refused_not_resolved(self) -> None:
        cr = {
            "apiVersion": CR_API,
            "kind": "MayhemRun",
            "metadata": {"name": "ref-run", "namespace": "shop"},
            "spec": {"drillRef": {"name": "checkout-chaos"}},
        }
        with pytest.raises(InvariantViolationError) as excinfo:
            k8s_controller.plan_from_cr(cr, _graph(), run_id=RUN_ID, **SNAPSHOTS)
        assert "k8s.cr_drillref_requires_cluster" in str(excinfo.value)

    def test_a_drill_body_is_not_a_run_envelope(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            k8s_controller.drill_spec_from_cr({**_drill_cr(), "kind": "MayhemRun"})
        assert "k8s.cr_bad_kind" in str(excinfo.value)

    @pytest.mark.parametrize(
        ("cr", "code"),
        [
            ({**_drill_cr(), "apiVersion": "chaos.io/v9"}, "k8s.cr_bad_api_version"),
            ({**_drill_cr(), "metadata": {}}, "k8s.cr_missing_name"),
            ({**_drill_cr(), "spec": None}, "k8s.cr_missing_spec"),
            (
                {
                    "apiVersion": CR_API,
                    "kind": "CronJob",
                    "metadata": {"name": "x"},
                    "spec": dict(DRILL_BODY),
                },
                "k8s.cr_unknown_kind",
            ),
        ],
    )
    def test_malformed_envelopes_are_refused_with_named_codes(
        self, cr: dict[str, Any], code: str
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            k8s_controller.plan_from_cr(cr, _graph(), run_id=RUN_ID, **SNAPSHOTS)
        assert code in str(excinfo.value)


# ── deploy surface parses ─────────────────────────────────────────────────────
DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "mayhem"


def _load_all(path: Path) -> list[dict[str, Any]]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


class TestDeploySurface:
    def test_crds_parse_and_name_the_three_kinds(self) -> None:
        kinds = {}
        for name in ("mayhem-drill-crd.yaml", "mayhem-experiment-crd.yaml", "mayhem-run-crd.yaml"):
            (doc,) = _load_all(DEPLOY / "crds" / name)
            assert doc["kind"] == "CustomResourceDefinition"
            kinds[doc["metadata"]["name"]] = doc["spec"]["names"]["kind"]
        assert kinds == {
            "mayhemdrills.mayhem.io": "MayhemDrill",
            "mayhemexperiments.mayhem.io": "MayhemExperiment",
            "mayhemruns.mayhem.io": "MayhemRun",
        }

    def test_rbac_parses_and_gives_the_controller_no_workload_writes(self) -> None:
        docs = _load_all(DEPLOY / "rbac" / "roles.yaml")
        (cluster_role,) = [d for d in docs if d.get("kind") == "ClusterRole"]
        verbs = {
            rule["resources"][0]: rule["verbs"]
            for rule in cluster_role["rules"]
            if rule.get("apiGroups") == ["apps"]
        }
        assert verbs  # workload reads exist for admission facts
        assert all(set(v) <= {"get", "list", "watch"} for v in verbs.values())

    def test_helm_stub_parses_and_refuses_latest_by_default(self) -> None:
        chart = yaml.safe_load(
            (DEPLOY / "helm" / "mayhem" / "Chart.yaml").read_text(encoding="utf-8")
        )
        assert chart["name"] == "mayhem"
        assert chart["version"].endswith("stub")
        values = yaml.safe_load(
            (DEPLOY / "helm" / "mayhem" / "values.yaml").read_text(encoding="utf-8")
        )
        assert values["controller"]["image"] == ""
        assert values["agent"]["image"] == ""
        assert "kube-system" in values["protectedNamespaces"]
        # Templates are Go templates, not plain YAML: assert shape by text.
        for template in ("controller-deployment.yaml", "agent-daemonset.yaml"):
            text = (DEPLOY / "helm" / "mayhem" / "templates" / template).read_text(encoding="utf-8")
            assert "required " in text and "is required" in text
            assert "mayhem-agent" in text or "mayhem-controller" in text
        daemonset = (DEPLOY / "helm" / "mayhem" / "templates" / "agent-daemonset.yaml").read_text(
            encoding="utf-8"
        )
        assert "MAYHEM_AGENT_LISTEN" in daemonset  # agents never listen


# ── kubectl plugin: one subcommand, one 08 route ─────────────────────────────
class TestKubectlPlugin:
    def test_plan_posts_the_file_bytes_to_plans(self, tmp_path: Path) -> None:
        drill = tmp_path / "drill.yaml"
        drill.write_text("targets: {}", encoding="utf-8")
        request = k8s_plugin.build_plan_request(drill, server="http://ctl:8080")
        assert request.method == "POST"
        assert request.url == "http://ctl:8080/api/v1/plans"
        assert request.body is not None and "targets" in str(request.body["drill_yaml"])

    def test_get_runs_lists_and_stop_posts(self) -> None:
        listed = k8s_plugin.build_list_runs_request(server="http://ctl:8080")
        assert (listed.method, listed.url) == ("GET", "http://ctl:8080/api/v1/runs")
        stopped = k8s_plugin.build_stop_request("run-1", server="http://ctl:8080")
        assert (stopped.method, stopped.url) == ("POST", "http://ctl:8080/api/v1/runs/run-1/stop")
        health = k8s_plugin.build_health_request(server="http://ctl:8080")
        assert (health.method, health.url) == ("GET", "http://ctl:8080/api/v1/health")

    def test_the_plugin_never_plans_or_admits(self) -> None:
        source = Path(k8s_plugin.__file__).read_text(encoding="utf-8")
        assert "plan_drill" not in source
        assert "validate_plan" not in source
        assert "urllib.request" in source  # the only I/O: the API call itself


def test_no_live_cluster_is_claimed_by_this_phase() -> None:
    assert KubernetesAdapter().is_available() is False
