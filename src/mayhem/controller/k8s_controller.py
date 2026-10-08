"""CRD controller compilation: CRs become frozen plans (plan 02 Phase 3).

The controller's one job is translation, not planning. A ``MayhemDrill``,
``MayhemExperiment``, or ``MayhemRun`` custom resource carries an authored
drill-spec body; this module validates the CR envelope (group/version/kind),
builds the :class:`~mayhem.domain.experiments.DrillSpec` the CLI would have
parsed from the same YAML, and compiles it through
:func:`~mayhem.controller.planner.plan_drill` — the single planner. There is
no parallel planner here by construction: this module imports ``plan_drill``
and nothing else that compiles.

What is deliberately *not* here
-------------------------------
* **No cluster I/O.** ``drillRef`` (a ``MayhemRun`` pointing at a stored
  ``MayhemDrill``) needs a live API read and is refused with
  ``k8s.cr_drillref_requires_cluster`` until the informer lands. Inline
  ``spec.drill`` is the only supported shape, and the refusal says so.
* **No live claim.** Every plan this module builds in the test suite came
  from a dict, not a cluster. ``KubernetesAdapter.is_available()`` stays
  ``False``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.controller.planner import plan_drill
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillSpec

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph

#: The group/version this controller reconciles. A CR from any other group is
#: not "an older mayhem" — it is somebody else's object.
CR_GROUP = "mayhem.io"
CR_VERSION = "v1alpha1"

CR_KIND_DRILL = "MayhemDrill"
CR_KIND_EXPERIMENT = "MayhemExperiment"
CR_KIND_RUN = "MayhemRun"

_CR_KINDS = frozenset({CR_KIND_DRILL, CR_KIND_EXPERIMENT, CR_KIND_RUN})


@dataclass(frozen=True)
class RunRequest:
    """A ``MayhemRun`` resolved to the drill it asks to run.

    ``run_name``/``namespace`` are the CR's own identity (for status writes);
    ``spec`` is the inline drill body. A ``drillRef`` run never becomes one of
    these — :func:`run_spec_from_cr` refuses it before a request exists.
    """

    run_name: str
    namespace: str
    spec: DrillSpec


def _envelope(cr: Mapping[str, Any], *, want_kind: str) -> Mapping[str, Any]:
    api_version = str(cr.get("apiVersion") or "")
    kind = str(cr.get("kind") or "")
    if api_version != f"{CR_GROUP}/{CR_VERSION}":
        raise InvariantViolationError(
            "k8s.cr_bad_api_version",
            f"CR apiVersion {api_version!r} is not {CR_GROUP}/{CR_VERSION}; "
            "this controller reconciles only its own group/version",
        )
    if kind != want_kind:
        raise InvariantViolationError(
            "k8s.cr_bad_kind",
            f"CR kind {kind!r} is not {want_kind}; refusing rather than coercing",
        )
    metadata = cr.get("metadata") or {}
    if not isinstance(metadata, dict) or not str(metadata.get("name") or "").strip():
        raise InvariantViolationError(
            "k8s.cr_missing_name",
            f"CR kind {want_kind} carries no metadata.name; a nameless run is unstatable",
        )
    spec = cr.get("spec")
    if not isinstance(spec, dict):
        raise InvariantViolationError(
            "k8s.cr_missing_spec",
            f"CR kind {want_kind} carries no spec mapping",
        )
    return spec


def drill_spec_from_mapping(data: Mapping[str, Any], *, name: str) -> DrillSpec:
    """A drill-spec body mapping plus a name, as the CLI's YAML would parse it.

    ``kind: drill`` is filled, never read: a CR body that declares its own
    ``kind`` and disagrees would be two answers, so the envelope wins.
    """
    body = dict(data)
    body["kind"] = "drill"
    body.setdefault("name", name)
    try:
        return DrillSpec.model_validate(body)
    except Exception as exc:
        raise InvariantViolationError(
            "k8s.cr_bad_drill_body",
            f"CR drill body does not parse as a DrillSpec: {exc}",
        ) from exc


def drill_spec_from_cr(cr: Mapping[str, Any]) -> DrillSpec:
    """The :class:`DrillSpec` a ``MayhemDrill`` CR authors."""
    spec = _envelope(cr, want_kind=CR_KIND_DRILL)
    metadata = cr["metadata"]
    assert isinstance(metadata, dict)
    return drill_spec_from_mapping(spec, name=str(metadata["name"]))


def experiment_spec_from_cr(cr: Mapping[str, Any]) -> DrillSpec:
    """The template a ``MayhemExperiment`` CR authors (its ``spec.drill``)."""
    spec = _envelope(cr, want_kind=CR_KIND_EXPERIMENT)
    drill = spec.get("drill")
    if not isinstance(drill, dict):
        raise InvariantViolationError(
            "k8s.cr_missing_drill_template",
            "MayhemExperiment.spec carries no `drill:` template mapping",
        )
    metadata = cr["metadata"]
    assert isinstance(metadata, dict)
    return drill_spec_from_mapping(drill, name=str(metadata["name"]))


def run_spec_from_cr(cr: Mapping[str, Any]) -> RunRequest:
    """The run a ``MayhemRun`` CR requests — inline ``spec.drill`` only.

    ``spec.drillRef`` is refused with a named debt code, not a fallback: a
    reference the controller cannot resolve inside this call would have to be
    resolved against a live API, which is exactly the informer work this phase
    does not do.
    """
    spec = _envelope(cr, want_kind=CR_KIND_RUN)
    metadata = cr["metadata"]
    assert isinstance(metadata, dict)
    name = str(metadata["name"])
    namespace = str(metadata.get("namespace") or "default")
    drill = spec.get("drill")
    if isinstance(drill, dict):
        return RunRequest(
            run_name=name,
            namespace=namespace,
            spec=drill_spec_from_mapping(drill, name=name),
        )
    ref = spec.get("drillRef")
    ref_name = ref.get("name") if isinstance(ref, dict) else None
    raise InvariantViolationError(
        "k8s.cr_drillref_requires_cluster",
        f"MayhemRun {namespace}/{name} uses `drillRef: {ref_name}`; reference "
        "resolution needs a live cluster informer over MayhemDrill objects, "
        "which this phase does not ship — inline `spec.drill` instead",
    )


def plan_from_cr(
    cr: Mapping[str, Any],
    graph: TopologyGraph,
    *,
    run_id: str,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
) -> ExecutionPlan:
    """Compile any of the three CR kinds through :func:`plan_drill`.

    ``MayhemExperiment`` compiles its template; ``MayhemRun`` compiles its
    inline drill. The plan is byte-comparable to a CLI-compiled plan over the
    same spec and ids — that equality is the phase's acceptance criterion and
    ``tests/unit/test_k8s_crds.py`` pins it.
    """
    kind = str(cr.get("kind") or "")
    if kind == CR_KIND_DRILL:
        spec = drill_spec_from_cr(cr)
    elif kind == CR_KIND_EXPERIMENT:
        spec = experiment_spec_from_cr(cr)
    elif kind == CR_KIND_RUN:
        spec = run_spec_from_cr(cr).spec
    else:
        raise InvariantViolationError(
            "k8s.cr_unknown_kind",
            f"CR kind {kind!r} is not one of {sorted(_CR_KINDS)}",
        )
    return plan_drill(
        run_id,
        spec,
        graph,
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
    )


__all__ = (
    "CR_GROUP",
    "CR_KIND_DRILL",
    "CR_KIND_EXPERIMENT",
    "CR_KIND_RUN",
    "CR_VERSION",
    "RunRequest",
    "drill_spec_from_cr",
    "drill_spec_from_mapping",
    "experiment_spec_from_cr",
    "plan_from_cr",
    "run_spec_from_cr",
)
