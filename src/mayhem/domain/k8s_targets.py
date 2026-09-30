"""Kubernetes selector and workload-safety domain types (v1.1.0 plan 02 phase 1).

Pure domain model for the two things the plan names as phase-1 deliverables:

1. :class:`K8sSelector` — the target-selector grammar the plan requires:
   name, namespace, labels, annotations, workload kind, node, percentage /
   random selection, and topology zone/region.
2. :class:`WorkloadFacts` plus :class:`K8sAdmissionVerdict` — the workload
   safety facts (replicas, PDB ``minAvailable``, readiness/liveness,
   workload-kind semantics, anti-affinity, topology spread, cluster health)
   and the refusals computed from them.

The headline differentiator is the **PDB rule as a pure function whose refusal
shows its arithmetic** — "replicas=10, PDB minAvailable=8, requested kill 4 →
DENY, expected availability after fault = 6, PDB requires >= 8". Nothing here
talks to a cluster: every function takes facts and returns facts.

Deliberate boundaries
---------------------
* **No live resolution, and none duplicated.** ``mayhem.agents.k8s_resolve``
  owns the 5-step live flow (locate workload → eligible Running pods → pick →
  named container → evidence). This module consumes its
  :class:`~mayhem.domain.resolution.ResolvedPodTarget` records; it never
  re-implements discovery or exec. Phase 2 wires them together.
* **Unresolved is drift, not a target.** A candidate that carries no resolved
  target lands in :attr:`K8sSelection.drift` (an exclusion), never in
  :attr:`K8sSelection.targets`.
* **Blueprint placeholders are never live-eligible.** The offline
  ``topology/providers/k8s_manifest.py`` provider emits ``state="blueprint"``
  ``PodNode`` placeholders; :attr:`K8sSelectionCandidate.live_eligible` refuses
  them by the same rule ``domain/target_selector.py`` uses, so an offline
  blueprint can never become a live selection (docs/README.md
  "Kubernetes status vocabulary").
* **An empty selection is explicit.** A selector matching nothing returns an
  empty :class:`K8sSelection` with a reason. It never degrades into an
  all-match.
* **Deterministic by construction.** Percentage/count/all/one consume the
  candidate set in hash-stable order; ``random`` is a single draw from an
  *injected* seed and refuses without one — never wall-clock, never the global
  RNG.
* **Node-scoped selection is not modelled here.** ``k8s.node_drain`` /
  ``k8s.node_pressure`` resolve through ``resolve_node`` /
  :class:`~mayhem.domain.resolution.ResolvedNodeTarget`; the target model in
  this plan is ``Cluster → Namespace → Workload → Pod → Container``.
"""

from __future__ import annotations

import math
import random
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.errors import InvariantViolationError, SelectionError
from mayhem.domain.resolution import ResolvedPodTarget
from mayhem.domain.target import SelectionMode, SelectionSpec

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.domain.topology import PodNode


# ── workload kinds ──────────────────────────────────────────────────────────
class WorkloadKind(StrEnum):
    """The workload kinds a Kubernetes fault can be aimed at.

    The members carry semantics, not just labels — :attr:`node_bound` and
    :attr:`ordered_identity` are what make a DaemonSet fault and a StatefulSet
    fault refuse for different reasons than a Deployment fault.
    """

    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    DAEMONSET = "daemonset"
    JOB = "job"
    POD = "pod"

    @property
    def node_bound(self) -> bool:
        """True when one pod exists per eligible node (DaemonSet).

        A node-bound pod does not reschedule to another node when it is killed;
        coverage only returns when the node does. This is the fact the
        DaemonSet admission rule refuses on.
        """
        return self is WorkloadKind.DAEMONSET

    @property
    def ordered_identity(self) -> bool:
        """True when each replica carries a stable identity (StatefulSet).

        StatefulSet pods are interchangeable only in name: the ordinal is part
        of the pod's hostname, its identity, and its volume claim. Killing two
        at once is not the same operation as killing one twice.
        """
        return self is WorkloadKind.STATEFULSET

    @property
    def replica_gated(self) -> bool:
        """True when replica count is the meaningful availability number.

        A Job runs to completion and a bare Pod has exactly one replica, so a
        replica-count rule (PDB and friends) is vacuous for them.
        """
        return self in (WorkloadKind.DEPLOYMENT, WorkloadKind.STATEFULSET, WorkloadKind.DAEMONSET)

    @property
    def restartable(self) -> bool:
        """True when the controller recreates a killed pod automatically."""
        return self in (WorkloadKind.DEPLOYMENT, WorkloadKind.STATEFULSET, WorkloadKind.DAEMONSET)

    @classmethod
    def parse(cls, value: str | None) -> WorkloadKind | None:
        """Best-effort parse of a Kubernetes kind string, ``None`` when unknown.

        Accepts both the API's CamelCase label (``"StatefulSet"``, as written
        to ``PodNode.owner_kind`` by the discovery and manifest providers) and
        the lowercase domain spelling (``"statefulset"``). An unrecognised kind
        is ``None`` rather than an exception: a pod owned by a ``ReplicaSet``
        is still a legitimate candidate, just an unclassified workload.
        """
        if not value:
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None


#: Kinds whose pods are gated on replica availability by the PDB rule.
REPLICA_GATED_KINDS: frozenset[WorkloadKind] = frozenset(
    kind for kind in WorkloadKind if kind.replica_gated
)

#: Why a selection came back with no target. ``matched`` and ``eligible`` on
#: :class:`K8sSelection` carry the counts; this carries the meaning.
EMPTY_SELECTION_REASON = (
    "selected nothing: no live-eligible pod matched the selector "
    "(blueprint placeholders and unresolved pins are drift, not targets)"
)


# ── selection candidates ────────────────────────────────────────────────────
class K8sTargetSource(StrEnum):
    """Where a selection candidate came from — the live/blueprint/unresolved axis.

    The distinction is the plan's honesty rule in enum form: only a ``LIVE``
    candidate backed by a resolved target may be selected.
    """

    LIVE = "live"  # a real pod resolved through the live flow
    BLUEPRINT = "blueprint"  # offline manifest placeholder (k8s_manifest.py)
    UNRESOLVED = "unresolved"  # nothing resolved yet — logical pin, not a target


class K8sSelectionCandidate(BaseModel):
    """One pod a :class:`K8sSelector` may select, with the facts it matches on.

    A candidate is *not* a target. It becomes one only when
    :attr:`live_eligible` holds — that is, when the live flow resolved it and
    the offline blueprint did not author it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)  # the pod name
    namespace: str = "default"
    target: ResolvedPodTarget | None = None  # resolved evidence; None ⇒ never a target
    source: K8sTargetSource = K8sTargetSource.LIVE
    state: str = "running"  # mirrors PodNode.state ("running" / "blueprint" / …)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    workload_kind: WorkloadKind | None = None
    workload_name: str = ""  # owning Deployment/StatefulSet/… name
    node: str = ""  # hosting cluster node (spec.nodeName)
    zone: str = ""  # topology.kubernetes.io/zone
    region: str = ""  # topology.kubernetes.io/region

    @property
    def is_blueprint(self) -> bool:
        """True for an offline manifest placeholder.

        Same predicate as ``domain/target_selector._is_blueprint`` so the two
        graph paths cannot drift apart.
        """
        return self.state == "blueprint" or self.source is K8sTargetSource.BLUEPRINT

    @property
    def live_eligible(self) -> bool:
        """True when this candidate may be selected as a live target.

        Requires a ``LIVE`` source, a real resolved target, and a non-blueprint
        state. Unresolved and blueprint candidates are ineligible by
        construction.
        """
        return (
            self.source is K8sTargetSource.LIVE
            and self.target is not None
            and not self.is_blueprint
        )

    @property
    def identity(self) -> tuple[str, str, str]:
        """Hash-stable ordering key: namespace, name, pod uid (k-plan-2 §2.5)."""
        return (self.namespace, self.name, self.target.pod_uid if self.target else "")

    @classmethod
    def from_pod_node(
        cls,
        pod: PodNode,
        *,
        target: ResolvedPodTarget | None = None,
        annotations: dict[str, str] | None = None,
        zone: str = "",
        region: str = "",
    ) -> K8sSelectionCandidate:
        """Project a topology ``PodNode`` onto a candidate.

        Used by the offline path (a manifest blueprint graph) so the selector
        sees the same field names the live path produces. The blueprint state
        is carried through verbatim, which is what keeps
        :attr:`live_eligible` false for every placeholder.
        """
        blueprint = pod.state == "blueprint"
        return cls(
            name=pod.name,
            namespace=pod.namespace or "default",
            target=target,
            source=K8sTargetSource.BLUEPRINT if blueprint else K8sTargetSource.LIVE,
            state=pod.state or "unknown",
            labels=dict(pod.labels),
            annotations=dict(annotations or {}),
            workload_kind=WorkloadKind.parse(pod.owner_kind),
            workload_name=pod.owner_name or "",
            node=pod.node_name or "",
            zone=zone,
            region=region,
        )


class K8sExclusionKind(StrEnum):
    """Why a candidate that *matched* the selector is not a target."""

    DRIFT = "drift"  # matched, but nothing resolved — logical pin
    BLUEPRINT = "blueprint"  # matched, but an offline manifest placeholder
    NOT_ELIGIBLE = "not_eligible"  # matched, but not a live resolved target


class K8sSelectionExclusion(BaseModel):
    """A matched candidate that is deliberately not a target, with the reason."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate: K8sSelectionCandidate
    kind: K8sExclusionKind
    reason: str


class K8sSelection(BaseModel):
    """The frozen outcome of one selector run.

    ``targets`` is what may be mutated; every other bucket explains why a
    matched candidate is not in it. An empty ``targets`` tuple is an explicit
    "selected nothing" — never a silent fallback to the whole set.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    selector: str = ""  # rendered selector, for the evidence note
    targets: tuple[ResolvedPodTarget, ...] = ()
    eligible: int = 0  # live-eligible candidates matching every dimension
    matched: int = 0  # candidates matching the selector, eligible or not
    excluded: tuple[K8sSelectionExclusion, ...] = ()
    reason: str = ""  # why the selection is empty

    @property
    def is_empty(self) -> bool:
        """True when the selector produced no target."""
        return not self.targets

    @property
    def drift(self) -> tuple[K8sSelectionExclusion, ...]:
        """Exclusions that are drift (matched, never resolved)."""
        return tuple(e for e in self.excluded if e.kind is K8sExclusionKind.DRIFT)

    @property
    def authority_keys(self) -> tuple[str, ...]:
        """``namespace/pod`` keys of the selected targets, in order."""
        return tuple(t.authority_key for t in self.targets)

    def exclusion_summary(self) -> str:
        """One-line count per exclusion bucket, for a refusal note."""
        parts = [f"selected {len(self.targets)} of {self.eligible} eligible"]
        for kind in K8sExclusionKind:
            count = sum(1 for e in self.excluded if e.kind is kind)
            if count:
                parts.append(f"{count} {kind.value}")
        return ", ".join(parts)


# ── the selector ────────────────────────────────────────────────────────────
class K8sSelector(BaseModel):
    """Target selector over a set of resolved Kubernetes pods.

    Dimensions (all optional; an empty dimension matches everything, never
    nothing):

    * ``name`` — the pod name;
    * ``workload_name`` / ``workload_kind`` — the owning workload identity;
    * ``namespace``;
    * ``labels`` / ``annotations`` — Kubernetes *subset* semantics
      (equality-based, like ``matchLabels``);
    * ``node`` — the hosting node name;
    * ``zones`` / ``regions`` — topology keys, membership over a set;
    * ``selection`` — ``one`` / ``all`` / ``count`` / ``percentage`` /
      ``random`` (the existing :class:`~mayhem.domain.target.SelectionSpec`
      grammar, reused rather than re-invented).

    Selection is deterministic: matching candidates are ordered by
    ``(namespace, name, pod uid)`` and consumed in that order. ``random`` is a
    single draw from an **injected** ``seed``; without one it refuses
    (:class:`~mayhem.domain.errors.SelectionError`), because a wall-clock or
    global-RNG draw would make a frozen plan unreplayable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = ""
    namespace: str = ""
    workload_name: str = ""
    workload_kind: WorkloadKind | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    node: str = ""
    zones: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    selection: SelectionSpec = Field(default_factory=SelectionSpec)

    # ── matching ────────────────────────────────────────────────────────────
    def matches(self, candidate: K8sSelectionCandidate) -> bool:
        """True when every *stated* dimension matches *candidate*.

        Unstated dimensions are wildcards, which is what makes an empty
        selector mean "the whole live set" — an authored-but-empty result
        still comes back as an explicit empty selection, because eligibility
        and ordering are enforced separately in :meth:`select`.
        """
        return all(
            predicate(candidate) for stated, predicate in self._dimensions() if stated
        )

    def _dimensions(
        self,
    ) -> tuple[tuple[bool, Callable[[K8sSelectionCandidate], bool]], ...]:
        """``(is_stated, predicate)`` per dimension, in plan order."""
        return (
            (bool(self.name), lambda c: c.name == self.name),
            (bool(self.namespace), lambda c: (c.namespace or "default") == self.namespace),
            (bool(self.workload_name), lambda c: c.workload_name == self.workload_name),
            (self.workload_kind is not None, lambda c: c.workload_kind == self.workload_kind),
            (bool(self.node), lambda c: c.node == self.node),
            (bool(self.zones), lambda c: c.zone in self.zones),
            (bool(self.regions), lambda c: c.region in self.regions),
            (bool(self.labels), lambda c: _labels_match(self.labels, c.labels)),
            (bool(self.annotations), lambda c: _labels_match(self.annotations, c.annotations)),
        )

    # ── selection ───────────────────────────────────────────────────────────
    def select(
        self,
        candidates: tuple[K8sSelectionCandidate, ...] | list[K8sSelectionCandidate],
        *,
        seed: int | None = None,
    ) -> K8sSelection:
        """Run the selector over *candidates*.

        Returns the selected :class:`~mayhem.domain.resolution.ResolvedPodTarget`
        records plus the exclusion buckets. Matching-but-ineligible candidates
        (unresolved, blueprint) are reported, never selected.
        """
        matched = tuple(c for c in candidates if self.matches(c))
        eligible = tuple(c for c in matched if c.live_eligible)
        ordered = tuple(sorted(eligible, key=lambda c: c.identity))
        excluded = tuple(self._exclude(c) for c in matched if not c.live_eligible)
        picked = self._dispatch(ordered, seed=seed)
        targets = tuple(
            c.target for c in picked if c.target is not None  # narrowed by live_eligible
        )
        return K8sSelection(
            selector=self.render(),
            targets=targets,
            eligible=len(eligible),
            matched=len(matched),
            excluded=excluded,
            # Every mode picks at least one candidate whenever the live-eligible
            # set is non-empty, so "no targets" always means "nothing eligible".
            reason="" if targets else EMPTY_SELECTION_REASON,
        )

    def _dispatch(
        self,
        ordered: tuple[K8sSelectionCandidate, ...],
        *,
        seed: int | None,
    ) -> tuple[K8sSelectionCandidate, ...]:
        """Apply the authored selection mode to the live-eligible set.

        An empty eligible set is an *empty selection* for every mode — there is
        nothing to exceed, so the explicit empty result stands rather than a
        mode-specific refusal. ``count_exceeds_eligible`` still fires when
        there are eligible pods but fewer than requested.
        """
        spec = self.selection
        if not ordered:
            return ()
        if spec.mode is SelectionMode.ALL:
            return ordered
        if spec.mode is SelectionMode.ONE:
            return ordered[:1]
        if spec.mode is SelectionMode.PERCENTAGE:
            pct = spec.percentage
            if pct is None:  # pragma: no cover - SelectionSpec forbids it
                raise SelectionError(
                    "selection.percentage_required",
                    "selection.mode 'percentage' requires selection.percentage",
                )
            # ceil, at least one, and slicing caps at the set size.
            return ordered[: max(1, math.ceil(len(ordered) * pct / 100.0))]
        if spec.mode is SelectionMode.COUNT:
            count = spec.count
            if count is None:  # pragma: no cover - SelectionSpec forbids it
                raise SelectionError(
                    "selection.count_required",
                    "selection.mode 'count' requires selection.count",
                )
            if count > len(ordered):
                raise SelectionError(
                    "selection.count_exceeds_eligible",
                    f"selection count {count} exceeds {len(ordered)} live-eligible pod(s)",
                )
            return ordered[:count]
        # random — a single draw from the injected seed, never a global RNG.
        if seed is None:
            raise SelectionError(
                "selection.seed_required",
                "selection.mode 'random' requires an injected seed; a wall-clock or "
                "global-RNG draw would make a frozen plan unreplayable",
            )
        return (random.Random(seed).choice(ordered),)

    # ── rendering ───────────────────────────────────────────────────────────
    def render(self) -> str:
        """The selector as a stable one-line evidence string."""
        parts: list[str] = []
        if self.namespace:
            parts.append(f"ns={self.namespace}")
        if self.name:
            parts.append(f"pod={self.name}")
        if self.workload_name or self.workload_kind is not None:
            kind = self.workload_kind.value if self.workload_kind else "*"
            parts.append(f"workload={kind}/{self.workload_name or '*'}")
        for key, value in sorted(self.labels.items()):
            parts.append(f"label:{key}={value}")
        for key, value in sorted(self.annotations.items()):
            parts.append(f"annotation:{key}={value}")
        if self.node:
            parts.append(f"node={self.node}")
        if self.zones:
            parts.append(f"zone in {{{','.join(self.zones)}}}")
        if self.regions:
            parts.append(f"region in {{{','.join(self.regions)}}}")
        parts.append(f"selection:{self.selection.mode.value}")
        return " ".join(parts)

    @staticmethod
    def _exclude(candidate: K8sSelectionCandidate) -> K8sSelectionExclusion:
        """Bucket one matched-but-ineligible candidate with its reason."""
        if candidate.is_blueprint:
            return K8sSelectionExclusion(
                candidate=candidate,
                kind=K8sExclusionKind.BLUEPRINT,
                reason=(
                    f"{candidate.namespace}/{candidate.name} is a manifest blueprint "
                    "placeholder (state=blueprint); offline graphs never select live pods"
                ),
            )
        if candidate.source is K8sTargetSource.UNRESOLVED or candidate.target is None:
            return K8sSelectionExclusion(
                candidate=candidate,
                kind=K8sExclusionKind.DRIFT,
                reason=(
                    f"{candidate.namespace}/{candidate.name} matched but has no resolved "
                    "live target; it is drift, not a target"
                ),
            )
        return K8sSelectionExclusion(
            candidate=candidate,
            kind=K8sExclusionKind.NOT_ELIGIBLE,
            # Defensive default: a source added after this phase (and not
            # LIVE/BLUEPRINT/UNRESOLVED) must never fall through into `targets`.
            reason=(
                f"{candidate.namespace}/{candidate.name} matched but is not a live "
                "resolved target"
            ),
        )


def _labels_match(wanted: dict[str, str], observed: dict[str, str]) -> bool:
    """Kubernetes ``matchLabels`` subset semantics: every wanted pair is present.

    An empty ``wanted`` map is a wildcard; the emptiness of the *result* is a
    separate question, answered by :meth:`K8sSelectionCandidate.live_eligible`
    and the exclusion buckets.
    """
    return all(observed.get(key) == value for key, value in wanted.items())


# ── workload safety facts ───────────────────────────────────────────────────
class TopologySpreadConstraint(BaseModel):
    """One ``topologySpreadConstraints[]`` entry (the relevant fields only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    topology_key: str = ""  # e.g. "topology.kubernetes.io/zone"
    max_skew: int = Field(default=1, ge=1)
    do_not_schedule: bool = False  # whenUnsatisfiable: DoNotSchedule

    @property
    def strict(self) -> bool:
        """True when the scheduler refuses to place rather than accepting skew."""
        return self.do_not_schedule


class WorkloadFacts(BaseModel):
    """Everything the workload-safety rules need, and nothing they do not.

    A fact set is *observed*, not authored: Phase 2 fills it from the live
    cluster (replica counts, PDB spec, pod template, node conditions) and then
    calls the pure rule functions below. Every rule is a pure function over
    this type, so a refusal is reproducible from the facts alone.

    Phase 1's rules gate on ``replicas`` alone. ``ready_replicas``,
    ``updated_replicas``, and the probe flags are carried because the plan names
    readiness/liveness as workload facts and Phase 2 consumes them when it
    decides whether an observation is confounded by an in-flight rollout; no
    rule below reads them yet.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # identity + kind semantics
    name: str = ""
    namespace: str = "default"
    kind: WorkloadKind = WorkloadKind.DEPLOYMENT

    # replicas
    replicas: int = Field(default=0, ge=0)
    ready_replicas: int = Field(default=0, ge=0)
    updated_replicas: int = Field(default=0, ge=0)

    # PodDisruptionBudget (mutually exclusive forms, as the API requires)
    pdb_min_available: int | None = Field(default=None, ge=0)
    pdb_max_unavailable: int | None = Field(default=None, ge=0)

    # probes
    readiness_probe: bool = False
    liveness_probe: bool = False
    startup_probe: bool = False

    # pod anti-affinity
    required_anti_affinity: bool = False
    preferred_anti_affinity: bool = False
    anti_affinity_domains: int = Field(default=0, ge=0)

    # topology spread
    topology_spread: tuple[TopologySpreadConstraint, ...] = ()
    topology_spread_domains: int = Field(default=0, ge=0)

    # StatefulSet: how many stable identities one disruption may take
    statefulset_rollout_budget: int = Field(default=1, ge=1)

    # DaemonSet: node coverage
    daemonset_nodes_ready: int = Field(default=0, ge=0)
    daemonset_nodes_total: int = Field(default=0, ge=0)
    daemonset_tolerates_total_loss: bool = False

    # cluster health
    cluster_nodes_ready: int = Field(default=0, ge=0)
    cluster_nodes_total: int = Field(default=0, ge=0)
    cluster_degradation_acknowledged: bool = False

    @model_validator(mode="after")
    def _check_pdb_form(self) -> WorkloadFacts:
        if self.pdb_min_available is not None and self.pdb_max_unavailable is not None:
            raise InvariantViolationError(
                "k8s.pdb_forms_exclusive",
                "PodDisruptionBudget declares minAvailable and maxUnavailable; "
                "the API forbids both",
            )
        return self

    @property
    def pdb_required_available(self) -> int | None:
        """The availability floor the PDB imposes, or ``None`` without a PDB.

        ``minAvailable`` is used directly; ``maxUnavailable`` converts to a floor
        of ``replicas - maxUnavailable``.
        """
        if self.pdb_min_available is not None:
            return self.pdb_min_available
        if self.pdb_max_unavailable is not None:
            return max(0, self.replicas - self.pdb_max_unavailable)
        return None

    @property
    def pdb_form(self) -> str:
        """Which PDB form produced :attr:`pdb_required_available`."""
        if self.pdb_min_available is not None:
            return "minAvailable"
        if self.pdb_max_unavailable is not None:
            return "maxUnavailable"
        return "none"


# ── admission verdicts ──────────────────────────────────────────────────────
class K8sAdmissionCheck(StrEnum):
    """The workload-safety rules, in the order the aggregate evaluates them."""

    PDB = "pdb"
    STATEFULSET_ORDINAL = "statefulset_ordinal"
    DAEMONSET_COVERAGE = "daemonset_coverage"
    ANTI_AFFINITY = "anti_affinity"
    TOPOLOGY_SPREAD = "topology_spread"
    CLUSTER_HEALTH = "cluster_health"


#: Stable code per check, so a refusal is machine-routable.
_CHECK_CODES: dict[K8sAdmissionCheck, str] = {
    K8sAdmissionCheck.PDB: "k8s.pdb_violation",
    K8sAdmissionCheck.STATEFULSET_ORDINAL: "k8s.statefulset_rollout_exceeded",
    K8sAdmissionCheck.DAEMONSET_COVERAGE: "k8s.daemonset_coverage_lost",
    K8sAdmissionCheck.ANTI_AFFINITY: "k8s.anti_affinity_no_free_domain",
    K8sAdmissionCheck.TOPOLOGY_SPREAD: "k8s.topology_spread_blocked",
    K8sAdmissionCheck.CLUSTER_HEALTH: "k8s.cluster_degraded",
}


class K8sAdmissionVerdict(BaseModel):
    """The admission outcome for one requested fault against one workload.

    A refusal is a *record*, not an exception: ``reason`` carries the observed
    numbers so the operator can see why the plan was stopped without reading
    the code. ``observed`` / ``required`` are the two sides of the comparison
    that produced the verdict.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    admitted: bool
    check: K8sAdmissionCheck
    code: str
    reason: str
    workload: str = ""  # namespace/name
    workload_kind: WorkloadKind | None = None
    kill_count: int = 0
    observed: int | None = None  # expected availability/coverage after the fault
    required: int | None = None  # the floor that must hold
    is_drift_safe: bool = False  # the fault is a drift risk, not a hard loss

    @property
    def rule(self) -> str:
        """The check name, for the refusal headline."""
        return self.check.value

    @property
    def summary(self) -> str:
        """One-line refusal (or admission) with the code."""
        state = "ADMIT" if self.admitted else "DENY"
        subject = f" on {self.workload}" if self.workload else ""
        return f"{self.code}: {state}{subject} — {self.reason}"

    @classmethod
    def admit(
        cls,
        check: K8sAdmissionCheck,
        *,
        workload: str = "",
        workload_kind: WorkloadKind | None = None,
        kill_count: int = 0,
        observed: int | None = None,
        required: int | None = None,
        note: str = "no workload-safety rule is violated",
    ) -> K8sAdmissionVerdict:
        """An admission: the rule was evaluated and holds."""
        return cls(
            admitted=True,
            check=check,
            code=_CHECK_CODES[check],
            reason=f"→ ADMIT, {note}",
            workload=workload,
            workload_kind=workload_kind,
            kill_count=kill_count,
            observed=observed,
            required=required,
        )

    @classmethod
    def deny(
        cls,
        check: K8sAdmissionCheck,
        reason: str,
        *,
        workload: str = "",
        workload_kind: WorkloadKind | None = None,
        kill_count: int = 0,
        observed: int | None = None,
        required: int | None = None,
    ) -> K8sAdmissionVerdict:
        """A refusal carrying the arithmetic that produced it."""
        return cls(
            admitted=False,
            check=check,
            code=_CHECK_CODES[check],
            reason=reason,
            workload=workload,
            workload_kind=workload_kind,
            kill_count=kill_count,
            observed=observed,
            required=required,
        )


# ── the rules (pure functions over WorkloadFacts) ───────────────────────────
def _subject(facts: WorkloadFacts) -> str:
    return f"{facts.namespace}/{facts.name}" if facts.name else facts.namespace


def _denial_head(facts: WorkloadFacts, kill_count: int, leading: str) -> str:
    """The shared refusal prefix: ``<observed facts>, requested kill N → DENY,``."""
    return f"{leading}, requested kill {kill_count} → DENY"


def check_pdb(facts: WorkloadFacts, *, kill_count: int) -> K8sAdmissionVerdict:
    """The PDB rule — the plan's headline differentiator.

    Pure over :class:`WorkloadFacts`. The refusal shows its arithmetic::

        replicas=10, PDB minAvailable=8, requested kill 4 → DENY,
        expected availability after fault = 6, PDB requires >= 8

    A non-replica-gated kind (Job, bare Pod) is not gated here: a Job runs to
    completion and a Pod has one replica, so a replica-count floor is vacuous.
    """
    subject = _subject(facts)
    if facts.kind not in REPLICA_GATED_KINDS:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.PDB,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            note=f"{facts.kind.value} replicas are not PDB-gated",
        )
    required = facts.pdb_required_available
    if required is None or kill_count <= 0:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.PDB,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            observed=facts.replicas,
            required=required,
            note=(
                f"replicas={facts.replicas}, no PodDisruptionBudget, "
                f"expected availability after fault = {max(0, facts.replicas - kill_count)}"
            ),
        )
    expected = facts.replicas - kill_count
    leading = f"replicas={facts.replicas}, PDB {facts.pdb_form}={required}"
    if expected >= required:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.PDB,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            observed=expected,
            required=required,
            note=(
                f"expected availability after fault = {expected}, "
                f"PDB requires >= {required}"
            ),
        )
    return K8sAdmissionVerdict.deny(
        K8sAdmissionCheck.PDB,
        f"{_denial_head(facts, kill_count, leading)}, "
        f"expected availability after fault = {expected}, PDB requires >= {required}",
        workload=subject,
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=expected,
        required=required,
    )


def check_statefulset_ordinal(facts: WorkloadFacts, *, kill_count: int) -> K8sAdmissionVerdict:
    """StatefulSet semantics: stable identities are not interchangeable.

    A StatefulSet's ordinals are pod hostnames and volume claims, so a
    simultaneous kill of *k* identities is a different operation from *k*
    single kills. Only the declared rollout budget is admitted.
    """
    subject = _subject(facts)
    budget = facts.statefulset_rollout_budget
    if facts.kind is not WorkloadKind.STATEFULSET or kill_count <= budget:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.STATEFULSET_ORDINAL,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            required=budget if facts.kind.ordered_identity else None,
            note=(
                "no StatefulSet rollout budget is exceeded"
                if facts.kind.ordered_identity
                else f"{facts.kind.value} carries no stable per-pod identity"
            ),
        )
    expected = max(0, facts.replicas - kill_count)
    leading = f"replicas={facts.replicas}, StatefulSet rollout budget={budget}"
    return K8sAdmissionVerdict.deny(
        K8sAdmissionCheck.STATEFULSET_ORDINAL,
        f"{_denial_head(facts, kill_count, leading)}, "
        f"expected available stable identities after fault = {expected}, "
        f"rollout budget allows at most {budget} per disruption",
        workload=subject,
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=expected,
        required=budget,
    )


def check_daemonset_coverage(facts: WorkloadFacts, *, kill_count: int) -> K8sAdmissionVerdict:
    """DaemonSet awareness: a killed pod only returns when its node does.

    A node-bound pod does not reschedule elsewhere, so losing the whole
    DaemonSet is losing node coverage, not losing replicas. Refuses only total
    coverage loss (or when the kill exceeds healthy coverage).
    """
    subject = _subject(facts)
    if facts.kind is not WorkloadKind.DAEMONSET or kill_count <= 0:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.DAEMONSET_COVERAGE,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            note=(
                "no DaemonSet node coverage is lost"
                if facts.kind.node_bound
                else f"{facts.kind.value} pods are not node-bound"
            ),
        )
    healthy = facts.daemonset_nodes_ready or facts.replicas
    total = facts.daemonset_nodes_total or healthy
    expected = healthy - kill_count
    if expected > 0 or facts.daemonset_tolerates_total_loss:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.DAEMONSET_COVERAGE,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            observed=expected,
            note=(
                f"expected DaemonSet coverage after fault = {expected} of {total} node(s)"
            ),
        )
    return K8sAdmissionVerdict.deny(
        K8sAdmissionCheck.DAEMONSET_COVERAGE,
        f"{_denial_head(facts, kill_count, f'replicas(healthy DaemonSet nodes)={healthy}')}, "
        f"expected DaemonSet coverage after fault = {max(0, expected)} of {total}, "
        "DaemonSet pods are node-bound and do not reschedule to another node",
        workload=subject,
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=max(0, expected),
        required=1,
    )


def check_anti_affinity(facts: WorkloadFacts, *, kill_count: int) -> K8sAdmissionVerdict:
    """Required anti-affinity: a replacement needs a *free* topology domain.

    Preferred anti-affinity is soft (the scheduler may violate it) and is
    therefore admitted with a note. Required anti-affinity turns a kill into a
    permanent loss when every domain is already occupied.
    """
    subject = _subject(facts)
    if not facts.required_anti_affinity or kill_count <= 0:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.ANTI_AFFINITY,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            note=(
                f"preferred anti-affinity across {facts.anti_affinity_domains} domain(s) is soft"
                if facts.preferred_anti_affinity
                else "no required pod anti-affinity is declared"
            ),
        )
    domains = facts.anti_affinity_domains
    free = max(0, domains - facts.replicas)
    if kill_count <= free:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.ANTI_AFFINITY,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            observed=free,
            note=f"expected free anti-affinity domains for replacement = {free}",
        )
    leading = (
        f"replicas={facts.replicas}, "
        f"required anti-affinity topology domains={domains}"
    )
    return K8sAdmissionVerdict.deny(
        K8sAdmissionCheck.ANTI_AFFINITY,
        f"{_denial_head(facts, kill_count, leading)}, "
        f"expected free domains for replacement = {free}, "
        "required anti-affinity cannot reschedule into an occupied domain",
        workload=subject,
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=free,
        required=kill_count,
    )


def check_topology_spread(facts: WorkloadFacts, *, kill_count: int) -> K8sAdmissionVerdict:
    """Strict (``DoNotSchedule``) topology spread blocks the replacement.

    A ``ScheduleAnyway`` constraint is a hint and never refuses; a strict one
    admits only a kill within ``maxSkew``, because a wider gap is unschedulable
    and the availability loss becomes permanent.
    """
    subject = _subject(facts)
    strict = next((c for c in facts.topology_spread if c.strict), None)
    if strict is None or kill_count <= strict.max_skew:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.TOPOLOGY_SPREAD,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            required=strict.max_skew if strict is not None else None,
            note=(
                f"topology spread {strict.topology_key!r} maxSkew={strict.max_skew} is honoured"
                if strict is not None
                else "no DoNotSchedule topology spread constraint is declared"
            ),
        )
    expected = max(0, facts.replicas - kill_count)
    leading = (
        f"replicas={facts.replicas}, topology spread key={strict.topology_key!r} "
        f"maxSkew={strict.max_skew} (DoNotSchedule)"
    )
    return K8sAdmissionVerdict.deny(
        K8sAdmissionCheck.TOPOLOGY_SPREAD,
        f"{_denial_head(facts, kill_count, leading)}, "
        f"expected available replicas after fault = {expected}, "
        f"scheduler requires maxSkew <= {strict.max_skew} across "
        f"{facts.topology_spread_domains} domain(s)",
        workload=subject,
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=expected,
        required=strict.max_skew,
    )


def check_cluster_health(facts: WorkloadFacts, *, kill_count: int) -> K8sAdmissionVerdict:
    """Cluster health: do not add a fault to an already-degraded cluster.

    A workload fault on a cluster with a NotReady node is not attributable —
    the observation cannot be separated from the pre-existing failure. The
    refusal names the counts and can be acknowledged explicitly.
    """
    subject = _subject(facts)
    ready, total = facts.cluster_nodes_ready, facts.cluster_nodes_total
    degraded = total > 0 and ready < total
    if kill_count <= 0 or not degraded or facts.cluster_degradation_acknowledged:
        return K8sAdmissionVerdict.admit(
            K8sAdmissionCheck.CLUSTER_HEALTH,
            workload=subject,
            workload_kind=facts.kind,
            kill_count=kill_count,
            observed=ready,
            required=total,
            note=(
                f"cluster nodes ready={ready}/{total}, no pre-existing degradation"
                if not degraded
                else "pre-existing cluster degradation acknowledged explicitly"
            ),
        )
    return K8sAdmissionVerdict.deny(
        K8sAdmissionCheck.CLUSTER_HEALTH,
        f"{_denial_head(facts, kill_count, f'cluster nodes ready={ready}/{total}')}, "
        f"expected healthy nodes after fault = {max(0, ready - kill_count)}, "
        "cluster is already degraded; acknowledge explicitly to proceed",
        workload=subject,
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=ready,
        required=total,
    )


#: Every rule, in the order the aggregate evaluates them (most specific first).
WORKLOAD_SAFETY_CHECKS: tuple[K8sAdmissionCheck, ...] = (
    K8sAdmissionCheck.PDB,
    K8sAdmissionCheck.STATEFULSET_ORDINAL,
    K8sAdmissionCheck.DAEMONSET_COVERAGE,
    K8sAdmissionCheck.ANTI_AFFINITY,
    K8sAdmissionCheck.TOPOLOGY_SPREAD,
    K8sAdmissionCheck.CLUSTER_HEALTH,
)


def _apply(check: K8sAdmissionCheck, facts: WorkloadFacts, kill_count: int) -> K8sAdmissionVerdict:
    if check is K8sAdmissionCheck.PDB:
        return check_pdb(facts, kill_count=kill_count)
    if check is K8sAdmissionCheck.STATEFULSET_ORDINAL:
        return check_statefulset_ordinal(facts, kill_count=kill_count)
    if check is K8sAdmissionCheck.DAEMONSET_COVERAGE:
        return check_daemonset_coverage(facts, kill_count=kill_count)
    if check is K8sAdmissionCheck.ANTI_AFFINITY:
        return check_anti_affinity(facts, kill_count=kill_count)
    if check is K8sAdmissionCheck.TOPOLOGY_SPREAD:
        return check_topology_spread(facts, kill_count=kill_count)
    return check_cluster_health(facts, kill_count=kill_count)


def evaluate_workload_admission(
    facts: WorkloadFacts,
    *,
    kill_count: int,
) -> tuple[K8sAdmissionVerdict, ...]:
    """Every workload-safety verdict for one requested fault, in rule order."""
    return tuple(_apply(check, facts, kill_count) for check in WORKLOAD_SAFETY_CHECKS)


def admit_workload_fault(
    facts: WorkloadFacts,
    *,
    kill_count: int,
) -> K8sAdmissionVerdict:
    """The aggregate gate: the first refusal wins, else an admission.

    Pure — the same facts and kill count always produce the same verdict, and
    a refusal always names the violated rule and the observed numbers.
    """
    verdicts = evaluate_workload_admission(facts, kill_count=kill_count)
    refused = next((v for v in verdicts if not v.admitted), None)
    if refused is not None:
        return refused
    return K8sAdmissionVerdict.admit(
        K8sAdmissionCheck.PDB,
        workload=_subject(facts),
        workload_kind=facts.kind,
        kill_count=kill_count,
        observed=facts.replicas - kill_count,
        note=(
            f"replicas={facts.replicas}, requested kill {kill_count} → ADMIT, "
            "every workload-safety rule holds"
        ),
    )
