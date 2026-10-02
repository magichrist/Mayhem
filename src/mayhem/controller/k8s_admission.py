"""Workload-aware Kubernetes admission for the plan-time gate (v1.1.0 plan 02 phase 2).

Phase 1 (``domain/k8s_targets.py``) shipped the vocabulary — ``K8sSelector``,
``WorkloadFacts``, ``K8sAdmissionVerdict`` and six pure workload-safety rules
whose refusals show their arithmetic — and no call site. This module is that
call site, and the only thing it is allowed to do is *ask*: every refusal it
produces is either a Phase-1 rule evaluated over observed facts or one of the
admission's own authorization/provenance refusals.

What this module is not
-----------------------
* **Not a second resolver.** ``mayhem.agents.k8s_resolve`` owns the live 5-step
  flow (locate workload → eligible Running pods → pick → named container →
  evidence record). Admission *consumes* the ``ResolvedPodTarget`` records that
  flow produced, through :class:`K8sAdmissionRequest`; it never calls
  ``workload()`` or ``pods_for()``, never re-picks a pod, and never re-reads a
  pod. A step whose resolution is missing is refused as drift — Phase 1's rule
  that unresolved is not a target — rather than repaired here.
* **Not the executability boundary.**
  ``controller/k8s_runtime.k8s_available_faults()`` stays where it is.
  Admission is *stricter* than that boundary (it admits every pod-resolved
  Kubernetes-scoped fault) but it never claims a fault is deliverable.
* **Not the identity system.** Plan 09 owns *who the run is*. Admission takes
  an **injected authorization predicate** over workload identity and refuses a
  target the predicate will not permit. :func:`namespace_protection` is the
  namespace half of that, written here so the wiring is provable; the
  RBAC/identity half is the caller's to supply (compose both, or pass
  ``K8sAdmissionInput.authorize`` a predicate that consults plan 09).
* **Not a live-cluster claim.**
  ``domain/k8s_adapter.KubernetesAdapter.is_available()`` stays ``False`` and
  nothing here rehabilitates it. No cluster has been accepted by this phase;
  the ledger in ``docs/v1.1.0/02_KUBERNETES_RUNTIME.md`` says so.

Refusal order, and why it is this order
---------------------------------------
Within one step, most-fundamental first:

1. **authorization** (injected predicate) — a target the run may not touch is
   refused before any cluster read, because no fact about it can matter.
2. **request provenance** — the resolver's record must be about the planned
   workload, and every pod in it must be in the planned namespace.
3. **live-target presence** — at least one resolved pod, each carrying a pod
   uid. Blueprint placeholders and unresolved pins are the exclusions that
   make this refusal, and they are named in it.
4. **the six Phase-1 rules** in ``WORKLOAD_SAFETY_CHECKS`` order (PDB →
   StatefulSet → DaemonSet → anti-affinity → topology spread → cluster health).
   The first refusal wins, which is exactly ``admit_workload_fault``'s rule;
   this module keeps the whole ordered tuple as evidence and derives the first
   refusal from it, so the two cannot disagree.
5. **observation validity** — an in-flight rollout or an already-unready
   workload makes the measurement indistinguishable from the pre-existing
   state, so the fault is refused *after* the hard availability arithmetic
   rather than before it: a PDB violation is a property of the requested
   fault, while a rollout is a property of the moment.

Both degradations are acknowledge-able through :class:`K8sAdmissionInput`; a
refusal nobody can acknowledge is not a gate.

``ready_replicas`` / ``updated_replicas`` / the probe flags
----------------------------------------------------------
Phase 1 carried these facts and no rule read them, on the record that Phase 2
would consume them "when it decides whether an observation is confounded by an
in-flight rollout". That is what :func:`observation_refusal` does:

* ``updated_replicas`` → the in-flight-rollout refusal
  (``k8s.rollout_in_flight``);
* ``ready_replicas`` *gated on* ``readiness_probe`` → the already-unready
  refusal (``k8s.unready_replicas``). Without a readiness probe a container is
  Ready as soon as it starts, so ``ready_replicas`` is not a health signal and
  must not be used to refuse a plan;
* ``liveness_probe`` / ``startup_probe`` → a recorded **warning**
  (``k8s.probe_absent``), never a refusal: with no liveness probe kubelet does
  not restart a killed container, so recovery depends entirely on the workload
  controller replacing the pod. That is evidence an operator should see; it is
  not grounds to refuse, and making it one would be a product decision this
  phase does not get to make.

A fact of ``0`` is treated as *not observed* rather than as evidence of a
rollout or of a total outage. That is a deliberate limit: a client which does
not populate the rollout field would otherwise refuse every plan, which is a
check that is unusable rather than safe. A populated-but-incomplete rollout
(``0 < updated_replicas < replicas``) and a populated health signal
(``ready_replicas > 0``) are the shapes the API actually reports.

What is deliberately *not* here
-------------------------------
The plan's Phase-2 sentence also names "active incidents, recent deployments".
Those are already read through the versioned policy bundle
(``PolicyDimension.INCIDENT_STATE`` / ``DEPLOYMENT_STATE`` in
``controller/policy_gate.derive_facts``, fed by ``PolicyGateInputs.observed``),
so a second reader here would be a second answer to the same question.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from mayhem.agents.k8s_resolve import K8sWorkload
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.k8s_targets import evaluate_workload_admission
from mayhem.domain.target import ResourceKind

if TYPE_CHECKING:
    from mayhem.domain.experiments import ExecutionPlan, PlannedFault
    from mayhem.domain.k8s_targets import K8sAdmissionVerdict, K8sSelectionExclusion, WorkloadFacts
    from mayhem.domain.resolution import ResolvedPodTarget


# ── rule ids ────────────────────────────────────────────────────────────────
# The six Phase-1 rules keep their own codes (``K8sAdmissionVerdict.code``);
# these are the admissions this module owns. One namespace, one prefix, so a
# log line is routable whichever half spoke.
RULE_AUTHORIZATION_DENIED = "k8s.authorization_denied"
RULE_NAMESPACE_PROTECTED = "k8s.namespace_protected"
RULE_REQUEST_MISMATCH = "k8s.admission_request_mismatch"
RULE_NAMESPACE_MISMATCH = "k8s.target_namespace_mismatch"
RULE_NO_LIVE_TARGET = "k8s.no_live_target"
RULE_WORKLOAD_MISSING = "k8s.workload_missing"
RULE_ROLLOUT_IN_FLIGHT = "k8s.rollout_in_flight"
RULE_UNREADY_REPLICAS = "k8s.unready_replicas"
RULE_PROBE_ABSENT = "k8s.probe_absent"  # warning, never a refusal
RULE_ADMISSION_ALLOW = "k8s.admission_allow"

#: Namespaces no chaos run may fault by default. Kubernetes owns these; a run
#: that needs one must say so explicitly (plan 09 binds the authorization).
DEFAULT_PROTECTED_NAMESPACES: frozenset[str] = frozenset(
    {"kube-system", "kube-public", "kube-node-lease"}
)

_REMEDIATION: dict[str, str] = {
    RULE_AUTHORIZATION_DENIED: (
        "run the drill as an identity the cluster's RBAC permits in that namespace, "
        "or narrow the target set (plan 09 binds the identity; admission only asks)"
    ),
    RULE_NAMESPACE_PROTECTED: (
        "target a namespace outside the protected set, or remove it from the protection "
        "set only once a run is authorized there"
    ),
    RULE_REQUEST_MISMATCH: (
        "re-resolve the step so the admission request describes the workload the plan "
        "targets; a stale request is drift, not a target"
    ),
    RULE_NAMESPACE_MISMATCH: (
        "resolve pods inside the planned namespace; a resolved pod outside it is a target "
        "the plan never named"
    ),
    RULE_NO_LIVE_TARGET: (
        "resolve a live pod for the step before admitting it — an unresolved pin or a "
        "manifest blueprint placeholder is not a target (a manifest blueprint can never "
        "be admitted; only a live-cluster run resolves one)"
    ),
    RULE_WORKLOAD_MISSING: (
        "check the workload still exists in the target namespace; a fault against a "
        "workload the API cannot find is not a measurable experiment"
    ),
    RULE_ROLLOUT_IN_FLIGHT: (
        "wait for the rollout to settle (updated_replicas == replicas) so the observation "
        "is attributable to the fault, or acknowledge the degraded workload explicitly"
    ),
    RULE_UNREADY_REPLICAS: (
        "restore the workload to ready_replicas == replicas first, or acknowledge the "
        "degraded workload explicitly"
    ),
}


def remediation_for(rule_id: str) -> str:
    """The operator-facing fix for one of this module's rule ids."""
    return _REMEDIATION.get(
        rule_id,
        "raise the workload's own availability floor (PDB / rollout budget / topology "
        "skew) so the requested fault fits inside it",
    )


# ── the injected seams ──────────────────────────────────────────────────────
class K8sAdmissionClient(Protocol):
    """The only cluster-facing read admission is allowed to make.

    One call returns the whole observed fact set, so a refusal is reproducible
    from a single read and two reads can never disagree with each other. It is
    deliberately *not* :class:`~mayhem.agents.k8s_resolve.K8sClusterClient`:
    that protocol carries ``pods_for``/``exec``/``workload``, and an admission
    client that exposes pod listing is one refactor away from re-resolving.
    Tests fake this; nothing here needs a cluster.
    """

    def workload_facts(self, workload: K8sWorkload) -> WorkloadFacts | None:
        """Every ``WorkloadFacts`` field for *workload*, ``None`` when it is gone.

        ``None`` is a refusal (``k8s.workload_missing``), not a fallback: a
        cluster that cannot answer "does this workload exist" cannot answer "is
        this fault safe against it" either.
        """
        ...


@dataclass(frozen=True)
class K8sAuthorization:
    """The injected authorization check's verdict for one workload.

    ``permitted=False`` plus a rule id and a reason is what a refusal records;
    the identity behind the decision is plan 09's business, not this module's.
    """

    permitted: bool
    rule_id: str = RULE_AUTHORIZATION_DENIED
    reason: str = ""
    remediation: str = ""


#: The injected predicate: workload identity in, verdict out. A bare lambda is
#: a legal authorizer, which is what makes the wiring provable in a test.
K8sAuthorizer = Callable[[K8sWorkload], K8sAuthorization]


def namespace_protection(
    *,
    allowed: frozenset[str] | None = None,
    protected: frozenset[str] = DEFAULT_PROTECTED_NAMESPACES,
) -> K8sAuthorizer:
    """Namespace protection as an injected authorizer.

    The namespace half of what the plan asks admission to enforce, written as a
    predicate so the call site (and its tests) can substitute an RBAC-aware one
    from plan 09 without this module knowing what an identity is.

    * a namespace in *protected* is refused before the allowlist is consulted:
      protection is the stronger statement, so it wins even for a namespace the
      allowlist would have permitted;
    * *allowed* is an allowlist — when given, a namespace outside it is
      refused; when ``None`` (the default) it is not consulted at all, so the
      predicate refuses only what it is told to protect.
    """

    def authorize(workload: K8sWorkload) -> K8sAuthorization:
        namespace = workload.namespace or "default"
        subject = f"{workload.kind}/{workload.name or '*'}"
        if namespace in protected:
            return K8sAuthorization(
                permitted=False,
                rule_id=RULE_NAMESPACE_PROTECTED,
                reason=(
                    f"namespace {namespace!r} is protected: this run may not fault {subject} in it"
                ),
                remediation=remediation_for(RULE_NAMESPACE_PROTECTED),
            )
        if allowed is not None and namespace not in allowed:
            return K8sAuthorization(
                permitted=False,
                rule_id=RULE_AUTHORIZATION_DENIED,
                reason=(
                    f"namespace {namespace!r} is outside this run's allowed namespaces "
                    f"{sorted(allowed)}: {subject} is not authorized for this run"
                ),
                remediation=remediation_for(RULE_AUTHORIZATION_DENIED),
            )
        return K8sAuthorization(permitted=True)

    return authorize


@dataclass(frozen=True)
class K8sAdmissionRequest:
    """The resolver's output for one planned step — the only target evidence.

    ``workload`` must be the workload the plan's scope names (checked, not
    assumed) and ``targets`` the pods the live flow already resolved for that
    step. ``excluded`` carries the Phase-1 exclusion buckets (drift /
    blueprint / not-eligible) so a refusal can *name* why nothing was live
    instead of only reporting that nothing was.
    """

    workload: K8sWorkload
    targets: tuple[ResolvedPodTarget, ...] = ()
    excluded: tuple[K8sSelectionExclusion, ...] = ()


@dataclass(frozen=True)
class K8sAdmissionInput:
    """Everything admission needs that the plan does not carry.

    ``requests`` is keyed by **plan step id**, not by fault id: one plan can
    carry two steps of the same fault against the same workload with two
    different resolutions, and a fault-id key would silently apply the first
    step's pods to the second. A fault whose step id is absent has no resolved
    evidence at all, which is the drift refusal.
    """

    client: K8sAdmissionClient
    authorize: K8sAuthorizer
    requests: Mapping[str, K8sAdmissionRequest] = field(default_factory=dict)
    # Explicit operator acknowledgements. Both default to False: a degradation
    # nobody has acknowledged is still a degradation.
    acknowledge_cluster_degradation: bool = False
    acknowledge_degraded_workload: bool = False
    context: str = ""  # kubeconfig context, carried into the refusal text


# ── the outcome ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class K8sAdmissionOutcome:
    """One step's admission verdict — refusal or admission — with its evidence.

    ``verdicts`` is the full ordered tuple Phase 1 produced, so a refusal can
    show every rule that was evaluated while :attr:`refusal` names the one that
    decided. ``rule_id`` is the deciding rule: a Phase-1 code for a
    workload-safety refusal, one of this module's ids otherwise.
    """

    fault_id: str
    workload: str
    namespace: str
    kind: str
    admitted: bool
    rule_id: str = RULE_ADMISSION_ALLOW
    reason: str = ""
    remediation: str = ""
    inputs: Mapping[str, object] = field(default_factory=dict)
    verdicts: tuple[K8sAdmissionVerdict, ...] = ()
    targets: tuple[str, ...] = ()  # authority keys of the resolved targets
    warnings: tuple[str, ...] = ()  # rule ids recorded as warnings, not refusals

    @property
    def refusal(self) -> K8sAdmissionVerdict | None:
        """The Phase-1 verdict that decided, or ``None`` for a non-rule refusal."""
        return next((v for v in self.verdicts if not v.admitted), None)

    @property
    def denied(self) -> bool:
        """True when this step was refused before any mutation."""
        return not self.admitted

    def describe(self) -> str:
        """One line, the same headline shape as ``K8sAdmissionVerdict.summary``."""
        state = "ADMIT" if self.admitted else "DENY"
        return f"{self.rule_id}: {state} on {self.workload} — {self.reason}"


# ── collection ──────────────────────────────────────────────────────────────
def k8s_workload_of(scope: object) -> K8sWorkload | None:
    """The workload identity a plan's frozen Kubernetes scope names.

    ``None`` for a non-Kubernetes scope and for a **node**-scoped one: node
    faults resolve to ``ResolvedNodeTarget`` and their safety is the node
    path's (k-plan-5), not a workload replica count's. Modelling that here
    would be inventing facts this phase cannot observe. Every other
    Kubernetes-scoped step is admitted.
    """
    runtime = getattr(scope, "runtime", None)
    kind = getattr(scope, "kind", None)
    if runtime != RuntimeLabel.KUBERNETES or not isinstance(kind, ResourceKind):
        return None
    if kind is ResourceKind.K8S_NODE:
        return None
    return K8sWorkload(
        namespace=getattr(scope, "namespace", "") or "default",
        kind=str(kind),
        name=getattr(scope, "name", ""),
    )


def collect_workload_facts(
    workload: K8sWorkload,
    client: K8sAdmissionClient,
    *,
    acknowledge_cluster_degradation: bool = False,
) -> WorkloadFacts | None:
    """One read for the whole fact set, pinned to *workload*'s identity.

    A client that answers about a *different* workload is a bug, not a plan
    property, so it raises :class:`~mayhem.domain.errors.InvariantViolationError`
    rather than returning a refusal an operator could "fix". The namespace and
    name are then pinned to the authorized identity: the authorization decision
    was made about *workload*, so the facts the rules read must be about
    *workload*.
    """
    observed = client.workload_facts(workload)
    if observed is None:
        return None
    if (observed.namespace, observed.name) != (workload.namespace, workload.name):
        raise InvariantViolationError(
            "k8s.admission_facts_mismatch",
            f"admission client returned facts for {observed.namespace}/{observed.name}, "
            f"but the admission asked about {workload.namespace}/{workload.name}",
        )
    return observed.model_copy(
        update={
            "namespace": workload.namespace,
            "name": workload.name,
            "cluster_degradation_acknowledged": (
                observed.cluster_degradation_acknowledged or acknowledge_cluster_degradation
            ),
        }
    )


def observation_refusal(
    facts: WorkloadFacts,
    *,
    kill_count: int,
    acknowledge: bool = False,
) -> tuple[str, str, dict[str, object]] | None:
    """Is this observation attributable to the fault? Phase 2's own rule.

    Consumes the facts Phase 1 carried but no Phase-1 rule read:
    ``updated_replicas`` (in-flight rollout) and ``ready_replicas`` gated on
    ``readiness_probe`` (already below desired availability). Returns
    ``(rule_id, reason, inputs)`` for the first refusal, or ``None``. See the
    module docstring for why a ``0`` means *not observed*.
    """
    replicas = facts.replicas
    if not acknowledge and 0 < facts.updated_replicas < replicas:
        return (
            RULE_ROLLOUT_IN_FLIGHT,
            f"replicas={replicas}, updated_replicas={facts.updated_replicas}, "
            f"requested kill {kill_count} → DENY, a rollout is in flight, so the "
            "observation cannot be attributed to the fault",
            {
                "replicas": replicas,
                "updated_replicas": facts.updated_replicas,
                "ready_replicas": facts.ready_replicas,
                "kill_count": kill_count,
                "observed": facts.updated_replicas,
                "required": replicas,
            },
        )
    if not acknowledge and facts.readiness_probe and 0 < facts.ready_replicas < replicas:
        expected = max(0, facts.ready_replicas - kill_count)
        return (
            RULE_UNREADY_REPLICAS,
            f"replicas={replicas}, ready_replicas={facts.ready_replicas} (readiness probe "
            f"present), requested kill {kill_count} → DENY, expected ready replicas after "
            f"fault = {expected}, the workload is already below its desired availability",
            {
                "replicas": replicas,
                "ready_replicas": facts.ready_replicas,
                "kill_count": kill_count,
                "observed": expected,
                "required": replicas,
            },
        )
    return None


def probe_warning(facts: WorkloadFacts) -> str | None:
    """The liveness/startup-probe note, or ``None`` when the workload probes.

    A container with no liveness probe is not restarted by kubelet after a
    fault, so recovery rides entirely on the workload controller replacing the
    pod. That is evidence, not a refusal — see the module docstring.
    """
    if facts.liveness_probe or facts.startup_probe:
        return None
    return (
        f"{facts.namespace}/{facts.name}: no liveness or startup probe, so kubelet will "
        "not restart a killed container; recovery depends entirely on the workload "
        "controller replacing the pod"
    )


def verdict_inputs(verdict: K8sAdmissionVerdict) -> dict[str, object]:
    """The observed/required numbers of a Phase-1 verdict, for the decision."""
    return {
        "observed": verdict.observed,
        "required": verdict.required,
        "verdict_kill_count": verdict.kill_count,
    }


# ── the gate ────────────────────────────────────────────────────────────────
def _provenance_refusal(
    step_id: str,
    fault: PlannedFault,
    workload: K8sWorkload,
    request: K8sAdmissionRequest,
    identity: dict[str, object],
) -> tuple[str, str, dict[str, object], tuple[str, ...]] | None:
    """The first refusal in steps 2 and 3, as ``(rule_id, reason, inputs, keys)``.

    Step 2 asks whether the resolver's record is about the workload the plan
    targets; step 3 asks whether it holds anything admissible. Neither needs
    the cluster, which is the point: a plan whose provenance is wrong is
    refused without spending a read on it.

    Every message here names the **step** as well as the fault, because a plan
    may carry the same fault twice against one workload with two resolutions: a
    refusal that named only the fault would be true of both steps and actionable
    for neither.
    """
    subject = f"{workload.namespace}/{workload.name}"
    step = f"step {step_id}"
    if request.workload != workload:
        return (
            RULE_REQUEST_MISMATCH,
            f"{subject}: the admission request describes "
            f"{request.workload.namespace}/{request.workload.name}, not the workload this "
            "step targets",
            {
                **identity,
                "request_namespace": request.workload.namespace,
                "request_workload": request.workload.name,
            },
            tuple(t.authority_key for t in request.targets),
        )
    stray = sorted(
        {
            t.namespace or "default"
            for t in request.targets
            if (t.namespace or "default") != workload.namespace
        }
    )
    keys = tuple(t.authority_key for t in request.targets)
    if stray:
        return (
            RULE_NAMESPACE_MISMATCH,
            f"{subject}: resolved pod(s) in namespace(s) {stray} are not in the planned "
            f"namespace {workload.namespace}; the plan never named them",
            {**identity, "resolved_namespaces": stray},
            keys,
        )
    if not request.targets:
        return (
            RULE_NO_LIVE_TARGET,
            f"{subject}: {fault.fault_id} ({step}) resolved to no live pod — "
            f"{_exclusion_summary(request)}",
            dict(identity),
            keys,
        )
    uidless = sorted(t.authority_key for t in request.targets if not t.pod_uid)
    if uidless:
        return (
            RULE_NO_LIVE_TARGET,
            f"{subject}: {fault.fault_id} ({step}) resolved record(s) {uidless} carry no "
            "pod uid, so they are not evidence of a live pod — admission does not re-read "
            "pods, so it cannot tell a deposed pod from a live one without that uid",
            {**identity, "uidless": uidless},
            keys,
        )
    return None


def admit_k8s_fault(
    step_id: str,
    fault: PlannedFault,
    admission: K8sAdmissionInput,
) -> K8sAdmissionOutcome:
    """Admit one planned Kubernetes fault, or refuse it with the reason.

    The refusal happens *before* any mutation: this runs inside
    ``safety.validate_plan``, which ``executor.execute`` calls over every step
    before it opens a run.
    """
    workload = k8s_workload_of(fault.target)
    if workload is None:
        raise InvariantViolationError(
            "k8s.admission_not_kubernetes",
            f"admission asked about step {step_id!r} ({fault.fault_id}), whose target is "
            "not a pod-resolved Kubernetes scope",
        )
    subject = f"{workload.namespace}/{workload.name}"
    identity: dict[str, object] = {
        "fault_id": fault.fault_id,
        "step_id": step_id,
        "namespace": workload.namespace,
        "workload": workload.name,
        "workload_kind": workload.kind,
        "context": admission.context,
    }
    warned: tuple[str, ...] = ()

    def _deny(
        rule_id: str,
        reason: str,
        inputs: dict[str, object],
        *,
        remediation: str = "",
        verdicts: tuple[K8sAdmissionVerdict, ...] = (),
        targets: tuple[str, ...] = (),
    ) -> K8sAdmissionOutcome:
        return K8sAdmissionOutcome(
            fault_id=fault.fault_id,
            workload=subject,
            namespace=workload.namespace,
            kind=workload.kind,
            admitted=False,
            rule_id=rule_id,
            reason=reason,
            remediation=remediation or remediation_for(rule_id),
            inputs=inputs,
            verdicts=verdicts,
            targets=targets,
            warnings=warned,
        )

    # 1. authorization — before any cluster read.
    decision = admission.authorize(workload)
    if not decision.permitted:
        rule_id = decision.rule_id or RULE_AUTHORIZATION_DENIED
        return _deny(
            rule_id,
            decision.reason or f"{subject} is not authorized for this run",
            identity,
            remediation=decision.remediation,
        )

    # 2. provenance — the request must describe the planned workload — and
    # 3. live targets. Both are properties of the plan plus the resolver's
    # record, so neither needs the cluster. A step with no request at all
    # defaults to an empty one over the planned workload, so "no resolved live
    # target" is one refusal with one message rather than two paths to it.
    request = admission.requests.get(step_id, K8sAdmissionRequest(workload=workload))
    provenance = _provenance_refusal(step_id, fault, workload, request, identity)
    if provenance is not None:
        rule_id, reason, inputs, keys = provenance
        return _deny(rule_id, reason, inputs, targets=keys)
    keys = tuple(t.authority_key for t in request.targets)
    kill_count = len(request.targets)

    # 4. observed facts, then the six Phase-1 rules in their own order.
    facts = collect_workload_facts(
        workload,
        admission.client,
        acknowledge_cluster_degradation=admission.acknowledge_cluster_degradation,
    )
    if facts is None:
        return _deny(
            RULE_WORKLOAD_MISSING,
            f"{subject}: the cluster does not report this {workload.kind} workload, so its "
            f"availability cannot be observed before mutating {kill_count} pod(s)",
            {**identity, "kill_count": kill_count},
            targets=keys,
        )
    verdicts = evaluate_workload_admission(facts, kill_count=kill_count)
    if probe_warning(facts) is not None:
        warned = (RULE_PROBE_ABSENT,)
    measured: dict[str, object] = {
        **identity,
        "kill_count": kill_count,
        "replicas": facts.replicas,
        "ready_replicas": facts.ready_replicas,
        "updated_replicas": facts.updated_replicas,
        "pdb_min_available": facts.pdb_min_available,
        "pdb_max_unavailable": facts.pdb_max_unavailable,
        "cluster_nodes_ready": facts.cluster_nodes_ready,
        "cluster_nodes_total": facts.cluster_nodes_total,
        "targets": list(keys),
    }
    refused = next((v for v in verdicts if not v.admitted), None)
    if refused is not None:
        return _deny(
            refused.code,
            refused.reason,
            {**measured, "check": refused.check.value, **verdict_inputs(refused)},
            verdicts=verdicts,
            targets=keys,
        )

    # 5. observation validity — Phase 2's consumption of the carried facts.
    confound = observation_refusal(
        facts, kill_count=kill_count, acknowledge=admission.acknowledge_degraded_workload
    )
    if confound is not None:
        rule_id, reason, inputs = confound
        return _deny(rule_id, reason, {**measured, **inputs}, verdicts=verdicts, targets=keys)
    return K8sAdmissionOutcome(
        fault_id=fault.fault_id,
        workload=subject,
        namespace=workload.namespace,
        kind=workload.kind,
        admitted=True,
        rule_id=RULE_ADMISSION_ALLOW,
        reason=(
            f"{kill_count} of {facts.replicas} replica(s) of {subject} admitted: every "
            "workload-safety rule holds and the observation is attributable"
        ),
        inputs=measured,
        verdicts=verdicts,
        targets=keys,
        warnings=warned,
    )


def admit_k8s_plan(
    plan: ExecutionPlan,
    admission: K8sAdmissionInput,
) -> tuple[K8sAdmissionOutcome, ...]:
    """Every Kubernetes-scoped step's outcome, in plan order.

    Non-Kubernetes steps produce nothing at all — that is the no-op property
    ``safety.validate_plan`` relies on.
    """
    outcomes: list[K8sAdmissionOutcome] = []
    for step in plan.steps:
        fault = step.fault
        if fault is None or k8s_workload_of(fault.target) is None:
            continue
        outcomes.append(admit_k8s_fault(step.id, fault, admission))
    return tuple(outcomes)


def _exclusion_summary(request: K8sAdmissionRequest) -> str:
    """The Phase-1 exclusion buckets as one line naming why nothing was live."""
    if not request.excluded:
        return (
            "no resolved live pod was supplied for this step (a manifest blueprint "
            "placeholder and an unresolved pin are both drift, never a target)"
        )
    counts: dict[str, int] = {}
    for exclusion in request.excluded:
        counts[exclusion.kind.value] = counts.get(exclusion.kind.value, 0) + 1
    buckets = ", ".join(f"{count} {kind}" for kind, count in sorted(counts.items()))
    return (
        f"{len(request.excluded)} matched-but-ineligible candidate(s) [{buckets}]: "
        f"{request.excluded[0].reason}"
    )


__all__ = (
    "DEFAULT_PROTECTED_NAMESPACES",
    "RULE_ADMISSION_ALLOW",
    "RULE_AUTHORIZATION_DENIED",
    "RULE_NAMESPACE_MISMATCH",
    "RULE_NAMESPACE_PROTECTED",
    "RULE_NO_LIVE_TARGET",
    "RULE_PROBE_ABSENT",
    "RULE_REQUEST_MISMATCH",
    "RULE_ROLLOUT_IN_FLIGHT",
    "RULE_UNREADY_REPLICAS",
    "RULE_WORKLOAD_MISSING",
    "K8sAdmissionClient",
    "K8sAdmissionInput",
    "K8sAdmissionOutcome",
    "K8sAdmissionRequest",
    "K8sAuthorization",
    "K8sAuthorizer",
    "admit_k8s_fault",
    "admit_k8s_plan",
    "collect_workload_facts",
    "k8s_workload_of",
    "namespace_protection",
    "observation_refusal",
    "probe_warning",
    "remediation_for",
    "verdict_inputs",
)
