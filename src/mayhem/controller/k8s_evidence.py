"""Safety and evidence integration for the Kubernetes lane (plan 02, Phase 4).

Phase 2 shipped the gate and its own ledger recorded, verbatim, why it was inert:
*"Nothing constructs a ``K8sAdmissionInput`` in production* — neither
``cli/services.py`` nor the executor does. So today every production run reaches
the gate with ``None``", and *"The executor does not yet build ``requests`` from its
``resolve_many`` output, so even a configured context would refuse every step as
unresolved."* This module is that missing half, and it closes the gap in three
pieces that belong together — a gate whose decision nothing can reconstruct is a
gate nobody can audit.

1. :func:`resolve_admission_requests` — turn ``resolve_many``'s output into the
   step-id-keyed :class:`~mayhem.controller.k8s_admission.K8sAdmissionRequest`
   map the gate consumes. **Step-id keying is load-bearing** and is preserved
   exactly: one plan can carry two steps of the same fault against the same
   workload with two different resolutions, so a fault-id key would silently
   apply step 1's pods to step 2. The negative control in
   ``tests/unit/test_k8s_evidence.py`` pins that.
2. :func:`admission_events` / :func:`drift_events` / :func:`run_phase_event` —
   the Kubernetes lane's events, in the **existing**
   :class:`~mayhem.domain.events.Event` / :class:`~mayhem.domain.events.EventKind`
   vocabulary. No new kind, no second stream; :data:`K8S_PHASE_KINDS` maps each
   run phase onto the kind that already stands for it.
3. :func:`seal_k8s_admission` — the decision (allow *or* refusal), its rule id,
   and the observed numbers, sealed into a chain and manifest through
   :class:`~mayhem.infra.attestation_store.AttestationRepository`. The sealed
   record is built from the same canonical bytes every other attestation uses and
   verified by the same
   :func:`~mayhem.domain.attestation.verify_chain`; this module adds **no second
   sealer** and no second verifier.

The executor hook
-----------------
:func:`plan_phase_admission` is the one call that makes all three happen around
``safety.validate_plan``. It is inert unless a ``SafetyContext`` carries a
``k8s_admission`` *and* the plan has a pod-resolved Kubernetes step; it never
mutates the caller's context (``SafetyContext`` is frozen, so it hands back a
copy carrying the resolved requests), and a resolution therefore never outlives
the block or leaks into a later run on the same context.

It also **builds** the lane's events and hands them back on
:attr:`K8sPlanPhase.events` rather than writing them, because
``events.run_id`` references ``runs(id)`` with foreign keys on and admission runs
before the run row is opened. Buffering is the honest order, not a workaround:
these are plan-phase facts about a run that has not opened yet, and on the
refusal path the run never opens — so a refused plan's decision is recorded in
the *sealed chain*, which is exactly the record that survives a plan the run
journal has no run to hang off.

Why the admission runs twice, and why that costs one read
-----------------------------------------------------------
The hook admits the plan itself so it has outcomes to journal and seal, and then
``validate_plan`` runs the gate again — ``safety.py`` owns the refusal and this
phase does not touch it. Two passes of a pure function over the same facts are
the same answer, and to make that true rather than merely likely the hook
installs :class:`_SingleReadAdmissionClient`, which reads each workload **once**
for the whole plan phase. That is the "two reads can never disagree with each
other" property ``K8sAdmissionClient`` documents, enforced instead of assumed:
one real cluster read per workload, two identical verdicts. A unit test pins the
read count.

Honesty invariants this module does not relax
--------------------------------------------
* A manifest-blueprint candidate is never resolved, so it never becomes a
  request target; a step whose candidates were all blueprint-eligible produces a
  request with the Phase-1 exclusion buckets attached and the gate refuses it as
  ``k8s.no_live_target`` naming the bucket.
* A resolved record with no pod uid is refused by the gate, not repaired here.
* ``KubernetesAdapter.is_available()`` stays ``False``. Nothing here rehabilitates
  it, and **no live cluster has been accepted by this phase** — every request
  this module builds in the test suite came from a fake cluster client.
* An admission decision that was not sealed is *detectable*:
  :func:`verify_k8s_admission_chain` reports a chain that is absent, short, or
  tampered with, and never returns ``valid=True`` for a run whose decision was
  never written.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from mayhem.controller.k8s_admission import (
    K8sAdmissionInput,
    K8sAdmissionOutcome,
    K8sAdmissionRequest,
    admit_k8s_plan,
    k8s_workload_of,
)
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    ManifestVerification,
    build_manifest,
    chain_root,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.errors import ResolutionError, SelectionError
from mayhem.domain.events import Event, EventKind

# ``_recorded_at`` is plan 12's single clock policy for attested events — a
# wall-clock/monotonic pair taken once for a chain. Re-implementing it here would
# be a second clock policy disagreeing with the first by a monotonic tick, so the
# private helper is imported rather than copied; it is the only private name this
# module reaches for, and :func:`seal_k8s_admission` is its only caller.
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
    _recorded_at,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from mayhem.agents.k8s_resolve import K8sWorkload, ResolutionOutcome
    from mayhem.controller.k8s_admission import K8sAdmissionClient
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.k8s_targets import WorkloadFacts
    from mayhem.domain.resolution import ResolvedPodTarget
    from mayhem.domain.target import TargetScope
    from mayhem.infra.store import Store


class PodResolver(Protocol):
    """The one resolver method this module calls.

    Narrower than :class:`~mayhem.agents.k8s_resolve.KubernetesRuntimeResolver`
    on purpose: :mod:`mayhem.agents.k8s_resolve` owns the live 5-step flow, and
    naming only ``resolve_many`` here means this module cannot drift into
    ``workload()``/``pods_for()``/``exec()`` — the exact re-resolution
    ``controller/k8s_admission.py`` refuses to do.
    """

    def resolve_many(
        self, scope: TargetScope, *, pod_action: str = ""
    ) -> Sequence[ResolutionOutcome]:
        """Every pod the scope's selection mode picks, from the live cluster."""
        ...


# ── sealed-chain identity ────────────────────────────────────────────────────
#: The chain event kind an admission decision is sealed under. It is a *chain*
#: kind (``AttestedEvent.event_kind``), not a ``domain.events.EventKind``: the two
#: vocabularies are separate by design — the first is what a verifier re-hashes
#: offline, the second is what the run journal renders. Reusing a ``domain.events``
#: value here would imply the journal row and the sealed row are the same fact.
EVENT_K8S_ADMISSION_DECIDED = "k8s.admission_decided"

#: The chain key suffix. ``attestation_chains.run_id`` is a PRIMARY KEY, so a
#: chain for the run itself is already claimed by ``seal_run_evidence`` at run
#: close — writing the admission decision under the bare run id would replace the
#: evidence chain (or be replaced by it) and the decision would be lost either
#: way. Namespacing the *chain key* keeps both: the rows are namespaced, the
#: events still name the real run, and both verify independently.
CHAIN_KEY_SUFFIX = ":k8s-admission"


def admission_chain_key(run_id: str) -> str:
    """The ``attestation_chains`` key this lane writes under for ``run_id``."""
    return f"{run_id}{CHAIN_KEY_SUFFIX}"


def admission_manifest_id(run_id: str) -> str:
    """The ``attestation_manifests`` id covering the admission chain."""
    return admission_chain_key(run_id)


# ── run-phase events (existing vocabulary only) ──────────────────────────────
#: Which already-existing ``EventKind`` stands for each Kubernetes run phase. No
#: member of :class:`~mayhem.domain.events.EventKind` is added by this phase; the
#: two kinds this lane needed beyond the lifecycle ones already existed
#: (``CHECK_EVALUATED`` renders into the API timeline's OBSERVE phase,
#: ``DRIFT_REPORTED`` likewise, and ``SAFETY_REFUSED`` into FAULT — see
#: ``domain/api.py``'s timeline map), so a reader, a renderer, and a projection
#: already know what to do with all of them.
K8S_PHASE_KINDS: Mapping[str, EventKind] = {
    "plan": EventKind.CHECK_EVALUATED,  # the workload-admission decision
    "run": EventKind.RUN_STARTED,
    "step": EventKind.STEP_STARTED,
    "fault": EventKind.FAULT_INJECTED,
    "admission": EventKind.CHECK_EVALUATED,
    "drift": EventKind.DRIFT_REPORTED,
}

#: The kinds a refusal is journaled under, in addition to the per-step decision.
K8S_REFUSAL_KIND = EventKind.SAFETY_REFUSED


def run_phase_event(
    phase: str,
    run_id: str,
    *,
    step_id: str = "",
    fault_id: str = "",
    detail: Mapping[str, object] | None = None,
) -> Event:
    """One Kubernetes lane event for *phase*, in the existing vocabulary.

    Raises:
        KeyError: If *phase* is not a phase :data:`K8S_PHASE_KINDS` names. An
            unknown phase is a caller bug; guessing a kind for it would put an
            event in the journal that no renderer and no timeline map expects.
    """
    payload: dict[str, object] = {"phase": phase, "lane": "k8s"}
    if step_id:
        payload["step"] = step_id
    if fault_id:
        payload["fault"] = fault_id
    if detail:
        payload.update(_plain(dict(detail)))
    return Event(kind=K8S_PHASE_KINDS[phase], run_id=run_id, detail=payload)


# ── request building from the resolver's output ──────────────────────────────
@dataclass(frozen=True)
class K8sResolutionNote:
    """What the resolver produced for one planned step, in one value.

    ``targets`` are the ``ResolvedPodTarget`` records ``resolve_many`` returned;
    ``error_code`` is the stable taxonomy code when resolution failed instead
    (``resolution.resource_missing``, ``selection.no_eligible_pods``, …). A note
    with either no targets or an error is *not resolved*, and a step that is not
    resolved is a refusal — never a repair, never a re-read here.
    """

    step_id: str
    fault_id: str
    workload: K8sWorkload
    targets: tuple[ResolvedPodTarget, ...] = ()
    drift: bool = False
    error_code: str = ""
    error: str = ""
    notes: tuple[str, ...] = ()

    @property
    def resolved(self) -> bool:
        """True when the live flow produced at least one pod target."""
        return bool(self.targets) and not self.error_code

    @property
    def authority_keys(self) -> tuple[str, ...]:
        """``namespace/pod`` of the resolved targets, in resolution order."""
        return tuple(t.authority_key for t in self.targets)

    def describe(self) -> str:
        """One line naming the step, the fault, and what resolution produced."""
        if self.error_code:
            state = f"UNRESOLVED ({self.error_code})"
        elif self.resolved:
            state = f"resolved {len(self.targets)} pod(s): {', '.join(self.authority_keys)}"
        else:
            state = "UNRESOLVED: the resolver returned no pod target"
        drift = ", drifted from the planned pick" if self.drift else ""
        return f"step {self.step_id} ({self.fault_id}): {state}{drift}"

    def drift_reason(self) -> str:
        """The note as one sentence, for a ``DRIFT_REPORTED`` detail.

        Names the stable taxonomy code when resolution failed, so a reader can
        look the failure up rather than parsing prose.
        """
        if self.error_code:
            detail = self.error or "no live pod was resolved for this step"
            return (
                f"step {self.step_id} ({self.fault_id}) could not be resolved "
                f"[{self.error_code}]: {detail}"
            )
        if not self.resolved:
            return (
                f"step {self.step_id} ({self.fault_id}) resolved to no live pod; "
                "an unresolved pin is drift, never a target"
            )
        return f"step {self.step_id} ({self.fault_id}) drifted: {self.describe()}"


def note_from_outcomes(
    step_id: str,
    fault_id: str,
    workload: K8sWorkload,
    outcomes: Sequence[ResolutionOutcome],
) -> K8sResolutionNote:
    """Fold ``resolve_many``'s output into one :class:`K8sResolutionNote`.

    Node resolutions are dropped rather than coerced: ``resolve_many`` is
    pod-only, but the union type on :class:`ResolutionOutcome` means a future
    caller could hand one over, and a node target presented to a pod workload's
    admission request would be exactly the kind of silent coercion this lane
    refuses.
    """
    targets: list[ResolvedPodTarget] = []
    drift = False
    notes: list[str] = []
    for outcome in outcomes:
        target = outcome.pod_or_none()
        if target is None:
            continue
        targets.append(target)
        drift = drift or outcome.drift
        if outcome.note:
            notes.append(outcome.note)
    return K8sResolutionNote(
        step_id=step_id,
        fault_id=fault_id,
        workload=workload,
        targets=tuple(targets),
        drift=drift,
        notes=tuple(notes),
    )


def request_from_note(note: K8sResolutionNote) -> K8sAdmissionRequest:
    """The gate's request for one resolved step.

    Built from the note, never re-derived: the workload is the resolver's own,
    and the targets are the records it returned. A note that failed to resolve
    produces a request with no targets, which the gate refuses as
    ``k8s.no_live_target`` — the same refusal a step with no request at all
    produces, so "unresolvable" and "never resolved" cannot be two answers.
    """
    return K8sAdmissionRequest(workload=note.workload, targets=note.targets)


def k8s_plan_targets(
    plan: ExecutionPlan,
) -> tuple[tuple[str, str, K8sWorkload, TargetScope], ...]:
    """``(step_id, fault_id, workload, scope)`` for every pod-resolved k8s step.

    Same predicate as ``admit_k8s_plan`` uses — ``k8s_workload_of`` on the
    step's fault target, which is ``None`` for a non-Kubernetes scope and for a
    **node** one — so the set of steps this module resolves and the set the gate
    walks cannot drift apart. The scope travels with the tuple because it is the
    resolver's own input: a request built about a caller-supplied scope instead
    of the plan's would be an admission request about a workload the plan never
    named.
    """
    found: list[tuple[str, str, K8sWorkload, TargetScope]] = []
    for step in plan.steps:
        fault = step.fault
        if fault is None or fault.target is None:
            continue
        workload = k8s_workload_of(fault.target)
        if workload is None:
            continue
        found.append((step.id, fault.fault_id, workload, fault.target))
    return tuple(found)


def k8s_plan_steps(plan: ExecutionPlan) -> tuple[tuple[str, str, K8sWorkload], ...]:
    """``(step_id, fault_id, workload)`` for every pod-resolved Kubernetes step."""
    return tuple(
        (step_id, fault_id, workload) for step_id, fault_id, workload, _ in k8s_plan_targets(plan)
    )


def resolve_admission_requests(
    plan: ExecutionPlan,
    resolver: PodResolver,
) -> tuple[Mapping[str, K8sAdmissionRequest], tuple[K8sResolutionNote, ...]]:
    """Resolve every pod-resolved Kubernetes step and key the requests by step id.

    Args:
        plan: The frozen plan about to be admitted.
        resolver: The live resolver (or anything with ``resolve_many``).

    Returns:
        ``(requests, notes)``. ``requests`` is keyed by **plan step id** — never
        by fault id, because two steps may carry the same fault against the same
        workload with two different resolutions. ``notes`` records what
        resolution did per step, including the failure taxonomy for a step it
        could not resolve, so the refusal and the journal entry can both name it.

    A resolution *failure* is recorded, never raised: this runs before
    ``validate_plan``, and the gate's ``k8s.no_live_target`` refusal is the
    operator-facing statement of the same fact. Raising here would replace a
    refusal that names the workload and the rule with a bare taxonomy code.
    """
    requests: dict[str, K8sAdmissionRequest] = {}
    notes: list[K8sResolutionNote] = []
    for step_id, fault_id, workload, scope in k8s_plan_targets(plan):
        action = fault_id.split(".", 1)[-1]
        try:
            outcomes = resolver.resolve_many(scope, pod_action=action)
        except (ResolutionError, SelectionError) as exc:
            notes.append(
                K8sResolutionNote(
                    step_id=step_id,
                    fault_id=fault_id,
                    workload=workload,
                    error_code=getattr(exc, "code", "") or "resolution.failed",
                    error=str(exc),
                )
            )
            continue
        note = note_from_outcomes(step_id, fault_id, workload, outcomes)
        notes.append(note)
        requests[step_id] = request_from_note(note)
    return requests, tuple(notes)


def build_k8s_admission_input(
    admission: K8sAdmissionInput,
    requests: Mapping[str, K8sAdmissionRequest],
    *,
    client: K8sAdmissionClient | None = None,
) -> K8sAdmissionInput:
    """A copy of *admission* carrying *requests* (and optionally *client*).

    Additive by construction: the acknowledgement flags, the authorizer, and the
    context travel through unchanged, so installing this on a ``SafetyContext``
    can only *add* what the gate can see — it can never relax a rule.
    """
    if not requests and client is None:
        return admission
    updates: dict[str, object] = {}
    if requests:
        updates["requests"] = dict(requests)
    if client is not None:
        updates["client"] = client
    return replace(admission, **updates)  # type: ignore[arg-type]


class _SingleReadAdmissionClient:
    """Reads each workload once for the whole plan phase.

    The gate is asked twice in one plan phase (see the module docstring) and
    ``K8sAdmissionClient`` promises that a refusal is reproducible from a single
    read. This is the mechanism that keeps that promise when the gate is asked
    twice: the second pass gets the first pass's answer for the same workload
    identity, so the two verdicts cannot disagree and the cluster is read once.

    Keyed by ``(namespace, kind, name)`` — the identity admission pins every fact
    to, which is the only identity a refusal can be about.
    """

    __slots__ = ("_cache", "_inner")

    def __init__(self, inner: K8sAdmissionClient) -> None:
        self._inner = inner
        self._cache: dict[tuple[str, str, str], object] = {}

    def workload_facts(self, workload: K8sWorkload) -> WorkloadFacts | None:
        key = (workload.namespace, workload.kind, workload.name)
        if key not in self._cache:
            self._cache[key] = self._inner.workload_facts(workload)
        return self._cache[key]  # type: ignore[return-value]

    @property
    def reads(self) -> int:
        """How many real cluster reads were spent (for tests and diagnostics)."""
        return len(self._cache)


# ── the executor hook ────────────────────────────────────────────────────────
@dataclass
class K8sPlanPhase:
    """What the plan phase resolved, admitted, sealed, and wants journaled."""

    #: The context to pass to ``validate_plan``. It is the caller's own context
    #: unchanged when this lane is inert, and otherwise a copy carrying the
    #: resolved requests — ``SafetyContext`` is a frozen dataclass, so it is
    #: replaced rather than mutated. ``dataclasses.replace`` passes the existing
    #: ``decisions``/``warnings`` *list objects* through, so every decision the
    #: gate records inside the block is still on the caller's context afterwards;
    #: this lane cannot swallow a refusal from the caller's point of view.
    safety: SafetyContext | None = None
    notes: tuple[K8sResolutionNote, ...] = ()
    outcomes: tuple[K8sAdmissionOutcome, ...] = ()
    #: Events the caller must journal **after the run row exists**. See
    #: :attr:`events` — this lane builds them and deliberately does not write
    #: them itself.
    events: tuple[Event, ...] = ()
    refused: bool = False
    refusal: BaseException | None = None
    seal_error: Exception | None = None
    seal: K8sAdmissionSeal | None = None

    @property
    def resolved_steps(self) -> tuple[str, ...]:
        """Step ids the resolver produced a live pod target for."""
        return tuple(note.step_id for note in self.notes if note.resolved)

    @property
    def unresolved_steps(self) -> tuple[str, ...]:
        """Step ids with no live target — each one is a refusal, named."""
        return tuple(note.step_id for note in self.notes if not note.resolved)

    @property
    def denied_steps(self) -> tuple[str, ...]:
        """Step ids the gate refused."""
        return tuple(str(o.inputs.get("step_id", "")) for o in self.outcomes if not o.admitted)


@contextlib.contextmanager
def plan_phase_admission(
    plan: ExecutionPlan,
    safety: SafetyContext | None,
    resolver_factory: Callable[[], PodResolver | None],
    *,
    seal: Callable[[tuple[K8sAdmissionOutcome, ...]], K8sAdmissionSeal | None] | None = None,
) -> Iterator[K8sPlanPhase]:
    """Resolve, admit, and seal a Kubernetes plan around ``validate_plan``.

    Args:
        plan: The frozen plan being admitted.
        safety: The caller's context. It is never mutated; the block runs against
            the copy in :attr:`K8sPlanPhase.safety`, which shares the caller's
            decision lists. The resolved requests therefore never outlive the
            block and cannot be carried into a later run on the same context.
        resolver_factory: Called **only** when the context is configured *and*
            the plan has a pod-resolved Kubernetes step. That laziness is load
            bearing: it is what keeps a Docker-only run from probing for kubectl.
        seal: Seals the outcomes into the attestation chain. ``None`` skips
            sealing — the gate still runs, the decision is just not durable.

    Yields:
        The :class:`K8sPlanPhase` for this block. Its ``safety`` is what to pass
        to ``validate_plan``, and its ``events`` are what to journal once the run
        row exists. The rest of it is only complete once the block has exited,
        because the seal happens then.

    Raises:
        Whatever the body raises, unchanged. A refusal must reach the caller as
            the refusal ``safety.validate_plan`` made, not as a sealing error.
    """
    phase = K8sPlanPhase(safety=safety)
    admission = None if safety is None else safety.k8s_admission
    if safety is None or admission is None or not k8s_plan_targets(plan):
        yield phase
        return
    resolver = resolver_factory()
    if resolver is None:
        # No cluster client: there is nothing to resolve, and a request built from
        # nothing would be a request with no targets — i.e. the same refusal the
        # gate makes for an unresolved step, arriving with an extra step.
        yield phase
        return

    requests, notes = resolve_admission_requests(plan, resolver)
    phase.notes = notes
    reader = _SingleReadAdmissionClient(admission.client)
    prepared = build_k8s_admission_input(admission, requests, client=reader)
    outcomes = admit_k8s_plan(plan, prepared)
    phase.outcomes = outcomes
    # Built here, written by the caller: ``events.run_id`` REFERENCES
    # ``runs(id)`` with foreign keys ON, and this block runs before
    # ``_open_run``, so writing these now would fail the foreign key. Buffering
    # is not a workaround — it is the honest order. These are *plan-phase* facts
    # about a run that has not opened yet, and on the refusal path the run never
    # opens, so their durable record is the sealed chain below rather than a
    # journal row hanging off no run.
    phase.events = (*drift_events(plan.run_id, notes), *admission_events(plan.run_id, outcomes))

    phase.safety = replace(safety, k8s_admission=prepared)
    body_error: BaseException | None = None
    try:
        yield phase
    except BaseException as exc:  # recorded, then re-raised unchanged
        body_error = exc
        raise
    finally:
        phase.refused = body_error is not None
        phase.refusal = body_error
        if seal is not None and outcomes:
            try:
                phase.seal = seal(outcomes)
            except Exception as exc:  # see the comment below
                phase.seal_error = exc
                if body_error is None:
                    # An unsealed decision the caller was told nothing about is
                    # the exact failure this phase exists to prevent, so on the
                    # *allow* path it propagates. On the refusal path the plan is
                    # already refused and stays refused; masking that refusal with
                    # a storage error would lose the more important fact, so the
                    # error stays on ``phase.seal_error`` for the caller to read.
                    raise


# ── events ───────────────────────────────────────────────────────────────────
def drift_events(run_id: str, notes: Sequence[K8sResolutionNote]) -> tuple[Event, ...]:
    """One ``DRIFT_REPORTED`` per observation that is not a clean resolution.

    Two observations qualify, and both are facts the run journal should carry:
    a step whose live pick differed from the plan-time pick, and a step the
    resolver could not resolve at all. A resolved, undrifted step produces no
    event — a drift report that fires on every healthy step teaches a reader to
    ignore it.
    """
    return tuple(
        run_phase_event(
            "drift",
            run_id,
            step_id=note.step_id,
            fault_id=note.fault_id,
            detail={
                "note": note.describe(),
                "reason": note.drift_reason(),
                "resolved": note.resolved,
                "drifted": note.drift,
            },
        )
        for note in notes
        if note.drift or not note.resolved
    )


def admission_events(run_id: str, outcomes: Sequence[K8sAdmissionOutcome]) -> tuple[Event, ...]:
    """The admission decision, per step, plus one refusal marker for the run.

    Every step's decision is a ``CHECK_EVALUATED`` carrying its rule id and the
    observed numbers — the *allow* decisions as much as the refusals, because
    "why was this allowed" is the question a later reader asks just as often.
    A run that refused adds one ``SAFETY_REFUSED`` naming the first deciding rule,
    which is the kind ``domain/api.py``'s timeline already renders as a fault
    event.
    """
    events: list[Event] = []
    for outcome in outcomes:
        events.append(
            run_phase_event(
                "admission",
                run_id,
                detail=admission_payload(outcome),
            )
        )
    refused = next((o for o in outcomes if not o.admitted), None)
    if refused is not None:
        events.append(
            Event(
                kind=K8S_REFUSAL_KIND,
                run_id=run_id,
                detail={
                    "phase": "plan",
                    "lane": "k8s",
                    "rule_id": refused.rule_id,
                    "workload": refused.workload,
                    "fault_id": refused.fault_id,
                    "step_id": str(refused.inputs.get("step_id", "")),
                    "reason": refused.reason,
                    "remediation": refused.remediation,
                },
            )
        )
    return tuple(events)


def admission_payload(outcome: K8sAdmissionOutcome) -> dict[str, object]:
    """One decision as a flat, JSON-safe record: rule id, numbers, and targets.

    Shared by the journal event and the sealed chain payload, so the two cannot
    disagree about what was decided — the journal is a rendering of the record,
    not a second answer to the same question.
    """
    identity = {"step_id", "fault_id", "namespace", "workload", "workload_kind", "context"}
    payload: dict[str, object] = {
        "step_id": outcome.inputs.get("step_id", ""),
        "fault_id": outcome.fault_id,
        "admitted": outcome.admitted,
        "rule_id": outcome.rule_id,
        "workload": outcome.workload,
        "namespace": outcome.namespace,
        "kind": outcome.kind,
        "reason": outcome.reason,
        "remediation": outcome.remediation,
        "targets": list(outcome.targets),
        "warnings": list(outcome.warnings),
        "observed": {k: v for k, v in outcome.inputs.items() if k not in identity},
        "verdicts": [
            {
                "check": verdict.check.value,
                "code": verdict.code,
                "admitted": verdict.admitted,
                "observed": verdict.observed,
                "required": verdict.required,
                "kill_count": verdict.kill_count,
            }
            for verdict in outcome.verdicts
        ],
    }
    projected = _plain(payload)
    return dict(projected) if isinstance(projected, dict) else payload


# ── sealing ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class K8sAdmissionSeal:
    """A sealed admission record, with the verdicts that prove it.

    Mirrors :class:`~mayhem.infra.attestation_store.SealedRun` for this lane: the
    events, the manifest over them, both verification verdicts, and the same
    unsigned-with-a-reason honesty state — this phase attests integrity, never
    authorship, exactly as plan 12 does.
    """

    run_id: str
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification
    signature_state: str = SIGNATURE_UNSIGNED_NO_SIGNING
    signature_reason: str = UNSIGNED_REASON_NO_SIGNING

    @property
    def chain_root(self) -> str:
        return chain_root(self.events)

    @property
    def signed(self) -> bool:
        """Always False here. Present so a caller cannot assume otherwise."""
        return self.manifest.signed

    @property
    def valid(self) -> bool:
        """True when both the chain and its manifest verify."""
        return self.chain_verification.valid and self.manifest_verification.valid

    @property
    def decisions(self) -> tuple[dict[str, object], ...]:
        """The recorded decisions, one per event, in chain order."""
        return tuple(dict(event.payload) for event in self.events)


def admission_chain_events(
    run_id: str,
    outcomes: Sequence[K8sAdmissionOutcome],
    *,
    recorded_at: AttestedTimestamp,
) -> tuple[AttestedEvent, ...]:
    """The unsealed chain events for one plan's admission decisions (pure).

    One event per outcome, in plan order, each carrying
    :func:`admission_payload`. The ``AttestedEvent.run_id`` is the **real** run
    id, so a reloaded event says which run it describes; only the chain row key is
    namespaced (see :func:`admission_chain_key`).
    """
    return tuple(
        AttestedEvent(
            event_id=f"{run_id}:k8s-admission:{str(o.inputs.get('step_id', '')) or o.fault_id}",
            event_kind=EVENT_K8S_ADMISSION_DECIDED,
            run_id=run_id,
            sequence=index,
            payload=admission_payload(o),
            recorded_at=recorded_at,
        )
        for index, o in enumerate(outcomes)
    )


def seal_k8s_admission(
    store: Store,
    run_id: str,
    outcomes: Sequence[K8sAdmissionOutcome],
    *,
    recorded_at: AttestedTimestamp | None = None,
    created_at: AttestedTimestamp | None = None,
) -> K8sAdmissionSeal | None:
    """Seal this plan's Kubernetes admission decisions into the attested chain.

    Writes through :class:`~mayhem.infra.attestation_store.AttestationRepository`
    — the module's own persistence, its own evidence-boundary gate, and its own
    verification. This function builds *events*; it does not build a sealer.

    Returns:
        The :class:`K8sAdmissionSeal`, or ``None`` when there is nothing to seal
        (a plan with no pod-resolved Kubernetes step). An empty chain is not
        written: a row that proves nothing is noise a later reader has to rule
        out.

    Raises:
        AttestationError: If the derived chain or manifest fails verification, in
            which case nothing is written.
        InvariantViolationError: From the evidence boundary, if the derived
            record carries a secret-classified field. Nothing is written.
    """
    if not outcomes:
        return None
    reading = _recorded_at(recorded_at)
    events = seal_events(
        admission_chain_events(run_id, outcomes, recorded_at=reading),
    )
    manifest = build_manifest(
        events,
        manifest_id=admission_manifest_id(run_id),
        run_id=run_id,
        signer_identity="",
        trust_root_ref="",
        created_at=created_at or reading,
        previous_manifest_digest=GENESIS_DIGEST,
    )
    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid Kubernetes admission chain for run "
            f"{run_id!r}: {'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid Kubernetes admission manifest for run "
            f"{run_id!r}: {'; '.join(manifest_verification.errors)}"
        )

    repository = AttestationRepository(store)
    repository.save_chain(admission_chain_key(run_id), events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    return K8sAdmissionSeal(
        run_id=run_id,
        events=events,
        manifest=manifest,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
    )


def load_k8s_admission(store: Store, run_id: str) -> K8sAdmissionSeal | None:
    """Reload a sealed admission record from stored bytes, or ``None``.

    Reload is exact: the rows carry the canonical JSON the digests were computed
    from, so what comes back verifies the same way it went in. The
    ``signature_state`` is reloaded rather than re-asserted, so an unsigned
    record stays visibly unsigned to whoever reads it.
    """
    repository = AttestationRepository(store)
    events = repository.load_chain(admission_chain_key(run_id))
    if not events:
        return None
    manifest = repository.load_manifest(admission_manifest_id(run_id))
    if manifest is None:
        return None
    state, reason = repository.load_signature_state(manifest.manifest_id)
    return K8sAdmissionSeal(
        run_id=run_id,
        events=events,
        manifest=manifest,
        chain_verification=verify_chain(events),
        manifest_verification=verify_manifest(manifest, events),
        signature_state=state,
        signature_reason=reason,
    )


def verify_k8s_admission_chain(store: Store, run_id: str) -> ChainVerification:
    """Re-verify the stored admission chain, naming an unsealed decision as absent.

    Delegates the re-hashing to
    :meth:`~mayhem.infra.attestation_store.AttestationRepository.verify_run_chain`,
    which reloads the stored bytes, calls the domain verifier, and additionally
    checks the stored root and count against the recomputed ones. A run whose
    decision was never sealed reports ``valid=False`` with "no chain stored" —
    an *unsealed* decision is detectable, never silently treated as allowed.
    """
    return AttestationRepository(store).verify_run_chain(admission_chain_key(run_id))


# ── helpers ──────────────────────────────────────────────────────────────────
def _plain(value: object) -> Any:
    """JSON-safe projection of an event/chain value.

    ``Event.detail`` and ``AttestedEvent.payload`` are both free-form by
    construction and both reach a JSON column, so anything a decision carries is
    projected here rather than trusted to serialize: an enum becomes its value, a
    tuple becomes a list, and anything else becomes its text. A refusal record
    that could not be written would be worse than one that is legible.
    """
    if isinstance(value, Enum):
        return _plain(value.value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


__all__ = (
    "CHAIN_KEY_SUFFIX",
    "EVENT_K8S_ADMISSION_DECIDED",
    "K8S_PHASE_KINDS",
    "K8S_REFUSAL_KIND",
    "K8sAdmissionSeal",
    "K8sPlanPhase",
    "K8sResolutionNote",
    "PodResolver",
    "admission_chain_events",
    "admission_chain_key",
    "admission_events",
    "admission_manifest_id",
    "admission_payload",
    "build_k8s_admission_input",
    "drift_events",
    "k8s_plan_steps",
    "load_k8s_admission",
    "note_from_outcomes",
    "plan_phase_admission",
    "request_from_note",
    "resolve_admission_requests",
    "run_phase_event",
    "seal_k8s_admission",
    "verify_k8s_admission_chain",
)
