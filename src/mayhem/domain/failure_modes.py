"""Standardised failure-mode taxonomy and the per-fault mapping over the catalog
(docs/v1.1.0/20_ENTERPRISE_PRODUCT_HARDENING.md, Phase 1, gap 55).

Plan 20 calls this "the backbone of enterprise reporting". That is a strong
sentence, and this module is built to be worth it or to visibly fail, never to
merely exist.

**The taxonomy is a fixed vocabulary of eighteen failure modes**, each with a
summary, the *distinguishing question* that separates it from its neighbours, and
recovery guidance (:class:`FailureModeProfile`). The distinguishing question is
the part that earns the vocabulary: "latency" and "network" are easy to
confuse, and the question that separates them — *did the request take longer, or
did the path change?* — is what makes a report entry reviewable instead of a
label somebody chose. A taxonomy entry with no recovery guidance is refused
(:func:`validate_failure_mode`): a mode nobody can act on is a category, not a
failure mode.

**Every catalog fault maps to at least one failure mode, and a test enforces
it.** :func:`unmapped_fault_ids` names the holes and :func:`validate_mappings`
raises on them. This is the plan's acceptance criterion, and it exists because
an unmapped fault is not a cosmetic gap: it is a fault the product can inject,
that an operator can hit in production, and that no enterprise report will have
a story for. The mapping is *data over* :data:`mayhem.domain.catalog.CATALOG`,
never a copy of it — the catalog stays the source of truth for fault truth, and
this module reads it.

**A mapping must answer six questions** — failure mode, mechanism, expected
symptom, risk, recovery, verification — and :func:`validate_mapping` refuses an
entry that answers any of them with an empty string. Three of the six are
cross-checked against the catalog rather than trusted:

* ``risk`` must equal the catalog's risk. A reporting library that restated a
  fault's risk as something lower would be the most dangerous kind of
  reclassification there is, and this module refuses to be the thing that does
  it.
* ``verification_method`` must equal the catalog's. The library may explain what
  a probe should show; it may not invent a different instrument.
* ``refusal_note`` must be present for a ``catalog_only`` entry and absent for
  an executable one. A report that presents a catalog-only fault as something
  that was injected is a false report, and the note is what stops it: the
  fault's expected symptom is *the plan-time refusal*, not an outage.

**A taxonomy with dead members is also a hole**, so
:func:`taxonomy_coverage` exists and a test asserts every one of the eighteen
modes has at least one fault behind it. A mode nothing maps to is a mode the
reports will never be able to discuss, which means the sentence "the taxonomy
covers availability" is doing work the data does not support.

**Compliance templates cannot assert compliance.** The plan's rule is explicit:
*provide templates/evidence mappings for customer compliance programs; do not
claim compliance solely because a template exists*. :class:`ComplianceControl`
therefore describes *what evidence a control would need* and carries a
``customer_obligations`` list of what the customer must still do;
:func:`require_non_asserting_template` refuses any template whose
``asserts_compliance`` is set, and :meth:`ComplianceControl.statement` is written
so that no value of any field turns it into an attestation. The field exists to
be refused — that is the honest shape for a prohibition, and it makes the
negative control in the test suite reachable.

Nothing here reads a clock, opens a file, or evaluates a policy. The whole module
is data plus pure lookups, so it sits inside the "domain layer has zero IO and no
upward imports" contract that the import-linter enforces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from mayhem.domain.catalog import CATALOG
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import VerificationMethod
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from mayhem.domain.faults import FaultDefinition

__all__ = [
    "COMPLIANCE_TEMPLATES",
    "FAILURE_MODES",
    "FAILURE_MODE_PROFILES",
    "ComplianceControl",
    "FailureMode",
    "FailureModeCoverage",
    "FailureModeProfile",
    "FaultFailureMapping",
    "compliance_statement",
    "failure_modes_for",
    "faults_for_mode",
    "mapped_fault_ids",
    "mapping_for",
    "require_non_asserting_template",
    "taxonomy_coverage",
    "unmapped_fault_ids",
    "validate_failure_mode",
    "validate_failure_modes",
    "validate_mapping",
    "validate_mappings",
]


class FailureMode(StrEnum):
    """The eighteen-member standardised taxonomy (plan 20 §"Failure-mode library").

    Ordered roughly from "the service is gone" to "somebody has to act". The
    order carries no meaning — a mode is identified by its name, not its
    position — but grouping them in the source the way a report groups them is
    worth the reading order.
    """

    AVAILABILITY = "availability"
    LATENCY = "latency"
    CORRECTNESS = "correctness"
    CAPACITY = "capacity"
    CONSISTENCY = "consistency"
    DURABILITY = "durability"
    PARTITION = "partition"
    DEPENDENCY = "dependency"
    SECURITY_CONTROL_FAILURE = "security_control_failure"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CLOCK = "clock"
    STORAGE = "storage"
    NETWORK = "network"
    PROCESS = "process"
    RUNTIME = "runtime"
    INFRASTRUCTURE = "infrastructure"
    CLOUD = "cloud"
    HUMAN_OPERATOR = "human_operator"


#: Every member, in declaration order.
FAILURE_MODES: Final[tuple[FailureMode, ...]] = tuple(FailureMode)


@dataclass(frozen=True, slots=True)
class FailureModeProfile:
    """One taxonomy member: what it is, what separates it, how it is recovered.

    ``distinguishing_question`` is the load-bearing field. Most of the real
    disagreements in a resilience review are disagreements about which mode was
    being described ("the network was slow" — was it latency, or a network
    fault?), and a question with a definite answer settles that faster than a
    definition does.

    ``recovery_guidance`` is required and validated as non-empty. A failure mode
    with no recovery guidance is a label on a report, and labels do not get a
    system back at 3am.
    """

    mode: FailureMode
    summary: str
    distinguishing_question: str
    recovery_guidance: str


FAILURE_MODE_PROFILES: Final[dict[FailureMode, FailureModeProfile]] = {
    profile.mode: profile
    for profile in (
        FailureModeProfile(
            mode=FailureMode.AVAILABILITY,
            summary="The workload is not serving the requests it is being asked to serve.",
            distinguishing_question=(
                "Did requests fail or stop being accepted at all? Latency and correctness "
                "are about requests that were served badly; availability is about requests "
                "that were not served."
            ),
            recovery_guidance=(
                "Restore the serving path first (process, replica, endpoint, or route), then "
                "establish what the unavailable period actually cost. An availability "
                "recovery with no cost accounting leaves the next sizing decision uninformed."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.LATENCY,
            summary="The workload served the request, later than the bound it promised.",
            distinguishing_question=(
                "Was the request completed within its latency objective? If it was, the "
                "mode is not latency regardless of what else was broken."
            ),
            recovery_guidance=(
                "Find where the time was spent before changing anything — the p50 is usually "
                "uninformative and the p99 or the dependency breakdown is where the cause is. "
                "Removing a latency fault that was actually a dependency fault hides the "
                "dependency."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.CORRECTNESS,
            summary="The workload returned a wrong, malformed, or damaged answer.",
            distinguishing_question=(
                "Did a client receive a response it should not have received — wrong data, "
                "wrong bytes, a duplicated application of an operation? A correct response that "
                "was merely late is latency, not correctness."
            ),
            recovery_guidance=(
                "Corruption and malformation are not undone by removing the fault: audit what "
                "was written or charged while the fault was active before declaring recovery. "
                "This is the mode where 'the fault is gone' and 'the system is correct' are "
                "different claims."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.CAPACITY,
            summary="The workload could not carry the demand placed on it.",
            distinguishing_question=(
                "Would this workload have coped with the same demand if it had more headroom? "
                "Capacity is about the ratio of demand to provision, not about the demand being "
                "unusual."
            ),
            recovery_guidance=(
                "Restore the provisioning (replicas, quota, connections, workers) and record "
                "the ratio that was exceeded. A capacity recovery without the ratio is a guess "
                "about next time."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.CONSISTENCY,
            summary="Two components that should agree did not.",
            distinguishing_question=(
                "Did any reader or writer observe a state that another component disagreed "
                "with? Inconsistency is only visible from two places at once, which is why it "
                "is measured as a disagreement and not as an error."
            ),
            recovery_guidance=(
                "Establish which side is authoritative and reconcile the other. Do not declare "
                "recovery from a single side agreeing with itself."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.DURABILITY,
            summary="Acknowledged work was lost or not persisted.",
            distinguishing_question=(
                "Did the system tell a client the work was accepted and then lose it? Durability "
                "failures are invisible until the next restart, so they are measured by restore "
                "or by a restart, not by a read."
            ),
            recovery_guidance=(
                "Recover from a backup or snapshot and count what was acknowledged in the "
                "window and not recovered. Mayhem observes this; it does not repair it."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.PARTITION,
            summary="A subset of the system could not reach the rest of it.",
            distinguishing_question=(
                "Did communication fail between components that were both still running? A "
                "partition leaves both sides healthy, which is why a per-component health check "
                "reports an all-clear during one."
            ),
            recovery_guidance=(
                "Restore the path, then reconcile the work each side performed while isolated. "
                "Healing the partition without reconciling converts an availability incident "
                "into a correctness one."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.DEPENDENCY,
            summary="A component behaved in a way its caller depends on.",
            distinguishing_question=(
                "Did a component outside the target misbehave? A dependency fault is visible "
                "from the caller and often invisible from inside the dependency itself."
            ),
            recovery_guidance=(
                "Recover the dependency if it is recoverable, and otherwise make the caller's "
                "degradation visible. A caller that fails the same way whether or not the "
                "dependency recovers has not demonstrated resilience to it."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.SECURITY_CONTROL_FAILURE,
            summary="A control that was supposed to hold did not.",
            distinguishing_question=(
                "Did a system accept, serve, or expose something it should have refused? Note "
                "that a control failing is not the same as an attacker acting, and this fault "
                "injects the first so the second can be tested."
            ),
            recovery_guidance=(
                "Restore the control and then check what it let through while it was failing. "
                "Certificate, TLS, and injection faults are the ones most often reported as "
                "'availability' when the availability of a control is the actual finding."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.RESOURCE_EXHAUSTION,
            summary="A bounded resource ran out.",
            distinguishing_question=(
                "Did a specific resource — memory, descriptors, connections, pids, inodes, quota "
                "— hit a limit? Exhaustion is the mode that masquerades as six others: ENOSPC "
                "looks like a disk fault, EMFILE looks like a networking fault, and a pids "
                "limit looks like a scheduling fault."
            ),
            recovery_guidance=(
                "Release the resource and record the limit that was reached, because the limit is "
                "the finding. Raising a limit to stop the symptom converts an exhaustion fault "
                "into a capacity decision that should be made deliberately."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.CLOCK,
            summary="Time itself was wrong for a component.",
            distinguishing_question=(
                "Was a timestamp wrong rather than a computation? Skew and a stopped clock "
                "produce failures far from the clock — expired tokens, refused certificates, "
                "out-of-order logs — which is why they are catalogued separately."
            ),
            recovery_guidance=(
                "Resynchronise from a reference source. Do not step a running system's clock "
                "backwards without checking the application's tolerance for it: a backwards step "
                "can invalidate more than the skew did."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.STORAGE,
            summary="A storage device or filesystem misbehaved.",
            distinguishing_question=(
                "Did the failure come from the storage substrate — mount, quota, capacity, IO, "
                "or device state — rather than from the process using it? Capacity exhaustion is "
                "resource_exhaustion; this mode is the substrate misbehaving."
            ),
            recovery_guidance=(
                "Restore the substrate, then verify what was written during the fault window. A "
                "read-only mount or a failed volume leaves durability unproven no matter how "
                "healthy the pod looks afterwards."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.NETWORK,
            summary="The network path between components changed behaviour.",
            distinguishing_question=(
                "Did the path itself misbehave — loss, reordering, duplication, corruption, MTU, "
                "congestion? Latency as an *observed symptom* is a separate mode; this one is "
                "about the path as the thing that changed."
            ),
            recovery_guidance=(
                "Restore the path, then check for the effects the path's misbehaviour causes "
                "downstream: duplicated operations need idempotency, reordering needs "
                "sequence-tolerant consumers, and corruption needs an audit of what was stored."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.PROCESS,
            summary="A process's execution lifecycle changed.",
            distinguishing_question=(
                "Did the process stop, die, hang, or restart? A process that is running and not "
                "serving is still a process fault until the serving evidence says otherwise."
            ),
            recovery_guidance=(
                "Recover the process and then establish what state it lost in the restart — "
                "in-memory queues and unsaved work are the usual answer, and it is the reason a "
                "process fault is often also a durability finding."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.RUNTIME,
            summary="The application's own runtime misbehaved.",
            distinguishing_question=(
                "Did the defect live in the application's logic or execution environment rather "
                "than in a resource, a device, or a dependency? Deadlocks, unhandled exceptions, "
                "and parser abuse belong here."
            ),
            recovery_guidance=(
                "Recover by restarting the runtime, and treat every occurrence as an application "
                "defect to fix. Restarts are the mitigation, not the remediation, and a report "
                "that only records the restart has recorded the mitigation."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.INFRASTRUCTURE,
            summary="A platform or cluster component misbehaved.",
            distinguishing_question=(
                "Was the defect in the substrate the workload runs on — node, scheduler, "
                "controller, networking agent — rather than in the workload or its dependencies? "
                "Node and controller faults affect every pod on that substrate at once."
            ),
            recovery_guidance=(
                "Recover the substrate and check the blast radius across the whole cluster before "
                "declaring the incident over: a node fault that has moved to another node is an "
                "ongoing incident, not a resolved one."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.CLOUD,
            summary="A managed or cloud-provider surface misbehaved.",
            distinguishing_question=(
                "Did the failure come from a provider-managed surface — registry, managed "
                "control plane, or a provider quota — where the fix is on the provider side of "
                "the boundary?"
            ),
            recovery_guidance=(
                "Fall back to the offline path (an imported bundle, a pinned artifact) and record "
                "the provider-side dependency, because the customer cannot fix it and the "
                "remediation belongs in the deployment model rather than the application."
            ),
        ),
        FailureModeProfile(
            mode=FailureMode.HUMAN_OPERATOR,
            summary="The system is waiting on a person to act.",
            distinguishing_question=(
                "Did nothing fail by itself, and is a deliberate human action required to make "
                "progress? Cordons, rollouts, and disruption budgets look like failures in a "
                "dashboard and are decisions in a runbook."
            ),
            recovery_guidance=(
                "Name the person and the decision, and time-box the wait. A disruption budget that "
                "blocks all voluntary work is a designed deadlock, and the recovery is a budget "
                "change made deliberately, not a retry."
            ),
        ),
    )
}


def validate_failure_mode(profile: FailureModeProfile) -> str:
    """Why ``profile`` is inadmissible as a taxonomy member, or ``""``.

    Rule ``failure_mode.recovery_guidance`` is the load-bearing one: a mode with
    no recovery statement is refused, because the whole point of naming a failure
    mode separately from a fault is that somebody can act on the name.
    """
    if not profile.summary.strip():
        return (
            f"failure_mode.summary: {profile.mode.value!r} has no summary; a taxonomy entry "
            "nobody can read is a label, not a failure mode"
        )
    if not profile.distinguishing_question.strip():
        return (
            f"failure_mode.distinguishing_question: {profile.mode.value!r} does not say how it "
            "is told apart from its neighbours, which is the only reason to name it separately"
        )
    if not profile.recovery_guidance.strip():
        return (
            f"failure_mode.recovery_guidance: {profile.mode.value!r} has no recovery statement, "
            "so a report that classifies a failure this way cannot say what anybody should do "
            "about it; a mode with no recovery is a category, not a failure mode"
        )
    return ""


def validate_failure_modes() -> str:
    """Why the taxonomy table itself is inadmissible, or ``""``.

    Three checks, all of which are about the table rather than its members: every
    member has a profile (so no mode is unnameable), no profile describes a mode
    outside the enum (so the vocabulary cannot drift), and every profile passes
    :func:`validate_failure_mode`.
    """
    missing = [mode.value for mode in FAILURE_MODES if mode not in FAILURE_MODE_PROFILES]
    if missing:
        return f"failure_mode.profile_missing: taxonomy member(s) {missing} have no profile"
    extra = sorted(
        profile.mode.value
        for profile in FAILURE_MODE_PROFILES.values()
        if profile.mode not in FAILURE_MODES
    )
    if extra:
        return f"failure_mode.profile_unknown: profile(s) {extra} describe no taxonomy member"
    for profile in FAILURE_MODE_PROFILES.values():
        reason = validate_failure_mode(profile)
        if reason:
            return reason
    return ""


# --- per-fault mapping --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FaultFailureMapping:
    """One catalog fault, answered in the six questions a report asks of it.

    ``failure_modes`` is a set because a fault genuinely has more than one mode
    often enough that forcing a single answer would push the author to pick the
    least interesting one. ``primary`` is the answer to "if you have to lead with
    one", and it must be a member of the set.

    ``refusal_note`` is non-empty exactly for ``catalog_only`` faults, and for
    those the expected symptom *is* the plan-time refusal: nothing is injected, so
    a report must not describe an outage that cannot have happened.
    """

    fault_id: str
    failure_modes: frozenset[FailureMode]
    primary: FailureMode
    mechanism: str
    expected_symptom: str
    risk: RiskLevel
    recovery: str
    verification_method: VerificationMethod
    verification: str
    refusal_note: str = ""

    @property
    def also(self) -> frozenset[FailureMode]:
        """The non-primary modes this fault also presents as."""
        return self.failure_modes - {self.primary}

    @property
    def is_refused(self) -> bool:
        """True when this fault cannot be executed, so nothing was injected."""
        return bool(self.refusal_note)


def validate_mapping(mapping: FaultFailureMapping) -> str:
    """Why ``mapping`` is inadmissible on its own terms, or ``""``.

    Rule ids: ``failure_mode.empty`` (no mode at all), ``failure_mode.primary``
    (the primary mode is not one of the mapped modes), ``failure_mode.mechanism``,
    ``failure_mode.expected_symptom``, ``failure_mode.recovery``, and
    ``failure_mode.verification`` (one of the six questions answered with
    nothing). The recovery and verification refusals are the ones the plan names
    directly: a mode you cannot recover and a mode you cannot verify are not
    yet a report.
    """
    if not mapping.failure_modes:
        return (
            f"failure_mode.empty: {mapping.fault_id!r} maps to no failure mode, so a report "
            "cannot classify it at all"
        )
    if mapping.primary not in mapping.failure_modes:
        return (
            f"failure_mode.primary: {mapping.fault_id!r} leads with "
            f"{mapping.primary.value!r} but does not map to it, so the answer and the set "
            "disagree"
        )
    for rule, value, question in (
        ("failure_mode.mechanism", mapping.mechanism, "why the fault behaves this way"),
        ("failure_mode.expected_symptom", mapping.expected_symptom, "what an observer should see"),
        ("failure_mode.recovery", mapping.recovery, "how the failure is undone"),
        ("failure_mode.verification", mapping.verification, "how the undo is known"),
    ):
        if not value.strip():
            return (
                f"{rule}: {mapping.fault_id!r} says nothing about {question}; a mapping that "
                "leaves a question unanswered is a reporting hole with a fault id attached"
            )
    return ""


def validate_mappings(definitions: Iterable[FaultDefinition] = CATALOG) -> None:
    """Raise unless every supplied definition has a valid, consistent mapping.

    ``definitions`` is the catalog by default, and is a parameter so a test can
    hand in a *narrowed* catalog and prove that a missing mapping fails rather
    than that the current table happens to be complete. Every check raises
    :class:`InvariantViolationError` with a rule id, because a partial report of
    what is missing is exactly the failure this function exists to prevent.

    Checks, in order: every definition is mapped; every mapping names a fault in
    ``definitions``; every mapping is internally valid; the mapping's risk and
    verification method equal the catalog's; and a ``catalog_only`` entry carries
    a refusal note while an executable one does not.
    """
    definitions_by_id = {definition.id: definition for definition in definitions}
    missing = sorted(set(definitions_by_id) - set(_MAPPINGS_BY_FAULT))
    if missing:
        raise InvariantViolationError(
            "failure_mode.unmapped",
            f"{len(missing)} catalog fault(s) map to no failure mode: {missing}. An unmapped "
            "fault can be injected and can be hit in production, and no report will have a "
            "story for it; add a mapping to failure_modes.py or remove the fault from the "
            "catalog",
        )
    unknown = sorted(set(_MAPPINGS_BY_FAULT) - set(definitions_by_id))
    if unknown:
        raise InvariantViolationError(
            "failure_mode.orphan",
            f"{len(unknown)} mapping(s) name a fault that is not in the supplied catalog: "
            f"{unknown}",
        )
    for fault_id in sorted(_MAPPINGS_BY_FAULT):
        mapping = _MAPPINGS_BY_FAULT[fault_id]
        definition = definitions_by_id[fault_id]
        reason = validate_mapping(mapping)
        if reason:
            raise InvariantViolationError(reason.split(":", 1)[0], reason.split(": ", 1)[1])
        if mapping.risk is not definition.risk:
            raise InvariantViolationError(
                "failure_mode.risk_mismatch",
                f"{fault_id!r}: the mapping reports risk {mapping.risk.value!r} but the "
                f"catalog declares {definition.risk.value!r}. A reporting library that "
                "restates a fault's risk as something lower is a reclassification, and this "
                "module refuses to make one",
            )
        if mapping.verification_method is not definition.verification_method:
            raise InvariantViolationError(
                "failure_mode.verification_mismatch",
                f"{fault_id!r}: the mapping verifies with {mapping.verification_method.value!r} "
                f"but the catalog declares {definition.verification_method!r}. The "
                "library may explain what a probe should show; it may not substitute a "
                "different instrument",
            )
        catalog_only = definition.catalog_only
        if catalog_only and not mapping.refusal_note:
            raise InvariantViolationError(
                "failure_mode.refusal_note_missing",
                f"{fault_id!r} is catalog-only and refuses at plan time, so its expected "
                "symptom is the refusal, but the mapping carries no refusal note and would "
                "describe an outage that cannot happen",
            )
        if not catalog_only and mapping.refusal_note:
            raise InvariantViolationError(
                "failure_mode.refusal_note_unexpected",
                f"{fault_id!r} is executable and cannot carry a refusal note; an executable "
                "fault described as refused is a report that hides a real capability",
            )


def unmapped_fault_ids(definitions: Sequence[FaultDefinition] = CATALOG) -> tuple[str, ...]:
    """Fault ids in ``definitions`` with no mapping, sorted.

    Returns rather than raises, so a report or a doctor check can *show* the
    holes. :func:`validate_mappings` is the version that refuses.
    """
    return tuple(sorted({definition.id for definition in definitions} - set(_MAPPINGS_BY_FAULT)))


def mapping_for(fault_id: str) -> FaultFailureMapping:
    """The mapping for ``fault_id``; an unknown id is a planning error.

    Mirrors :func:`mayhem.domain.catalog.definition_for` so that asking about a
    fault that does not exist fails the same way from both sides.
    """
    try:
        return _MAPPINGS_BY_FAULT[fault_id]
    except KeyError:
        known = ", ".join(sorted(_MAPPINGS_BY_FAULT))
        msg = f"fault {fault_id!r} has no failure-mode mapping (known: {known})"
        raise LookupError(msg) from None


def failure_modes_for(fault_id: str) -> frozenset[FailureMode]:
    """Every failure mode ``fault_id`` presents as, primary included."""
    return mapping_for(fault_id).failure_modes


def mapped_fault_ids() -> frozenset[str]:
    """Every fault id that has a mapping."""
    return frozenset(_MAPPINGS_BY_FAULT)


def faults_for_mode(mode: FailureMode) -> tuple[str, ...]:
    """Every mapped fault that presents as ``mode``, sorted."""
    if mode not in FAILURE_MODE_PROFILES:
        known = ", ".join(m.value for m in FAILURE_MODES)
        msg = f"failure mode {mode!r} is not in the taxonomy (known: {known})"
        raise LookupError(msg) from None
    return tuple(
        sorted(
            fault_id
            for fault_id, mapping in _MAPPINGS_BY_FAULT.items()
            if mode in mapping.failure_modes
        )
    )


@dataclass(frozen=True, slots=True)
class FailureModeCoverage:
    """How much of the catalog sits behind each mode, and which modes are empty.

    ``empty`` is the interesting half. A taxonomy member with no fault behind it
    is a mode the reports can name but never populate, which means any sentence
    about the product's coverage of that mode is unearned.

    ``by_mode`` is exposed as a read-only :class:`~types.MappingProxyType`, not
    a plain ``dict``. ``frozen=True`` stops attribute rebinding but does not
    reach inside the container, so a mutable dict here would let a caller edit
    the coverage counts in place — raising ``verified`` to ``complete`` on an
    object that is supposed to be a *measurement* rather than a claim. The
    proxy is built once in ``__post_init__`` and the dict is never handed out,
    so the frozen dataclass is frozen all the way down.
    """

    by_mode: Mapping[FailureMode, int] = field(default_factory=dict)
    mapped: int = 0
    total: int = 0

    def __post_init__(self) -> None:
        # ``object.__setattr__`` because ``frozen=True`` forbids the ordinary
        # assignment, and this runs inside ``__init__`` where the proxy has to
        # be installed before anything can read the field.
        object.__setattr__(self, "by_mode", MappingProxyType(dict(self.by_mode)))

    @property
    def empty(self) -> tuple[FailureMode, ...]:
        """Taxonomy members with no fault behind them, in taxonomy order."""
        return tuple(mode for mode in FAILURE_MODES if not self.by_mode.get(mode))

    @property
    def complete(self) -> bool:
        """True when every catalog fault is mapped and no mode is empty."""
        return self.mapped == self.total and not self.empty

    def count(self, mode: FailureMode) -> int:
        return self.by_mode.get(mode, 0)

    def share_pct(self, mode: FailureMode) -> float:
        """Share of the catalog presenting as ``mode``, to three decimals."""
        if not self.total:
            return 0.0
        return round(100.0 * self.count(mode) / self.total, 3)


def taxonomy_coverage(definitions: Sequence[FaultDefinition] = CATALOG) -> FailureModeCoverage:
    """Count the catalog against the taxonomy.

    A fault mapping to three modes counts once per mode, so the counts sum to more
    than :attr:`FailureModeCoverage.total` — that is what "presents as" means, and
    the shares are therefore shares of presentations rather than of faults.
    """
    counts: dict[FailureMode, int] = dict.fromkeys(FAILURE_MODES, 0)
    for fault_id in mapped_fault_ids():
        for mode in _MAPPINGS_BY_FAULT[fault_id].failure_modes:
            counts[mode] = counts.get(mode, 0) + 1
    return FailureModeCoverage(
        by_mode=counts, mapped=len(mapped_fault_ids()), total=len(definitions)
    )


# --- compliance templates ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplianceControl:
    """A template for one control a customer's compliance programme asks about.

    A template here is a *request for evidence* and a list of the customer's own
    remaining obligations. It is not an attestation, and this type is built so it
    cannot become one:

    * :attr:`asserts_compliance` may not be ``True``.
      :func:`require_non_asserting_template` refuses it by name, and the test
      suite's negative control sets it and asserts the refusal.
    * :attr:`customer_obligations` must be non-empty and must not look like an
      empty formality, so a template cannot be written that pushes the whole
      burden onto "the customer must do what they must do".
    * :attr:`required_evidence` names *kinds* of evidence and says so. A control
      whose evidence list is a claim that the evidence exists is the exact failure
      the plan warns about, so the list is what a pack would have to produce.
    """

    control_id: str
    framework: str
    title: str
    covered_failure_modes: frozenset[FailureMode]
    required_evidence: tuple[str, ...]
    customer_obligations: tuple[str, ...]
    #: Always ``False`` in a shipped template. It exists so the prohibition is
    #: reachable and testable rather than merely documented.
    asserts_compliance: bool = False

    @property
    def evidence_complete(self) -> bool:
        """True when every kind of evidence this control names has been supplied.

        A statement about the *supplied* evidence, never about conformance: this
        is the strongest thing the type can say, and saying it is deliberate.
        """
        return bool(self.required_evidence)

    def statement(self) -> str:
        """The only sentence this type can produce about conformance.

        Structurally incapable of asserting compliance: it names what the
        template asks for, what the customer still owes, and it says plainly that
        the template is not a finding. Every branch of this method ends in the
        same disclosure, so no field value can change the answer.
        """
        modes = ", ".join(sorted(mode.value for mode in self.covered_failure_modes)) or "none"
        obligations = "; ".join(self.customer_obligations) or "none recorded"
        return (
            f"{self.framework} {self.control_id} ({self.title}) is a template: it maps the "
            f"failure modes {modes} to the evidence kinds it would need "
            f"({', '.join(self.required_evidence) or 'none recorded'}) and records the "
            f"customer's remaining obligations ({obligations}). This template is not a "
            "finding, an assessment, or an attestation of conformance; the customer must "
            "perform their own assessment, and mayhem's evidence informs it without "
            "concluding it"
        )


def require_non_asserting_template(control: ComplianceControl) -> None:
    """Raise unless ``control`` makes no compliance claim.

    Rule ``compliance.template_must_not_assert``. The plan's honesty rule is
    "do not claim compliance solely because a template exists", so the one thing a
    template is never allowed to do is claim conformance — and this is where that
    is enforced rather than merely written down.
    """
    if control.asserts_compliance:
        raise InvariantViolationError(
            "compliance.template_must_not_assert",
            f"{control.framework} {control.control_id!r} sets asserts_compliance=True. A "
            "template's existence is not evidence of conformance: the template describes what "
            "evidence a customer would need and what they must still do, and asserting "
            "compliance from it would be a claim about someone else's control programme",
        )
    if not control.required_evidence:
        raise InvariantViolationError(
            "compliance.template_must_request_evidence",
            f"{control.framework} {control.control_id!r} names no evidence. A template that "
            "asks for nothing cannot support a finding either, and shipping one would "
            "imply a mapping exists where there is none",
        )
    if not control.customer_obligations:
        raise InvariantViolationError(
            "compliance.template_must_record_obligations",
            f"{control.framework} {control.control_id!r} records no customer obligations. A "
            "control is satisfied by the customer's own programme, not by a document in this "
            "repository, and a template that implies otherwise is the overclaim the plan "
            "warns about",
        )
    if not control.covered_failure_modes:
        raise InvariantViolationError(
            "compliance.template_must_cover_failure_modes",
            f"{control.framework} {control.control_id!r} covers no failure mode, so it maps to "
            "nothing in the taxonomy and is a document with no subject",
        )


def compliance_statement(control: ComplianceControl) -> str:
    """Validate ``control`` and return its non-asserting statement.

    The convenience pairing: there is no way to obtain the sentence about a
    control without having passed the check that the control does not assert
    compliance.
    """
    require_non_asserting_template(control)
    return control.statement()


# Two illustrative templates, deliberately modest. They exist to show the shape
# and to give the tests something real to assert against; they are not a
# compliance programme, and neither their presence nor their absence says
# anything about mayhem's or any customer's conformance to anything.
COMPLIANCE_TEMPLATES: Final[tuple[ComplianceControl, ...]] = (
    ComplianceControl(
        control_id="A.5.1",
        framework="illustrative-control-set",
        title="Resilience evidence is produced and retained for critical services",
        covered_failure_modes=frozenset(
            {FailureMode.AVAILABILITY, FailureMode.DURABILITY, FailureMode.CAPACITY}
        ),
        required_evidence=(
            "sealed evidence bundle digest for each run"
            "the failure-mode taxonomy entry each run exercised"
            "the execution-mode marker for each run",
        ),
        customer_obligations=(
            "decide which of their services are in scope for this control"
            "run the evidence collection themselves; mayhem produces the evidence, it does "
            "not assess the control"
            "assess the evidence against their own criteria and accept or reject it",
        ),
    ),
    ComplianceControl(
        control_id="A.5.2",
        framework="illustrative-control-set",
        title="Third-party dependency behaviour is exercised and observed",
        covered_failure_modes=frozenset(
            {FailureMode.DEPENDENCY, FailureMode.PARTITION, FailureMode.LATENCY}
        ),
        required_evidence=(
            "sealed evidence bundle digest for each dependency run"
            "the dependency and failure mode each run exercised"
            "the verification probe that confirmed recovery",
        ),
        customer_obligations=(
            "confirm with each provider which failure behaviours they permit mayhem to inject"
            "decide the recovery objective each dependency must meet"
            "accept or reject the evidence against their own criteria",
        ),
    ),
)


# --- the per-fault table --------------------------------------------------------


def _m(
    fault_id: str,
    primary: FailureMode,
    *,
    also: tuple[FailureMode, ...],
    mechanism: str,
    symptom: str,
    risk: RiskLevel,
    method: VerificationMethod,
    recovery: str,
    verification: str,
    refusal: str = "",
) -> FaultFailureMapping:
    """Build one mapping entry. Thin, so the table below is the readable part.

    ``risk`` and ``method`` are stated by the author rather than read from the
    catalog, on purpose: :func:`validate_mappings` cross-checks the two, so the
    cross-check is a real pin against a library that quietly restates a fault as
    less risky or verifies it with a different instrument. Reading them from the
    catalog would make the check vacuous.
    """
    return FaultFailureMapping(
        fault_id=fault_id,
        failure_modes=frozenset({primary, *also}),
        primary=primary,
        mechanism=mechanism,
        expected_symptom=symptom,
        risk=risk,
        recovery=recovery,
        verification_method=method,
        verification=verification,
        refusal_note=refusal,
    )


_REFUSED_NOTHING_INJECTED = (
    "the catalog entry refuses at plan time in this release, so nothing is injected and no "
    "system is perturbed"
)

#: The per-fault mapping table, one entry per catalog fault.
#:
#: Ordered as :data:`mayhem.domain.catalog.CATALOG` is, so a reader comparing the
#: two files side by side finds the same fault in the same place. Each entry
#: answers the six questions the plan names: failure mode (primary plus any
#: others the fault genuinely presents as), mechanism, expected symptom, risk,
#: recovery, and verification.
_MAPPINGS: Final[tuple[FaultFailureMapping, ...]] = (
    # -- process lifecycle -------------------------------------------------------
    _m(
        "proc.pause",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="SIGSTOP suspends the process where it stands: it is alive and holds its "
        "sockets, but stops making progress and stops meeting its own deadlines",
        symptom="the process stays resident and its ports stay open while nothing answers them; an "
        "orchestrator checking liveness by pid still reports it healthy",
        risk=RiskLevel.LOW,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="SIGCONT resumes the process in place, so all in-process state survives — this is "
        "the cheapest fault in the catalog to undo and the easiest to miss in monitoring",
        verification="the pid's process state leaves 'T' (stopped) and the service answers again",
    ),
    _m(
        "process.stop",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a stop signal asks the process to terminate and the runtime tears it down, "
        "running whatever shutdown hooks the application registered",
        symptom="the process leaves the process table, its endpoint disappears from discovery, and "
        "in-flight requests are dropped rather than completed",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="the supervisor (or an operator) starts the process again; nothing in-process "
        "survives, and whether the service comes back depends entirely on the supervisor",
        verification="the original pid is gone and the service answers on a new pid",
    ),
    _m(
        "process.kill",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="SIGKILL cannot be caught, blocked, or handled, so the kernel removes the "
        "process immediately without running a single shutdown path",
        symptom="an abrupt disappearance: no shutdown hooks run, sockets are reset, buffered work "
        "is lost, and anything the process was mid-way through writing is truncated",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="restart, plus whatever the application needed to rebuild in memory; work that "
        "was only in the process's memory is not recoverable by anyone, including mayhem",
        verification="the pid is absent from the process table and the replacement has a new pid "
        "and a new start time",
    ),
    _m(
        "process.crash_loop",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY, FailureMode.CAPACITY),
        mechanism="the process is started, exits non-zero, and is restarted repeatedly on a fixed "
        "interval rather than being repaired",
        symptom="the service flaps between up and down: requests succeed in bursts and fail in "
        "between, and the success rate becomes a function of restart timing rather than of "
        "load",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="fix the exit cause. Restarting faster only multiplies the flap rate and burns "
        "the window in which the service happens to be up",
        verification="the restart count climbs while the service reports up, and the success ratio "
        "falls in proportion to the time spent down",
    ),
    _m(
        "process.startup_delay",
        FailureMode.AVAILABILITY,
        also=(FailureMode.RUNTIME,),
        mechanism="startup gating holds the process in a not-ready state while it waits on an "
        "application-aware readiness hook that mayhem has no way to drive generically",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the readiness-hook gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.PROCESS_EXIT,
        recovery="none from this entry — it is refused. process.crash_loop exercises lifecycle "
        "recovery through a path mayhem can actually drive",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the readiness-hook reason and never reaches a target",
        refusal="catalog-only: startup gating requires an application-aware readiness hook, so the "
        "entry is refused at plan time rather than injected",
    ),
    # -- cpu and memory ----------------------------------------------------------
    _m(
        "cpu.saturate",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.LATENCY, FailureMode.CAPACITY),
        mechanism="the target is given a larger CPU budget than the cores it needs, so every "
        "thread competes for a share of a fixed number of processors",
        symptom="request latency climbs and the queue behind the target grows; throughput usually "
        "falls as well, because saturated threads spend their time waiting to be scheduled",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="remove the imposed load; the target returns to its baseline share as soon as the "
        "budget is restored, with no in-process state involved",
        verification="cpu.utilization sits at the injected percentage during the window and "
        "returns to baseline on undo",
    ),
    _m(
        "cpu.throttle",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.LATENCY,),
        mechanism="a cgroup CPU quota caps the target below a single core, so it is throttled even "
        "on a host with idle processors — the reserve-share case, not the contention "
        "case",
        symptom="latency rises while host-wide CPU stays low, which is the signature that "
        "separates a quota from contention and is why this is not a duplicate of "
        "cpu.saturate",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="restore the cgroup quota; the kernel resumes running the target's threads at "
        "full width immediately",
        verification="the cgroup's throttling counters climb during the window and stop the moment "
        "the quota is restored",
    ),
    _m(
        "cpu.burst",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.LATENCY,),
        mechanism="short CPU bursts are imposed above the target's steady share rather than a "
        "sustained saturation, so the average looks unremarkable",
        symptom="tail latency spikes while the mean CPU looks normal: the p50 says nothing and the "
        "p99 says everything, which is why this fault is a latency-sensitivity test",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="remove the bursts; because the duty cycle is bounded there is no accumulated "
        "state to unwind",
        verification="CPU samples show spikes at the injected duty cycle and the average returns "
        "to baseline",
    ),
    _m(
        "mem.exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY, FailureMode.AVAILABILITY),
        mechanism="anonymous memory is committed to the target until it approaches the cgroup or "
        "host limit; the reclaim mode returns blocks continuously instead of growing the "
        "footprint further",
        symptom="allocation slows, then either the OOM killer terminates the process or the "
        "runtime's own allocator fails requests — the fault can end in an availability "
        "event rather than a slow one",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="free the committed blocks. A process that was OOM-killed is restarted, so "
        "recovery includes whatever that restart costs",
        verification="memory.used rises to the injected percentage and the target either survives "
        "the window or is recorded as OOM-killed; either way it returns to baseline "
        "after undo",
    ),
    _m(
        "mem.leak",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="the target allocates at a fixed rate and retains every block, so its footprint "
        "grows monotonically for as long as the window lasts",
        symptom="memory climbs steadily with no plateau, and the climb does not reverse when load "
        "drops: the target eventually fails to allocate rather than recovering",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="restart the process. Nothing in the application releases what it has leaked, so "
        "this fault has no in-place undo and the footprint is still high before the "
        "restart",
        verification="the memory slope matches the injected rate and the footprint is still "
        "elevated immediately before undo, which is what separates a leak from a "
        "spike",
    ),
    _m(
        "mem.freeze",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="a memory footprint is committed and then held for a bounded window instead of "
        "being grown, so the OOM risk is constant rather than increasing",
        symptom="the target sits at a fixed elevated footprint; the observable difference from "
        "mem.exhaust is that the pressure does not worsen with time, which is the point of "
        "having both entries",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="release the frozen blocks at the end of the hold window; no restart is involved",
        verification="memory sits at the injected size for exactly the hold window and returns to "
        "baseline immediately afterwards",
    ),
    _m(
        "mem.swap_pressure",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.LATENCY,),
        mechanism="resident pages are pushed out to swap, so memory is technically available and "
        "practically slow",
        symptom="latency rises while memory metrics look healthy — the fault that makes a memory "
        "problem present as a disk problem, and the reason it is catalogued separately",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="let the pages return to memory. Sustained swap usually means the working set "
        "does not fit, so removing the pressure without fixing that just restores the "
        "fault's preconditions",
        verification="swap-in and swap-out counters rise during the window and fall back after "
        "undo, and the latency returns with them",
    ),
    # -- storage -----------------------------------------------------------------
    _m(
        "fs.fill",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.STORAGE, FailureMode.DURABILITY),
        mechanism="marker files consume free space on the chosen filesystem until writes fail; the "
        "path is a parameter, so /tmp, /var/log, and any other writable path are equally "
        "valid targets",
        symptom="write and log operations fail with ENOSPC while reads keep working, so the "
        "failure presents as application-specific rather than as a full disk",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="remove the marker files; the filesystem returns to its prior free space. "
        "Whatever the application failed to write during the window is not written "
        "retroactively",
        verification="free space drops to the injected percentage and a write fails, then both "
        "return to normal after undo",
    ),
    _m(
        "fs.inode_exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.STORAGE,),
        mechanism="zero-byte files consume free inodes, so blocks remain available while the "
        "filesystem can no longer create a new file",
        symptom="file creation fails with ENOSPC on a filesystem that still reports free space — "
        "the same error code as fs.fill on a different resource, which is why the two are "
        "separate entries and separate mappings",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="delete the marker files, returning the inodes; the filesystem is fully restored "
        "because no data was written",
        verification="free inodes reach zero while free blocks remain, and file creation fails",
    ),
    _m(
        "fs.io_stress",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.STORAGE, FailureMode.LATENCY),
        mechanism="sustained reads and/or writes are issued against the chosen path, consuming the "
        "device's queue depth",
        symptom="everything waiting on that storage slows, including unrelated paths on the same "
        "device — the scope of the slowdown is the evidence that the device, not the path, "
        "is the constrained thing",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="stop the workers; queued IO drains as throughput returns to normal",
        verification="read and write latency rise for the duration of the window and return to "
        "baseline after undo",
    ),
    _m(
        "fs.read_only",
        FailureMode.STORAGE,
        also=(FailureMode.AVAILABILITY, FailureMode.DURABILITY),
        mechanism="the mount is remounted read-only, so writes fail at the filesystem layer before "
        "the application ever sees them",
        symptom="read paths keep working while every write path fails; on restart the journal may "
        "refuse to mount at all, so a read-only mount can outlive the process that hit it",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="remount read-write. Writes the application buffered while read-only are not "
        "recovered by mayhem, and the durability of anything written in that window is "
        "unproven until it has been read back",
        verification="a write probe fails and a read probe succeeds while the mount options show "
        "read-only, and the write probe succeeds again after undo",
    ),
    _m(
        "fs.quota",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.STORAGE,),
        mechanism="a filesystem quota is imposed below what the workload normally uses, so the "
        "device has space the workload may not spend",
        symptom="writes fail at the quota boundary with a quota error while the device reports "
        "free space — an error that is easy to misread as a permissions problem",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="raise or remove the quota; files already written remain subject to it and are "
        "not affected by the change",
        verification="a write past the quota fails with a quota-specific error and succeeds after "
        "undo",
    ),
    _m(
        "fs.write_delay",
        FailureMode.LATENCY,
        also=(FailureMode.STORAGE,),
        mechanism="writes to the target path are held before completing rather than being rejected "
        "or lost",
        symptom="write-heavy paths slow down, and a synchronous commit path turns that delay "
        "straight into a request-latency regression at the caller",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="remove the hold; queued writes drain, so the recovery is complete only once the "
        "queue has emptied",
        verification="write duration rises during the window and returns to baseline, and the "
        "queue depth falls back to normal",
    ),
    _m(
        "fs.corrupt",
        FailureMode.CORRECTNESS,
        also=(FailureMode.DURABILITY, FailureMode.STORAGE),
        mechanism="file content is altered in place so the bytes no longer match what was written, "
        "while the file's metadata still claims it is intact",
        symptom="checksums and parsers fail, and a database may refuse to start on a corrupted "
        "page. The failure surfaces far from the write that caused it, usually at the next "
        "read or the next restart",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="restore from a backup or a snapshot. Mayhem does not reverse corrupted bytes, "
        "and 'the fault is gone' says nothing about whether the data is recoverable",
        verification="a checksum probe fails on the target file during the window and passes after "
        "a restore, which is the only form of verification that means anything here",
    ),
    _m(
        "fs.read_error",
        FailureMode.STORAGE,
        also=(FailureMode.CORRECTNESS,),
        mechanism="reads would return errors while the file itself stayed intact — the substrate "
        "failing to deliver rather than the data being wrong",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the read-error gap",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="none from this entry — it is refused. fs.io_stress and fs.corrupt are the "
        "executable paths to storage misbehaviour in this release",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the read-error reason and never reaches a target",
        refusal="catalog-only: read-error injection has no executable path, so the entry is "
        "refused at plan time rather than injected",
    ),
    _m(
        "fs.permission_failure",
        FailureMode.SECURITY_CONTROL_FAILURE,
        also=(FailureMode.STORAGE,),
        mechanism="file ownership or mode is changed so the service account is denied the access "
        "it had — a control failing rather than an attacker acting",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the permission-change gap",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.STORAGE_ACCESS,
        recovery="none from this entry — it is refused. Restore ownership and mode out of band, "
        "and verify as the service account rather than as root",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the permission-change reason and never reaches a target",
        refusal="catalog-only: permission mutation is not implemented, so the entry is refused at "
        "plan time rather than injected",
    ),
    # -- network path ------------------------------------------------------------
    _m(
        "net.latency",
        FailureMode.LATENCY,
        also=(FailureMode.NETWORK,),
        mechanism="outbound packets on the target's path are held before being forwarded, adding a "
        "delay to every traversal rather than to one connection",
        symptom="requests through the path slow by roughly the injected delay, and throughput "
        "falls as queues fill — so a latency fault eventually becomes a capacity fault",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="remove the delay; in-flight requests complete, and the queue above the path "
        "drains afterwards",
        verification="round-trip time rises by approximately the injected seconds and returns to "
        "baseline on undo",
    ),
    _m(
        "net.packet_loss",
        FailureMode.AVAILABILITY,
        also=(FailureMode.NETWORK, FailureMode.LATENCY),
        mechanism="a fraction of packets on the path is dropped rather than delivered",
        symptom="requests fail at a rate roughly matching the loss, usually as timeouts or resets; "
        "the tail latency rises faster than the median, which is the usual tell",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="stop dropping. Retries succeed once the path is clean, so recovery is immediate "
        "for idempotent work and not immediate for anything else",
        verification="probe success rate falls to roughly one minus the loss and recovers on undo",
    ),
    _m(
        "net.bandwidth",
        FailureMode.CAPACITY,
        also=(FailureMode.NETWORK, FailureMode.LATENCY),
        mechanism="the path is shaped down to a bandwidth ceiling below what the traffic needs",
        symptom="throughput plateaus at the ceiling and latency rises as queues fill, so until the "
        "ceiling is found this fault reads as a latency fault",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="restore the shaping ceiling; the queue drains at the new rate rather than "
        "instantly",
        verification="bytes per second plateau at the injected ceiling and return to baseline",
    ),
    _m(
        "net.load",
        FailureMode.CAPACITY,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="the interface is loaded with traffic until the path itself is saturated",
        symptom="throughput stops rising while latency and drops climb together — congestion "
        "collapse, which is a different thing from being slow",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="remove the offered load; the queue drains and the path returns to its normal "
        "operating point",
        verification="interface utilisation sits at the injected load and drop counters rise with "
        "it, then both settle after undo",
    ),
    _m(
        "net.partition",
        FailureMode.PARTITION,
        also=(FailureMode.NETWORK, FailureMode.AVAILABILITY),
        mechanism="the target is cut off from its peers: traffic in both directions is dropped, so "
        "each side keeps running and neither can see the other",
        symptom="the target is unreachable from one side and may still answer locally, which is "
        "the split brain this fault exists to demonstrate — both halves report healthy",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.NETWORK_PATH,
        recovery="restore connectivity. Work performed independently on both sides during the "
        "partition has to be reconciled by the application; mayhem does not reconcile it",
        verification="reachability fails from the partitioned side and is restored after undo",
    ),
    _m(
        "net.connection_reset",
        FailureMode.AVAILABILITY,
        also=(FailureMode.NETWORK,),
        mechanism="connections are reset with RST rather than closed cleanly, so the peer learns "
        "of the failure immediately instead of on a timeout",
        symptom="in-flight requests fail immediately with a connection reset while new connections "
        "may still be accepted, so the fault looks intermittent from the client",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="stop resetting; clients reconnect, and the clients that gave up do not come back "
        "on their own",
        verification="a probe sees RST during the window and a clean close after undo",
    ),
    _m(
        "net.connection_refuse",
        FailureMode.AVAILABILITY,
        also=(FailureMode.NETWORK, FailureMode.DEPENDENCY),
        mechanism="connection attempts are rejected as though nothing were listening, with no "
        "handshake and no reset",
        symptom="every new connection is refused while existing ones may keep working, which is "
        "the classic half-open listener and the reason a capacity-based view can look "
        "healthy",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.NETWORK_PATH,
        recovery="stop refusing; the listener accepts again as soon as the fault is removed",
        verification="connect() is refused during the window and succeeds after undo",
    ),
    _m(
        "net.reorder",
        FailureMode.CORRECTNESS,
        also=(FailureMode.NETWORK, FailureMode.LATENCY),
        mechanism="packets are held and released out of order, so delivery order stops matching "
        "send order without anything being lost",
        symptom="tail latency spikes, and any request that depends on ordering — a "
        "sequence-sensitive protocol, a stream, a checksum chain — can fail even though no "
        "packet was dropped",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="stop reordering. A consumer that assumed ordering may need its own recovery, "
        "because the packets all arrived",
        verification="a sequence-sensitive exchange fails during the window and succeeds after "
        "undo",
    ),
    _m(
        "net.duplicate",
        FailureMode.CORRECTNESS,
        also=(FailureMode.NETWORK,),
        mechanism="packets are delivered more than once, so the peer observes the same message "
        "twice without any indication that it was repeated",
        symptom="a non-idempotent operation is applied twice: double charges, duplicate rows, or a "
        "state machine that advances two steps for one command",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="stop duplicating. The effects of duplicates already applied are not undone by "
        "mayhem, so recovery includes finding them",
        verification="an idempotency probe counts double deliveries during the window",
    ),
    _m(
        "net.congestion",
        FailureMode.CAPACITY,
        also=(FailureMode.NETWORK, FailureMode.LATENCY),
        mechanism="the path is driven into congestion so packets queue and are then dropped at the "
        "tail rather than at a bottleneck the sender controls",
        symptom="throughput plateaus, latency climbs, and drops appear — all three together, not "
        "any one alone, which is how a congestion fault is told from a slow one",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="remove the offered load; the queue drains and drops stop",
        verification="interface drop counters and latency rise together during the window and "
        "settle after undo",
    ),
    _m(
        "net.corrupt",
        FailureMode.CORRECTNESS,
        also=(FailureMode.NETWORK,),
        mechanism="payload bytes are altered in transit, so the receiver's checksum fails on data "
        "the sender believes it sent successfully",
        symptom="the receiver rejects the data (a CRC failure, a TLS alert, or an application "
        "checksum error) while the sender sees a successful send — so the fault is only "
        "visible on the far side of the path",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="stop corrupting. Anything already stored from a corrupted payload stays "
        "corrupted; mayhem does not repair it",
        verification="a checksum probe fails on the received data during the window and passes "
        "after undo",
    ),
    _m(
        "net.interface_down",
        FailureMode.AVAILABILITY,
        also=(FailureMode.NETWORK,),
        mechanism="the target interface is brought administratively down, so the host loses the "
        "network rather than degrading it",
        symptom="the host is unreachable from outside itself while local loopback traffic still "
        "works, which is the discriminator between an interface fault and a path fault",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.NETWORK_PATH,
        recovery="bring the interface up. Anything that timed out while it was down is gone, so "
        "recovery is a return to service rather than a resumption",
        verification="the interface state is down during the window and up after undo",
    ),
    _m(
        "net.mtu_mismatch",
        FailureMode.CORRECTNESS,
        also=(FailureMode.NETWORK, FailureMode.PARTITION),
        mechanism="the path MTU is smaller than the endpoints assume, so large packets are dropped "
        "in transit while small ones pass",
        symptom="small requests succeed and large ones hang — the 'works until you send something "
        "big' signature, which is routinely mistaken for an application bug",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.NETWORK_PATH,
        recovery="align the MTU on both ends; a partial fix leaves the large-packet case failing",
        verification="a small-packet probe succeeds while a large-packet probe times out, and both "
        "succeed after undo",
    ),
    _m(
        "net.tcp_half_open",
        FailureMode.PARTITION,
        also=(FailureMode.NETWORK, FailureMode.AVAILABILITY),
        mechanism="one direction of established TCP connections is black-holed without a FIN or an "
        "RST, so neither peer learns that anything is wrong",
        symptom="requests hang until timeout. No error is raised on either side, and both peers "
        "believe the connection is open for the whole window",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.NETWORK_PATH,
        recovery="restore the path. The half-open state is only cleared by the peers' own "
        "timeouts, so recovery may lag the fix by one timeout interval",
        verification="requests hang with no error during the window and complete after undo",
    ),
    _m(
        "net.conn_exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY, FailureMode.NETWORK),
        mechanism="connection state is consumed until the conntrack table or the ephemeral port "
        "range is exhausted, so new connections cannot be created",
        symptom="new outbound connections fail with no route or refused, from a host whose "
        "application, CPU, and memory all look healthy — the failure surface is the "
        "network and the cause is a limit",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.NETWORK_PATH,
        recovery="let connection state expire; mayhem does not break established connections, so "
        "recovery waits out the timeout on the table's own schedule",
        verification="the conntrack count reaches its limit and new connections fail, then recover "
        "after undo",
    ),
    # -- http and application behaviour ------------------------------------------
    _m(
        "node.service_stop",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE, FailureMode.DEPENDENCY),
        mechanism="the host's service manager is told to stop the unit the target depends on, so "
        "the dependency disappears from the host's own point of view",
        symptom="the unit leaves its active state and anything on that host depending on it loses "
        "its dependency without a network-level failure anywhere",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_EXIT,
        recovery="start the unit; dependents on that host restart or fail until it returns, and "
        "the recovery is only complete when they have recovered too",
        verification="the unit is inactive during the window and active after undo",
    ),
    _m(
        "http.error_injection",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="responses on the target's HTTP surface are replaced with an error status the "
        "application never produced",
        symptom="client-visible 4xx/5xx that originates at the edge rather than in application "
        "logic; error rates, alerting, and dashboards all move",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="stop injecting; the endpoint's own responses return immediately",
        verification="a client observes the injected status code and normal responses resume after "
        "undo",
    ),
    _m(
        "http.latency",
        FailureMode.LATENCY,
        also=(FailureMode.NETWORK,),
        mechanism="the target's HTTP handler is held before responding, adding delay inside the "
        "application rather than on the path",
        symptom="client-observed latency rises, and upstream callers time out once the delay "
        "exceeds their own timeout — so the fault migrates from latency to availability as "
        "it deepens",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="remove the hold; the handler returns to its normal service time",
        verification="client-side duration rises to the injected delay and falls back on undo",
    ),
    _m(
        "http.upstream_timeout",
        FailureMode.LATENCY,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="the handler's call to its own upstream is held past the caller's timeout, so "
        "the timeout fires in a component that is not the slow one",
        symptom="the client sees a 504 or its own timeout while the upstream is healthy — the most "
        "commonly misattributed latency fault there is, and the reason the mapping records "
        "the dependency mode alongside latency",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="remove the hold. The server-side request may still complete after the client "
        "gave up, so a successful recovery is not evidence that nothing happened",
        verification="the client times out while the upstream's own latency is normal, and both "
        "recover on undo",
    ),
    _m(
        "http.response_truncate",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the response body is cut short part-way through the stream rather than being "
        "replaced or delayed",
        symptom="clients fail with a truncated-body or JSON parse error rather than a status code, "
        "and the amount received varies per request, which makes it look like flaky data "
        "rather than a transport fault",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="stop truncating. Clients that retried may have applied the partial effect twice, "
        "so recovery is not complete until the duplicates are accounted for",
        verification="a client reports a short read during the window and a complete body after "
        "undo",
    ),
    _m(
        "http.header_inject",
        FailureMode.SECURITY_CONTROL_FAILURE,
        also=(FailureMode.CORRECTNESS,),
        mechanism="response headers are injected that the application never set, so the client's "
        "view of the response is shaped by something outside the application",
        symptom="cache keys, framing decisions, or security headers change under injected "
        "influence; a validating proxy may reject the response outright",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="stop injecting headers. Anything already poisoned downstream — a cache entry, a "
        "stored response — may persist until it expires",
        verification="the injected header is observed by a client and absent after undo",
    ),
    _m(
        "http.stream_stall",
        FailureMode.LATENCY,
        also=(FailureMode.AVAILABILITY,),
        mechanism="an in-progress response stream stops advancing without being closed, so the "
        "transfer is neither progressing nor failing",
        symptom="the client hangs mid-body while the server still considers the request open, so "
        "neither side can distinguish a slow client from a stalled server",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="close or resume the stream. Meanwhile only the client's own timeout ends "
        "anything, which is why the observable outage can exceed the injected window",
        verification="bytes stop arriving part-way through a response during the window and resume "
        "after undo",
    ),
    _m(
        "app.response_5xx",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the application returns 5xx responses with no injected fault underneath — the "
        "fault here is the absence of a cause, injected deliberately",
        symptom="error rates rise with nothing in the topology changed, which is the point: the "
        "fault exercises the path that reports a failure nothing else can explain",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="the application must fix its own error path. Mayhem observes this rather than "
        "causing it, so there is no undo and the recovery belongs to the application "
        "owner",
        verification="the 5xx rate rises during the window and falls back after undo, and no other "
        "signal moves with it",
    ),
    _m(
        "app.exception",
        FailureMode.RUNTIME,
        also=(FailureMode.CORRECTNESS,),
        mechanism="an unhandled exception would be raised on a chosen request path, inside the "
        "application's own error handling",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the application-exception gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="none from this entry — it is refused. Raising an arbitrary application exception "
        "is not something mayhem can do generically without the application cooperating",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the application-exception reason and never reaches a request",
        refusal="catalog-only: generic exception injection needs an application-aware hook, so the "
        "entry is refused at plan time rather than injected",
    ),
    _m(
        "app.deadlock",
        FailureMode.RUNTIME,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a lock-ordering cycle would be created so the request path stops making "
        "progress without failing",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the deadlock-injection gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="none from this entry — it is refused. Mayhem cannot reach inside an "
        "application's lock graph to create a cycle in it",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the deadlock-injection reason and never reaches a request",
        refusal="catalog-only: deadlock injection requires application-level lock instrumentation, "
        "so the entry is refused at plan time rather than injected",
    ),
    _m(
        "load.spike",
        FailureMode.CAPACITY,
        also=(FailureMode.LATENCY,),
        mechanism="the request rate against the target rises well above its measured steady state",
        symptom="latency and the error rate rise with the load. The target degrades before it "
        "saturates, because queueing consumes capacity that is not doing useful work",
        risk=RiskLevel.LOW,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="return the load to baseline; latency follows the queue down rather than snapping "
        "back",
        verification="the request rate matches the injected spike and latency returns after undo",
    ),
    _m(
        "fuzz.protocol_abuse",
        FailureMode.CORRECTNESS,
        also=(FailureMode.RESOURCE_EXHAUSTION, FailureMode.SECURITY_CONTROL_FAILURE),
        mechanism="malformed or abusive requests are sent at the target's parser, so the "
        "validation path is exercised with input no normal client would send",
        symptom="validation rejects them (the system holds) or the parser spends disproportionate "
        "CPU on them (it does not); the observable difference between those two outcomes "
        "is exactly what this fault measures",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.HTTP_RESPONSE,
        recovery="stop the abusive requests. A parser that crashed under them is recovered by "
        "restart, and the crash itself is the finding rather than the recovery",
        verification="the target's 4xx/5xx mix and its CPU during abuse are both recorded, and "
        "both return to baseline after undo",
    ),
    # -- databases and dependencies ---------------------------------------------
    _m(
        "db.slow_query",
        FailureMode.LATENCY,
        also=(FailureMode.CAPACITY, FailureMode.DEPENDENCY),
        mechanism="queries on the target connection are slowed in flight, so the database looks "
        "busy without doing more work",
        symptom="end-to-end latency grows with database time as the dominant component, and the "
        "pool is held longer, so effective concurrency falls — the same fault degrades "
        "latency and capacity at once",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="remove the slowdown; queued queries drain afterwards, so the recovery completes "
        "only once the queue has emptied",
        verification="query duration rises while the server reports no additional CPU, which is "
        "what separates a slow query from a busy server",
    ),
    _m(
        "db.connection_exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY, FailureMode.AVAILABILITY),
        mechanism="connection slots are held so that the pool or the server's own limit is reached "
        "before any query is slow",
        symptom="new connections are refused or time out while existing work proceeds normally, "
        "which makes the fault look like a slow query until the connection count is read",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="release the held slots; the pool refills, and requests that timed out while it "
        "was empty do not automatically return",
        verification="the connection count reaches the server limit and new connections fail, then "
        "recover after undo",
    ),
    _m(
        "db.query_error",
        FailureMode.CORRECTNESS,
        also=(FailureMode.DEPENDENCY,),
        mechanism="queries on the target session fail with a database error rather than timing out "
        "or returning wrong rows",
        symptom="the dependent feature returns an error, and whether partial work is left behind "
        "depends on the application's transaction boundaries rather than on the fault",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop failing queries. Any transaction left open by the failures has to be "
        "reconciled by the application; mayhem does not commit or roll back on its behalf",
        verification="the database error code is observed from the target and normal queries "
        "resume after undo",
    ),
    _m(
        "dependency.block",
        FailureMode.AVAILABILITY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="calls to the upstream dependency are dropped before they leave the target, so "
        "the dependency never sees the request",
        symptom="the dependency is unreachable from the target. Retries and circuit breakers may "
        "convert this into fail-fast behaviour or into an open circuit, which changes the "
        "symptom without changing the cause",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop blocking. Outstanding calls fail rather than resume, so recovery means "
        "retries succeeding, not in-flight work completing",
        verification="the dependency probe fails from the target during the window and succeeds "
        "after undo",
    ),
    _m(
        "dependency.timeout",
        FailureMode.LATENCY,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="the dependency's responses are held past the caller's own timeout, so the "
        "caller gives up while the dependency still holds the request",
        symptom="the caller's timeout fires rather than the dependency reporting an error, and "
        "held threads and connections accumulate while the dependency's own metrics look "
        "healthy",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop delaying; the held calls time out and the caller releases their resources, "
        "so recovery completes one timeout after the fault is removed",
        verification="the dependency's own latency is normal while the caller's timeout rate "
        "rises, and both recover on undo",
    ),
    _m(
        "dependency.flap",
        FailureMode.AVAILABILITY,
        also=(FailureMode.CONSISTENCY, FailureMode.DEPENDENCY),
        mechanism="the dependency alternates between succeeding and failing rather than failing "
        "consistently",
        symptom="requests fail intermittently. Every individual sample looks fine, which is why "
        "this class of fault is diagnosed from aggregate behaviour and not from a single "
        "trace",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop flapping. Load balancers and circuit breakers may need to be reset before "
        "behaviour returns to normal, so the recovery is not instantaneous",
        verification="the success rate alternates between the two states during the window and "
        "settles after undo",
    ),
    _m(
        "dependency.rate_limit",
        FailureMode.CAPACITY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the dependency throttles the caller as though its quota were exhausted, "
        "rejecting rather than slowing",
        symptom="requests are rejected outright instead of queueing, so work is shed rather than "
        "degraded — the opposite of a latency fault at the same request volume",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop exceeding the limit. The quota refills over time, so recovery is measured "
        "in the dependency's refill window rather than in the fault duration",
        verification="the 429 rate rises during the window and the dependency's quota indicator "
        "returns to normal",
    ),
    _m(
        "dependency.connection_refuse",
        FailureMode.AVAILABILITY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the dependency refuses new connections as though it were down, while the ones "
        "it already accepted keep working",
        symptom="connection errors at the client with existing connections surviving, so a partial "
        "outage is visible as a slow service rather than as an error rate",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop refusing; new connections succeed, and callers that gave up do not return "
        "without retrying",
        verification="connect() from the target fails during the window and succeeds after undo",
    ),
    _m(
        "dependency.malformed_response",
        FailureMode.CORRECTNESS,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the dependency would return a response violating the contract it advertises, so "
        "the caller's own validation is what fails",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the response-rewriting gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="none from this entry — it is refused. It stays refused until a "
        "response-rewriting path exists, because a proxy that mangles a live response to "
        "make a point is a worse problem than the missing test",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the response-rewriting reason and never reaches a target",
        refusal="catalog-only: response rewriting has no implementation, so the entry is refused "
        "at plan time rather than injected",
    ),
    _m(
        "dependency.response_truncate",
        FailureMode.CORRECTNESS,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the dependency's response is cut short part-way through, so the caller receives "
        "a payload that began correctly and stops",
        symptom="the caller fails to parse or gets a short payload, and it is routinely reported "
        "as corrupt data in the caller rather than as a dependency fault",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="stop truncating. Partial effects the caller already applied are not rolled back "
        "by mayhem, so a clean recovery of the transport is not a recovery of the data",
        verification="the caller reports a short read during the window and a complete payload "
        "after undo",
    ),
    _m(
        "dependency.circuit_open",
        FailureMode.AVAILABILITY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the caller's circuit breaker for the dependency is driven open, so calls stop "
        "before they leave",
        symptom="calls fail fast without reaching the dependency, which means the dependency is "
        "healthy and idle while the caller reports an outage — the most confusing pairing "
        "in the catalog, and the reason the mapping records the dependency explicitly",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="the breaker half-opens after its cooldown; sustained failure during the "
        "half-open probe closes it again, so recovery is conditional rather than "
        "automatic",
        verification="the dependency's own request rate drops to zero while the caller's error "
        "rate rises, and the breaker closes after undo",
    ),
    # -- name resolution and TLS -------------------------------------------------
    _m(
        "dns.resolve_delay",
        FailureMode.LATENCY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="responses on the resolution path are held before being returned, so the lookup "
        "is slow rather than absent",
        symptom="name resolution is slow, so every first connection is slow while cached lookups "
        "stay fast — which makes the fault intermittent from the application's point of "
        "view",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DNS_RESOLUTION,
        recovery="remove the delay; cached entries and queued lookups both recover, and the "
        "resolution rate returns to normal once the cache refills",
        verification="lookup response time rises by approximately the injected delay and returns "
        "to baseline",
    ),
    _m(
        "dns.timeout",
        FailureMode.AVAILABILITY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the resolution path is dropped so lookups never complete and never answer",
        symptom="resolution fails; anything not already cached cannot resolve, while cached "
        "entries keep working until they expire — so the outage appears to grow rather "
        "than start",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DNS_RESOLUTION,
        recovery="restore the resolution path. The apparent end of the outage is governed by cache "
        "expiry rather than by the fix, which is a recovery that reports itself late",
        verification="a lookup fails during the window and succeeds after undo",
    ),
    _m(
        "dns.servfail",
        FailureMode.CORRECTNESS,
        also=(FailureMode.DEPENDENCY,),
        mechanism="the resolver returns SERVFAIL rather than dropping the query, so the failure is "
        "fast and explicitly named",
        symptom="resolution fails immediately with a named error rather than a timeout, and a "
        "caller that treats SERVFAIL as 'try another name' can mask the failure entirely",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.DNS_RESOLUTION,
        recovery="restore authoritative answers; resolution succeeds again without waiting for any "
        "cache to expire",
        verification="a lookup returns SERVFAIL during the window and a normal answer with its "
        "records after undo",
    ),
    _m(
        "dns.nxdomain",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="the resolver answers NXDOMAIN for names that do exist — a wrong answer rather "
        "than a failure, which is why it is mapped separately from SERVFAIL",
        symptom="resolution fails with 'no such host' for a name that resolves normally, and "
        "callers with a fallback to another name may never notice",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DNS_RESOLUTION,
        recovery="restore correct answers. Negative entries already cached keep lying until they "
        "expire, so recovery lags the fix by the negative TTL",
        verification="a known-good name returns NXDOMAIN during the window and a normal answer "
        "after undo",
    ),
    _m(
        "tls.certificate_expired",
        FailureMode.SECURITY_CONTROL_FAILURE,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="the served certificate's validity window is made to exclude the current time, "
        "so a control that is working correctly rejects the endpoint",
        symptom="validating clients refuse the connection while non-validating clients are "
        "unaffected, which is precisely the point: the fault measures whether validation "
        "is actually happening on the path",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="restore a valid certificate and reload the endpoint. Clients that cached the "
        "failure keep failing until the cache expires",
        verification="a validating client fails the handshake during the window and succeeds after "
        "undo, and the failure is reported as a certificate validity error rather "
        "than a timeout",
    ),
    _m(
        "tls.handshake_failure",
        FailureMode.SECURITY_CONTROL_FAILURE,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="the handshake is broken — incompatible parameters, an aborted negotiation, or a "
        "protocol version the peer will not accept",
        symptom="connection establishment fails at the TLS layer, so it appears as a connection "
        "error with no application involvement and often gets misfiled as a network fault",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.DEPENDENCY_RESPONSE,
        recovery="restore the handshake configuration; established connections are unaffected, so "
        "recovery is visible only to new connections",
        verification="a TLS probe fails during the window and completes the handshake after undo",
    ),
    # -- containers and process resources ----------------------------------------
    _m(
        "container.kill",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the container's main process is killed from outside, so the runtime's own "
        "shutdown path is bypassed entirely",
        symptom="the container exits; whether it returns is entirely up to its restart policy, and "
        "in-memory state does not survive either way",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.PROCESS_EXIT,
        recovery="let the restart policy act, or start the container again. A container with no "
        "restart policy does not come back, and that is the finding",
        verification="container state leaves running and returns after undo",
    ),
    _m(
        "container.restart",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the container is stopped and started again, so it is recreated rather than "
        "resumed",
        symptom="the container is briefly absent from discovery, and nothing in its memory "
        "survives the recreate",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.PROCESS_EXIT,
        recovery="the container is already running again by the time the restart completes, so "
        "this fault's recovery is part of its own execution",
        verification="the container's id changes across the restart and the service answers "
        "afterwards",
    ),
    _m(
        "container.pause",
        FailureMode.PROCESS,
        also=(FailureMode.LATENCY,),
        mechanism="the container's processes are frozen with the cgroup freezer while the "
        "container itself stays in the running state",
        symptom="the container reports running to the orchestrator while answering nothing — the "
        "failure the runtime's own status cannot see, and the reason this is a distinct "
        "entry from a stop",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.PROCESS_EXIT,
        recovery="unfreeze the cgroup; the processes resume exactly where they were, so recovery "
        "is immediate and complete",
        verification="container state still reports running while probes time out, and probes "
        "recover on undo",
    ),
    _m(
        "fd.exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="file descriptors are held open until the per-process or system limit is "
        "reached, so the process can no longer create any",
        symptom="open() fails with EMFILE, and because sockets are descriptors, sockets and files "
        "fail together — which makes the fault look like a networking or permissions "
        "problem",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="release the descriptors. Mayhem does not raise the limit, so a process that "
        "legitimately needs more than the limit allows stays broken",
        verification="the open-descriptor count reaches the limit and open() fails, then both "
        "recover after undo",
    ),
    _m(
        "process.thread_exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="threads are created until the process or system thread limit is reached",
        symptom="thread creation fails, and a runtime that needs a thread per connection becomes "
        "unable to accept any — so the failure is total while the process still looks "
        "alive",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="let the threads drain. A runtime that already wedged its request handling needs "
        "the process restarted rather than merely relieved",
        verification="the thread count reaches the limit and creation fails, then recovers after "
        "undo",
    ),
    _m(
        "process.child_exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="child processes are spawned until the process or cgroup pids limit is reached",
        symptom="fork/exec fails, and a process that supervises children — a build, a job runner, "
        "a sidecar supervisor — can no longer do anything at all",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="drain the children; a wedged supervisor needs the process restarted, since it "
        "cannot recover by itself once it can no longer fork",
        verification="the child count reaches the limit and spawning fails, then recovers",
    ),
    _m(
        "process.restart_delay",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the process is asked to restart but its replacement's start is held, so the gap "
        "is longer than the restart itself implies",
        symptom="a longer outage than a routine restart would cause: a supervisor with a slow "
        "start turns an ordinary restart into an availability event",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="release the start hold. The process comes up late rather than not at all, so the "
        "recovery is a return to service at a lower rate than before",
        verification="the gap between stop and ready exceeds the injected delay and returns to "
        "normal after undo",
    ),
    _m(
        "process.oom_kill",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.PROCESS,),
        mechanism="the target would be OOM-killed from outside rather than allocating its way "
        "there, so the killer acts on another process's behalf",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the external-OOM-kill gap",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PROCESS_SIGNAL,
        recovery="none from this entry — it is refused. mem.exhaust reaches the same end state "
        "through allocation the target does itself, which is the executable path",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the external-OOM-kill reason and never reaches a target",
        refusal="catalog-only: killing a process from the outside is not implemented, so the entry "
        "is refused at plan time rather than injected",
    ),
    # -- clock -------------------------------------------------------------------
    _m(
        "clock.skew",
        FailureMode.CLOCK,
        also=(FailureMode.CORRECTNESS,),
        mechanism="the target's clock is moved away from real time, so every wall-clock comparison "
        "it makes is wrong even though its arithmetic is right",
        symptom="failures appear far from the clock: tokens look expired or not yet valid, "
        "certificate validation fails, and log ordering becomes meaningless across hosts",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PLATFORM_STATE,
        recovery="resynchronise from a reference source. Do not step a running system's clock "
        "backwards without checking the application's tolerance: a backwards step can "
        "invalidate more than the original skew did",
        verification="the offset from a reference host matches the injected skew and returns to "
        "zero afterwards",
    ),
    _m(
        "clock.freeze",
        FailureMode.CLOCK,
        also=(FailureMode.CORRECTNESS,),
        mechanism="the target's clock would stop advancing entirely, so time-dependent logic sees "
        "no passage rather than a wrong value",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the clock-freeze gap",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.PLATFORM_STATE,
        recovery="none from this entry — it is refused. A stopped clock cannot be unfrozen by a "
        "timer mayhem can restart, and freezing one that is already stopped is "
        "indistinguishable from doing nothing",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the clock-freeze reason and never reaches a target",
        refusal="catalog-only: clock freeze has no executable path, so the entry is refused at "
        "plan time rather than injected",
    ),
    # -- hypervisor and device surfaces ------------------------------------------
    _m(
        "cpu.steal",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the hypervisor would take CPU time from the guest, so the workload is starved "
        "by something it can neither observe nor control",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the hypervisor-injection gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="none from this entry — it is refused. The remedy is to move the workload off a "
        "contended hypervisor, which is an infrastructure action rather than a test",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the hypervisor-injection reason and never reaches a target",
        refusal="catalog-only: hypervisor CPU steal cannot be injected by mayhem, so the entry is "
        "refused at plan time rather than injected",
    ),
    _m(
        "cpu.interrupt_storm",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="an interrupt rate would be imposed high enough to consume the target's entire "
        "CPU budget from outside the workload",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the interrupt-injection gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="none from this entry — it is refused. The device generating the interrupts has "
        "to be addressed; the workload cannot defend itself against them",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the interrupt-injection reason and never reaches a target",
        refusal="catalog-only: interrupt-rate injection is not implemented, so the entry is "
        "refused at plan time rather than injected",
    ),
    _m(
        "mem.fragment",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="the allocator would be pushed into a fragmented state so that large contiguous "
        "allocations fail while small ones still succeed",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the allocator-control gap",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="none from this entry — it is refused. A genuine fragmentation fault needs "
        "allocator-level control mayhem does not have, and a stand-in would prove nothing "
        "about the allocator",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the allocator-control reason and never reaches a target",
        refusal="catalog-only: allocator fragmentation has no injection path, so the entry is "
        "refused at plan time rather than injected",
    ),
    _m(
        "mem.oom_kill",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.PROCESS,),
        mechanism="the target would be killed by the OOM killer without having allocated the "
        "memory itself, so it dies for another component's allocation",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the external-OOM-kill gap",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.RESOURCE_METRIC,
        recovery="none from this entry — it is refused. mem.exhaust and k8s.pod_oom are the "
        "executable paths to an OOM-killed process in this release",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the external-OOM-kill reason and never reaches a target",
        refusal="catalog-only: external OOM kills are not implemented, so the entry is refused at "
        "plan time rather than injected",
    ),
    # -- kubernetes: nodes and platform components -------------------------------
    _m(
        "k8s.node_pressure",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="the node's conditions report DiskPressure, MemoryPressure, or PIDPressure, so "
        "the scheduler and the kubelet both treat the node as unfit for work",
        symptom="pods on the node are evicted or refuse to start and new pods avoid it, while the "
        "cluster as a whole looks merely busy from outside the node",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="relieve the pressure and let the kubelet clear the condition; the node rejoins "
        "scheduling only once it reports itself healthy, which lags the relief",
        verification="the node's conditions report the pressure during the window and not after "
        "undo, and its pod count returns",
    ),
    _m(
        "k8s.node_disk_pressure",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="the node reports DiskPressure, typically after image layers or logs grow on its "
        "writable layer",
        symptom="pods are evicted and new pods avoid the node. A node can reach DiskPressure with "
        "plenty of free space if a separate volume filled, so 'the disk is fine' is not a "
        "refutation of this fault",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="free space on the node and wait for the condition to clear before expecting "
        "scheduling to resume",
        verification="the node reports DiskPressure during the window and its pod count falls, "
        "then both recover after undo",
    ),
    _m(
        "k8s.node_memory_pressure",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="allocatable memory on the node falls short of what is running plus what is "
        "requested, so the kubelet begins reclaiming",
        symptom="pods are evicted and rescheduled. The eviction here is the node protecting itself "
        "rather than a defect in the workload, which is why this leads with infrastructure",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="add memory to the node or relieve its usage, then let the condition clear before "
        "treating the cluster as steady",
        verification="the node reports MemoryPressure during the window and evictions are recorded "
        "against it",
    ),
    _m(
        "k8s.node_pid_pressure",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="the node exhausts its process-ID space, so no new container can be created on "
        "it at all",
        symptom="container creation fails with a pids error while the node stays up and keeps "
        "serving everything already on it — a failure of new work on a healthy-looking "
        "node",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="reclaim pids by stopping processes. Ids are not reusable while their process "
        "lives, so recovery is a process-lifetime problem rather than a configuration one",
        verification="the node reports PIDPressure and container creation fails, then succeeds "
        "after undo",
    ),
    _m(
        "k8s.node_not_ready",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the node stops reporting Ready to the control plane, so it stops being "
        "considered for work and its pods stop being reconciled",
        symptom="pods on the node are eventually evicted and the control plane reassigns them; a "
        "service with no ready endpoint elsewhere then fails for its clients",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the kubelet so the node reports Ready again; the pods it lost are "
        "rescheduled by their controllers, not by the node",
        verification="the node's Ready condition goes false during the window and its pods are "
        "evicted",
    ),
    _m(
        "k8s.node_network_partition",
        FailureMode.PARTITION,
        also=(FailureMode.INFRASTRUCTURE, FailureMode.AVAILABILITY),
        mechanism="a node is cut off from the control plane and from its peers, so it keeps "
        "serving locally while the control plane believes it is gone",
        symptom="the node goes NotReady and its pods leave the control plane's endpoint list, yet "
        "they may still be serving — the split brain this fault exists to demonstrate, and "
        "the reason neither side can be trusted on its own",
        risk=RiskLevel.CRITICAL,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore connectivity and reconcile the control plane's view with reality before "
        "trusting either. Rescheduling the same pods elsewhere while the node still "
        "serves them is a second incident, not a recovery",
        verification="the node reports NotReady and the control plane's endpoint list excludes its "
        "pods while a direct probe to those pods still answers",
    ),
    _m(
        "k8s.node_drain",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.CAPACITY,),
        mechanism="the node is cordoned and its pods are evicted in respect of disruption budgets, "
        "so capacity leaves the cluster in an orderly way",
        symptom="capacity on the node falls as pods move elsewhere, and a drain stalls part-way "
        "when a disruption budget forbids the next eviction",
        risk=RiskLevel.CRITICAL,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="uncordon the node. Evictions that already completed are not automatically "
        "undone, so recovery means re-admitting capacity rather than restoring the old "
        "layout",
        verification="the node is cordoned and its pod count falls during the window, then both "
        "recover after undo",
    ),
    _m(
        "k8s.node_cordon",
        FailureMode.HUMAN_OPERATOR,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the node is marked unschedulable so no new pod lands on it, while the pods "
        "already there keep running untouched",
        symptom="new pods avoid the node and capacity quietly shrinks without a single eviction — "
        "on a dashboard this looks like stability, and it is a decision somebody made",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="uncordon the node; existing pods are unaffected, so the recovery is one command "
        "and the whole risk was in leaving it cordoned",
        verification="the node is cordoned during the window and schedulable again after undo",
    ),
    _m(
        "k8s.taint_evict",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.CAPACITY,),
        mechanism="a taint is applied that existing pods do not tolerate, so the kubelet evicts "
        "them and the scheduler stops placing new work there",
        symptom="pods leave the node and are rescheduled. A NoSchedule taint whose existing pods "
        "do not tolerate it is the most common surprise in a node-pool change, because "
        "nothing fails — the pods just move",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="remove the taint or add tolerations. Evicted pods return only if capacity exists "
        "elsewhere, so a drain into a full cluster loses them rather than relocating them",
        verification="pods leave the node during the window and return after the taint is removed",
    ),
    _m(
        "k8s.nvidia_smi_error",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.CAPACITY,),
        mechanism="the node's GPU inventory stops reporting devices, so the device plugin "
        "advertises no allocatable GPUs",
        symptom="GPU-backed pods stay unschedulable with a device-plugin error while non-GPU "
        "workloads on the same node are unaffected, which is what makes it easy to misread "
        "as a scheduling or quota problem",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the device plugin. On clusters without NVIDIA device-plugin support the "
        "documented node-state families are the alternative, and the catalog's "
        "deprecation path says so",
        verification="the node reports zero allocatable devices and the GPU pod stays Pending, "
        "then both recover after undo",
    ),
    _m(
        "k8s.preemption_failure",
        FailureMode.CAPACITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="a higher-priority pod cannot preempt a lower-priority one, so priority order is "
        "not honoured and the urgent pod waits",
        symptom="the priority pod stays Pending with a preemption event while the low-priority "
        "pods keep running and serving — the cluster is not doing what its own priorities "
        "say it will do",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="free capacity or reduce the waiting pod's request. Preemption also refuses "
        "across nodes when the resources are not fungible, which the event names "
        "explicitly",
        verification="the priority pod is Pending with a preemption event and the lower-priority "
        "pods still run",
    ),
    _m(
        "k8s.kube_proxy_failure",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.AVAILABILITY,),
        mechanism="kube-proxy on a node stops programming service routing rules, so that node "
        "cannot steer traffic to Services",
        symptom="ClusterIP and Service traffic fails on that node while direct pod-to-pod traffic "
        "still works, and other nodes are entirely unaffected — so a client holding a "
        "connection to a healthy node sees no symptom at all",
        risk=RiskLevel.CRITICAL,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restart or repair kube-proxy so the rules are reprogrammed. Recovery is "
        "node-scoped, and a node that is still failing keeps serving a fraction of the "
        "traffic with no cluster-level signal to announce it",
        verification="a ClusterIP probe fails from the affected node and succeeds from another, "
        "then recovers on the first after undo",
    ),
    # -- kubernetes: pods and scaling --------------------------------------------
    _m(
        "k8s.pod_oom",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the pod's memory limit is crossed and the kubelet's OOM killer terminates the "
        "container",
        symptom="the container exits with reason OOMKilled and is restarted on a new attempt; the "
        "pod object itself stays Running, so the loss is visible only in the restart count",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="raise the limit or reduce the footprint. Restarts alone do not help, because the "
        "same allocation happens again on the next attempt",
        verification="the pod reports OOMKilled and its restart count climbs during the window",
    ),
    _m(
        "k8s.pod_pressure",
        FailureMode.INFRASTRUCTURE,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="the pod's resource requests cannot be satisfied on any node in the cluster",
        symptom="the pod stays Pending with an unschedulable event, so a workload that scaled out "
        "does not gain the capacity it asked for",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="free capacity, lower the request, or add a node; the controller keeps retrying "
        "in the meantime, so a relief shows up without any further action",
        verification="the pod is Pending with a scheduling event naming the resource it could not "
        "get, and it binds after undo",
    ),
    _m(
        "k8s.pod_unschedulable",
        FailureMode.CAPACITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="no node satisfies the pod's requests, selectors, or taints, so the scheduler "
        "declines to bind it",
        symptom="the pod stays Pending with a FailedScheduling event naming the reason, and the "
        "workload's ready count stays below its desired count for as long as that persists",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="add capacity, relax the constraint, or remove the taint; the scheduler retries "
        "periodically, so recovery is observed on a later attempt rather than immediately",
        verification="the pod is Pending with a FailedScheduling event naming the unsatisfied "
        "constraint, and it binds after undo",
    ),
    _m(
        "k8s.pod_pending",
        FailureMode.CAPACITY,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the pod has not been bound to a node, so it contributes nothing to the workload "
        "it belongs to",
        symptom="the pod is Pending and the workload's ready replicas stay below the desired "
        "count. For a workload scaled from zero this is indistinguishable from an outage "
        "to its clients",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="bind the pod. The pending duration is exactly the time the workload was "
        "under-provisioned, so it belongs in the availability accounting rather than in a "
        "footnote",
        verification="the pod's phase is Pending and the workload's ready replicas are below the "
        "desired count",
    ),
    _m(
        "k8s.schedule_delay",
        FailureMode.LATENCY,
        also=(FailureMode.CAPACITY,),
        mechanism="the scheduler binds the pod later than it otherwise would, so the start of a "
        "replacement is delayed rather than refused",
        symptom="the pod sits Pending briefly. A replacement replica is late to serve, and a "
        "rollout appears to stall at a step that is actually progressing slowly",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the binding completes on its own once the delay is removed; nothing needs to be "
        "retried by hand",
        verification="the interval from pod creation to Running rises during the window and "
        "returns afterwards",
    ),
    _m(
        "k8s.replica_reduce",
        FailureMode.CAPACITY,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the workload's replica count is reduced below its declared value, so serving "
        "capacity is withdrawn deliberately rather than by a failure",
        symptom="endpoints drop as pods terminate. A horizontal autoscaler may immediately scale "
        "back, which can mask the injection entirely — an honest reason to record the "
        "final replica count rather than the requested one",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="scale back to the declared replica count; pods are recreated rather than "
        "restored, so recovery costs what the original rollout cost",
        verification="the declared replica count falls and the endpoint count follows, then both "
        "recover after undo",
    ),
    _m(
        "k8s.deployment_scale_failure",
        FailureMode.CAPACITY,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a Deployment's replica count is changed in a way its controller cannot realise, "
        "so the declared intent and the actual world disagree",
        symptom="the declared count and the actual pod count diverge. The pod list is the fact and "
        "the declared count is the intention, and a report that quotes only the declared "
        "count will be wrong",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="correct the declared count; the controller converges once it can act, and until "
        "then the declared count is a wish rather than a fact",
        verification="the declared and actual replica counts disagree and the pod count does not "
        "match the declaration",
    ),
    _m(
        "k8s.statefulset_scale_failure",
        FailureMode.CAPACITY,
        also=(FailureMode.CONSISTENCY,),
        mechanism="a StatefulSet's scale is changed in a way the controller cannot realise, and "
        "its ordered semantics constrain what may terminate first",
        symptom="ordinals go missing or extra, and a scale-down cannot proceed until the higher "
        "ordinals terminate — so a failed scale-down looks stuck rather than failed",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="correct the declaration and let the ordinals settle; recovery here is ordered "
        "rather than instant, so a mid-recovery snapshot is not a failed recovery",
        verification="the ordinals present do not match the declared replica count and the "
        "controller reports a scale failure event",
    ),
    _m(
        "k8s.pod_crash_loop",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the container exits non-zero repeatedly and the kubelet restarts it with "
        "increasing backoff",
        symptom="the pod alternates between Running and CrashLoopBackOff, and a service backed "
        "only by this pod loses its endpoint on every cycle — the availability cost is the "
        "fraction of time the container is actually up",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="fix the exit cause. Backoff lengthens with each restart, so leaving it unfixed "
        "makes the service available for a smaller and smaller share of the time",
        verification="the restart count climbs and the Ready condition toggles during the window",
    ),
    _m(
        "k8s.crash_loop",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="every pod of a workload exits non-zero repeatedly, so the whole deployment "
        "cycles together rather than one pod at a time",
        symptom="the same signature as k8s.pod_crash_loop seen from the workload: every pod's "
        "restart count rises together and the deployment's available replicas oscillate in "
        "step",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="fix the exit cause; treating the workload-level and pod-level views separately "
        "would double-count one event in a report",
        verification="the restart counts across the deployment's pods climb in step",
    ),
    _m(
        "k8s.pod_restart_churn",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="containers are restarted repeatedly on a short interval — faster than a "
        "meaningful amount of work can complete",
        symptom="availability collapses to the fraction of time a container happens to be up, and "
        "any request with a warm-up period fails every single time rather than "
        "occasionally",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="fix whatever is causing the restarts. The churn is a symptom, and a run that "
        "ends with the churn still going is a failed run rather than a completed one",
        verification="the restart count rises rapidly during the window and the Ready condition "
        "toggles",
    ),
    _m(
        "k8s.pod_kill",
        FailureMode.PROCESS,
        also=(FailureMode.INFRASTRUCTURE, FailureMode.AVAILABILITY),
        mechanism="the kubelet terminates the container without an orderly shutdown, so no grace "
        "period is honoured",
        symptom="the container disappears and the restart count climbs; nothing drains, so "
        "in-flight work on that container is lost rather than completed",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the kubelet restarts the container on a new attempt, and the pod's readiness "
        "clocks over again",
        verification="the restart count rises during the window and the pod serves again",
    ),
    _m(
        "k8s.pod_evict",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="an eviction is requested against the pod — node pressure, a drain, or an "
        "explicit eviction — and the kubelet honours it",
        symptom="the pod is removed and, for a controller-managed workload, rescheduled elsewhere "
        "or not at all. A standalone pod is simply gone",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the owning controller reschedules; a standalone pod is not coming back, and that "
        "distinction is the difference between an outage and a relocation",
        verification="the pod leaves the node and a replacement appears, or the eviction event is "
        "recorded",
    ),
    _m(
        "k8s.pod_delete_uncontrolled",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the pod object is deleted directly, bypassing the controller's own "
        "reconciliation path and every policy attached to it",
        symptom="for a controller-managed workload a replacement appears quickly, which can make "
        "the deletion look harmless. For a bare pod the workload is simply gone with "
        "nothing left to restore it",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the owning controller recreates it; a bare pod has to be re-created by a human "
        "or from an external manifest, and the difference is worth naming in a report",
        verification="the pod's UID disappears and, where a controller owns it, a new UID appears",
    ),
    _m(
        "k8s.pod_startup_fail",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the startup probe fails, so the kubelet stops waiting and restarts the "
        "container before it ever became ready",
        symptom="the container restarts without ever reaching Ready, which by restart count alone "
        "is indistinguishable from a crash loop",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="make startup succeed within the probe's budget; until it does, the kubelet keeps "
        "restarting on the same schedule",
        verification="the container never reaches Ready and the startup-probe event is recorded",
    ),
    _m(
        "k8s.pod_liveness_fail",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the liveness probe fails repeatedly and the kubelet restarts the container",
        symptom="the container restarts on a liveness event while the pod object never changes "
        "phase, so a dashboard built on pod phase shows nothing at all",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="fix whatever the probe detects; the kubelet keeps restarting the container until "
        "the probe passes",
        verification="the restart count rises together with a liveness-probe-failed event",
    ),
    _m(
        "k8s.pod_readiness_fail",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the readiness probe fails, so the endpoints controller removes the pod from "
        "service without touching the container",
        symptom="the pod is Running but receives no traffic, and requests fail at the service with "
        "no endpoints rather than at the pod — the failure is reported by a different "
        "component from the one that caused it",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="make the readiness probe pass; traffic returns as soon as the endpoints are "
        "republished, which is a controller round-trip rather than an instant",
        verification="the pod is Running with Ready false and the service has no endpoint for it, "
        "then both recover after undo",
    ),
    _m(
        "k8s.pod_partition",
        FailureMode.PARTITION,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the pod is isolated from the nodes and services it depends on, so it keeps its "
        "own local behaviour while losing everything outside itself",
        symptom="the pod stays Ready and serves whatever is local to it while every cross-node "
        "call fails — a pod whose own health says all-clear and whose reachability says "
        "otherwise",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the network path, then reconcile whatever the pod and its peers each did "
        "while isolated; healing the partition without reconciling turns an availability "
        "incident into a correctness one",
        verification="a cross-node probe fails during the window and succeeds after undo",
    ),
    _m(
        "k8s.pod_latency",
        FailureMode.LATENCY,
        also=(FailureMode.NETWORK,),
        mechanism="the pod's own request path is held before traffic flows, so the delay is inside "
        "the pod rather than on the path to it",
        symptom="in-pod request latency rises while the pod stays Ready and its endpoints stay "
        "published, so availability looks untouched",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="remove the hold; latency returns to its prior distribution",
        verification="an in-cluster probe's latency rises during the window and falls back after "
        "undo",
    ),
    _m(
        "k8s.sidecar_termination",
        FailureMode.PROCESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a sidecar container in the pod is terminated while the main container keeps "
        "running",
        symptom="the pod remains Ready while a capability the sidecar provided — logging, metrics "
        "relay, a service proxy — disappears, so the pod is healthy and functionally "
        "incomplete",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the kubelet restarts the sidecar. A sidecar that keeps exiting takes the whole "
        "pod down with it through its own restart policy",
        verification="the sidecar's restart count rises and the capability it provided stops "
        "appearing in the pod's output",
    ),
    _m(
        "k8s.container_termination_delay",
        FailureMode.AVAILABILITY,
        also=(FailureMode.RESOURCE_EXHAUSTION,),
        mechanism="container termination is held past its grace period, so the old container is "
        "still running while its replacement starts",
        symptom="two pods overlap for one workload, so it is briefly over-provisioned — and a "
        "delayed termination holding a ReadWriteOnce volume blocks the replacement "
        "entirely, which is the same fault with a much worse outcome",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="release the termination; the kubelet kills the container once the grace period "
        "expires, and any volume conflict clears with it",
        verification="the termination duration exceeds the grace period during the window and "
        "returns to normal after undo",
    ),
    _m(
        "k8s.workload_stall",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="a workload stops progressing: its controller makes no further change to "
        "anything, in either direction",
        symptom="replica counts and pod UIDs are frozen — neither converging nor failing, which "
        "reads as 'stable' on a dashboard and is not. A stall is the absence of a signal, "
        "and its absence is the signal",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the controller has to be able to act again. Nothing recovers a stalled "
        "controller by waiting, so a stall that outlives its window is an unresolved "
        "incident",
        verification="replica counts and pod UIDs stop changing while the workload's conditions do "
        "not report Ready",
    ),
    # -- kubernetes: services, networking, images, storage, autoscaling -----------
    _m(
        "k8s.network_policy",
        FailureMode.SECURITY_CONTROL_FAILURE,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a NetworkPolicy object is applied that selects the pod and denies the traffic "
        "it depends on, so the enforcement point is the policy rather than the pod",
        symptom="traffic to or from the pod is dropped at the network layer while the pod itself "
        "stays Ready. Two views of the same event disagree, and only a connection probe "
        "resolves which one is telling the truth",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore or amend the policy; the pod never restarted, so recovery is immediate "
        "once the rule is right",
        verification="a connection probe fails during the window and succeeds after the policy is "
        "restored",
    ),
    _m(
        "k8s.service_no_endpoints",
        FailureMode.AVAILABILITY,
        also=(FailureMode.INFRASTRUCTURE,),
        mechanism="the service's selector matches no ready pod, or its endpoints object is "
        "emptied, so there is nothing for the service to route to",
        symptom="connections to the service fail with no endpoints while every pod is individually "
        "healthy. The selector is the fault, not the pods, and the pod list will not show "
        "it",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore a matching ready pod or correct the selector; the endpoints are "
        "republished on the next controller sync, so recovery is a round-trip rather than "
        "instant",
        verification="the service has no endpoints and a connection probe fails, then both recover "
        "after undo",
    ),
    _m(
        "k8s.service_endpoint_flap",
        FailureMode.AVAILABILITY,
        also=(FailureMode.CONSISTENCY,),
        mechanism="endpoints are added and removed repeatedly, so the set of backends a client may "
        "land on changes every few seconds",
        symptom="requests alternate between hitting a pod and failing, and a client holding a "
        "stale connection cache may reach a pod that has already terminated",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="stop flapping; clients with stale connection caches may still fail briefly "
        "afterwards, so the recovery lags the fix",
        verification="the endpoint count oscillates during the window and settles after undo",
    ),
    _m(
        "k8s.service_port_mismatch",
        FailureMode.AVAILABILITY,
        also=(FailureMode.CORRECTNESS,),
        mechanism="the service port does not match the container port the pod actually listens on",
        symptom="connections are refused or reset at the service while a direct connection to the "
        "pod's port works — the discriminator between a port problem and a pod problem, "
        "and the cheapest diagnosis in the catalog if you know to try it",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="correct the port mapping; the endpoints controller republishes and the service "
        "starts working without any pod restarting",
        verification="the service probe fails while a direct pod-port probe succeeds, then both "
        "succeed after undo",
    ),
    _m(
        "k8s.service_dns_mismatch",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="a service's DNS name resolves to something other than that service, so the "
        "address is well-formed and the destination is wrong",
        symptom="traffic reaches the wrong endpoint entirely — a correctness failure presenting as "
        "an availability failure somewhere else in the system, which is why this leads "
        "with correctness",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="correct the DNS record or the service naming; the resolver's cache means "
        "recovery is not visible to existing clients immediately",
        verification="the resolved address differs from the service's cluster IP during the window "
        "and matches it after undo",
    ),
    _m(
        "k8s.service_5xx",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the pods behind the service return 5xx responses, with the service object "
        "itself unchanged and healthy",
        symptom="client-visible errors with a healthy control plane. The cause is inside the pods, "
        "so a platform-level view of the incident shows nothing wrong at all",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="the backing pods must recover; the service object is not at fault and nothing "
        "about the service needs changing",
        verification="the 5xx rate from a service-connection probe rises during the window and "
        "falls after undo",
    ),
    _m(
        "k8s.dns_failure",
        FailureMode.AVAILABILITY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="in-cluster name resolution stops resolving service names, while pod-to-IP "
        "traffic is untouched",
        symptom="every workload that resolves a service name fails and pod-to-IP traffic still "
        "works — the discriminator between cluster DNS being broken and the applications "
        "being broken",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore cluster DNS. Cached entries mask the outage until they expire, so the "
        "apparent recovery trails the fix by an unpredictable interval",
        verification="a service-name lookup fails from inside a pod during the window and succeeds "
        "after undo",
    ),
    _m(
        "k8s.dns_delay",
        FailureMode.LATENCY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="cluster DNS responses are held before being returned to in-cluster resolvers",
        symptom="resolution is slow rather than failing, so the effect appears as scattered "
        "timeouts across many unrelated workloads at once",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="remove the hold; lookup duration returns to its prior distribution",
        verification="lookup duration from inside a pod rises during the window and returns to "
        "baseline",
    ),
    _m(
        "k8s.dns_timeout",
        FailureMode.LATENCY,
        also=(FailureMode.DEPENDENCY,),
        mechanism="cluster DNS lookups are held past the resolver's own timeout, so the resolver "
        "gives up rather than the server answering slowly",
        symptom="resolution fails by timeout rather than by error, which attributes the failure to "
        "the caller instead of to DNS — the same misattribution as any timeout fault, and "
        "the reason the recovery guidance names the resolver",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="remove the hold; lookups return answers again, and the cache repopulates over "
        "the following interval",
        verification="lookup attempts from inside a pod time out during the window and return "
        "answers after undo",
    ),
    _m(
        "k8s.configmap_corrupt",
        FailureMode.CORRECTNESS,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a mounted ConfigMap's content is altered so it is no longer the configuration "
        "the application was written against",
        symptom="consumers fail to parse the config, and a mounted file changes underneath a "
        "running pod — which many applications never re-read, so the damage is uneven "
        "across the fleet",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the ConfigMap content. A pod that read the bad value at startup keeps it "
        "until it is restarted, so recovery is not fleet-wide even when it appears to be",
        verification="the mounted content changes and consumers fail, then both recover after undo",
    ),
    _m(
        "k8s.secret_unavailable",
        FailureMode.SECURITY_CONTROL_FAILURE,
        also=(FailureMode.AVAILABILITY,),
        mechanism="a Secret referenced by the pod is missing or becomes unreadable, so a control "
        "the application depends on is simply absent",
        symptom="the pod cannot start (a missing key or a container-config error), or a running "
        "pod loses access to the value on its next refresh",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the Secret. A pod that started with a cached value may keep working, "
        "which makes the recovery look partial rather than complete",
        verification="the pod reports the secret error and a consumer of the value fails, then "
        "both recover after undo",
    ),
    _m(
        "k8s.image_pull_failure",
        FailureMode.CLOUD,
        also=(FailureMode.AVAILABILITY, FailureMode.DEPENDENCY),
        mechanism="the image reference cannot be resolved or the pull is denied, so the kubelet "
        "cannot obtain the image the pod asked for",
        symptom="the pod sits in ErrImagePull or ImagePullBackOff and never starts. The failure is "
        "in the kubelet's event stream rather than in the workload, so a workload "
        "dashboard shows nothing at all",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="fix the reference, the registry credentials, or the private registry "
        "configuration; the kubelet retries with backoff, so recovery is observed on a "
        "later attempt rather than immediately",
        verification="the pod is in ImagePullBackOff with the pull error event, then reaches "
        "Running after undo",
    ),
    _m(
        "k8s.image_pull_slow",
        FailureMode.CLOUD,
        also=(FailureMode.LATENCY, FailureMode.DEPENDENCY),
        mechanism="the registry would be paced so the pull takes far longer than usual, which is a "
        "provider-side rate limit rather than a workload problem",
        symptom=_REFUSED_NOTHING_INJECTED
        + "; the expected outcome is the plan-time refusal naming the registry-pacing gap",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="none from this entry — it is refused, and it is catalog-only for that reason "
        "rather than for want of a mapping: pacing somebody else's registry from inside a "
        "fault injection is not something mayhem should be doing to a shared service",
        verification="the plan-time refusal is the result: an experiment naming this fault is "
        "refused with the registry-pacing reason and never reaches a target",
        refusal="catalog-only: registry pacing has no implementation, so the entry is refused at "
        "plan time rather than injected",
    ),
    _m(
        "k8s.pod_image_pull_delay",
        FailureMode.LATENCY,
        also=(FailureMode.CLOUD,),
        mechanism="the image pull is slowed so the container starts much later than usual, without "
        "failing",
        symptom="pod startup is delayed while the pod sits in ContainerCreating. The readiness "
        "clock has not started yet, so a naive latency SLO shows no breach at all during "
        "the delay",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="remove the delay; the container starts on its normal schedule",
        verification="image pull duration rises during the window and returns to baseline",
    ),
    _m(
        "k8s.persistent_volume_delay",
        FailureMode.LATENCY,
        also=(FailureMode.STORAGE,),
        mechanism="volume I/O is held before completing, so the storage substrate is slow rather "
        "than unavailable",
        symptom="every operation touching the volume is slow, including mount-dependent startup, "
        "so pods appear to hang rather than to fail",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="release the hold; queued I/O drains, so recovery completes only once the queue "
        "has emptied",
        verification="volume read latency rises during the window and returns to baseline",
    ),
    _m(
        "k8s.persistent_volume_error",
        FailureMode.STORAGE,
        also=(FailureMode.AVAILABILITY, FailureMode.DURABILITY),
        mechanism="volume I/O returns errors, so the substrate fails to deliver rather than merely "
        "delivering slowly",
        symptom="reads and writes fail with an I/O error, and the filesystem may be remounted "
        "read-only — which turns an availability fault into a durability one, since "
        "anything written in between is in doubt",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the volume backend. Data written during the failure window is not "
        "recovered by mayhem and its durability is unproven until it has been read back",
        verification="volume I/O probes fail during the window and succeed after undo",
    ),
    _m(
        "k8s.persistent_volume_detach",
        FailureMode.STORAGE,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the volume is force-detached from its node, so the pod loses the volume it was "
        "mounted against",
        symptom="the pod's volume access fails hard. An attached-but-wrong node can hold the "
        "volume, and a multi-attach error leaves both pods unable to mount it — the worst "
        "outcome in the catalog, and the reason its risk is critical",
        risk=RiskLevel.CRITICAL,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="reattach the volume to a node that can mount it. The data is intact; what is "
        "lost is availability, and any write in flight at the moment of detach is in "
        "doubt",
        verification="the volume reports detached or Multi-Attach and pod volume mounts fail, then "
        "recover after undo",
    ),
    _m(
        "k8s.persistent_volume_mount_failure",
        FailureMode.AVAILABILITY,
        also=(FailureMode.STORAGE,),
        mechanism="the volume cannot be mounted into the pod, so the pod never reaches Running",
        symptom="the pod stays Pending or ContainerCreating with a mount event, and the workload's "
        "capacity never materialises at all",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the volume's mountability. A pod stuck in ContainerCreating does not "
        "retry onto another node by itself, so this needs the storage side fixed rather "
        "than patience",
        verification="the pod reports the mount event and never reaches Running during the window",
    ),
    _m(
        "k8s.persistent_volume_claim_pending",
        FailureMode.CAPACITY,
        also=(FailureMode.STORAGE,),
        mechanism="a PersistentVolumeClaim cannot be bound to a volume, so the pod waiting on it "
        "cannot start either",
        symptom="the claim is Pending and the dependent pod cannot start. In a StatefulSet this "
        "blocks every ordinal after it, so one unbound claim can stop a whole ordered "
        "workload",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="provide a matching volume or adjust the claim's request; the binder retries, so "
        "a relief shows up without further action",
        verification="the claim is Pending and the dependent pod remains unscheduled during the "
        "window",
    ),
    _m(
        "k8s.resource_quota_exhaust",
        FailureMode.RESOURCE_EXHAUSTION,
        also=(FailureMode.CAPACITY,),
        mechanism="the namespace's resource quota is consumed, so the admission controller refuses "
        "any new pod that would exceed it",
        symptom="pod creation is rejected with a quota error while every existing pod is "
        "unaffected — a failure of new work only, which is easily mistaken for a "
        "scheduling problem because the pod also does not run",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="release quota by deleting objects or raising the limit. Rejected pods are not "
        "retried automatically, so a pod admitted after the fix has to be created again",
        verification="a pod creation attempt is rejected with a quota event and admitted after "
        "undo",
    ),
    _m(
        "k8s.hpa_scale_delay",
        FailureMode.LATENCY,
        also=(FailureMode.CAPACITY,),
        mechanism="the autoscaler's metrics arrive late, so its scaling decisions are made on "
        "stale data",
        symptom="load is met by existing capacity for longer than it should be, and the autoscaler "
        "reports a stale metric rather than no metric — which is what makes the delay so "
        "hard to see from outside",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore metrics delivery. A delayed scale-up under sustained load becomes an SLO "
        "breach that the autoscaler's own graph shows as nothing at all",
        verification="the autoscaler's last-scale time lags the load increase during the window "
        "and catches up after undo",
    ),
    _m(
        "k8s.hpa_scale_failure",
        FailureMode.CAPACITY,
        also=(FailureMode.AVAILABILITY,),
        mechanism="the autoscaler cannot read its metrics, or cannot act on the ones it reads",
        symptom="the replica count is stuck while load grows, and the autoscaler's own conditions "
        "report a metrics failure — so the object says it is failing rather than simply "
        "not scaling, which is the more useful of the two signals",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the metrics pipeline or the autoscaler's configuration; until it can "
        "act, the workload's capacity is fixed at whatever it happened to be",
        verification="the autoscaler's conditions report a metrics failure and replicas do not "
        "change under load",
    ),
    _m(
        "k8s.hpa_oscillation",
        FailureMode.LATENCY,
        also=(FailureMode.CAPACITY,),
        mechanism="the autoscaler scales up and down repeatedly around its target metric instead "
        "of settling on a value",
        symptom="the replica count oscillates and pods are created and destroyed continuously, so "
        "cold-start cost is paid over and over and the service is less available than at "
        "any stable scale would be",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="add scale-down stabilisation or widen the target range. Without one the "
        "oscillation continues indefinitely, so the end of the fault window is not the "
        "end of the finding",
        verification="replicas change repeatedly in both directions during the window and settle "
        "after undo",
    ),
    # -- kubernetes: decisions a person has to make -------------------------------
    _m(
        "k8s.rollout_pause",
        FailureMode.HUMAN_OPERATOR,
        also=(FailureMode.AVAILABILITY,),
        mechanism="an in-progress rollout is paused with the controller's pause annotation, so the "
        "controller stops acting on the Deployment",
        symptom="the workload sits part-way between two ReplicaSets: new pods are not created and "
        "old ones are not removed. Traffic is served by the old version and the rollout "
        "simply stops, which a status dashboard reports as healthy",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="resume the rollout. Until then the version in service is whatever was serving "
        "when the pause was set, so a paused rollout is a deployment that will not reach "
        "its own declared version",
        verification="the rollout's paused condition is true during the window and false after "
        "undo",
    ),
    _m(
        "k8s.rollout_failure",
        FailureMode.HUMAN_OPERATOR,
        also=(FailureMode.AVAILABILITY, FailureMode.CORRECTNESS),
        mechanism="the new ReplicaSet cannot become ready, so the rollout stalls or is marked "
        "failed with the old version still serving",
        symptom="some pods run the old version and some the new, so traffic is split across two "
        "behaviours and a bug report from that window may describe either one",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="roll back to the previous ReplicaSet. A rollout left stalled holds both versions "
        "indefinitely, so the version split is not a transient state to be waited out",
        verification="the rollout's progress condition reports failure and the old ReplicaSet is "
        "still serving",
    ),
    _m(
        "k8s.pdb_violation",
        FailureMode.HUMAN_OPERATOR,
        also=(FailureMode.AVAILABILITY,),
        mechanism="an eviction is attempted that the workload's disruption budget forbids, so the "
        "request is accepted and the eviction does not happen",
        symptom="the drain stalls with the eviction blocked. A node drain that appears to hang is "
        "usually waiting on a budget rather than on a pod, and nothing is failing while it "
        "waits",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="adjust the budget or the workload's replica count. A budget that admits nothing "
        "blocks all voluntary disruption indefinitely, which is a designed deadlock "
        "rather than a fault to retry",
        verification="the eviction is denied with a budget-related event and the pod remains "
        "running",
    ),
    _m(
        "k8s.pdb_over_eviction",
        FailureMode.HUMAN_OPERATOR,
        also=(FailureMode.AVAILABILITY,),
        mechanism="more pods are evicted than the disruption budget intended to allow, so the "
        "budget exists and does not hold",
        symptom="availability falls below the budget's own floor. A budget that permits more than "
        "it accounts for is worse than none, because it is trusted as a guarantee",
        risk=RiskLevel.HIGH,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="restore the budget's floor before the next drain. Pods already evicted are the "
        "outage, and restoring the budget does not restore them",
        verification="ready replicas fall below the budget's minimum available during the window",
    ),
    _m(
        "k8s.eviction_block",
        FailureMode.HUMAN_OPERATOR,
        also=(FailureMode.AVAILABILITY,),
        mechanism="eviction is blocked for the workload by its budget, so a deliberate action by a "
        "person has no effect",
        symptom="node drains and cluster upgrades stall part-way. Nothing is failing and nothing "
        "is progressing, which is the hardest class of incident to diagnose from metrics "
        "alone",
        risk=RiskLevel.MEDIUM,
        method=VerificationMethod.KUBERNETES_OBJECT,
        recovery="raise the budget's minimum available or add replicas before retrying the drain; "
        "the retry on its own will be refused identically",
        verification="the eviction request is refused during the window and accepted after undo",
    ),
)

_MAPPINGS_BY_FAULT: Final[dict[str, FaultFailureMapping]] = {
    mapping.fault_id: mapping for mapping in _MAPPINGS
}

if len(_MAPPINGS_BY_FAULT) != len(_MAPPINGS):  # pragma: no cover - table-authoring guard
    _duplicates = sorted(
        fault_id
        for fault_id in _MAPPINGS_BY_FAULT
        if sum(1 for mapping in _MAPPINGS if mapping.fault_id == fault_id) > 1
    )
    raise InvariantViolationError(
        "failure_mode.duplicate", f"failure-mode table has duplicate fault ids: {_duplicates}"
    )
