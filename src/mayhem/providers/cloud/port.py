"""The cloud transport port and the adapter contract (v1.1.0 plan 06, Phase 2).

Phase 1 shipped the *words* of a cloud fault in :mod:`mayhem.domain.cloud` and
no IO at all. This module is where those words meet a provider, and the whole
design exists to keep one constraint honest: **Mayhem's declared dependencies
are pydantic, typer, click, pyyaml, structlog and kubernetes** — there is no
boto3, no google-cloud, no azure-mgmt, and this phase does not add one. So an
adapter cannot call a cloud API directly, and pretending otherwise would mean
either an undeclared dependency or a hand-rolled HTTP client pretending to be an
SDK.

Instead the cloud lives behind :class:`CloudTransport`, a three-call port, and
everything above it is provider-neutral:

    list_resources(query) -> records        # enumerate one class, one account/region
    read_resource(query, resource_id)      # one fresh read, for verification
    mutate(command) -> receipt             # one provider-native operation call

That is the seam. A later phase binds boto3 (or the Google or Azure SDK) to this
port by translating SDK exceptions into :class:`TransportFailure` and SDK
payloads into :class:`ResourceRecord`/:class:`MutationReceipt`. **Nothing in this
package opens a socket, and no real cloud SDK is wired.** The port *is* the
deliverable, and that it is unbound is stated rather than papered over.

**Where the provider-specific knowledge lives.** With no SDK there is one thing
an adapter still genuinely knows, and it is a *table*, not code: which
provider-native operation each :class:`~mayhem.domain.cloud.CloudActionKind`
means for each resource class, what the compensating operation is, and which
fields verify reads to decide.
:class:`ReversibleCapability` and :class:`IrreversibleCapability` are separate
models over a shared :class:`ActionCapability` base for the same reason Phase 1
made ``ReversibleCloudAction`` and ``IrreversibleCloudAction`` separate: an
adapter that cannot roll an action back has no ``compensate_operation`` field to
fill in, because the field does not exist on the model it is declared with and
the model forbids extras. There is no per-provider branch anywhere in the
lifecycle — :class:`CloudAdapter` implements it once — so a new provider adds
rows, not special cases.

**Cost, honestly.** Mayhem bundles no price table. So an estimate is either
priced from an operator-supplied :class:`CloudRateCard` — which carries its own
``source``, because Mayhem cannot vouch for numbers it did not read — or it is
explicitly UNPRICED: ``expected_low == expected_high == 0.0`` with the operation
counts (API calls, instance-hours, volume operations) disclosed in the
``basis``, where a ``0.0`` means *unknown*, never *free*. The pre-execution gate
then refuses an UNPRICED action whenever a ceiling was actually declared
(:data:`CLOUD_COST_UNPRICED`): Mayhem cannot certify that an action it cannot
price fits a limit somebody wrote down. ``ceiling == 0.0`` means *no ceiling was
declared*, which is the same default-deny posture as
``DEFAULT_CLOUD_ROLE_GRANTS = frozenset()`` — nothing is assumed.

**Counts are counted, not estimated.** Every result carries ``api_calls``: the
number of transport round-trips the step actually made, metered at the port
boundary. The cost estimate *projects* the calls an action will make (including
a reserve for compensation and its verification); the count on the returned
result is *measured*. Where the two differ the measured one is the truth, which
is exactly the distinction a fabricated dollar figure would erase.

**No silent success.** Every public method returns a typed record carrying
``StepOutcome``/``TargetOutcome``, never a string, and a ``COMPLETED`` mutating
result is *unconstructible* without a verification that confirmed.
"""

from __future__ import annotations

from abc import ABC
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mayhem.domain.budgets import RESOURCE_PRECISION, ResourceScope
from mayhem.domain.cloud import (
    CLOUD_PERMISSION_DENIED,
    CLOUD_ROLE_PROVIDER_MISMATCH,
    CloudAction,
    CloudActionKind,
    CloudProviderRef,
    CloudRefused,
    CloudResourceClass,
    CloudResourceIdentity,
    CloudRoleRef,
    CloudSelector,
    CloudSelectorKind,
    CloudSpec,
    CloudTarget,
    CloudTargetIntent,
    CostCeilingDecision,
    CostEstimate,
    ReversibleCloudAction,
    check_cost_ceiling,
    check_role_can_perform,
    ensure_selector_is_specific,
    requires_elevated_approval,
    resolve_cloud_target,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.domain.provider import ProviderPermission
from mayhem.providers.permissions import ProviderPermissionSet

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "CLOUD_ACTION_UNSUPPORTED",
    "CLOUD_COMPENSATION_UNAVAILABLE",
    "CLOUD_COST_UNPRICED",
    "CLOUD_DURATION_REQUIRED",
    "CLOUD_IDENTITY_UNREPRESENTABLE",
    "CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED",
    "CLOUD_RECEIPT_MISMATCH",
    "CLOUD_RESOURCE_CONFLICT",
    "CLOUD_TRANSPORT_FAILURE",
    "CLOUD_UNKNOWN_RESOURCE_CLASS",
    "CLOUD_VERIFICATION_FAILED",
    "CLOUD_VERIFICATION_UNAVAILABLE",
    "ActionCapability",
    "CloudAdapter",
    "CloudAdapterError",
    "CloudCapability",
    "CloudOperationCounts",
    "CloudPermissionAnalysis",
    "CloudRateCard",
    "CloudRoleRef",
    "CloudStep",
    "CloudStepResult",
    "CloudTransport",
    "CompensationResult",
    "DiscoveryRequest",
    "DiscoveryResult",
    "ExecutionResult",
    "ExpectedState",
    "IrreversibleCapability",
    "MutationCommand",
    "MutationReceipt",
    "PreflightResult",
    "ResolutionResult",
    "ResourceQuery",
    "ResourceRecord",
    "ReversibleCapability",
    "TransportConflict",
    "TransportFailure",
    "VerificationOutcome",
    "VerifyPhase",
]


# --- refusal codes ------------------------------------------------------------
#
# Phase 1 named the codes an adapter, a CLI renderer or an evidence record may
# branch on, and those are reused verbatim rather than re-spelled:
# ``CLOUD_SELECTOR_WILDCARD``, ``CLOUD_SELECTOR_EMPTY``,
# ``CLOUD_TARGET_UNRESOLVED``, ``CLOUD_AMBIGUOUS_RESOLUTION``,
# ``CLOUD_PERMISSION_DENIED``, ``CLOUD_ROLE_PROVIDER_MISMATCH`` and
# ``CLOUD_COST_CEILING_EXCEEDED`` all arrive here straight from
# :mod:`mayhem.domain.cloud`. The codes below are the ones Phase 2 needed and
# Phase 1 had no vocabulary for: what an adapter says when it does not implement
# an action, will not pay for one it cannot price, or cannot undo.

CLOUD_ACTION_UNSUPPORTED = "cloud.action_unsupported"
CLOUD_COMPENSATION_UNAVAILABLE = "cloud.compensation_unavailable"
CLOUD_COST_UNPRICED = "cloud.cost_unpriced"
CLOUD_DURATION_REQUIRED = "cloud.duration_required"
CLOUD_IDENTITY_UNREPRESENTABLE = "cloud.identity_unrepresentable"
CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED = "cloud.irreversible_approval_required"
CLOUD_RECEIPT_MISMATCH = "cloud.receipt_mismatch"
CLOUD_RESOURCE_CONFLICT = "cloud.resource_conflict"
CLOUD_TRANSPORT_FAILURE = "cloud.transport_failure"
CLOUD_UNKNOWN_RESOURCE_CLASS = "cloud.unknown_resource_class"
CLOUD_VERIFICATION_FAILED = "cloud.verification_failed"
CLOUD_VERIFICATION_UNAVAILABLE = "cloud.verification_unavailable"


class CloudStep(StrEnum):
    """The five lifecycle steps plus the three pre-execution analyses.

    Named so an evidence record can say which step produced a decision without
    parsing prose. Each concrete result pins its own ``step`` through
    :attr:`CloudStepResult.expected_step`, so a ``CostPreview`` cannot be filed
    as an ``ExecutionResult`` even by a caller who sets the field by hand.
    """

    DISCOVER = "discover"
    RESOLVE = "resolve"
    ESTIMATE_COST = "estimate_cost"
    ANALYZE_PERMISSION = "analyze_permission"
    EXECUTE = "execute"
    COMPENSATE = "compensate"
    VERIFY = "verify"


class VerifyPhase(StrEnum):
    """Which post-condition verify is being asked about.

    Not a boolean: an action has two distinct observable states, the one the
    action produced and the one compensation restores, and both are provider
    field assertions. A verify that could only ask "did it work?" could not tell
    a successful rollback from a successful fault.
    """

    APPLIED = "applied"
    COMPENSATED = "compensated"


# --- the transport port --------------------------------------------------------


class TransportFailure(RuntimeError):  # noqa: N818 — public API, not a stdlib error
    """A remote call failed.

    **The binding's obligation.** Every exception an SDK raises for a remote
    failure must be translated into this type (or :class:`TransportConflict`) by
    the binding, because the adapter boundary catches exactly this and
    :class:`CloudAdapterError`. Mayhem deliberately does not catch bare
    ``Exception`` there: a bug inside Mayhem must not be able to masquerade as a
    cloud refusal. The price of that choice is that a binding which forgets to
    wrap an SDK exception produces a traceback rather than a ``StepOutcome`` —
    a louder failure, on purpose.

    Attributes:
        provider: The cloud key the call was addressed to.
        operation: The provider-native operation name, verbatim.
        message: The binding's own description of the failure.
    """

    def __init__(self, provider: str, operation: str, message: str) -> None:
        self.provider = provider
        self.operation = operation
        self.message = message
        super().__init__(f"{provider} {operation!r} failed: {message}")


class TransportConflict(TransportFailure):
    """The cloud refused the call because of the resource's current state.

    Distinct from a plain failure because the cloud's answer is meaningful: "an
    instance that is already stopped cannot be stopped" is contention with the
    resource's own lifecycle, not an outage, and it maps to
    :attr:`TargetOutcome.RESOURCE_CONFLICT` rather than
    :attr:`TargetOutcome.FAILED_TO_APPLY`.
    """


class ResourceQuery(BaseModel):
    """What to enumerate: one resource class, in one account, in one region.

    ``service`` is the provider-native collection the record came from — ``ec2``
    on AWS, ``compute`` on GCP and on Azure, ``sqladmin`` on GCP — declared by
    the adapter's own table rather than guessed here. It is the information a
    real binding needs to pick a client and a method, and it travels with the
    query so the binding has to know nothing about Mayhem.
    """

    model_config = ConfigDict(frozen=True)

    provider: CloudProviderRef
    resource_class: CloudResourceClass
    account: str
    region: str
    service: str = Field(min_length=1)

    def describe(self) -> str:
        return f"{self.service}/{self.resource_class.value} in {self.account}/{self.region}"


class ResourceRecord(BaseModel):
    """One resource as the transport reports it.

    ``fields`` is the provider's own state, **verbatim and unrenamed**
    (``State.Name`` on EC2, ``powerState`` on Azure, ``status`` on Cloud SQL).
    Verification compares those keys, so renaming them here would mean the
    evidence record no longer matches the console an operator is looking at.
    """

    model_config = ConfigDict(frozen=True)

    query: ResourceQuery
    resource_id: str
    tags: frozenset[str] = frozenset()
    fields: dict[str, str] = Field(default_factory=dict)

    def identity(self) -> CloudResourceIdentity:
        """This record as an exact :class:`CloudResourceIdentity`.

        Raises:
            ValidationError: If the transport reported something Mayhem cannot
                represent — an empty id, or a tag carrying a glob metacharacter.
                The adapter converts that into a failed discovery rather than
                letting an unrepresentable resource reach an inventory.
        """
        return CloudResourceIdentity(
            provider=self.query.provider,
            resource_class=self.query.resource_class,
            account=self.query.account,
            region=self.query.region,
            resource_id=self.resource_id,
            tags=self.tags,
        )


class MutationCommand(BaseModel):
    """One provider-native operation against one exact resource.

    ``operation`` is the name from the adapter's capability table, carried
    verbatim (``ec2:StopInstances``, ``compute.instances.stop``,
    ``virtualMachines/powerOff``). A binding maps it to one SDK call; Mayhem
    never translates it, so an evidence record names the same operation the
    provider's own audit log will.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    operation: str = Field(min_length=1)
    query: ResourceQuery
    resource_id: str
    parameters: dict[str, str] = Field(default_factory=dict)

    @property
    def subject(self) -> str:
        """``operation on resource_id`` — what an audit log would call it."""
        return f"{self.operation} on {self.resource_id}"


class MutationReceipt(BaseModel):
    """The provider's answer to one :class:`MutationCommand`.

    A receipt is a **claim**, not evidence: it says the provider accepted the
    call. Nothing here is ``COMPLETED`` on a receipt alone —
    :meth:`CloudAdapter.execute` and :meth:`CloudAdapter.compensate` both verify
    afterwards, because an adapter that reported success from a receipt would be
    reading the cloud's async behaviour off a synchronous return value.
    """

    model_config = ConfigDict(frozen=True)

    operation: str = Field(min_length=1)
    resource_id: str
    request_id: str = Field(min_length=1)
    fields: dict[str, str] = Field(default_factory=dict)


@runtime_checkable
class CloudTransport(Protocol):
    """Three calls: enumerate, read once, act once.

    The smallest port that supports the five lifecycle steps. ``discover`` and
    ``resolve`` are both enumeration (the second narrows to exactly one);
    ``verify`` is a read; ``execute`` and ``compensate`` are the only two that
    mutate, and they differ only in ``operation``.

    The protocol is structural, so a binding is any object with these three
    methods — including the recorded-payload replay the tests use. **No
    implementation of this protocol ships in Mayhem**; there is no live binding.
    """

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]: ...

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None: ...

    def mutate(self, command: MutationCommand) -> MutationReceipt: ...


# --- verification --------------------------------------------------------------


class ExpectedState(BaseModel):
    """A post-condition expressed in the provider's own field names.

    Three assertion shapes, because cloud state is not only enumerable:
    ``equal`` (the field must hold this value), ``present`` (the field must
    exist and be non-empty) and ``absent`` (missing or empty). GCP's failover,
    for example, is observed by a ``failoverReplica`` block appearing — there is
    no value to compare against, and refusing to assert "a replica now exists"
    would mean never verifying a failover at all.

    An empty :class:`ExpectedState` is refused: a verify asserting nothing would
    return ``COMPLETED`` for any resource, including one that is perfectly
    healthy because the action never landed.
    """

    model_config = ConfigDict(frozen=True)

    equal: dict[str, str] = Field(default_factory=dict)
    present: tuple[str, ...] = ()
    absent: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_not_vacuous(self) -> ExpectedState:
        if not self.equal and not self.present and not self.absent:
            raise ValueError(
                "expected state asserts nothing; a verify with no assertion would "
                "confirm any resource, including one the action never touched"
            )
        overlap = sorted(set(self.present) & set(self.absent))
        if overlap:
            raise ValueError(
                f"expected state requires field(s) {', '.join(overlap)} to be both "
                "present and absent"
            )
        return self

    def check(self, observed: Mapping[str, str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Return ``(matched, violated)`` against *observed* provider fields."""
        matched: list[str] = []
        violated: list[str] = []
        for key, value in sorted(self.equal.items()):
            if observed.get(key) == value:
                matched.append(key)
            else:
                violated.append(f"{key}={observed.get(key, '<absent>')!r} != {value!r}")
        for key in self.present:
            if observed.get(key):
                matched.append(key)
            else:
                violated.append(f"{key} is absent or empty")
        for key in self.absent:
            if observed.get(key):
                violated.append(f"{key}={observed[key]!r} is present")
            else:
                matched.append(key)
        return tuple(matched), tuple(violated)

    def describe(self) -> str:
        parts = [f"{k}={v!r}" for k, v in sorted(self.equal.items())]
        parts += [f"{k} present" for k in self.present]
        parts += [f"{k} absent" for k in self.absent]
        return ", ".join(parts)


class VerificationOutcome(BaseModel):
    """What a fresh read said about the expected state.

    ``evidence`` is the string an evidence record would persist: the observed
    provider fields, not an opinion about them.
    """

    model_config = ConfigDict(frozen=True)

    outcome: StepOutcome
    target_outcome: TargetOutcome | None = None
    phase: VerifyPhase = VerifyPhase.APPLIED
    expected: ExpectedState
    observed: dict[str, str] = Field(default_factory=dict)
    matched: tuple[str, ...] = ()
    violated: tuple[str, ...] = ()
    resource_present: bool = True
    reason: str = ""
    api_calls: int = Field(default=0, ge=0)

    @property
    def confirmed(self) -> bool:
        """True when the read found the resource *and* every assertion held."""
        return self.outcome is StepOutcome.COMPLETED and self.resource_present

    @property
    def evidence(self) -> str:
        fields = ", ".join(f"{k}={v!r}" for k, v in sorted(self.observed.items()))
        return f"{self.expected.describe()} | observed: {fields or '<no fields>'}"


# --- capabilities --------------------------------------------------------------


class ActionCapability(BaseModel):
    """What one provider can do to one class for one action kind.

    The shared half. ``execute_operation`` is the provider-native name;
    ``billable_instance_hours`` states whether the action leaves the resource in
    a billable compute state for its duration; ``volume_operations`` counts
    volume operations the action performs.

    The last two are *declarations about the provider*, not measurements — they
    are what makes a cost estimate disclosable instead of blank, and they are
    asserted by this table rather than discovered at runtime so a reviewer can
    read the claim instead of trusting it. An adapter that has not demonstrated
    one of these on a sandbox account (the plan's Phase 2 acceptance) is making
    the declaration only, and the STATUS ledger says so.

    There is deliberately **no post-condition field on the shared base**. Only a
    capability with a compensation can state one: see
    :class:`ReversibleCapability` and :class:`IrreversibleCapability`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: CloudActionKind
    resource_class: CloudResourceClass
    service: str = Field(min_length=1)
    execute_operation: str = Field(min_length=1)
    summary: str = Field(min_length=1, max_length=300)
    billable_instance_hours: bool = False
    volume_operations: int = Field(default=0, ge=0)

    @property
    def key(self) -> tuple[CloudActionKind, CloudResourceClass]:
        """The ``(kind, class)`` pair this capability is filed under."""
        return (self.kind, self.resource_class)

    @property
    def label(self) -> str:
        """``kind/class`` — how a capability matrix names this row."""
        return f"{self.kind.value}/{self.resource_class.value}"


class ReversibleCapability(ActionCapability):
    """A capability with a compensating operation that preserves the identity.

    ``compensate_operation`` is required and so are both post-conditions:
    ``apply_verify`` is what :meth:`CloudAdapter.execute` checks and
    ``compensate_verify`` is what :meth:`CloudAdapter.compensate` checks. A
    compensation that cannot be verified is therefore not declarable. The plan's
    acceptance criterion ("every adapter action demonstrates
    compensate→verify") is pushed into the type rather than left to a review
    checklist.
    """

    compensate_operation: str = Field(min_length=1)
    apply_verify: ExpectedState
    compensate_verify: ExpectedState


class IrreversibleCapability(ActionCapability):
    """A capability the provider cannot roll back.

    There is no ``compensate_operation`` field on this model and
    ``extra="forbid"`` is inherited from :class:`ActionCapability`, so passing
    one is a validation error rather than a silently ignored argument. That is
    the mechanism: an adapter that cannot undo something has no field in which
    to say it can. ``rationale`` is required for the same reason
    :class:`~mayhem.domain.cloud.IrreversibleCloudAction` requires one — "we
    could not think of a rollback" has to be written down before execution
    rather than discovered during an incident.

    **No post-condition, on purpose.** The only post-state a destructive
    operation can honestly assert is *absence*, and Phase 1's vocabulary has no
    rung for it: :attr:`StepOutcome.TARGET_DRIFT` means the planned identity is
    no longer the object present, which is the opposite claim from "the resource
    was destroyed as intended". So :meth:`CloudAdapter.verify` refuses an
    irreversible capability with :data:`CLOUD_VERIFICATION_UNAVAILABLE` rather
    than filing a confirmed deletion as drift. An irreversible action that left
    a resource present and observable would need a post-condition field added
    here, which is a later phase's call to make rather than this one's.
    """

    rationale: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _check_rationale(self) -> IrreversibleCapability:
        if not self.rationale.strip():
            raise ValueError(
                f"irreversible {self.kind.value}/{self.resource_class.value} must state "
                "why the cloud cannot roll it back"
            )
        return self


type CloudCapability = ReversibleCapability | IrreversibleCapability
"""Any declared capability. A gate holding this union must branch on which model
it received, so "no compensation" can never be treated as a missing field."""


# --- cost ----------------------------------------------------------------------


class CloudOperationCounts(BaseModel):
    """The quantities a cost estimate is built from, every one of them countable.

    ``api_calls`` is *projected* here; the *measured* count lands in
    :attr:`CloudStepResult.api_calls` and is what a post-run evidence record
    should compare against this projection.
    """

    model_config = ConfigDict(frozen=True)

    api_calls: int = Field(ge=0)
    instance_hours: float = Field(ge=0.0)
    volume_operations: int = Field(ge=0)
    duration_s: float | None = None

    def describe(self) -> str:
        hours = "unknown" if self.duration_s is None else f"{self.instance_hours:.6g}"
        return (
            f"api_calls={self.api_calls}, instance_hours={hours}h, "
            f"volume_operations={self.volume_operations}"
        )


class CloudRateCard(BaseModel):
    """Operator-supplied unit rates for one provider/class/region.

    **Mayhem bundles no prices and ships no price table.** This model exists so
    a *priced* estimate is possible for somebody who holds a rate card, and it
    carries a mandatory ``source`` because a number Mayhem cannot trace is a
    number a reviewer must refuse to trust. No cloud SDK, no pricing API and no
    currency conversion happens anywhere in this package.

    ``high_factor`` widens the low bound into the high bound, standing in for
    the uncertainty a real rate card's ranges carry. ``ge=1.0`` by construction,
    so a card can never produce an inverted range.
    """

    model_config = ConfigDict(frozen=True)

    provider: CloudProviderRef
    resource_class: CloudResourceClass
    region: str
    source: str = Field(min_length=1)
    micros_per_api_call: float = Field(default=0.0, ge=0.0)
    micros_per_instance_hour: float = Field(default=0.0, ge=0.0)
    micros_per_volume_operation: float = Field(default=0.0, ge=0.0)
    high_factor: float = Field(default=1.0, ge=1.0)

    def covers(
        self, provider: CloudProviderRef, resource_class: CloudResourceClass, region: str
    ) -> bool:
        """True when this card's rates apply to exactly this target."""
        return (
            self.provider == provider
            and self.resource_class is resource_class
            and self.region == region
        )

    def price(self, counts: CloudOperationCounts) -> tuple[float, float]:
        """Return ``(low, high)`` in ``currency_micros`` for *counts*."""
        low = (
            counts.api_calls * self.micros_per_api_call
            + counts.instance_hours * self.micros_per_instance_hour
            + counts.volume_operations * self.micros_per_volume_operation
        )
        return low, low * self.high_factor


# --- requests and results ------------------------------------------------------


class DiscoveryRequest(BaseModel):
    """Enumerate one resource class in one account/region.

    Deliberately not a :class:`~mayhem.domain.cloud.CloudSelector`: a selector
    must name at least one exact identifier or tag, because a selector resolves
    to *a* resource. Enumeration asks a different question — "what is here?" —
    and its answer is one exact intent per resource, which is the shape
    :data:`CLOUD_AMBIGUOUS_RESOLUTION`'s remediation asks a plan to be written
    in.

    ``identifiers`` and ``tags`` are an optional *narrowing*, and when either is
    supplied it is held to the same exact-match rule a selector is: a glob
    metacharacter is refused with :data:`CLOUD_SELECTOR_WILDCARD` before any call
    reaches the transport.
    """

    model_config = ConfigDict(frozen=True)

    provider: CloudProviderRef
    resource_class: CloudResourceClass
    account: str
    region: str
    identifiers: tuple[str, ...] = ()
    tags: frozenset[str] = frozenset()


class CloudStepResult(BaseModel):
    """Common shape of everything an adapter returns.

    A failure is a typed ``outcome`` plus a machine-readable ``code`` and
    structured ``details`` — never a bare string, and never an exception a caller
    must catch to learn what happened. ``api_calls`` is metered at the port
    boundary, so it counts calls that actually happened.

    ``expected_step`` is what pins ``step``: it is a class variable, so each
    result type declares the step it is allowed to carry and a
    ``CostPreview`` mislabelled as an ``ExecutionResult`` is refused rather than
    filed.
    """

    model_config = ConfigDict(frozen=True)

    step: CloudStep
    outcome: StepOutcome
    expected_step: ClassVar[CloudStep | None] = None
    target_outcome: TargetOutcome | None = None
    code: str = ""
    reason: str = ""
    details: dict[str, object] = Field(default_factory=dict)
    api_calls: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _check_step(self) -> CloudStepResult:
        expected = type(self).expected_step
        if expected is not None and self.step is not expected:
            raise ValueError(
                f"{type(self).__name__} carries step {self.step.value!r}, but only "
                f"{expected.value!r} is valid for it"
            )
        return self

    @property
    def ok(self) -> bool:
        """True when the step completed."""
        return self.outcome is StepOutcome.COMPLETED

    @property
    def denied(self) -> bool:
        """True when the step did not complete."""
        return not self.ok


class DiscoveryResult(CloudStepResult):
    """What enumeration found: the exact identities, and one intent each."""

    step: CloudStep = CloudStep.DISCOVER
    expected_step: ClassVar[CloudStep | None] = CloudStep.DISCOVER
    identities: tuple[CloudResourceIdentity, ...] = ()
    intents: tuple[CloudTargetIntent, ...] = ()
    query: ResourceQuery | None = None


class ResolutionResult(CloudStepResult):
    """A selector resolved to exactly one target — or was refused.

    ``target`` is non-``None`` only on success, and
    :func:`~mayhem.domain.cloud.resolve_cloud_target` is the only thing that can
    put one there, so a resolved result cannot exist without a selector that
    actually selected the identity it names.
    """

    step: CloudStep = CloudStep.RESOLVE
    expected_step: ClassVar[CloudStep | None] = CloudStep.RESOLVE
    target: CloudTarget | None = None
    identities: tuple[CloudResourceIdentity, ...] = ()


class CostPreview(BaseModel):
    """A cost estimate computed *before* execution, and what it is based on.

    ``priced`` is the honesty switch. ``False`` means ``expected_low`` and
    ``expected_high`` are both ``0.0`` **because Mayhem has no rate card for this
    target**, not because the action is free, and ``counts`` carries the
    quantities that *would* have to be priced. ``True`` means ``price_source``
    names the operator-supplied card the numbers came from.

    Not a :class:`CloudStepResult` because it is not a step on the lifecycle —
    it is an analysis run before one — but it reports the same outcome pair so
    a caller gates on one vocabulary.
    """

    step: CloudStep = CloudStep.ESTIMATE_COST
    outcome: StepOutcome
    target_outcome: TargetOutcome | None = None
    code: str = ""
    reason: str = ""
    counts: CloudOperationCounts
    priced: bool = False
    price_source: str = ""
    estimate: CostEstimate | None = None
    ceiling_decision: CostCeilingDecision | None = None
    details: dict[str, object] = Field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome is StepOutcome.COMPLETED

    @property
    def denied(self) -> bool:
        return not self.ok


class CloudPermissionAnalysis(CloudStepResult):
    """ "Can this role perform this action?", in the existing vocabulary.

    Two halves, reported together because a role can satisfy one and fail the
    other:

    * ``missing`` is what the *action* declared and the role lacks, from
      Phase 1's :func:`~mayhem.domain.cloud.check_role_can_perform`, which names
      each permission and reports a cross-provider role separately from a
      missing grant; and
    * ``adapter_missing`` is what the *adapter* needs in order to talk to the
      cloud at all — ``network`` and ``target:read`` — checked through the
      existing :class:`~mayhem.providers.permissions.ProviderPermissionSet`
      rather than a second permission model written here.

    The two existing models must answer identically or the analysis is refused
    (:data:`CLOUD_PERMISSION_DENIED`), because two disagreeing permission models
    means "can this role do it" has no single answer to report.
    """

    step: CloudStep = CloudStep.ANALYZE_PERMISSION
    expected_step: ClassVar[CloudStep | None] = CloudStep.ANALYZE_PERMISSION
    role_id: str
    missing: tuple[str, ...] = ()
    adapter_missing: tuple[str, ...] = ()


class _VerifiedStepResult(CloudStepResult):
    """Shared validator for the two mutating steps.

    ``COMPLETED`` requires a verification that confirmed. This is the
    "compensate that reports success without verify evidence is refused"
    requirement made structural: it is not merely refused downstream, it is
    *unconstructible*, so no caller, fixture or future subclass can hand anyone a
    successful mutation nobody checked.
    """

    receipt: MutationReceipt | None = None
    verification: VerificationOutcome | None = None

    @model_validator(mode="after")
    def _require_verification_for_success(self) -> _VerifiedStepResult:
        if self.outcome is StepOutcome.COMPLETED:
            if self.verification is None:
                raise ValueError(
                    f"{self.step.value} reported completed with no verification "
                    "evidence; a mutation is a claim until a fresh read confirms it"
                )
            if not self.verification.confirmed:
                raise ValueError(
                    f"{self.step.value} reported completed but its verification did "
                    f"not confirm: {self.verification.reason}"
                )
        return self


class ExecutionResult(_VerifiedStepResult):
    """The result of one :meth:`CloudAdapter.execute`."""

    step: CloudStep = CloudStep.EXECUTE
    expected_step: ClassVar[CloudStep | None] = CloudStep.EXECUTE
    target: CloudTarget | None = None
    estimate: CostEstimate | None = None


class CompensationResult(_VerifiedStepResult):
    """The result of one :meth:`CloudAdapter.compensate`.

    Carries the same evidence requirement as :class:`ExecutionResult` and asks
    ``verify`` about the *compensated* post-state rather than the applied one, so
    "the rollback was accepted" and "the rollback happened" stay two different
    claims.
    """

    step: CloudStep = CloudStep.COMPENSATE
    expected_step: ClassVar[CloudStep | None] = CloudStep.COMPENSATE


class PreflightResult(BaseModel):
    """Every pre-execution gate, run together before any mutation.

    Exists so the admission gate (plan 09) and the cost-ceiling hook (Phase 4)
    have one call site, and so the ordering is stated once: the first refusal
    wins, and nothing here touches the transport — ``api_calls`` is therefore
    always ``0``, which is the property worth having on a pre-mutation hook.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    allowed: bool
    permission: CloudPermissionAnalysis
    cost: CostPreview
    capability: CloudCapability | None = None
    reason: str = ""
    api_calls: int = 0

    def describe(self) -> str:
        if self.allowed:
            return f"preflight allows {self.action_id}"
        return f"preflight refuses {self.action_id}: {self.reason}"


# --- the adapter ---------------------------------------------------------------


class CloudAdapterError(Exception):
    """The single typed boundary an adapter converts into a failed result.

    Carries the outcome mapping so the conversion is stated once rather than at
    every ``except`` site: :class:`TransportConflict` becomes
    :attr:`TargetOutcome.RESOURCE_CONFLICT`, a plain transport failure becomes
    :attr:`TargetOutcome.FAILED_TO_APPLY`, and the exception carries the
    ``StepOutcome`` for the step that was running.
    """

    def __init__(
        self,
        *,
        code: str,
        reason: str,
        outcome: StepOutcome = StepOutcome.FAILED,
        target_outcome: TargetOutcome = TargetOutcome.FAILED_TO_APPLY,
        details: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.reason = reason
        self.outcome = outcome
        self.target_outcome = target_outcome
        self.details: dict[str, object] = dict(details or {})
        super().__init__(f"[{code}] {reason}")


class _CallMeter:
    """Counts transport round-trips for one public call.

    A per-call counter rather than a field on the adapter: adapters would be
    used from more than one thread in a real run, and a shared counter would make
    ``api_calls`` a lie under concurrency.
    """

    __slots__ = ("calls",)

    def __init__(self) -> None:
        self.calls = 0


def _code_of(exc: Exception) -> str:
    """The machine-readable code carried by any of the three boundary types."""
    if isinstance(exc, (CloudAdapterError, CloudRefused)):
        return exc.code
    if isinstance(exc, InvariantViolationError):
        return exc.rule
    return ""


def _details_of(exc: Exception) -> dict[str, object]:
    """The structured details carried by any of the three boundary types."""
    if isinstance(exc, (CloudAdapterError, CloudRefused)):
        return dict(exc.details)
    return {}


def _outcome_of(exc: Exception) -> StepOutcome:
    if isinstance(exc, CloudAdapterError):
        return exc.outcome
    return StepOutcome.FAILED


def _target_outcome_of(exc: Exception) -> TargetOutcome:
    if isinstance(exc, CloudAdapterError):
        return exc.target_outcome
    return TargetOutcome.FAILED_TO_APPLY


class CloudAdapter(ABC):
    """The provider contract every cloud adapter implements.

    Five lifecycle steps (:meth:`discover`, :meth:`resolve`, :meth:`execute`,
    :meth:`compensate`, :meth:`verify`) and three pre-execution analyses
    (:meth:`estimate_cost`, :meth:`analyze_permission`, :meth:`preflight`).

    **The lifecycle is implemented here, once.** A subclass supplies a *table* —
    :attr:`provider_key`, :attr:`services`, :attr:`capabilities` — and nothing
    else. That is what makes the three adapters testable against one conformance
    suite: a provider that adds an operation adds a row, and a provider that
    cannot undo something adds an :class:`IrreversibleCapability` row rather
    than a special case in the code.

    Every method catches :class:`CloudAdapterError`, :class:`CloudRefused` and
    :class:`InvariantViolationError` at its own boundary, so a refusal the domain
    made and a failure at the port reach the caller in one shape.
    """

    #: The cloud key this adapter speaks for, matching
    #: :attr:`~mayhem.domain.cloud.CloudProviderRef.key`.
    provider_key: ClassVar[str]
    #: Resource class -> provider-native service/collection name.
    services: ClassVar[Mapping[CloudResourceClass, str]]
    #: ``(kind, resource_class)`` -> capability. A pair absent from this table is
    #: reported unsupported; it is never approximated by a near-miss.
    capabilities: ClassVar[Mapping[tuple[CloudActionKind, CloudResourceClass], CloudCapability]]
    #: What the *adapter* needs, as opposed to what the *action* declares: it
    #: opens a network connection and reads targets. Checked through
    #: :class:`~mayhem.providers.permissions.ProviderPermissionSet`.
    adapter_permissions: frozenset[ProviderPermission] = frozenset(
        {ProviderPermission.NETWORK, ProviderPermission.TARGET_READ}
    )

    def __init__(
        self,
        transport: CloudTransport,
        *,
        rate_cards: Sequence[CloudRateCard] = (),
    ) -> None:
        self.transport = transport
        self.rate_cards: tuple[CloudRateCard, ...] = tuple(rate_cards)

    # -- the provider table ----------------------------------------------------

    def capability_for(self, action: CloudAction) -> CloudCapability | None:
        """The declared capability for *action*, or ``None`` if unsupported."""
        return self.capabilities.get((action.kind, action.target.resource_class))

    def service_for(self, resource_class: CloudResourceClass) -> str | None:
        """The provider-native service name for *resource_class*, if known."""
        return self.services.get(resource_class)

    def sandbox_permissions_for(self, role: CloudRoleRef) -> ProviderPermissionSet:
        """The role's grants expressed in the loader layer's permission model.

        Exposed so the integration is inspectable: the analysis below is not a
        parallel permission system written here, it is this existing type being
        asked the same question the domain asks, and the two answers are compared
        rather than assumed equal.
        """
        return ProviderPermissionSet(provider_id=role.role_id, granted=role.granted)

    def supported_actions(self) -> tuple[tuple[CloudActionKind, CloudResourceClass], ...]:
        """Every supported pair, sorted, for a capability matrix in a report."""
        return tuple(sorted(self.capabilities, key=lambda pair: (pair[0].value, pair[1].value)))

    def irreversible_actions(self) -> tuple[tuple[CloudActionKind, CloudResourceClass], ...]:
        """The pairs Mayhem cannot roll back, per adapter.

        Reportable before a plan is authored, which is the point: "which of these
        can be undone" is an operator's question and answering it from a type
        rather than a docstring means it cannot rot.
        """
        return tuple(
            key
            for key, capability in sorted(self.capabilities.items())
            if isinstance(capability, IrreversibleCapability)
        )

    # -- the port boundary -----------------------------------------------------

    def _list(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        try:
            return tuple(self.transport.list_resources(query))
        except TransportConflict as exc:
            raise self._transport_error(
                exc, target_outcome=TargetOutcome.RESOURCE_CONFLICT
            ) from exc
        except TransportFailure as exc:
            raise self._transport_error(exc) from exc

    def _read(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        try:
            return self.transport.read_resource(query, resource_id)
        except TransportConflict as exc:
            raise self._transport_error(
                exc, target_outcome=TargetOutcome.RESOURCE_CONFLICT
            ) from exc
        except TransportFailure as exc:
            raise self._transport_error(exc) from exc

    def _mutate(self, command: MutationCommand) -> MutationReceipt:
        try:
            receipt = self.transport.mutate(command)
        except TransportConflict as exc:
            raise self._transport_error(
                exc, target_outcome=TargetOutcome.RESOURCE_CONFLICT
            ) from exc
        except TransportFailure as exc:
            raise self._transport_error(exc) from exc
        # A binding that answers with a different operation than it was asked for
        # has either substituted an action or mislabelled its own return; either
        # way the receipt is not evidence for *this* action, so it is refused
        # rather than filed.
        if receipt.operation != command.operation:
            raise CloudAdapterError(
                code=CLOUD_RECEIPT_MISMATCH,
                reason=(
                    f"transport was asked for {command.operation!r} on "
                    f"{command.resource_id!r} and returned a receipt naming "
                    f"{receipt.operation!r}"
                ),
                details={
                    "requested": command.operation,
                    "returned": receipt.operation,
                    "resource_id": command.resource_id,
                },
            )
        return receipt

    @staticmethod
    def _transport_error(
        exc: TransportFailure,
        *,
        target_outcome: TargetOutcome = TargetOutcome.FAILED_TO_APPLY,
    ) -> CloudAdapterError:
        return CloudAdapterError(
            code=CLOUD_TRANSPORT_FAILURE,
            reason=str(exc),
            target_outcome=target_outcome,
            details={"provider": exc.provider, "operation": exc.operation},
        )

    # -- step 1: discover ------------------------------------------------------

    def discover(self, request: DiscoveryRequest) -> DiscoveryResult:
        """Enumerate one resource class into exact identities and intents.

        Returns one :class:`~mayhem.domain.cloud.CloudTargetIntent` per exact
        identity, each naming exactly that one resource. That is the shape a plan
        has to be written in: the multi-match refusal exists so somebody authors
        one intent per resource and accepts each, and discovery's output is those
        intents ready to author.

        Two properties beyond enumeration:

        * a narrowing, when supplied, is held to the selector's exact-match rule
          *before* any call leaves the process; and
        * a transport that reports an id or tag Mayhem cannot represent is
          refused with :data:`CLOUD_IDENTITY_UNREPRESENTABLE` rather than passed
          through, because an identity that does not validate is not a resource
          as far as anything downstream is concerned.

        Identities are sorted by canonical id, so two enumerations of the same
        inventory produce identical intents — the same determinism Phase 1's
        resolution guarantees.
        """
        meter = _CallMeter()
        try:
            if request.identifiers or request.tags:
                ensure_selector_is_specific(identifiers=request.identifiers, tags=request.tags)
            query = self._query_for_request(request)
            records = _narrow(self._list(query), request)
            identities = _identities(records)
            return DiscoveryResult(
                outcome=StepOutcome.COMPLETED,
                identities=identities,
                intents=tuple(_intent_for(identity) for identity in identities),
                query=query,
                reason=f"discovered {len(identities)} exact {request.resource_class.value}",
                api_calls=meter.calls,
            )
        except (CloudAdapterError, CloudRefused, InvariantViolationError) as exc:
            return DiscoveryResult(
                outcome=_outcome_of(exc),
                target_outcome=_target_outcome_of(exc),
                code=_code_of(exc),
                reason=str(exc),
                details=_details_of(exc),
                api_calls=meter.calls,
            )

    # -- step 2: resolve -------------------------------------------------------

    def resolve(self, intent: CloudTargetIntent) -> ResolutionResult:
        """Resolve an intent to exactly one target, or refuse.

        Delegates the judgement to
        :func:`~mayhem.domain.cloud.resolve_cloud_target`, the only path to a
        :class:`~mayhem.domain.cloud.CloudTarget`, which refuses *both* zero
        matches and two or more. Phase 2 adds no tolerance: an adapter that
        quietly took the first of four matches would re-implement, less safely,
        the refusal Phase 1 exists to force somebody to write down.
        """
        meter = _CallMeter()
        try:
            if intent.provider.key != self.provider_key:
                raise CloudAdapterError(
                    code=CLOUD_ROLE_PROVIDER_MISMATCH,
                    reason=(
                        f"adapter {self.provider_key!r} cannot resolve an intent for "
                        f"{intent.provider.key!r}"
                    ),
                    details={
                        "adapter": self.provider_key,
                        "intent_provider": intent.provider.key,
                    },
                )
            selector = intent.selector
            query = ResourceQuery(
                provider=intent.provider,
                resource_class=selector.resource_class,
                account=selector.account,
                region=selector.region,
                service=self._required_service(selector.resource_class),
            )
            identities = _identities(self._list(query))
            target = resolve_cloud_target(intent, list(identities))
            return ResolutionResult(
                outcome=StepOutcome.COMPLETED,
                target=target,
                identities=identities,
                reason=f"resolved {target.identity.canonical_id}",
                api_calls=meter.calls,
            )
        except (CloudAdapterError, CloudRefused, InvariantViolationError) as exc:
            return ResolutionResult(
                outcome=_outcome_of(exc),
                target_outcome=_target_outcome_of(exc),
                code=_code_of(exc),
                reason=str(exc),
                details=_details_of(exc),
                api_calls=meter.calls,
            )

    # -- analysis: cost --------------------------------------------------------

    def operation_counts(
        self, action: CloudSpec, capability: CloudCapability
    ) -> CloudOperationCounts:
        """Project the operations *action* will perform.

        Counted from the capability's own declarations plus the action's
        duration — not from a price table and not from a guess:

        * ``api_calls`` is the two calls the action itself needs (one mutate, one
          verification read) plus, when a compensation exists, two more for it.
          A run that will be paid back costs more than the fault, and an estimate
          that omitted the rollback would understate every reversible action.
        * ``instance_hours`` is ``duration_s / 3600`` and is ``0.0`` unless the
          capability declares the action leaves the resource billing compute. A
          stopped EC2 instance and a GCP ``TERMINATED`` instance bill no compute;
          an Azure instance that is merely *powered off* is still allocated and
          still bills. That difference is exactly why the flag sits on the
          capability instead of being computed here.
        * ``volume_operations`` is copied from the capability.
        """
        calls = 2
        if isinstance(capability, ReversibleCapability):
            calls += 2
        duration = action.duration_s
        hours = (
            duration / 3600.0
            if capability.billable_instance_hours and duration is not None
            else 0.0
        )
        return CloudOperationCounts(
            api_calls=calls,
            instance_hours=hours,
            volume_operations=capability.volume_operations,
            duration_s=duration,
        )

    def estimate_cost(self, action: CloudSpec, *, ceiling: float = 0.0) -> CostPreview:
        """Compute the cost estimate *before* execution, or refuse to.

        Three refusals, none of them a number Mayhem made up:

        * :data:`CLOUD_ACTION_UNSUPPORTED` — nothing to price for an action this
          provider does not implement.
        * :data:`CLOUD_DURATION_REQUIRED` — a capability that keeps the resource
          billing, on an action that states no ``duration_s``. Mayhem cannot
          project instance-hours it was not given the length of, and guessing
          would be precisely the fabricated figure this phase must not produce.
        * :data:`CLOUD_COST_UNPRICED` — no rate card covers this
          provider/class/region *and* a ceiling was declared. An unpriced action
          cannot be shown to fit a limit somebody wrote down.

        A priced estimate inherits Phase 1's own refusal as well: a ceiling below
        the estimate's high bound is ``RULE_COST_CEILING_BELOW_HIGH``, reported
        as a failed preview rather than raised past the adapter boundary.
        """
        capability = self.capability_for(action)
        if capability is None:
            return CostPreview(
                outcome=StepOutcome.FAILED,
                target_outcome=TargetOutcome.FAILED_TO_APPLY,
                code=CLOUD_ACTION_UNSUPPORTED,
                reason=self._unsupported_reason(action),
                counts=CloudOperationCounts(api_calls=0, instance_hours=0.0, volume_operations=0),
            )
        if capability.billable_instance_hours and action.duration_s is None:
            calls = 4 if isinstance(capability, ReversibleCapability) else 2
            return CostPreview(
                outcome=StepOutcome.FAILED,
                target_outcome=TargetOutcome.FAILED_TO_APPLY,
                code=CLOUD_DURATION_REQUIRED,
                reason=(
                    f"{self.provider_key} {action.kind.value}/"
                    f"{action.target.resource_class.value} leaves the resource in a "
                    "billable compute state but the action states no duration_s, so "
                    "instance-hours cannot be projected without inventing a number"
                ),
                counts=CloudOperationCounts(
                    api_calls=calls,
                    instance_hours=0.0,
                    volume_operations=capability.volume_operations,
                ),
                details={
                    "kind": action.kind.value,
                    "resource_class": action.target.resource_class.value,
                },
            )
        counts = self.operation_counts(action, capability)
        card = self._rate_card(action)
        if card is None:
            return self._unpriced_preview(action, counts, ceiling)
        low, high = card.price(counts)
        basis = f"priced from operator rate card source={card.source!r}; {counts.describe()}"
        try:
            estimate = CostEstimate(
                scope=ResourceScope.EXPERIMENT,
                scope_key=action.target.identity.account,
                expected_low=low,
                expected_high=high,
                expected=_midpoint(low, high),
                ceiling=ceiling,
                basis=basis,
            )
        except InvariantViolationError as exc:
            return CostPreview(
                outcome=StepOutcome.FAILED,
                target_outcome=TargetOutcome.FAILED_TO_APPLY,
                code=exc.rule,
                reason=str(exc),
                counts=counts,
                priced=True,
                price_source=card.source,
                details={"ceiling": ceiling, "expected_high": high},
            )
        return CostPreview(
            outcome=StepOutcome.COMPLETED,
            counts=counts,
            priced=True,
            price_source=card.source,
            estimate=estimate,
            ceiling_decision=check_cost_ceiling(estimate, estimate.expected_high),
            reason=(
                f"priced estimate for {action.action_id}: {counts.describe()}; source "
                f"{card.source!r}"
            ),
        )

    def _unpriced_preview(
        self,
        action: CloudSpec,
        counts: CloudOperationCounts,
        ceiling: float,
    ) -> CostPreview:
        """The UNPRICED preview, or the refusal a declared ceiling forces."""
        identity = action.target.identity
        basis = (
            f"UNPRICED: mayhem bundles no rate card for "
            f"{self.provider_key}/{action.target.resource_class.value}/"
            f"{identity.region}; disclosed counts are {counts.describe()}; "
            "expected_low=expected_high=0 currency_micros means no price is known, "
            "not that the action is free"
        )
        if ceiling > 0.0:
            return CostPreview(
                outcome=StepOutcome.FAILED,
                target_outcome=TargetOutcome.FAILED_TO_APPLY,
                code=CLOUD_COST_UNPRICED,
                reason=(
                    f"cost for {action.action_id} is UNPRICED ({counts.describe()}) and a "
                    f"ceiling of {ceiling:g} currency_micros was declared; mayhem cannot "
                    "certify an action it cannot price fits a declared ceiling"
                ),
                counts=counts,
                priced=False,
                details={
                    "ceiling": ceiling,
                    "region": identity.region,
                    "resource_class": action.target.resource_class.value,
                },
            )
        estimate = CostEstimate(
            scope=ResourceScope.EXPERIMENT,
            scope_key=identity.account,
            expected_low=0.0,
            expected_high=0.0,
            expected=0.0,
            ceiling=ceiling,
            basis=basis,
        )
        return CostPreview(
            outcome=StepOutcome.COMPLETED,
            counts=counts,
            priced=False,
            estimate=estimate,
            ceiling_decision=check_cost_ceiling(estimate, estimate.expected_high),
            reason=(
                f"UNPRICED estimate for {action.action_id}: {counts.describe()}; no "
                "ceiling was declared, so nothing is being certified"
            ),
        )

    def _rate_card(self, action: CloudSpec) -> CloudRateCard | None:
        identity = action.target.identity
        for card in self.rate_cards:
            if card.covers(identity.provider, action.target.resource_class, identity.region):
                return card
        return None

    # -- analysis: permission --------------------------------------------------

    def analyze_permission(self, role: CloudRoleRef, action: CloudSpec) -> CloudPermissionAnalysis:
        """ "Can this role perform this action?", in the existing vocabulary.

        Two halves, two existing models:

        * the *action* half is Phase 1's
          :func:`~mayhem.domain.cloud.check_role_can_perform`, which reports a
          cross-provider role separately from a missing grant and names each
          missing permission; and
        * the *adapter* half is
          :meth:`ProviderPermissionSet.check`
          against :attr:`adapter_permissions` — the adapter needs ``network`` and
          ``target:read`` to do anything at all, whatever the action declared.

        The two must agree. :attr:`CloudRoleRef.granted` and
        ``ProviderPermissionSet.granted`` come from the same grant, and if the
        loader-layer model ever answers differently from the domain model the
        analysis is refused with :data:`CLOUD_PERMISSION_DENIED` rather than
        reported — because "can this role do it" would then have two answers.
        """
        try:
            decision = check_role_can_perform(role, action)
            sandbox = self.sandbox_permissions_for(role)
            adapter_missing = sandbox.check(self.adapter_permissions)
            domain_missing = role.missing_for(action)
            sandbox_missing = sandbox.check(action.required_permissions)
            if sandbox_missing != domain_missing:
                raise CloudRefused(
                    CLOUD_PERMISSION_DENIED,
                    (
                        f"the domain permission model and the sandbox permission model "
                        f"disagree about role {role.role_id!r}: "
                        f"{list(domain_missing)} vs {list(sandbox_missing)}"
                    ),
                    details={
                        "role_id": role.role_id,
                        "domain_missing": list(domain_missing),
                        "sandbox_missing": list(sandbox_missing),
                    },
                    remediation=(
                        "the loader-layer grant and the domain grant must name the same "
                        "permissions; this is an internal inconsistency, not an IAM "
                        "problem"
                    ),
                )
            missing = tuple(decision.missing) + adapter_missing
            if missing:
                return CloudPermissionAnalysis(
                    outcome=StepOutcome.FAILED,
                    target_outcome=TargetOutcome.FAILED_TO_APPLY,
                    code=decision.code,
                    role_id=role.role_id,
                    missing=decision.missing,
                    adapter_missing=adapter_missing,
                    reason=(
                        f"role {role.role_id!r} cannot perform {action.action_id!r}: "
                        f"missing {', '.join(sorted(missing))}"
                    ),
                    details={
                        "action_required": sorted(p.value for p in action.required_permissions),
                        "adapter_required": sorted(p.value for p in self.adapter_permissions),
                        "granted": sorted(p.value for p in role.granted),
                    },
                )
            return CloudPermissionAnalysis(
                outcome=StepOutcome.COMPLETED,
                role_id=role.role_id,
                reason=decision.reason,
            )
        except (CloudAdapterError, CloudRefused, InvariantViolationError) as exc:
            return CloudPermissionAnalysis(
                outcome=_outcome_of(exc),
                target_outcome=_target_outcome_of(exc),
                code=_code_of(exc),
                role_id=role.role_id,
                reason=str(exc),
                details=_details_of(exc),
            )

    # -- analysis: every gate together ----------------------------------------

    def preflight(
        self, action: CloudSpec, *, role: CloudRoleRef, ceiling: float = 0.0
    ) -> PreflightResult:
        """Run every pre-execution gate, in the order stated here.

        The order is deliberate: unsupported action (no point costing something
        that will not run), then irreversible action (it needs plan 09's elevated
        approval, which does not exist yet), then permission, then cost.
        Nothing here touches the transport, so a refusal costs no API calls.
        """
        capability = self.capability_for(action)
        if capability is None:
            return PreflightResult(
                action_id=action.action_id,
                allowed=False,
                permission=CloudPermissionAnalysis(
                    outcome=StepOutcome.COMPLETED,
                    role_id=role.role_id,
                    reason="not evaluated: the action is unsupported",
                ),
                cost=CostPreview(
                    outcome=StepOutcome.FAILED,
                    target_outcome=TargetOutcome.FAILED_TO_APPLY,
                    code=CLOUD_ACTION_UNSUPPORTED,
                    reason=self._unsupported_reason(action),
                    counts=CloudOperationCounts(
                        api_calls=0, instance_hours=0.0, volume_operations=0
                    ),
                ),
                reason=(
                    f"{self.provider_key} does not implement "
                    f"{action.kind.value}/{action.target.resource_class.value}"
                ),
            )
        cost = self.estimate_cost(action, ceiling=ceiling)
        permission = self.analyze_permission(role, action)
        if isinstance(capability, IrreversibleCapability) and requires_elevated_approval(action):
            return PreflightResult(
                action_id=action.action_id,
                allowed=False,
                permission=permission,
                cost=cost,
                capability=capability,
                reason=(
                    f"{capability.execute_operation} is declared irreversible "
                    f"({capability.rationale!r}) and plan 09 has not defined elevated "
                    "approval, so no irreversible cloud action can be executed in this "
                    "phase"
                ),
            )
        if permission.denied:
            return PreflightResult(
                action_id=action.action_id,
                allowed=False,
                permission=permission,
                cost=cost,
                capability=capability,
                reason=permission.reason,
            )
        if cost.denied:
            return PreflightResult(
                action_id=action.action_id,
                allowed=False,
                permission=permission,
                cost=cost,
                capability=capability,
                reason=cost.reason,
            )
        return PreflightResult(
            action_id=action.action_id,
            allowed=True,
            permission=permission,
            cost=cost,
            capability=capability,
            reason=(
                "permission and cost gates pass"
                if cost.priced
                else (f"permission gate passes; cost is UNPRICED ({cost.counts.describe()})")
            ),
        )

    # -- step 3: execute -------------------------------------------------------

    def execute(
        self, action: CloudSpec, *, role: CloudRoleRef, ceiling: float = 0.0
    ) -> ExecutionResult:
        """Mutate the resource, then verify it.

        Never returns ``COMPLETED`` on a receipt alone. The sequence is: every
        pre-execution gate, one :class:`MutationCommand` through the port, one
        fresh read, and ``COMPLETED`` only if that read confirms
        :attr:`ActionCapability.apply_verify`.

        An irreversible action is refused here with
        :data:`CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED` rather than executed,
        because plan 09 has not defined what supplying elevated approval looks
        like and guessing a token here would be inventing a policy. A gate
        refusal means the transport is never touched, so a denied permission and
        an unpriced action are both safe to try.
        """
        meter = _CallMeter()
        try:
            capability = self._required_capability(action)
            if isinstance(capability, IrreversibleCapability):
                raise CloudAdapterError(
                    code=CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED,
                    reason=(
                        f"{capability.execute_operation} is declared irreversible "
                        f"({capability.rationale!r}); an irreversible cloud action cannot "
                        "be executed before plan 09 defines elevated approval"
                    ),
                    details={
                        "operation": capability.execute_operation,
                        "resource_class": capability.resource_class.value,
                    },
                )
            gate = self.preflight(action, role=role, ceiling=ceiling)
            if not gate.allowed:
                raise CloudAdapterError(
                    code=gate.cost.code if gate.cost.denied else gate.permission.code,
                    reason=gate.reason,
                    details={"action_id": action.action_id},
                )
            receipt = self._mutate(self._command(action, capability.execute_operation))
            meter.calls += 1
            verification = self.verify(action, phase=VerifyPhase.APPLIED)
            meter.calls += verification.api_calls
            if not verification.confirmed:
                raise CloudAdapterError(
                    code=CLOUD_VERIFICATION_FAILED,
                    reason=(
                        f"{capability.execute_operation} returned receipt "
                        f"{receipt.request_id!r} but the expected applied state was not "
                        f"observed: {verification.reason}"
                    ),
                    details={
                        "operation": capability.execute_operation,
                        "request_id": receipt.request_id,
                        "violated": list(verification.violated),
                    },
                )
            return ExecutionResult(
                outcome=StepOutcome.COMPLETED,
                target=action.target,
                receipt=receipt,
                verification=verification,
                estimate=gate.cost.estimate,
                reason=(
                    f"{capability.execute_operation} on "
                    f"{action.target.identity.canonical_id} confirmed by "
                    f"{verification.evidence}"
                ),
                api_calls=meter.calls,
            )
        except (CloudAdapterError, CloudRefused, InvariantViolationError) as exc:
            return ExecutionResult(
                outcome=_outcome_of(exc),
                target_outcome=_target_outcome_of(exc),
                code=_code_of(exc),
                reason=str(exc),
                details={"action_id": action.action_id, **_details_of(exc)},
                api_calls=meter.calls,
            )

    # -- step 4: compensate ----------------------------------------------------

    def compensate(
        self, action: ReversibleCloudAction, *, role: CloudRoleRef
    ) -> CompensationResult:
        """Undo a reversible action, then verify the rollback.

        The parameter is typed ``ReversibleCloudAction``, and Phase 1 made that
        a *sibling* model of ``IrreversibleCloudAction`` rather than a subtype —
        so no instance is both, and an irreversible action cannot be handed to
        the rollback path at all. Behind the annotation the capability table is
        the second lock: :class:`IrreversibleCapability` has no
        ``compensate_operation`` field and no ``compensate_verify``, so even a
        caller who ignored the annotation finds nothing to send and nothing to
        check, and gets :data:`CLOUD_COMPENSATION_UNAVAILABLE` instead.

        Like :meth:`execute`, it never returns ``COMPLETED`` on a receipt: the
        rollback is verified against ``compensate_verify``, so "the rollback was
        accepted" and "the rollback happened" stay two claims. The permission
        gate runs here too — a rollback mutates, so it needs
        ``target:mutate`` just as the fault did.
        """
        meter = _CallMeter()
        try:
            capability = self._required_capability(action)
            if not isinstance(capability, ReversibleCapability):
                rationale = (
                    capability.rationale if isinstance(capability, IrreversibleCapability) else ""
                )
                raise CloudAdapterError(
                    code=CLOUD_COMPENSATION_UNAVAILABLE,
                    reason=(
                        f"{self.provider_key} declares {capability.label} as irreversible "
                        f"and offers no compensating operation"
                        + (f": {rationale!r}" if rationale else "")
                    ),
                    details={
                        "operation": capability.execute_operation,
                        "rationale": rationale,
                    },
                )
            analysis = self.analyze_permission(role, action)
            if analysis.denied:
                raise CloudAdapterError(
                    code=analysis.code, reason=analysis.reason, details=analysis.details
                )
            receipt = self._mutate(self._command(action, capability.compensate_operation))
            meter.calls += 1
            verification = self.verify(action, phase=VerifyPhase.COMPENSATED)
            meter.calls += verification.api_calls
            if not verification.confirmed:
                raise CloudAdapterError(
                    code=CLOUD_VERIFICATION_FAILED,
                    reason=(
                        f"{capability.compensate_operation} returned receipt "
                        f"{receipt.request_id!r} but the expected compensated state was "
                        f"not observed: {verification.reason}"
                    ),
                    details={
                        "operation": capability.compensate_operation,
                        "request_id": receipt.request_id,
                        "violated": list(verification.violated),
                    },
                )
            return CompensationResult(
                outcome=StepOutcome.COMPLETED,
                receipt=receipt,
                verification=verification,
                reason=(
                    f"{capability.compensate_operation} on "
                    f"{action.target.identity.canonical_id} confirmed by "
                    f"{verification.evidence}"
                ),
                api_calls=meter.calls,
            )
        except (CloudAdapterError, CloudRefused, InvariantViolationError) as exc:
            return CompensationResult(
                outcome=_outcome_of(exc),
                target_outcome=_target_outcome_of(exc),
                code=_code_of(exc),
                reason=str(exc),
                details=_details_of(exc),
                api_calls=meter.calls,
            )

    # -- step 5: verify --------------------------------------------------------

    def verify(
        self, action: CloudSpec, *, phase: VerifyPhase = VerifyPhase.APPLIED
    ) -> VerificationOutcome:
        """Ask the cloud what state the resource is actually in.

        The only step that reads without mutating, and the only one that can
        report :attr:`StepOutcome.TARGET_DRIFT`: a resource the transport can no
        longer see means the plan named something that is not the object present,
        which is *mismatched*, never failed.

        No permission gate runs here — verify is a read, it cannot mutate, and a
        rollback's own verification must not be blocked by the rollback's own
        permission. What it does require is ``network`` and ``target:read`` from
        whoever drives it, which :meth:`analyze_permission` reports.
        """
        meter = _CallMeter()
        try:
            capability = self._required_capability(action)
            expected = _expectation_for(capability, phase)
            identity = action.target.identity
            record = self._read(self._query_for(action.target), identity.resource_id)
            meter.calls += 1
            if record is None:
                return VerificationOutcome(
                    outcome=StepOutcome.TARGET_DRIFT,
                    target_outcome=TargetOutcome.TARGET_DRIFT,
                    phase=phase,
                    expected=expected,
                    resource_present=False,
                    reason=(
                        f"{self.provider_key} reports no "
                        f"{identity.resource_class.value} named {identity.resource_id!r} "
                        f"in {identity.account}/{identity.region}; the planned target is "
                        "not the object present"
                    ),
                    api_calls=meter.calls,
                )
            matched, violated = expected.check(record.fields)
            if violated:
                return VerificationOutcome(
                    outcome=StepOutcome.FAILED,
                    target_outcome=TargetOutcome.FAILED_TO_APPLY,
                    phase=phase,
                    expected=expected,
                    observed=dict(record.fields),
                    matched=matched,
                    violated=violated,
                    reason=(
                        f"{self.provider_key} {identity.resource_id!r} does not hold the "
                        f"{phase.value} state: {'; '.join(violated)}"
                    ),
                    api_calls=meter.calls,
                )
            return VerificationOutcome(
                outcome=StepOutcome.COMPLETED,
                phase=phase,
                expected=expected,
                observed=dict(record.fields),
                matched=matched,
                reason=(
                    f"{self.provider_key} {identity.resource_id!r} holds the "
                    f"{phase.value} state: {expected.describe()}"
                ),
                api_calls=meter.calls,
            )
        except (CloudAdapterError, CloudRefused, InvariantViolationError) as exc:
            return VerificationOutcome(
                outcome=_outcome_of(exc),
                target_outcome=_target_outcome_of(exc),
                phase=phase,
                expected=_fallback_expected(),
                reason=str(exc),
                api_calls=meter.calls,
            )

    # -- internals -------------------------------------------------------------

    def _command(self, action: CloudSpec, operation: str) -> MutationCommand:
        return MutationCommand(
            action_id=action.action_id,
            operation=operation,
            query=self._query_for(action.target),
            resource_id=action.target.identity.resource_id,
        )

    def _query_for(self, target: CloudTarget) -> ResourceQuery:
        return ResourceQuery(
            provider=target.provider,
            resource_class=target.resource_class,
            account=target.identity.account,
            region=target.identity.region,
            service=self._required_service(target.resource_class),
        )

    def _query_for_request(self, request: DiscoveryRequest) -> ResourceQuery:
        return ResourceQuery(
            provider=request.provider,
            resource_class=request.resource_class,
            account=request.account,
            region=request.region,
            service=self._required_service(request.resource_class),
        )

    def _required_service(self, resource_class: CloudResourceClass) -> str:
        service = self.service_for(resource_class)
        if service is None:
            supported = ", ".join(sorted(cls.value for cls in self.services))
            raise CloudAdapterError(
                code=CLOUD_UNKNOWN_RESOURCE_CLASS,
                reason=(
                    f"adapter {self.provider_key!r} declares no provider-native service "
                    f"for resource class {resource_class.value!r}; the classes it knows "
                    f"are {supported}"
                ),
                details={"resource_class": resource_class.value},
            )
        return service

    def _required_capability(self, action: CloudSpec) -> CloudCapability:
        capability = self.capability_for(action)
        if capability is None:
            raise CloudAdapterError(
                code=CLOUD_ACTION_UNSUPPORTED,
                reason=self._unsupported_reason(action),
                details={
                    "kind": action.kind.value,
                    "resource_class": action.target.resource_class.value,
                    "supported": [
                        f"{kind.value}/{resource_class.value}"
                        for kind, resource_class in self.supported_actions()
                    ],
                },
            )
        return capability

    def _unsupported_reason(self, action: CloudSpec) -> str:
        supported = ", ".join(
            f"{kind.value}/{resource_class.value}"
            for kind, resource_class in self.supported_actions()
        )
        return (
            f"{self.provider_key} does not implement "
            f"{action.kind.value}/{action.target.resource_class.value}; supported pairs "
            f"are {supported}"
        )


# --- module helpers ------------------------------------------------------------


def _midpoint(low: float, high: float) -> float:
    """The range midpoint at Phase 1's replay-stable precision.

    Passed to ``CostEstimate`` explicitly rather than left to its
    ``mode="before"`` validator, so the static constructor signature matches
    what is built here. Phase 1 then checks the value against its own midpoint,
    so a drift in this rounding is a refusal rather than a silent disagreement
    between two derivations of the same number.
    """
    return round((low + high) / 2.0, RESOURCE_PRECISION)


def _narrow(
    records: Sequence[ResourceRecord], request: DiscoveryRequest
) -> tuple[ResourceRecord, ...]:
    """Apply the request's optional exact narrowing to *records*."""
    return tuple(
        record
        for record in records
        if (not request.identifiers or record.resource_id in request.identifiers)
        and (not request.tags or request.tags <= record.tags)
    )


def _identities(records: Sequence[ResourceRecord]) -> tuple[CloudResourceIdentity, ...]:
    """Convert records to identities, or refuse one Mayhem cannot represent."""
    identities: list[CloudResourceIdentity] = []
    for record in records:
        try:
            identities.append(record.identity())
        except ValidationError as exc:
            raise CloudRefused(
                CLOUD_IDENTITY_UNREPRESENTABLE,
                (
                    f"transport reported a resource Mayhem cannot represent as an exact "
                    f"identity ({exc.error_count()} validation failure(s) on "
                    f"{record.resource_id!r})"
                ),
                details={"resource_id": record.resource_id, "service": record.query.service},
                remediation=(
                    "a resource id and every tag must be exact strings without glob "
                    "metacharacters; the transport must not normalise them"
                ),
            ) from exc
    # Sorted by canonical id, never by provider API order, so two enumerations of
    # the same inventory produce byte-identical intents.
    identities.sort(key=lambda identity: identity.canonical_id)
    return tuple(identities)


def _intent_for(identity: CloudResourceIdentity) -> CloudTargetIntent:
    """One exact intent naming exactly *identity* and nothing else."""
    return CloudTargetIntent(
        provider=identity.provider,
        selector=CloudSelector(
            resource_class=identity.resource_class,
            kind=CloudSelectorKind.IDENTIFIER,
            account=identity.account,
            region=identity.region,
            identifiers=(identity.resource_id,),
        ),
    )


def _expectation_for(capability: CloudCapability, phase: VerifyPhase) -> ExpectedState:
    """The post-condition *phase* asks about, or a refusal when there is none."""
    if not isinstance(capability, ReversibleCapability):
        raise CloudAdapterError(
            code=CLOUD_VERIFICATION_UNAVAILABLE,
            reason=(
                f"{capability.label} is declared irreversible, so it states no "
                "post-condition; the only thing a destructive operation can honestly "
                "assert is that the resource is gone, and target_drift means the "
                "opposite claim"
            ),
            details={"operation": capability.execute_operation},
        )
    if phase is VerifyPhase.APPLIED:
        return capability.apply_verify
    return capability.compensate_verify


def _fallback_expected() -> ExpectedState:
    """A never-satisfied expectation, for a verify that failed before it ran.

    Not a placeholder for a real post-condition: the key does not exist on any
    provider, so a verification built from this can never report ``COMPLETED``
    even if someone kept the result.
    """
    return ExpectedState(equal={"__mayhem.verify_never_ran__": "1"})
