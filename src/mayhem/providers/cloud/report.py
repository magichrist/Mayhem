"""The cloud decision report: what mayhem decided, and what it did not do
(v1.1.0 plan 06, Phases 3 and 4).

Where this module sits, and why it is not in ``domain``
-------------------------------------------------------
:mod:`mayhem.providers.cloud.port` defines the contract a report has to talk
about — :class:`~mayhem.providers.cloud.port.CloudStep`,
:class:`~mayhem.providers.cloud.port.CostPreview`,
:class:`~mayhem.providers.cloud.port.CloudPermissionAnalysis`,
:class:`~mayhem.providers.cloud.port.VerificationOutcome`. A report that could
not carry those would either restate them (and drift) or flatten them to strings
(and lose the typed outcome an operator triages on). The layering contract puts
``providers`` above ``domain``, so this module lives beside the adapter rather
than in ``domain`` even though it performs no IO. Nothing here imports
``mayhem.infra``, ``mayhem.agents``, ``mayhem.toolkit`` or ``mayhem.controller``.

The split this module exists to hold
------------------------------------
Phase 1 wrote the vocabulary and Phase 2 wrote the adapter lifecycle, and both
left one thing unstated: **who applied the mechanism?** A cloud fault is decided
here and applied in AWS, GCP or Azure, and mayhem in this build can only do the
first half. So every value carries two orthogonal facts that must never be
collapsed into one boolean:

* :attr:`CloudDecisionReport.decision` — ``PERMITTED`` or ``REFUSED``. Pure. It is
  answerable with no network, no credential and no transport, and answering it
  costs nothing, which is why it is checked *first*.
* :attr:`CloudDecisionReport.mechanism_state` — whether the mechanism happened.
  Every member of that enum is a fact about mayhem's own reachability.

and the field that keeps them apart is
:attr:`CloudDecisionReport.mechanism_applied`, which is ``False`` **and refuses to
be set to** ``True``. That refusal is the module's whole point. A report that
claimed mayhem had applied a cloud mechanism would be a claim about AWS, GCP or
Azure, and nothing in this repository can support one — :class:`CloudTransport`
has no implementation here at all. The same discipline as
:attr:`mayhem.domain.lowlevel_report.PrimitiveExplanation.mechanism_applied`, for
the same reason.

What is *not* refused: the port's own claim
-------------------------------------------
:meth:`CloudMechanismObservation.applied` is a **port** asserting that it did
something. Mayhem cannot verify a port's honesty, only its shape, so the honest
move is to record the claim — with the witness the port cited — beside a
``mechanism_applied`` that still says no. A binding that lies can therefore make
its own claim look good; it cannot make mayhem's report say the mechanism ran.
This is the split :mod:`mayhem.domain.lowlevel_admission` draws between
:class:`~mayhem.domain.lowlevel_admission.MechanismObservation` (the port's
answer) and :class:`~mayhem.domain.lowlevel_admission.AdmissionReport` (mayhem's
verdict), and the reason both exist.

Wiring findings and environment findings are different findings
--------------------------------------------------------------
:attr:`CloudMechanismState` keeps :data:`~CloudMechanismState.TRANSPORT_UNAVAILABLE`
(a wiring finding: nothing is bound, so mayhem never had a way to look) apart from
:data:`~CloudMechanismState.CREDENTIAL_REVOKED` (an environment finding: mayhem
asked the grant source and the answer was no). Both block; conflating them sends
an operator to debug the wrong system at 3am. :attr:`CloudMechanismState.witness`
is the predicate that separates them — mayhem looked, and got an answer, or it did
not look at all.

Credentials never enter a report
--------------------------------
The only credential-bearing field is :class:`CloudCredentialUse`, which holds the
*reference* metadata a reviewer needs (which grant, for what purpose, under whose
principal) and has ``extra="forbid"``, so a resolved value cannot be smuggled in
as an unexpected key. The mechanism — handing a decoded credential to an SDK —
belongs to a binding that does not exist here, and the engine that would drive it
lives in :mod:`mayhem.controller.cloud_engine`, which reads
:class:`~mayhem.infra.secret_resolver.ResolutionReceipt` rather than
:class:`~mayhem.infra.secret_resolver.ResolvedSecret`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.providers.cloud.port import (
    CloudCapability,
    CloudPermissionAnalysis,
    CloudStep,
    CostPreview,
    IrreversibleCapability,
    MutationReceipt,
    ReversibleCapability,
    VerificationOutcome,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "CLOUD_CREDENTIAL_IN_REPORT",
    "CLOUD_MECHANISM_NOT_APPLIED_NOTICE",
    "RULE_CREDENTIAL_IN_REPORT",
    "RULE_DECISION_CODE_MISSING",
    "RULE_REPORT_APPLIED_WITHOUT_WITNESS",
    "RULE_REPORT_CHECK_FIELD_BLANK",
    "RULE_REPORT_DUPLICATE_CHECK",
    "RULE_REPORT_MECHANISM_APPLIED",
    "CloudCapabilityRow",
    "CloudCheckStatus",
    "CloudCredentialUse",
    "CloudDecision",
    "CloudDecisionCheck",
    "CloudDecisionReport",
    "CloudMechanismObservation",
    "CloudMechanismState",
    "capability_rows",
    "check_status_blocks",
    "describe_report",
    "report_payload",
]


# =============================================================================
# The notice
# =============================================================================

#: The sentence that must sit next to every cloud decision.
#:
#: It exists as a module constant — rather than as prose in each renderer —
#: for the reason :data:`mayhem.providers.pack.SIGNATURE_TRUST_NOTICE` does: a
#: caveat that lives in one renderer is a caveat the other renderer drops, and a
#: caveat that lives only in a docstring is not a caveat at all. It is carried on
#: every :class:`CloudDecisionReport` and on every JSON record, so a consumer
#: rendering a subset of fields still finds it.
#:
#: It says three things, and each is separately load-bearing: mayhem *decides*
#: (so the decision logic is real and worth reading), mayhem *decides but does not
#: call* (so a permitted action is not a performed action), and *no provider has
#: been contacted* (so the absence is a property of the build rather than a
#: runtime condition somebody should retry).
CLOUD_MECHANISM_NOT_APPLIED_NOTICE: Final[str] = (
    "mayhem decides which provider API call a cloud fault implies, with which parameters, "
    "against which exact resource, under which IAM role and cost ceiling — and in this "
    "build it makes no such call. No AWS, GCP or Azure API has been contacted by anything "
    "under mayhem.providers.cloud: the CloudTransport port has no implementation in this "
    "repository, so nothing here has enumerated, read or mutated a cloud resource. Read a "
    "capability row as the decision a real binding would have to satisfy, never as an "
    "observation of a cloud, and read a permitted decision as 'nothing was refused', never "
    "as 'the fault was injected'."
)

#: The refusal rule a report gets when it is asked to claim the mechanism.
#:
#: Not a :data:`~mayhem.infra.secret_resolver` boundary rule and not a gate rule:
#: it is raised by a pydantic validator inside this module, so it is named here
#: for the same reason Phase 1 named its codes — a caller should be able to
#: branch on it.
RULE_REPORT_MECHANISM_APPLIED = "cloud.report_mechanism_applied"

RULE_REPORT_APPLIED_WITHOUT_WITNESS = "cloud.report_applied_without_witness"
RULE_REPORT_CHECK_FIELD_BLANK = "cloud.report_check_field_blank"
RULE_REPORT_DUPLICATE_CHECK = "cloud.report_duplicate_check"

#: A refusal with no rule of its own, and a credential field with no witness.
RULE_DECISION_CODE_MISSING = "cloud.decision_code_missing"
RULE_CREDENTIAL_IN_REPORT = "cloud.credential_in_report"

#: A credential value in a report, named as a field rather than detected as one.
#:
#: :func:`~mayhem.infra.secret_resolver.require_persistable_document` refuses a
#: *field whose name* is graded ``secret``, which is the right primary guard. This
#: constant is the second, narrower one: it is what a test plants to prove the
#: guard has teeth, and it is exported so a future report field cannot be named
#: this by accident without a reviewer noticing the name is already taken.
CLOUD_CREDENTIAL_IN_REPORT = "credential_value"


# =============================================================================
# Statuses
# =============================================================================


class CloudCheckStatus(StrEnum):
    """What one pre-execution check concluded.

    The same three members
    :class:`mayhem.domain.lowlevel_admission.LowLevelStatus` has, for the same
    reason: ``UNAVAILABLE`` is not a soft ``REFUSED``. A refused check is "mayhem
    looked and the answer was no"; an unavailable one is "mayhem had no way to
    look". Both block, and the difference is what an operator triaging at 3am
    needs — one is an environment finding, the other a wiring finding.
    """

    PASS = "pass"
    REFUSED = "refused"
    UNAVAILABLE = "unavailable"


def check_status_blocks(status: CloudCheckStatus) -> bool:
    """True for every status that blocks. Total over :class:`CloudCheckStatus`.

    Written ``is not PASS`` so a status this build does not recognise blocks
    rather than passes by omission — the asymmetry
    :func:`mayhem.domain.lowlevel_admission.refuses_gate` states for the same
    reason, and the same reason it exists: a gate that passes by omission is a
    gate whose new default is "allow".
    """
    return status is not CloudCheckStatus.PASS


class CloudDecision(StrEnum):
    """Mayhem's verdict on a plan, with no reference to any cloud.

    ``PERMITTED`` means *nothing was refused*. It does not mean the fault was
    injected, the resource changed, or the compensation ran. The distinction is
    carried by :attr:`~CloudDecisionReport.mechanism_state` and by
    :attr:`~CloudDecisionReport.mechanism_applied`, and a renderer that collapses
    the three into "success" is the exact failure this enum exists to prevent —
    which is why the member is called ``PERMITTED`` and not ``OK``.
    """

    PERMITTED = "permitted"
    REFUSED = "refused"

    @property
    def allowed(self) -> bool:
        return self is CloudDecision.PERMITTED


class CloudMechanismState(StrEnum):
    """Whether the cloud mechanism happened, and if not, why not.

    Five members, and the split that matters is :attr:`witness`:

    ==========================  ========  ===========================================
    state                       witness   what it is
    ==========================  ========  ===========================================
    ``NOT_ATTEMPTED``           n/a       a pure analysis; no mechanism was needed
    ``TRANSPORT_UNAVAILABLE``   no        *wiring*: nothing bound, or it misbehaved
    ``CREDENTIAL_UNAVAILABLE``  no        *wiring*: no credential resolver bound
    ``CREDENTIAL_REVOKED``      yes       *environment*: the grant source said no
    ``PORT_CLAIMED``            yes       a bound port answered; mayhem records the
                                            claim and does not vouch for it
    ==========================  ========  ===========================================

    The three no-witness members are the ones
    :mod:`mayhem.controller.preflight_gate` calls ``UNAVAILABLE`` and
    :mod:`mayhem.domain.lowlevel_admission` calls the same: mayhem could not see
    the mechanism, so it certified nothing. ``CREDENTIAL_REVOKED`` is the opposite
    and the reason this enum exists rather than a boolean — mayhem looked at the
    grant source and the answer was no, which is an environment finding that a
    rotation runbook can act on and a wiring finding cannot.
    """

    NOT_ATTEMPTED = "not_attempted"
    TRANSPORT_UNAVAILABLE = "transport_unavailable"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    CREDENTIAL_REVOKED = "credential_revoked"
    PORT_CLAIMED = "port_claimed"

    @property
    def witness(self) -> bool:
        """True when mayhem asked something and got an answer.

        The witness/envionment split. A ``False`` here means "mayhem had no way to
        look", so the finding is about wiring; a ``True`` means something answered,
        so the finding is about the environment it answered from.
        """
        return self in (CloudMechanismState.CREDENTIAL_REVOKED, CloudMechanismState.PORT_CLAIMED)

    @property
    def blocks(self) -> bool:
        """Whether this state stops the mechanism from having happened.

        ``NOT_ATTEMPTED`` does not block because nothing was ever going to be
        attempted — it is what a pure analysis reports. ``PORT_CLAIMED`` does not
        block because a bound port did answer; what mayhem refuses to do is
        *endorse* the answer, which
        :attr:`~CloudDecisionReport.mechanism_applied` handles.
        """
        return self in (
            CloudMechanismState.TRANSPORT_UNAVAILABLE,
            CloudMechanismState.CREDENTIAL_UNAVAILABLE,
            CloudMechanismState.CREDENTIAL_REVOKED,
        )

    @property
    def finding(self) -> str:
        """``"environment"`` or ``"wiring"`` — which system to go and look at."""
        return "environment" if self.witness else "wiring"


# =============================================================================
# Checks
# =============================================================================


@dataclass(frozen=True, slots=True)
class CloudDecisionCheck:
    """One check, its verdict, and the witness behind it.

    A non-blank ``evidence_ref`` is required on **every** status, for
    :mod:`mayhem.controller.preflight_gate`'s reason: the refusal is both what an
    operator acts on at 3am and what an auditor re-reads a week later, so it has
    to say what was looked at. A check that passed still has to say what it read.
    """

    name: str
    status: CloudCheckStatus
    detail: str
    evidence_ref: str

    def __post_init__(self) -> None:
        for field_name in ("name", "detail", "evidence_ref"):
            if not getattr(self, field_name).strip():
                msg = (
                    f"a cloud decision check's {field_name} must be non-blank; a refusal "
                    "that does not say what it looked at is not actionable"
                )
                raise InvariantViolationError(RULE_REPORT_CHECK_FIELD_BLANK, msg)

    @property
    def blocks(self) -> bool:
        return check_status_blocks(self.status)

    def describe(self) -> str:
        return f"{self.name}={self.status.value} ({self.evidence_ref})"


@dataclass(frozen=True, slots=True)
class CloudMechanismObservation:
    """What a bound port *said* it did. A claim, recorded, not endorsed.

    ``applied`` is allowed to be ``True`` here even though
    :attr:`CloudDecisionReport.mechanism_applied` refuses it, and the difference
    is the whole module. This is the port's assertion; mayhem cannot verify a
    port's honesty and can only check that the answer is shaped like an answer.
    ``evidence_ref`` is therefore mandatory even on the negative observations — an
    ``unavailable`` that cites nothing names no witness, and a refusal without a
    witness is indistinguishable from a guess.

    ``applied and not available`` is refused because both facts come from one
    answer: a port cannot report having done something while reporting itself
    unable to look.
    """

    available: bool
    applied: bool
    evidence_ref: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            msg = (
                "a cloud mechanism observation must cite something, even when it reports "
                "nothing; an uncited observation is indistinguishable from a guess"
            )
            raise InvariantViolationError(RULE_REPORT_APPLIED_WITHOUT_WITNESS, msg)
        if self.applied and not self.available:
            msg = (
                "a cloud mechanism cannot be applied while reporting itself unavailable: "
                "the two facts come from the same answer"
            )
            raise InvariantViolationError(RULE_REPORT_APPLIED_WITHOUT_WITNESS, msg)

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "applied": self.applied,
            "evidence_ref": self.evidence_ref,
            "detail": self.detail,
        }


# =============================================================================
# Credentials
# =============================================================================


class CloudCredentialUse(BaseModel):
    """Which credential a plan would use, and never what it is.

    Six reference-metadata fields and ``extra="forbid"``, and there is no field of
    type ``str`` that a caller could fill with a decoded credential and pass
    unnoticed — every field here is one a grant, a receipt or an author wrote, and
    :attr:`redacted` marks the one that must never be filled from a resolved
    value.

    :mod:`mayhem.controller.cloud_engine` builds these from
    :meth:`~mayhem.infra.secret_resolver.ResolutionReceipt.to_dict`, so the
    construction path reads metadata rather than a
    :class:`~mayhem.infra.secret_resolver.ResolvedSecret`. ``extra="forbid"`` is
    what makes that structural: a caller that tried to pass
    ``{"canonical_key": ..., "secret_value": ...}`` would be refused at
    construction rather than quietly persisted.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str = Field(min_length=1)
    canonical_key: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    scope_token: str = Field(min_length=1)
    principal: str = ""
    environment: str = ""

    @property
    def redacted(self) -> bool:
        """Always ``True``: a value was never in scope to be written.

        Carried on the payload so a consumer does not have to *know* that to omit
        one — the same reason
        :attr:`mayhem.domain.lowlevel_report.PrimitiveExplanation.notice` exists.
        """
        return True

    @classmethod
    def of(
        cls,
        *,
        provider: str,
        canonical_key: str,
        purpose: str,
        scope_token: str,
        principal: str = "",
        environment: str = "",
    ) -> CloudCredentialUse:
        """Build from reference metadata, refusing anything secret-shaped."""
        if CLOUD_CREDENTIAL_IN_REPORT in {canonical_key, purpose, scope_token, principal}:
            msg = (
                f"a cloud report may not carry a field named {CLOUD_CREDENTIAL_IN_REPORT!r}; "
                "cloud credential evidence is the reference, never the value"
            )
            raise InvariantViolationError(RULE_CREDENTIAL_IN_REPORT, msg)
        return cls(
            provider=provider,
            canonical_key=canonical_key,
            purpose=purpose,
            scope_token=scope_token,
            principal=principal,
            environment=environment,
        )

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, object]) -> CloudCredentialUse:
        """Build from a receipt's metadata mapping, refusing unknown keys.

        The receipt's own ``to_dict`` is the only intended source. ``extra=
        "forbid"`` on this model is what turns "somebody added a field to the
        receipt" into a refusal rather than a value in an evidence payload.
        """
        return cls.of(
            provider=str(metadata["provider"]),
            canonical_key=str(metadata["canonical_key"]),
            purpose=str(metadata["purpose"]),
            scope_token=str(metadata["scope_token"]),
            principal=str(metadata.get("principal", "")),
            environment=str(metadata.get("environment", "")),
        )


# =============================================================================
# Capability rows
# =============================================================================


class CloudCapabilityRow(BaseModel):
    """One adapter capability, rendered with its honesty fields intact.

    Phase 6's deliverable is a capability matrix that says what the cloud API
    actually supports as against what mayhem wraps, and this is that matrix's row
    type. Three fields do the honesty work and each is load-bearing:

    * ``compensate_operation`` is ``None`` exactly when
      :class:`~mayhem.providers.cloud.port.IrreversibleCapability` says it must
      be — "the cloud offers no rollback" is a value a matrix can print, not a
      sentence in a docstring;
    * ``reversible`` is derived from which of the two capability models the row
      came from, so a matrix cannot claim a rollback for a destructive operation;
      and
    * ``mechanism_applied`` is ``False`` and refuses ``True``, exactly as on
      :class:`CloudDecisionReport`, so a capability matrix cannot be read as a
      transcript.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str
    kind: str
    resource_class: str
    service: str
    execute_operation: str
    summary: str
    reversible: bool
    compensate_operation: str | None = None
    irreversible_rationale: str = ""
    apply_verify: str = ""
    compensate_verify: str = ""
    billable_instance_hours: bool = False
    volume_operations: int = 0
    demonstrated_on_sandbox_account: bool = False
    mechanism_applied: bool = False
    notice: str = CLOUD_MECHANISM_NOT_APPLIED_NOTICE

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.kind}/{self.resource_class}"

    @model_validator(mode="after")
    def _row_is_honest(self) -> CloudCapabilityRow:
        if self.mechanism_applied:
            raise ValueError(
                "mechanism_applied cannot be True: no CloudTransport implementation "
                "ships in this repository, so no row in a capability matrix describes "
                "an operation mayhem has performed against a provider"
            )
        if self.reversible and not self.compensate_operation:
            raise ValueError(
                f"{self.label} is marked reversible but names no compensating "
                "operation; 'reversible' without one is a claim a matrix would be "
                "printing as fact"
            )
        if not self.reversible and self.compensate_verify:
            raise ValueError(
                f"{self.label} is marked irreversible yet asserts a compensated "
                "post-state; an irreversible operation has no post-state to verify"
            )
        if self.reversible and not self.apply_verify:
            raise ValueError(
                f"{self.label} is marked reversible but asserts no applied post-state; "
                "a verification with nothing to assert confirms any resource"
            )
        return self

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "kind": self.kind,
            "resource_class": self.resource_class,
            "label": self.label,
            "service": self.service,
            "execute_operation": self.execute_operation,
            "compensate_operation": self.compensate_operation,
            "reversible": self.reversible,
            "irreversible_rationale": self.irreversible_rationale,
            "apply_verify": self.apply_verify,
            "compensate_verify": self.compensate_verify,
            "billable_instance_hours": self.billable_instance_hours,
            "volume_operations": self.volume_operations,
            "demonstrated_on_sandbox_account": self.demonstrated_on_sandbox_account,
            "mechanism_applied": self.mechanism_applied,
            "notice": self.notice,
            "summary": self.summary,
        }


def capability_rows(capability: CloudCapability, *, provider: str) -> CloudCapabilityRow:
    """One :class:`CloudCapabilityRow` for *capability*, honestly derived.

    ``demonstrated_on_sandbox_account`` is ``False`` for every row in this build
    and is not a parameter, because no adapter action has been demonstrated on a
    sandbox account — the plan's own Phase 2 acceptance, which
    ``docs/v1.1.0/06_CLOUD_PROVIDERS.md`` records as unmet. Making it a field a
    caller could set to ``True`` would let a matrix claim the demonstration this
    build has not performed; making it a constant makes the absence visible on
    every row instead of once in a docstring.
    """
    reversible = isinstance(capability, ReversibleCapability)
    return CloudCapabilityRow(
        provider=provider,
        kind=capability.kind.value,
        resource_class=capability.resource_class.value,
        service=capability.service,
        execute_operation=capability.execute_operation,
        summary=capability.summary,
        reversible=reversible,
        compensate_operation=(
            capability.compensate_operation if reversible else None
        ),
        irreversible_rationale=(
            capability.rationale if isinstance(capability, IrreversibleCapability) else ""
        ),
        apply_verify=capability.apply_verify.describe() if reversible else "",
        compensate_verify=capability.compensate_verify.describe() if reversible else "",
        billable_instance_hours=capability.billable_instance_hours,
        volume_operations=capability.volume_operations,
    )


# =============================================================================
# The report
# =============================================================================


class CloudDecisionReport(BaseModel):
    """One cloud decision: what was decided, what was checked, what was not done.

    :attr:`mechanism_applied` is the field this module exists to keep false, and
    its validator refuses ``True`` for the same reason
    :attr:`mayhem.domain.lowlevel_report.PrimitiveExplanation.mechanism_applied`
    does: promoting it requires a real cloud, and this build has none.

    :attr:`notice` carries :data:`CLOUD_MECHANISM_NOT_APPLIED_NOTICE` on every
    value *and* every payload, so a renderer cannot print a cloud decision
    without the caveat being available to it.

    :attr:`decision` and :attr:`mechanism_state` are deliberately separate fields
    and neither derives from the other. ``PERMITTED`` with
    ``TRANSPORT_UNAVAILABLE`` is the normal state of this build and is a complete,
    honest description: mayhem's gates passed, and nothing happened.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1)
    decision: CloudDecision
    step: CloudStep | None = None
    provider: str = ""
    action_id: str = ""
    role_id: str = ""
    code: str = ""
    reason: str = ""
    checks: tuple[CloudDecisionCheck, ...] = ()
    mechanism_state: CloudMechanismState = CloudMechanismState.NOT_ATTEMPTED
    mechanism_observation: CloudMechanismObservation | None = None
    capability: CloudCapabilityRow | None = None
    permission: CloudPermissionAnalysis | None = None
    cost: CostPreview | None = None
    receipt: MutationReceipt | None = None
    verification: VerificationOutcome | None = None
    credential: CloudCredentialUse | None = None
    api_calls: int = Field(default=0, ge=0)
    timestamp: AttestedTimestamp | None = None
    mechanism_applied: bool = False
    notice: str = CLOUD_MECHANISM_NOT_APPLIED_NOTICE
    details: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _report_is_honest(self) -> CloudDecisionReport:
        if self.mechanism_applied:
            raise ValueError(
                "mechanism_applied cannot be True: no CloudTransport implementation "
                "ships in this repository and no provider API has been contacted. "
                "Promoting this field requires the mechanism, not a flag. A port's own "
                "claim belongs in mechanism_observation, where mayhem records it "
                "without vouching for it."
            )
        names = [check.name for check in self.checks]
        repeated = sorted({name for name in names if names.count(name) > 1})
        if repeated:
            msg = f"the cloud decision report repeats a check: {repeated}"
            raise InvariantViolationError(RULE_REPORT_DUPLICATE_CHECK, msg)
        if self.decision is CloudDecision.REFUSED and not self.code:
            msg = (
                f"the cloud decision report for {self.subject!r} refuses without naming a "
                "refusal code; 'refused' with nothing to branch on is not actionable"
            )
            raise InvariantViolationError(RULE_DECISION_CODE_MISSING, msg)
        return self

    # -- predicates ------------------------------------------------------------

    @property
    def permitted(self) -> bool:
        """True when nothing was refused. Never a claim that anything happened."""
        return self.decision.allowed

    @property
    def blocked_checks(self) -> tuple[CloudDecisionCheck, ...]:
        """Every check that blocks, in report order."""
        return tuple(check for check in self.checks if check.blocks)

    @property
    def blocking(self) -> bool:
        """Whether the mechanism is blocked, by a check or by the mechanism state."""
        return bool(self.blocked_checks) or self.mechanism_state.blocks

    @property
    def observed(self) -> bool:
        """Whether a bound port *claimed* the effect and mayhem kept the claim.

        This is the closest thing to "it happened" a report in this build can
        honestly offer, and even it is only a port's assertion. It is **not**
        :attr:`mechanism_applied`, which is permanently ``False``: a fake transport
        binding one in a test must not be able to make mayhem's own report say a
        cloud was contacted.
        """
        return (
            self.mechanism_state is CloudMechanismState.PORT_CLAIMED
            and self.mechanism_observation is not None
            and self.mechanism_observation.applied
        )

    @property
    def completed(self) -> bool:
        """Whether mayhem saw the effect it decided on, with a verification.

        Deliberately narrow: a bound port's claim *and* a
        :class:`~mayhem.providers.cloud.port.VerificationOutcome` that confirmed.
        A port claim with no verification is not completion, which is the same
        structural rule ``_VerifiedStepResult`` enforces on the adapter's own
        results.
        """
        return self.observed and self.verification is not None and self.verification.confirmed

    @property
    def finding(self) -> str:
        """Which system to look at for the thing that blocked this."""
        if self.blocked_checks or self.mechanism_state is CloudMechanismState.PORT_CLAIMED:
            return "policy"
        return self.mechanism_state.finding

    # -- projections -----------------------------------------------------------

    def to_payload(self) -> dict[str, object]:
        """The JSON-safe record, with the notice carried twice on purpose.

        At the top *and* on the record's own fields, for the reason
        :func:`mayhem.cli.lowlevel_cmd.primitives_payload` gives: a consumer that
        keeps one record must still be able to find the caveat without having read
        the document's header, and a caveat that only exists at the top is a caveat
        a per-record renderer drops.
        """
        payload: dict[str, object] = {
            "schema_version": CLOUD_REPORT_SCHEMA_VERSION,
            "subject": self.subject,
            "decision": self.decision.value,
            "step": self.step.value if self.step is not None else None,
            "provider": self.provider,
            "action_id": self.action_id,
            "role_id": self.role_id,
            "code": self.code,
            "reason": self.reason,
            "checks": [check.describe() for check in self.checks],
            "blocking_checks": [check.name for check in self.blocked_checks],
            "mechanism_state": self.mechanism_state.value,
            "mechanism_finding": self.mechanism_state.finding,
            "mechanism_witnessed": self.mechanism_state.witness,
            "mechanism_applied": self.mechanism_applied,
            "mechanism_observation": (
                self.mechanism_observation.to_dict() if self.mechanism_observation else None
            ),
            "observed": self.observed,
            "completed": self.completed,
            "capability": self.capability.to_payload() if self.capability else None,
            "permission": (
                self.permission.model_dump(mode="json") if self.permission is not None else None
            ),
            "cost": self.cost.model_dump(mode="json") if self.cost is not None else None,
            "receipt": self.receipt.model_dump(mode="json") if self.receipt is not None else None,
            "verification": (
                self.verification.model_dump(mode="json") if self.verification is not None else None
            ),
            "credential": self.credential.model_dump(mode="json") if self.credential else None,
            "api_calls": self.api_calls,
            "timestamp": (
                self.timestamp.model_dump(mode="json") if self.timestamp is not None else None
            ),
            "notice": self.notice,
            "details": self.details,
        }
        payload["report_digest"] = report_digest_of(payload)
        return payload

    def describe(self) -> str:
        return describe_report(self)


CLOUD_REPORT_SCHEMA_VERSION: Final[str] = "1.0"


def report_digest_of(payload: Mapping[str, object]) -> str:
    """A stable digest over a report payload, excluding the digest field itself.

    The correlation key between a cloud action's audit line and a Mayhem evidence
    record. Excluding ``report_digest`` is what makes it computable: including the
    field being computed is the one thing that cannot be.
    """
    return sha256_hex(
        canonical_json({key: value for key, value in payload.items() if key != "report_digest"})
    )


def report_payload(report: CloudDecisionReport) -> dict[str, object]:
    """The CLI's and any other surface's shared projection.

    One function, so ``--json`` and the rendered lines cannot disagree about which
    fields exist — the failure :func:`mayhem.cli.lowlevel_cmd.primitives_payload`
    exists to prevent for plan 04's surface.
    """
    return report.to_payload()


def describe_report(report: CloudDecisionReport) -> str:
    """One screen of text: the verdict, the checks, the mechanism, the caveat."""
    lines = [
        f"{report.subject}: {report.decision.value}"
        + (f" [{report.code}]" if report.code else "")
    ]
    if report.reason:
        lines.append(f"  reason: {report.reason}")
    for check in report.checks:
        lines.append(f"  check {check.name}: {check.status.value} — {check.detail}")
    lines.append(
        f"  mechanism: {report.mechanism_state.value} "
        f"({report.mechanism_state.finding} finding, witnessed="
        f"{str(report.mechanism_state.witness).lower()}), "
        f"applied={str(report.mechanism_applied).lower()}"
    )
    if report.observed:
        observation = report.mechanism_observation
        lines.append(
            "  port claim: "
            f"applied={str(observation.applied).lower()} witness={observation.evidence_ref}"
            " (recorded, not endorsed by mayhem)"
        )
    lines.append(f"  api calls: {report.api_calls}")
    lines.append(f"  notice: {report.notice}")
    return "\n".join(lines)