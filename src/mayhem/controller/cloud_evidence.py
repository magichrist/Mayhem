"""Safety and evidence integration for the cloud lane (v1.1.0 plan 06, Phase 4).

Phase 3 shipped the read-only ``mayhem cloud`` surface and Phase 1 wrote down,
in :mod:`mayhem.domain.cloud`, exactly one sentence about this phase's job:

    :func:`check_cost_ceiling` is what compares spend against it, and it is
    pure so Phase 4 can call it before mutating anything.

This module is that wiring, and it closes three gaps that belong together:

1. **`admit_cloud_action` — the pre-mutation gate.** One call that answers
   "may this cloud action run?" in a fixed order — permission, cost ceiling,
   damage quota — and refuses *before anything mutates*. Every refusal is a
   :class:`~mayhem.domain.cloud.CloudRefused` code or a damage-quota rule id
   that already exists; this module invents no new refusal vocabulary.

2. **Blast-radius and damage-quota accounting — the same ledger, not a
   second one.** The gate charges the caller's
   :class:`~mayhem.domain.quota.DamageLedger` through
   :func:`mayhem.providers.participation.charge_provider_blast` — the same
   call a native step and a third-party provider step make, so a cloud action
   and a fault cannot disagree about what a run costs. What is *not* the same
   is said on every charge: a cloud action id is not in the fault catalog, so
   :func:`~mayhem.domain.quota.damage_weight` prices it at
   :data:`~mayhem.domain.quota.UNRESOLVED_FAULT_WEIGHT` — the top rung, the
   fail-safe direction — and :attr:`BlastCharge.weight_source` reports
   ``unresolved_conservative`` rather than letting a reader assume a catalog
   price was found. Pricing cloud action ids is a catalog decision (plan 05);
   this module does not invent one.

   **Region/AZ blast rules are plan 07's**, and this gate does not preview
   them: a refused-for-quota cloud action is refused on the quota's own
   ``damage_quota.*`` ids, and a regional explosion radius is a different
   limit owned by a different plan. The notice carries that boundary so a
   reader cannot mistake "within quota" for "regionally bounded".

3. **`seal_cloud_decision` — the evidence correlation.** Every decision,
   allow *or* refusal, is sealed into a chain through the ordinary
   :class:`~mayhem.infra.attestation_store.AttestationRepository` — the module
   adds no second sealer and no second verifier. Each event is timestamped
   with the plan-12 clock policy (:func:`mayhem.infra.attestation_store.
   _recorded_at`, a wall-clock + monotonic pair taken once for the chain), and
   its payload names everything the provider's own audit log would name —
   action id, canonical resource id, account, region, projected spend, rule
   id — so a sealed row and a console log can be joined without a second
   correlation scheme. The chain row is namespaced under
   :func:`cloud_chain_key` for the same reason
   :func:`mayhem.controller.k8s_evidence.admission_chain_key` is:
   ``attestation_chains.run_id`` is a primary key already claimed by the
   run-evidence chain.

The gate never executes. ``admit_cloud_action`` holds no transport and calls
no mutating adapter method — ``analyze_permission`` and ``estimate_cost``
are both analysis, both transport-free in this build. The caller runs
``adapter.execute`` itself, *after* the gate permitted and *after* (or
before, if it prefers) the decision is sealed; a permitted-but-unsealed
action is detectable through
:func:`verify_cloud_decision_chain`, which reports an absent chain as
invalid rather than letting silence read as approval — the same honesty rule
:func:`mayhem.controller.k8s_evidence.verify_k8s_admission_chain` states for
the Kubernetes lane.

Boundary note: this module persists only through
``AttestationRepository.save_chain`` / ``save_manifest``, which are
themselves the registered
``BOUNDARY_CALL_SITES`` rows (``tests/unit/test_evidence_boundary.py``), so
no new row is owed here — the same argument
:mod:`mayhem.providers.participation` records for not owing one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

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
from mayhem.domain.cloud import (
    CLOUD_PERMISSION_DENIED,
    CloudRefused,
    CloudSpec,
    ensure_cost_ceiling,
    requires_elevated_approval,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
    _recorded_at,
)
from mayhem.providers.cloud.port import CLOUD_COST_UNPRICED
from mayhem.providers.participation import (
    BlastCharge,
    ProviderAction,
    charge_provider_blast,
)

if TYPE_CHECKING:
    from mayhem.domain.quota import DamageLedger, DamageQuota
    from mayhem.infra.store import Store
    from mayhem.providers.cloud.port import CloudAdapter, CloudRoleRef, CostPreview

__all__ = [
    "CHAIN_KEY_SUFFIX",
    "CLOUD_ADMISSION_NOTICE",
    "CLOUD_NO_REGION_BLAST_RULES_NOTE",
    "EVENT_CLOUD_ACTION_DECIDED",
    "CloudAdmissionOutcome",
    "CloudDecisionSeal",
    "CloudGateStage",
    "admit_cloud_action",
    "cloud_chain_key",
    "cloud_manifest_id",
    "decision_chain_events",
    "decision_payload",
    "load_cloud_decisions",
    "seal_cloud_decision",
    "verify_cloud_decision_chain",
]


# =============================================================================
# Constants
# =============================================================================


#: The sentence every admission outcome carries.
#:
#: A module constant rather than docstring prose for the reason
#: :data:`mayhem.providers.participation.PROVIDER_PARTICIPATION_NOTICE` is: a
#: surface that renders a decision must be able to render the caveat next to it
#: without remembering the wording. It says the three things a reader of an
#: ``admitted=true`` row must not get wrong: the gate computed a decision and
#: performed nothing; the mechanism claim belongs to the port, not to mayhem;
#: and the damage charge prices an uncatalogued id conservatively.
CLOUD_ADMISSION_NOTICE: Final[str] = (
    "mayhem computed this cloud admission decision and mutated nothing: the gate is "
    "analysis only, and the action runs only when its caller executes it against a "
    "transport. Damage is charged on the shared ledger at the conservative top rung "
    "because a cloud action id is not a catalog fault id."
)


#: The plan-07 boundary, stated where a reader would otherwise assume the opposite.
#:
#: "Within quota" is a claim about damage-seconds per target. It is not a claim
#: about how many resources in a region one action could take down — that limit
#: is plan 07's region/AZ blast rule, and nothing here evaluates it. Carried on
#: every outcome so a payload rendered six months from now still answers the
#: question "did anyone check the regional blast?" honestly.
CLOUD_NO_REGION_BLAST_RULES_NOTE: Final[str] = (
    "this decision does not evaluate region/AZ blast rules; those are plan 07's "
    "limits and are not enforced on this path"
)


#: The chain event kind a cloud admission decision is sealed under.
#:
#: A *chain* kind (``AttestedEvent.event_kind``), not a
#: ``domain.events.EventKind`` — the two vocabularies are separate by design,
#: and reusing a journal kind would imply the journal row and the sealed row are
#: the same fact. They are not: the first renders in a run timeline, the second
#: is what a verifier re-hashes offline.
EVENT_CLOUD_ACTION_DECIDED: Final[str] = "cloud.action_decided"


#: The chain key suffix. ``attestation_chains.run_id`` is a PRIMARY KEY already
#: claimed by ``seal_run_evidence`` at run close, so the cloud lane writes under
#: a namespaced key — rows are namespaced, events still name the real run, and
#: both chains verify independently. The same namespacing
#: :func:`mayhem.controller.k8s_evidence.admission_chain_key` uses.
CHAIN_KEY_SUFFIX: Final[str] = ":cloud-actions"


def cloud_chain_key(run_id: str) -> str:
    """The ``attestation_chains`` key the cloud lane writes under for *run_id*."""
    return f"{run_id}{CHAIN_KEY_SUFFIX}"


def cloud_manifest_id(run_id: str) -> str:
    """The ``attestation_manifests`` id covering the cloud-decision chain."""
    return cloud_chain_key(run_id)


# =============================================================================
# The gate
# =============================================================================


class CloudGateStage(StrEnum):
    """Which check refused, or ``NONE`` when the action was admitted.

    A closed vocabulary in refusal order, so an operator reading a payload
    knows both *what* refused and *how far* the action got — an action refused
    on IAM never reached a price, and one refused on cost never touched the
    ledger. Collapsing the stages into a boolean would hide exactly the
    progression a triage needs.
    """

    #: The role cannot perform the action, or the adapter lacks its own
    #: permissions. Refused before any price was computed.
    PERMISSION = "permission"

    #: The cost stage refused: unsupported action, missing duration on a
    #: billable action, an unpriced action under a declared ceiling, a
    #: ceiling below the estimate's high bound, or a projected spend above
    #: the ceiling. Refused before the ledger was touched.
    COST = "cost"

    #: The damage quota refused the charge. The charge is already on the
    #: ledger — the ledger records what the plan *attempted*, and this is the
    #: ledger's own documented charge-then-judge semantics.
    DAMAGE_QUOTA = "damage_quota"

    #: Every stage passed. The caller may execute the action; the charge is
    #: on the ledger and the decision is sealable.
    NONE = "none"


@dataclass(frozen=True, slots=True)
class CloudAdmissionOutcome:
    """One cloud action's admission decision, with the numbers behind it.

    ``preview`` and ``blast`` are the port's and the participation module's
    own values, held rather than copied into new fields — re-expressing their
    numbers here would be a second implementation of two arithmetics this
    module must not own. ``rule_id`` is the refusing rule's stable id
    (``cloud.*``, ``cloud.cost_*`` or ``damage_quota.*``) and is empty when
    admitted.
    """

    action: CloudSpec
    run_id: str
    owner_agent: str
    stage: CloudGateStage
    admitted: bool
    rule_id: str = ""
    reason: str = ""
    remediation: str = ""
    projected_spend: float = 0.0
    preview: CostPreview | None = None
    blast: BlastCharge | None = None
    notice: str = CLOUD_ADMISSION_NOTICE

    @property
    def refused(self) -> bool:
        return not self.admitted

    @property
    def weight_source(self) -> str:
        """Where the damage weight came from, as a stable string."""
        if self.blast is None:
            return ""
        return self.blast.weight_source.value

    def to_dict(self) -> dict[str, object]:
        """The flat, JSON-safe record the journal event and the chain share."""
        identity = self.action.target.identity
        payload: dict[str, object] = {
            "action_id": self.action.action_id,
            "kind": self.action.kind.value,
            "reversibility": self.action.reversibility.value,
            "requires_elevated_approval": requires_elevated_approval(self.action),
            "provider": identity.provider.key,
            "resource": identity.canonical_id,
            "account": identity.account,
            "region": identity.region,
            "run_id": self.run_id,
            "owner_agent": self.owner_agent,
            "stage": self.stage.value,
            "admitted": self.admitted,
            "refused": self.refused,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "remediation": self.remediation,
            "projected_spend": self.projected_spend,
            "weight_source": self.weight_source,
            "region_blast_rules": CLOUD_NO_REGION_BLAST_RULES_NOTE,
            "notice": self.notice,
        }
        if self.preview is not None:
            payload["cost"] = _preview_payload(self.preview)
        if self.blast is not None:
            payload["blast"] = self.blast.to_dict()
        projected = _plain(payload)
        return dict(projected) if isinstance(projected, dict) else payload


def _preview_payload(preview: CostPreview) -> dict[str, object]:
    """The cost half of a payload: priced-ness, the range, and the ceiling."""
    estimate = preview.estimate
    return {
        "priced": preview.priced,
        "price_source": preview.price_source,
        "expected_low": estimate.expected_low if estimate else 0.0,
        "expected_high": estimate.expected_high if estimate else 0.0,
        "ceiling": estimate.ceiling if estimate else 0.0,
        "unit": estimate.unit if estimate else "currency_micros",
        "basis": estimate.basis if estimate else "",
        "counts_api_calls": preview.counts.api_calls,
        "counts_instance_hours": preview.counts.instance_hours,
        "counts_volume_operations": preview.counts.volume_operations,
        "ceiling_decision_allowed": (
            preview.ceiling_decision.allowed if preview.ceiling_decision else None
        ),
    }


def admit_cloud_action(
    adapter: CloudAdapter,
    action: CloudSpec,
    role: CloudRoleRef,
    *,
    run_id: str,
    owner_agent: str,
    duration_s: float | None = None,
    ceiling: float,
    quota: DamageQuota,
    ledger: DamageLedger,
    projected_spend: float | None = None,
) -> CloudAdmissionOutcome:
    """Answer "may this cloud action run?" — and refuse before anything mutates.

    Three stages, in the order the failure matters in:

    1. **Permission.** ``analyze_permission`` answers "can this role perform
       this action?", covering both the action's declared grants and the
       adapter's own needs. A refusal names the missing permission — "IAM
       said no" with no name is a refusal an operator cannot act on.
    2. **Cost.** ``estimate_cost`` prices the action against the declared
       ceiling and refuses the whole family of dishonest answers itself:
       unsupported, missing duration, unpriced-under-a-declared-ceiling,
       ceiling-below-high. On a priced estimate the pure
       :func:`~mayhem.domain.cloud.ensure_cost_ceiling` then judges the
       *projected spend* — the caller's declared projection, or the
       estimate's own high bound when none is given — so a plan that says
       "this may cost up to X" is refused while X still fits no ceiling,
       before anything mutates. Nothing on this stage touches the ledger.
    3. **Damage quota.** The action is charged to the caller's ledger through
       :func:`mayhem.providers.participation.charge_provider_blast` — the
       same call a native step makes — and judged against *quota*. The charge
       lands even when it breaches: the ledger records what the plan
       attempted, and rolling the number back would make the ledger disagree
       with the world.

    A permitted outcome is permission to *call* ``adapter.execute`` — nothing
    more. This module never executes, never holds a transport, and never
    claims a mechanism was applied.

    Args:
        duration_s: The caller's declared fault duration, in seconds. When
            ``None``, the action's own ``duration_s`` is charged — the same
            number the cost stage priced instance-hours from, so the charge
            and the price cannot disagree about how long this action runs.
            Zero is refused by
            :class:`~mayhem.providers.participation.ProviderAction` before
            any stage runs: a zero- or negative-duration mutation is not a
            mutation, and an action with no duration at all and no caller
            duration is a caller bug, not an admission outcome.

    Raises:
        ProviderParticipationError: Only for a malformed duration, which is a
            caller bug rather than an admission outcome. Every *policy*
            refusal is returned as a value, because the caller asked a
            question and the honest shape of an answer is a record, not an
            exception to catch.
    """
    provider_action = ProviderAction(
        provider_id=adapter.provider_key,
        fault_id=action.action_id,
        run_id=run_id,
        owner_agent=owner_agent,
        node_ids=(action.target.identity.canonical_id,),
        duration_s=duration_s if duration_s is not None else (action.duration_s or 0.0),
        operation_id=action.action_id,
    )

    # -- stage 1: permission -------------------------------------------------
    try:
        analysis = adapter.analyze_permission(role, action)
    except CloudRefused as refusal:
        # A role that belongs to another cloud raises rather than returning an
        # outcome (analyze_permission's contract for cloud.role_provider_mismatch).
        # It is still a PERMISSION refusal — the gate's stage mapping — never an
        # escape past the gate.
        return CloudAdmissionOutcome(
            action=action,
            run_id=run_id,
            owner_agent=owner_agent,
            stage=CloudGateStage.PERMISSION,
            admitted=False,
            rule_id=refusal.code,
            reason=str(refusal),
            remediation=refusal.remediation,
        )
    if analysis.denied:
        missing = tuple(analysis.missing) + tuple(analysis.adapter_missing)
        return CloudAdmissionOutcome(
            action=action,
            run_id=run_id,
            owner_agent=owner_agent,
            stage=CloudGateStage.PERMISSION,
            admitted=False,
            rule_id=analysis.code or CLOUD_PERMISSION_DENIED,
            reason=analysis.reason,
            remediation=(
                f"grant {', '.join(sorted(missing))} to role {role.role_id!r}, or "
                "author the action against a role that already holds them"
            ),
        )

    # -- stage 2: cost -------------------------------------------------------
    preview = adapter.estimate_cost(action, ceiling=ceiling)
    if preview.denied:
        return CloudAdmissionOutcome(
            action=action,
            run_id=run_id,
            owner_agent=owner_agent,
            stage=CloudGateStage.COST,
            admitted=False,
            rule_id=preview.code,
            reason=preview.reason,
            remediation=(
                "supply a rate card covering this provider/class/region, declare a "
                "ceiling at or above the estimate's high bound, or state a duration_s "
                "for a billable action"
            ),
            projected_spend=0.0,
        )
    estimate = preview.estimate
    if estimate is None:
        # A preview that completed without an estimate cannot be certified
        # against a ceiling — fail closed rather than crash on the None the
        # CostPreview type permits. Unknown is not free.
        return CloudAdmissionOutcome(
            action=action,
            run_id=run_id,
            owner_agent=owner_agent,
            stage=CloudGateStage.COST,
            admitted=False,
            rule_id=CLOUD_COST_UNPRICED,
            reason=(
                f"cost preview for {action.action_id!r} completed without an "
                "estimate, so no ceiling can be certified against it"
            ),
            remediation=(
                "supply a rate card covering this provider/class/region so the "
                "preview carries a priced estimate"
            ),
            projected_spend=0.0,
            preview=preview,
        )
    projected = float(projected_spend) if projected_spend is not None else estimate.expected_high
    try:
        ensure_cost_ceiling(estimate, projected)
    except CloudRefused as refusal:
        return CloudAdmissionOutcome(
            action=action,
            run_id=run_id,
            owner_agent=owner_agent,
            stage=CloudGateStage.COST,
            admitted=False,
            rule_id=refusal.code,
            reason=str(refusal),
            remediation=refusal.remediation,
            projected_spend=projected,
            preview=preview,
        )

    # -- stage 3: damage quota (charges first, judges second) ----------------
    blast = charge_provider_blast(ledger, provider_action, quota)
    if blast.exceeded:
        return CloudAdmissionOutcome(
            action=action,
            run_id=run_id,
            owner_agent=owner_agent,
            stage=CloudGateStage.DAMAGE_QUOTA,
            admitted=False,
            rule_id=blast.rule_id,
            reason=(
                f"{blast.charge.reason} — charged by cloud action "
                f"{action.action_id!r} at weight {blast.charge.weight:g} "
                f"({blast.weight_source.value}) on resource "
                f"{action.target.identity.canonical_id!r}. The charge stays on the "
                "ledger: it records what the plan attempted."
            ),
            remediation=blast.charge.remediation,
            projected_spend=projected,
            preview=preview,
            blast=blast,
        )

    return CloudAdmissionOutcome(
        action=action,
        run_id=run_id,
        owner_agent=owner_agent,
        stage=CloudGateStage.NONE,
        admitted=True,
        rule_id="",
        reason=(
            f"{action.action_id} admitted: permission granted, projected spend "
            f"{projected:g} within ceiling {ceiling:g}, damage charge "
            f"{blast.charge.step_damage_s:g} damage-seconds within quota"
        ),
        projected_spend=projected,
        preview=preview,
        blast=blast,
    )


# =============================================================================
# Sealing
# =============================================================================


def decision_payload(outcome: CloudAdmissionOutcome) -> dict[str, object]:
    """One decision as a flat, JSON-safe record.

    Shared by the sealed chain payload, so a sealed row and a rendered report
    cannot disagree about what was decided — the chain is the record and the
    report is a rendering of it, never a second answer.
    """
    return outcome.to_dict()


def decision_chain_events(
    run_id: str,
    outcomes: list[CloudAdmissionOutcome] | tuple[CloudAdmissionOutcome, ...],
    *,
    recorded_at: AttestedTimestamp,
) -> tuple[AttestedEvent, ...]:
    """The unsealed chain events for one run's cloud decisions (pure).

    One event per outcome, in decision order, each carrying
    :func:`decision_payload`. The ``AttestedEvent.run_id`` is the **real** run
    id, so a reloaded event says which run it describes; only the chain row
    key is namespaced (see :func:`cloud_chain_key`).
    """
    return tuple(
        AttestedEvent(
            event_id=f"{run_id}:cloud-actions:{outcome.action.action_id}",
            event_kind=EVENT_CLOUD_ACTION_DECIDED,
            run_id=run_id,
            sequence=index,
            payload=decision_payload(outcome),
            recorded_at=recorded_at,
        )
        for index, outcome in enumerate(outcomes)
    )


@dataclass(frozen=True)
class CloudDecisionSeal:
    """A sealed cloud-decision record, with the verdicts that prove it.

    Mirrors :class:`~mayhem.controller.k8s_evidence.K8sAdmissionSeal` for the
    cloud lane: the events, the manifest over them, both verification
    verdicts, and the same unsigned-with-a-reason honesty state — this phase
    attests integrity, never authorship, exactly as plan 12 does.
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
        """Always False in this build. Present so a caller cannot assume."""
        return self.manifest.signed

    @property
    def valid(self) -> bool:
        """True when both the chain and its manifest verify."""
        return self.chain_verification.valid and self.manifest_verification.valid

    @property
    def decisions(self) -> tuple[dict[str, object], ...]:
        """The recorded decisions, one per event, in chain order."""
        return tuple(dict(event.payload) for event in self.events)


def seal_cloud_decision(
    store: Store,
    run_id: str,
    outcomes: list[CloudAdmissionOutcome] | tuple[CloudAdmissionOutcome, ...],
    *,
    recorded_at: AttestedTimestamp | None = None,
    created_at: AttestedTimestamp | None = None,
) -> CloudDecisionSeal | None:
    """Seal this run's cloud admission decisions into the attested chain.

    Writes through
    :class:`~mayhem.infra.attestation_store.AttestationRepository` — the
    module's own persistence, its own evidence-boundary rows, and its own
    verification. This function builds *events*; it does not build a sealer.
    Every event is timestamped with the plan-12 clock policy: a wall-clock +
    monotonic pair taken once for the chain via
    :func:`mayhem.infra.attestation_store._recorded_at` (imported rather than
    re-implemented, so two clock policies cannot disagree by a monotonic tick
    — the same reasoning
    :mod:`mayhem.controller.k8s_evidence` records for its private import).

    Returns:
        The :class:`CloudDecisionSeal`, or ``None`` when there is nothing to
        seal. An empty chain is not written: a row that proves nothing is
        noise a later reader has to rule out.

    Raises:
        AttestationError: If the derived chain or manifest fails verification,
            in which case nothing is written.
    """
    if not outcomes:
        return None
    reading = _recorded_at(recorded_at)
    events = seal_events(
        decision_chain_events(run_id, outcomes, recorded_at=reading),
    )
    manifest = build_manifest(
        events,
        manifest_id=cloud_manifest_id(run_id),
        run_id=run_id,
        signer_identity="",
        trust_root_ref="",
        created_at=created_at or reading,
        previous_manifest_digest=GENESIS_DIGEST,
    )
    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid cloud decision chain for run "
            f"{run_id!r}: {'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid cloud decision manifest for run "
            f"{run_id!r}: {'; '.join(manifest_verification.errors)}"
        )

    repository = AttestationRepository(store)
    repository.save_chain(cloud_chain_key(run_id), events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    return CloudDecisionSeal(
        run_id=run_id,
        events=events,
        manifest=manifest,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
    )


def load_cloud_decisions(store: Store, run_id: str) -> CloudDecisionSeal | None:
    """Reload a sealed cloud-decision record from stored bytes, or ``None``.

    Reload is exact: the rows carry the canonical JSON the digests were
    computed from, so what comes back verifies the same way it went in. The
    ``signature_state`` is reloaded rather than re-asserted, so an unsigned
    record stays visibly unsigned to whoever reads it.
    """
    repository = AttestationRepository(store)
    events = repository.load_chain(cloud_chain_key(run_id))
    if not events:
        return None
    manifest = repository.load_manifest(cloud_manifest_id(run_id))
    if manifest is None:
        return None
    state, reason = repository.load_signature_state(manifest.manifest_id)
    return CloudDecisionSeal(
        run_id=run_id,
        events=events,
        manifest=manifest,
        chain_verification=verify_chain(events),
        manifest_verification=verify_manifest(manifest, events),
        signature_state=state,
        signature_reason=reason,
    )


def verify_cloud_decision_chain(store: Store, run_id: str) -> ChainVerification:
    """Re-verify the stored cloud-decision chain, naming an unsealed run absent.

    Delegates the re-hashing to
    :meth:`~mayhem.infra.attestation_store.AttestationRepository.verify_run_chain`,
    which reloads the stored bytes, calls the domain verifier, and additionally
    checks the stored root and count against the recomputed ones. A run whose
    decisions were never sealed reports ``valid=False`` with "no chain stored" —
    an *unsealed* decision is detectable, never silently treated as allowed.
    """
    return AttestationRepository(store).verify_run_chain(cloud_chain_key(run_id))


# =============================================================================
# Helpers
# =============================================================================


def _plain(value: object) -> Any:
    """JSON-safe projection of a payload value.

    ``AttestedEvent.payload`` reaches a JSON column, so anything a decision
    carries is projected here rather than trusted to serialize: an enum
    becomes its value, a tuple becomes a list, and anything else becomes its
    text. A refusal record that could not be written would be worse than one
    that is legible.
    """
    if isinstance(value, StrEnum):
        return _plain(value.value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
