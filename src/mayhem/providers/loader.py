"""Provider and fault-pack loading — the single enforcement point (plan 17 Phase 2).

Everything a third-party artifact has to survive before mayhem will hold a
:class:`~mayhem.domain.provider.ProviderRegistration` for it passes through this
module: a catalog document or a set of entry points is read here, its
declaration is gated here, its implementation is materialised here, and its
sandbox profile is chosen here. Nothing else in the codebase constructs a
registration from an artifact the provider ecosystem did not author — that
one-way property is what makes this module the place to audit.

The gates, in the order :meth:`ProviderLoader.load_catalog` applies them. Every
one of them refuses, and each has a negative control in
``tests/unit/test_provider_sandbox.py``:

============================  ==========================================
code                          refused because
============================  ==========================================
``catalog_invalid``           the catalog is unreadable, not JSON, or not a catalog
``provider_wire_field_unknown``  the declaration carries a wire field this core does not implement
``provider_api_incompatible``  the declaration is a different ``mayhem.provider/vN``
``provider_version_unreadable``  the running core version cannot be compared
``provider_version_unsupported``  the declared release window excludes this Mayhem
``provider_engine_unsupported``   the declared engine lanes exclude this run
``provider_permission_denied``   the declaration asks for a permission outside the grant
``provider_permission_undeclared``  a capability/locator/fault asks for an undeclared permission
``provider_capability_undeclared`` a fault names a capability or locator it did not declare
``provider_fault_id_shadows_builtin``  a declared fault id is already a mayhem catalog fault
``provider_id_shadows_builtin``  the provider id is already a built-in provider
``provider_parameter_default_invalid``  a fault's own parameter defaults fail its declared grammar
``provider_evidence_missing``  a mutating fault resolves no evidence schema
``provider_sandbox_mechanism_unapplied``  the profile needs a mechanism this build does not apply
``provider_implementation_missing``  the entry point has no implementation
``provider_factory_invalid``  the implementation is not callable but must be
``provider_metadata_invalid``  entry-point metadata is malformed or names another provider
``provider_behavior_mismatch``  the loaded runtime advertises what it did not declare
``provider_already_registered``  the id is taken
``provider_load_failed``       anything else, named by type
============================  ==========================================

Two of those are worth reading twice. ``provider_permission_undeclared`` and
``provider_capability_undeclared`` re-check the declaration graph at the gate
even though the model validates the same rules on construction. The model is the
first line and stays the primary one; the gate is the second, and it exists
because a declaration handed over by an entry point is built by a
``model_copy`` this module itself performs — "the object I was given is a valid
declaration" must not be an assumption of the enforcement point.

Everything else in that table is a rule the models do *not* have: a wire field
this core does not implement, a fault's own defaults failing its own grammar, a
mutation with no evidence mapping, an id that shadows a built-in, a runtime that
advertises more than it declared, and a profile that needs a mechanism this build
cannot apply. Those are the checks that make this module the single enforcement
point rather than a second reader of the same sentence.

One protocol, two documents (gap 37)
-------------------------------------
A "Mayhem-compatible provider" is *one* protocol with two halves:

* :data:`MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL` — the declaration schema of
  :mod:`mayhem.domain.provider`, written by plan 17;
* :data:`MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_PARTS` — the plan-03 fabric
  command envelope, :class:`mayhem.domain.fabric.FabricCommand`, which every
  dispatch travels in.

:data:`MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL` is not a new identifier: it *is*
:data:`mayhem.domain.provider.PROVIDER_DECLARATION_SCHEMA_VERSION`, imported
below. Do not mint a second protocol id, and do not re-specify either half here
— ``docs/v1.1.0/17_EXTENSION_SDK_PROVIDER_PROTOCOL.md`` and
``docs/v1.1.0/03_EXECUTION_FABRIC.md`` describe the same protocol from their two
angles, and a third document that defines its own would be the second protocol
this note exists to prevent.

Phase 4: the lane's safety and evidence integration
---------------------------------------------------
Three things changed, and each one is a refusal of an easy lie.

**The sandbox default is now deny.** :data:`DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT`
is ``True``. Phase 2 shipped it ``False`` and left the decision open; it is made
here, with the reasoning at that constant, because the honest consequence is
that with no seccomp filter, AppArmor profile, SELinux label or container in this
build, a provider that requests any permission at all no longer loads unless a
caller says it accepts an unconfined runtime — and that acceptance is itself
sealed. **No seccomp filter is built or applied and nothing here changes that**;
the default decides whether mayhem will *run* an unconfined third-party runtime,
not whether mayhem can confine one.

**The engine axis is checkable.** :func:`detect_engine_lane` derives a real lane
from a registry that holds exactly one engine runtime, ``running_engine`` accepts
an :class:`~mayhem.domain.faults.EngineLane` member, and
:meth:`ProviderLoader.compatibility_report` carries a per-declaration
``engine_verdict`` of ``not_declared`` / ``unverified`` / ``matched`` /
``mismatched``. "We did not look" is now a value in the report, not merely an
axis missing from a list.

**Provider activity is sealed.** :class:`ProviderActivityLedger` writes every
load, admission, sandbox decision, permission denial and provider-initiated
action into the existing attested chain through
:class:`~mayhem.infra.attestation_store.AttestationRepository` — the same event
type, the same canonicaliser, the same verifier — with the evidence schema
resolved from the provider's **own** declared
:class:`~mayhem.domain.provider.EvidenceMapping`, and every activity carrying an
:class:`~mayhem.domain.evidence.ActionOutcome` from the same closed vocabulary a
native action uses. Registration and permission changes are additionally recorded
in :class:`~mayhem.infra.audit_stream.AuditStream` as privileged actions.

The ledger is opt-in because a loader cannot invent a database: pass ``store=``
to seal. When it is absent the loader is **loud** — every inspection carries
``evidence["sealed"] = False`` plus :data:`UNSEALED_ACTIVITY_NOTICE` — so
"observed and discarded" can never be rendered as "recorded and clean".

Honesty note, carried by every refusal this module produces: mayhem **cannot**
verify a signature. See :data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`.
A digest check is integrity, not provenance, and neither a sandbox profile nor
a compatibility bound is a trust signal. Sealing a provider activity proves the
recorded bytes are unaltered and in order; it does **not** prove who wrote the
provider, because the manifests this module writes are unsigned for the reason
:mod:`mayhem.infra.attestation_store` stores beside every one of them.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import PackageNotFoundError, entry_points, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import ValidationError

from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    RetentionClass,
    build_manifest,
    content_digest,
    seal_events,
)
from mayhem.domain.catalog import CATALOG, validate_catalog
from mayhem.domain.common import utc_now
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.evidence import ActionOutcome
from mayhem.domain.fabric import FABRIC_PROTOCOL_VERSION
from mayhem.domain.faults import (
    EngineLane,
    FailureDomain,
    FaultCategory,
    FaultDefinition,
    MaturityLevel,
    Reversibility,
    TargetKind,
    VerificationMethod,
)
from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    PROVIDER_DECLARATION_SCHEMA_VERSION,
    PROVIDER_DECLARATION_WIRE_FIELDS,
    PROVIDER_FAULT_WIRE_FIELDS,
    CapabilityDescriptor,
    EvidenceSchema,
    FaultDeclaration,
    ImplementationKind,
    ImplementationReference,
    ProviderCatalog,
    ProviderCompatibilityError,
    ProviderError,
    ProviderMetadata,
    ProviderMutation,
    ProviderNotFoundError,
    ProviderPermission,
    ProviderPermissionError,
    ProviderRegistration,
    ProviderSource,
    TargetLocator,
    ensure_compatibility_bounds,
    ensure_declared_permissions,
    fault_parameter_problems,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind
from mayhem.infra.attestation_store import MUTATING_ACTION_OUTCOMES, AttestationRepository
from mayhem.infra.audit_stream import DEFAULT_STREAM_ID, AuditEntry, AuditStream
from mayhem.providers.builtin import create_builtin_registry
from mayhem.providers.pack import (
    SIGNATURE_TRUST_NOTICE,
    FaultPack,
    PackFault,
    PackValidationError,
    load_pack,
    pack_assurance,
    validate_pack,
)
from mayhem.providers.permissions import ProviderPermissionSet, SandboxRefusal
from mayhem.providers.sandbox import (
    ProviderActivity,
    ProviderActivityKind,
    SandboxEnforcer,
    SandboxProfile,
    select_profile,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, MutableMapping, Sequence

    from mayhem.domain.attestation import ChainVerification
    from mayhem.domain.provider import ProviderEvidenceRecord
    from mayhem.infra.store import Store
    from mayhem.providers.registry import ProviderRegistry

METADATA_ENTRY_POINT_GROUP = "mayhem.provider.metadata"
IMPLEMENTATION_ENTRY_POINT_GROUP = "mayhem.providers"

#: The version a local, untagged build reports — the ``fallback-version`` of
#: ``[tool.hatch.version]``. Restated rather than read: importing pyproject is
#: not something a loader may do, and a build that cannot read its own version
#: must still be able to compare a provider's bounds against *something* ordered.
FALLBACK_CORE_VERSION: Final[str] = "1.0.0.dev0"

#: The shape :class:`~mayhem.domain.provider.CompatibilityBounds` can order.
#: Mirrors the private ``_VERSION`` of :mod:`mayhem.domain.provider` on purpose:
#: the domain's is private, and a loader that guessed at the shape would refuse
#: every provider on an unparsable core version.
_ORDERABLE_VERSION = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-.][0-9A-Za-z.+-]+)?$"
)


def core_version() -> str:
    """The running Mayhem version, in a form compatibility bounds can order.

    Prefers the installed distribution's version, because that is what a user is
    actually running, and falls back to :data:`FALLBACK_CORE_VERSION` in two
    cases: the distribution is not installed (a source checkout), or its version
    is not ``major.minor.patch[prerelease]``.

    The second fallback matters more than it looks. ``ensure_compatibility_bounds``
    raises ``provider_version_unreadable`` on a version it cannot order, so a
    distribution reporting something exotic would refuse *every* provider — a
    self-inflicted outage caused by a version string, not by any provider.
    """
    try:
        candidate = version("mayhem-cli")
    except PackageNotFoundError:  # pragma: no cover — depends on the environment
        return FALLBACK_CORE_VERSION
    if _ORDERABLE_VERSION.fullmatch(candidate):
        return candidate
    return FALLBACK_CORE_VERSION


# ── gap 37: one protocol, two documents ──────────────────────────────────────

#: The protocol a third-party provider implements to be Mayhem-compatible.
#: An alias, not a definition: the declaration schema already versions itself
#: (:data:`~mayhem.domain.provider.PROVIDER_DECLARATION_SCHEMA_VERSION`), and a
#: second id for the same artifact is how two protocols get built by accident.
MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL: Final[str] = PROVIDER_DECLARATION_SCHEMA_VERSION

#: The two halves, named as importable symbols so a reader (and
#: ``tests/unit/test_provider_sandbox.py``) can resolve them instead of taking
#: this module's word for it. The declaration half is a module of record; the
#: execution half is plan 03's envelope.
MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_PARTS: Final[tuple[tuple[str, str], ...]] = (
    ("mayhem.domain.provider", "ProviderMetadata"),
    ("mayhem.domain.fabric", "FabricCommand"),
)

#: The two documents that describe that protocol, one per half.
MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS: Final[tuple[str, ...]] = (
    "docs/v1.1.0/17_EXTENSION_SDK_PROVIDER_PROTOCOL.md",
    "docs/v1.1.0/03_EXECUTION_FABRIC.md",
)


def compatible_provider_protocol() -> dict[str, object]:
    """The gap-37 protocol identity, as data a caller or a test can assert on.

    Returns the protocol id, both halves as ``module:symbol``, both documents,
    and the transport framing that carries an envelope between controller and
    agent. That last field is :data:`mayhem.domain.fabric.FABRIC_PROTOCOL_VERSION`
    (``mayhem/1``) and is *framing*, not the provider protocol — a reader who
    mistakes one for the other is exactly the confusion this function exists to
    prevent.
    """
    return {
        "protocol": MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL,
        "parts": tuple(
            f"{module}:{symbol}" for module, symbol in (MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_PARTS)
        ),
        "documents": MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS,
        "fabric_framing": FABRIC_PROTOCOL_VERSION,
    }


# ── Phase 4: the engine axis, and the provider activity ledger ──────────────────

#: Whether a loader refuses a provider whose sandbox profile needs a mechanism
#: this build does not apply. **``True``, deliberately.**
#:
#: Phase 2 shipped this at ``False`` and left the decision open. It is made here,
#: and the reasoning is worth recording because the default is the whole policy:
#:
#: * mayhem applies **no** confinement mechanism at all in this build. A profile
#:   is a decision mayhem makes and can refuse with; the operating system has
#:   not been touched (see :data:`mayhem.providers.sandbox.MechanismState`).
#: * Every non-empty declared permission set carries at least one
#:   ``DECLARED_NOT_APPLIED`` mechanism, so ``False`` means: *any* provider that
#:   asks for anything runs unconfined, by default, from a plain
#:   ``ProviderLoader()``.
#: * The alternative refusal rule — "refuse only what declares a world-reaching
#:   permission" — was considered and rejected. It would admit an unconfined
#:   third-party runtime precisely because the runtime *said* it needed nothing
#:   dangerous, and mayhem cannot verify that claim. A default that depends on an
#:   unverifiable statement is not a safety posture, it is a trust signal wearing
#:   one, which is the exact confusion this module's docstring refuses to create.
#:
#: The cost is real and is not hidden: with no seccomp filter, AppArmor profile,
#: SELinux label or container in this build, **a provider that requests any
#: permission at all does not load by default** — only a declaration that
#: requests nothing is admitted. The escape hatch is one explicit constructor
#: argument, and this module records the use of it: an admission under
#: ``require_sandbox_enforcement=False`` is sealed with
#: :data:`~mayhem.domain.evidence.ActionOutcome.ACKNOWLEDGED_NO_BACKEND` and the
#: profile's unapplied mechanism list, so "we ran it unconfined" is a fact in the
#: chain rather than a default nobody chose deliberately.
DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT: Final[bool] = True

#: The ``run_id`` the provider activity chain is sealed under. Provider activity
#: is not a run: :func:`~mayhem.domain.attestation.verify_chain` requires every
#: event in a chain to share one ``run_id``, and this lane spans every provider
#: load in a process. Named as a lane rather than as a run for the same reason
#: :mod:`mayhem.infra.audit_stream` gives every entry its stream id.
PROVIDER_ACTIVITY_CHAIN_ID: Final[str] = "mayhem.providers"

#: The one ``event_kind`` a sealed provider activity carries. Single kind, many
#: activities: the payload's ``activity_kind`` is the fine-grained vocabulary
#: (:class:`~mayhem.providers.sandbox.ProviderActivityKind`), so filtering the
#: chain by ``event_kind`` answers "did this lane seal anything at all" and
#: filtering by ``activity_kind`` answers "what did it decide".
EVENT_PROVIDER_ACTIVITY: Final[str] = "provider.activity"

#: Audit-stream actions this lane records. Declared here, as module constants,
#: rather than added to :mod:`mayhem.infra.audit_stream`'s vocabulary: that
#: module is not this lane's to edit, and a spelled-out constant at the one call
#: site honours the same "one place to grep" rule its own constants exist for.
AUDIT_PROVIDER_REGISTERED: Final[str] = "audit.provider.registered"
AUDIT_PROVIDER_PERMISSIONS_CHANGED: Final[str] = "audit.provider.permissions_changed"

#: Who an audit entry says performed a provider action. A recorded claim, not an
#: authenticated identity: :mod:`mayhem.infra.audit_stream` signs nothing, and a
#: loader cannot change that.
DEFAULT_PROVIDER_PRINCIPAL: Final[str] = "mayhem.provider_loader"

#: What a load report says when the loader had nowhere to seal to. Spelled out
#: rather than left as an empty dict, because the difference between "sealed and
#: verified" and "observed and thrown away" is the whole point of the sealed
#: chain, and a caller must not have to infer it from an absent key.
UNSEALED_ACTIVITY_NOTICE: Final[str] = (
    "this loader was constructed without a store, so provider activity was observed but "
    "nothing was sealed: no attestation chain and no audit entry exist for it. Read this "
    "as 'not recorded', never as 'recorded and clean'."
)

#: Engine lane names that mayhem knows, as provider ids. The built-in runtimes
#: are named after the lanes they drive, which is why a registry is a usable
#: answer to "what lane is this run on" when it holds exactly one of them.
_ENGINE_LANE_PROVIDER_IDS: Final[frozenset[str]] = frozenset(lane.value for lane in EngineLane)


def detect_engine_lane(registry: ProviderRegistry) -> EngineLane | None:
    """The engine lane *registry* can name, or ``None`` when it cannot.

    The honest answer to "which engine lane is this process on", derived from the
    only thing the loader can actually see: the runtimes that are registered to
    execute. The built-in registry registers ``docker``, ``podman`` **and**
    ``kubernetes``, so on an unfiltered registry the answer is ``None`` — three
    candidates is not a lane, and picking the first would be a guess with a
    signature.

    A caller that has narrowed its registry to one runtime gets that lane, and
    can hand it to :class:`ProviderLoader` as ``running_engine`` so the engine
    axis is verified rather than skipped. ``None`` means **unchecked**, and
    :meth:`ProviderLoader.compatibility_report` says so for every declaration
    that actually declares an engine constraint — the report is what keeps "we
    did not look" from being rendered as "we looked and it was fine".

    Not a trust signal and not a compatibility check: it names the lane, and
    :func:`~mayhem.domain.provider.ensure_compatibility_bounds` decides what that
    means for a given declaration.
    """
    candidates = sorted(registry.ids() & _ENGINE_LANE_PROVIDER_IDS)
    if len(candidates) != 1:
        return None
    return EngineLane(candidates[0])


class ProviderActivityLedger:
    """Provider activity, sealed into Mayhem's attested chain (plan 17 Phase 4).

    One record per provider activity, written through the *existing* attestation
    machinery and nothing else: an :class:`~mayhem.domain.attestation.AttestedEvent`
    of kind :data:`EVENT_PROVIDER_ACTIVITY`, appended to a chain stored by
    :class:`~mayhem.infra.attestation_store.AttestationRepository`, committed by
    a rolling manifest, and — for the two privileged actions — recorded in
    :class:`~mayhem.infra.audit_stream.AuditStream`. There is no second event
    type, no second table, no second verifier and no second canonicaliser here;
    if the format ever needs to change it changes in
    :mod:`mayhem.domain.attestation`.

    Two properties are worth stating because both are costs, not features:

    * **No signature.** Every manifest this writes is unsigned, with plan 12's own
      reason stored beside it, and the chain proves integrity and order only.
      Authorship is not established and nothing here may imply otherwise.
    * **The whole lane chain is rewritten on every append.** The store's primary
      key is ``(run_id, sequence)``, so an append has to re-verify and re-write
      from sequence 0. That is fine for a lane whose length is the number of
      provider decisions in one process, and it is the price of not inventing a
      second table to append to.

    What a provider contributes is the *declared* schema, not a mayhem-invented
    one: :meth:`record_provider_activity` resolves
    :meth:`~mayhem.domain.provider.ProviderMetadata.evidence_for` through the
    declarations the loader shares with it, so an activity recorded by a sandbox
    enforcer that has never seen a declaration still lands inside the provider's
    own evidence mapping.
    """

    def __init__(
        self,
        store: Store,
        *,
        lane_id: str = PROVIDER_ACTIVITY_CHAIN_ID,
        principal: str = DEFAULT_PROVIDER_PRINCIPAL,
        audit: AuditStream | None = None,
        stream_id: str = DEFAULT_STREAM_ID,
        declarations: MutableMapping[str, ProviderMetadata] | None = None,
    ) -> None:
        self._store = store
        self._lane_id = lane_id
        self._principal = principal
        self._declarations: MutableMapping[str, ProviderMetadata] = (
            declarations if declarations is not None else {}
        )
        self._repository = AttestationRepository(store)
        self._audit = audit if audit is not None else AuditStream(store, stream_id=stream_id)
        self._activities: list[ProviderActivity] = []

    @property
    def lane_id(self) -> str:
        """The ``run_id`` this lane's chain is sealed under."""
        return self._lane_id

    @property
    def principal(self) -> str:
        """The recorded claim of who performed the actions in this lane."""
        return self._principal

    @property
    def audit_stream(self) -> AuditStream:
        return self._audit

    @property
    def activities(self) -> tuple[ProviderActivity, ...]:
        """Every activity sealed through this ledger, oldest first."""
        return tuple(self._activities)

    def declare(self, metadata: ProviderMetadata) -> None:
        """Teach the ledger a provider's declared evidence schema."""
        self._declarations[metadata.provider_id] = metadata

    def forget(self, provider_id: str) -> None:
        """Stop resolving evidence schemas through *provider_id*'s declaration."""
        self._declarations.pop(provider_id, None)

    def _resolved(self, activity: ProviderActivity) -> ProviderActivity:
        """*activity* carrying the provider's declared schema, when it has one."""
        if activity.evidence_schema:
            return activity
        metadata = self._declarations.get(activity.provider_id)
        if metadata is None:
            return activity
        schema = metadata.evidence_schema
        if activity.fault_id:
            schema = metadata.evidence_for(activity.fault_id) or schema
        return activity.with_declared_evidence(schema.name, schema.version)

    @property
    def manifest_id(self) -> str:
        return f"{self._lane_id}:provider-activity"

    def chain(self) -> tuple[AttestedEvent, ...]:
        """The sealed chain as stored, reloaded from disk rather than remembered."""
        return self._repository.load_chain(self._lane_id)

    def verify(self) -> ChainVerification:
        """Re-verify the stored chain offline, with the domain verifier."""
        return self._repository.verify_run_chain(self._lane_id)

    def record_provider_activity(self, activity: ProviderActivity) -> ProviderEvidenceRecord:
        """Seal one activity and return the evidence record for it.

        Order matters and is the same order
        :meth:`~mayhem.infra.attestation_store.AttestationRepository.save_chain`
        documents: build, seal, then persist in one transaction. The evidence
        record is built *before* the write so its digest is in the sealed payload
        — a chain that carried only a pointer to a record nobody can find would
        be a chain about nothing.
        """
        resolved = self._resolved(activity)
        self._activities.append(resolved)
        evidence = resolved.to_evidence()
        events = self._repository.load_chain(self._lane_id)
        sequence = len(events)
        reading = AttestedTimestamp(
            wall_clock=resolved.recorded_at,
            monotonic_ns=time.monotonic_ns(),
            uncertainty_ms=0.0,
            source="system",
        )
        unsealed = AttestedEvent(
            event_id=f"{self._lane_id}:{sequence:06d}:{resolved.kind.value}",
            event_kind=EVENT_PROVIDER_ACTIVITY,
            run_id=self._lane_id,
            sequence=sequence,
            payload={
                **resolved.to_dict(),
                "lane": self._lane_id,
                "principal": self._principal,
                "evidence_digest": content_digest(evidence.model_dump(mode="json")),
                # Deliberately narrower than
                # ``MUTATING_ACTION_OUTCOMES``: an *admission* that succeeded
                # while naming mechanisms this build cannot install carries
                # ACKNOWLEDGED_NO_BACKEND, and reading the native set alone would
                # record loading a provider as a mutation, which it is not.
                "mutating": (
                    resolved.kind is ProviderActivityKind.ACTION
                    and resolved.action_outcome in MUTATING_ACTION_OUTCOMES
                ),
            },
            recorded_at=reading,
        )
        previous = events[-1].chain_link if events else GENESIS_DIGEST
        # ``sealed_event`` is one event, never a sequence: a pydantic model is
        # iterable (over its *fields*), so unpacking one with ``*`` silently
        # builds a tuple of key/value pairs instead of a chain.
        (sealed_event,) = seal_events([unsealed], previous_digest=previous)
        chain = (*events, sealed_event)
        self._repository.save_chain(self._lane_id, chain)
        self._commit_manifest(chain, reading)
        return evidence

    def _commit_manifest(
        self, events: tuple[AttestedEvent, ...], reading: AttestedTimestamp
    ) -> None:
        """Commit the lane chain to a manifest, chained to the previous one.

        ``previous_manifest_digest`` is what links one lane commit to the last:
        the event chain cannot be hung off a previous run's root (plan 12's
        one-chain-per-run rule), so the linkage lives at the manifest layer,
        which is where plan 12 put it.
        """
        stored = self._repository.load_manifest(self.manifest_id)
        manifest = build_manifest(
            events,
            manifest_id=self.manifest_id,
            run_id=self._lane_id,
            signer_identity="",
            trust_root_ref="",
            retention_class=RetentionClass.HOT,
            created_at=reading,
            previous_manifest_digest=(
                stored.manifest_digest if stored is not None else GENESIS_DIGEST
            ),
        )
        self._repository.save_manifest(manifest)

    # -- the two privileged actions, in the audit stream --------------------- #

    def record_registration(
        self,
        provider_id: str,
        *,
        source: str,
        profile_id: str,
        permissions: Iterable[ProviderPermission],
        fault_ids: Iterable[str] = (),
        declared_version: str = "",
    ) -> AttestedEvent:
        """Record that a provider entered the registry.

        Both places, deliberately: a sealed chain event so the registration is
        part of the attested history of this lane, and an audit entry so it is a
        *privileged action* an operator can list. A provider entering a registry
        is as much an administrative act as a manifest being deleted.
        """
        granted = sorted(permission.value for permission in permissions)
        self.record_provider_activity(
            ProviderActivity(
                provider_id=provider_id,
                kind=ProviderActivityKind.LOAD,
                outcome="registered",
                action_outcome=ActionOutcome.APPLIED,
                target_id=provider_id,
                operation_id=f"provider.register:{provider_id}",
                recorded_at=utc_now(),
                details={
                    "source": source,
                    "declared_version": declared_version,
                    "sandbox_profile": profile_id,
                    "permissions": granted,
                    "fault_ids": list(fault_ids),
                },
            )
        )
        return self._audit.record(
            AuditEntry(
                principal=self._principal,
                action=AUDIT_PROVIDER_REGISTERED,
                target=provider_id,
                subject_run_id=self._lane_id,
                detail={
                    "source": source,
                    "declared_version": declared_version,
                    "sandbox_profile": profile_id,
                    "permissions": granted,
                    "fault_ids": list(fault_ids),
                },
            )
        )

    def record_permission_change(
        self,
        provider_id: str,
        *,
        previous: Iterable[ProviderPermission],
        granted: Iterable[ProviderPermission],
        reason: str = "",
        actor: str = "",
    ) -> AttestedEvent:
        """Record a change to what a provider may ask for.

        Audit stream only, and the split is the point: the chain records *what the
        provider did*, and the stream records *what was done to the provider's
        grant*. A widened grant is an administrative act with no provider action
        behind it, so putting it in the chain would make the chain answer a
        question nobody asked.

        ``previous`` and ``granted`` both travel in the payload. A permission log
        that records only the new state cannot answer "what could it do before",
        which is the question an incident review actually asks.
        """
        detail: dict[str, object] = {
            "previous_permissions": sorted(permission.value for permission in previous),
            "granted_permissions": sorted(permission.value for permission in granted),
        }
        if reason:
            detail["reason"] = reason
        if actor:
            detail["actor"] = actor
        return self._audit.record(
            AuditEntry(
                principal=actor or self._principal,
                action=AUDIT_PROVIDER_PERMISSIONS_CHANGED,
                target=provider_id,
                subject_run_id=self._lane_id,
                detail=detail,
            )
        )


def _factory_for(runtime: object) -> Callable[[], object]:
    """Bind *runtime* into a zero-arg factory, by value.

    An already-materialized runtime is handed to the registry as-is; the
    default-argument lambda this replaces (``lambda runtime=runtime:
    runtime``) could not be typed because the default's own type was
    unresolvable.  A closure over a *parameter* gives the same bind-at-call
    semantics — each returned factory closes over its own ``runtime``.
    """

    def factory() -> object:
        return runtime

    return factory


#: The identifier shape ``ProviderMetadata`` enforces, restated so a bad pack id
#: is refused with a pack-worded message instead of a pydantic dump.
_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")

#: Permissions that mean "this fault touches the world". A read-only fault may
#: only ever declare :attr:`ProviderPermission.TARGET_READ`.
_ACTION_PERMISSIONS: frozenset[ProviderPermission] = frozenset(ProviderPermission) - {
    ProviderPermission.TARGET_READ
}


class ProviderLoadError(ProviderError, ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderLoadFailure:
    provider_id: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ProviderInspection:
    provider_id: str
    status: str
    source: str
    metadata: dict[str, Any] | None = None
    error: ProviderLoadFailure | None = None
    #: The sandbox profile chosen for this provider, the compatibility axes this
    #: run actually checked, and what was sealed about it. All three are additive
    #: and all three default to ``None`` so a caller that never asked for them
    #: keeps the shape it had. ``sandbox`` carries the profile's own ``notice``,
    #: so a caller that renders it cannot render a profile without the caveat;
    #: ``evidence`` carries ``sealed``, and when that is ``False`` it carries the
    #: notice saying nothing was written anywhere, so a report rendered from an
    #: inspection cannot call a decision "recorded" when it only happened in
    #: memory.
    sandbox: dict[str, Any] | None = None
    compatibility: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "provider_id": self.provider_id,
            "status": self.status,
            "source": self.source,
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        if self.sandbox is not None:
            payload["sandbox"] = self.sandbox
        if self.compatibility is not None:
            payload["compatibility"] = self.compatibility
        if self.evidence is not None:
            payload["evidence"] = self.evidence
        return payload


@dataclass(frozen=True, slots=True)
class ProviderLoadReport:
    providers: tuple[ProviderInspection, ...] = ()
    loaded: tuple[str, ...] = ()
    failures: tuple[ProviderLoadFailure, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "providers": [provider.to_dict() for provider in self.providers],
            "loaded": list(self.loaded),
            "failures": [failure.to_dict() for failure in self.failures],
        }


# ── fault packs: reading a file, establishing what it proves ─────────────────


def builtin_fault_ids() -> frozenset[str]:
    """Every fault id mayhem already owns, read live from the catalog.

    Read live rather than cached at import so a pack can never be admitted
    because this module was imported before the catalog grew.
    """
    return frozenset(definition.id for definition in CATALOG)


def read_pack_document(path: str | Path) -> tuple[dict[str, Any], str]:
    """Read a pack file into a document plus the sha256 of the bytes read.

    Every failure mode of a real filesystem — missing, unreadable, a directory,
    empty, non-UTF-8, not JSON, JSON but not an object — is reported as a
    :class:`PackValidationError` with a message a user can act on. Nothing here
    raises a bare ``OSError`` or lets a ``json``/``UnicodeDecodeError`` trace
    escape, because a stack trace is not an answer about someone else's file.
    """
    resolved = Path(path)
    try:
        raw = resolved.read_bytes()
    except IsADirectoryError as exc:
        raise PackValidationError(
            f"cannot read fault pack {resolved}: it is a directory, not a pack file"
        ) from exc
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise PackValidationError(f"cannot read fault pack {resolved}: {detail}") from exc
    if not raw.strip():
        raise PackValidationError(f"fault pack {resolved} is empty; expected a JSON pack document")
    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PackValidationError(
            f"fault pack {resolved} is not UTF-8 text, so it is not a pack document"
        ) from exc
    except json.JSONDecodeError as exc:
        raise PackValidationError(
            f"fault pack {resolved} is not valid JSON: {exc.msg} "
            f"at line {exc.lineno} column {exc.colno}"
        ) from exc
    if not isinstance(document, dict):
        raise PackValidationError(
            f"fault pack {resolved} is a JSON {type(document).__name__}, "
            "not a JSON object describing a pack"
        )
    return document, hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class PackAssurance:
    """What loading a pack established — and, more importantly, what it did not.

    ``signature_verified`` is a real field with a real ``False`` value in this
    build, not an omitted one. A consumer must not read the presence of
    ``signature_present`` as permission to say "verified".
    """

    provider_id: str
    digest: str
    digest_verified: bool
    signature_present: bool
    signature_verified: bool
    signature_scheme: str
    signer_claimed: str
    signer_trusted: bool
    development_only: bool
    assurance: str
    notice: str = SIGNATURE_TRUST_NOTICE

    @classmethod
    def for_pack(cls, pack: FaultPack, *, digest_verified: bool) -> PackAssurance:
        values = pack_assurance(pack, digest_verified=digest_verified)
        return cls(
            provider_id=pack.manifest.provider_id,
            digest=str(values["digest"]),
            digest_verified=digest_verified,
            signature_present=bool(values["signature_present"]),
            signature_verified=bool(values["signature_verified"]),
            signature_scheme=str(values["signature_scheme"]),
            signer_claimed=str(values["signer_claimed"]),
            signer_trusted=bool(values["signer_trusted"]),
            development_only=bool(values["development_only"]),
            assurance=str(values["assurance"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "digest": self.digest,
            "digest_verified": self.digest_verified,
            "signature_present": self.signature_present,
            "signature_verified": self.signature_verified,
            "signature_scheme": self.signature_scheme,
            "signer_claimed": self.signer_claimed,
            "signer_trusted": self.signer_trusted,
            "development_only": self.development_only,
            "assurance": self.assurance,
            "notice": self.notice,
        }


@dataclass(frozen=True, slots=True)
class PackRuntime:
    """What a registered pack *is* in 1.0: catalog metadata, never code.

    ``executable`` is a field rather than an omission so that a caller reading
    the runtime object cannot infer executability from its mere existence.
    """

    provider_id: str
    signer_claimed: str
    digest: str
    fault_ids: tuple[str, ...]
    executable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "signer_claimed": self.signer_claimed,
            "digest": self.digest,
            "fault_ids": list(self.fault_ids),
            "executable": self.executable,
        }


@dataclass(frozen=True, slots=True)
class LoadedPack:
    """A pack that passed every gate, plus everything it did and did not prove."""

    pack: FaultPack
    registration: ProviderRegistration
    definitions: tuple[FaultDefinition, ...]
    assurance: PackAssurance
    report: dict[str, Any]
    path: str = ""

    def runtime(self) -> PackRuntime:
        return PackRuntime(
            provider_id=self.pack.manifest.provider_id,
            signer_claimed=self.pack.signer,
            digest=self.assurance.digest,
            fault_ids=tuple(fault.id for fault in self.pack.faults),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "pack": self.pack.to_dict(),
            "report": self.report,
            "assurance": self.assurance.to_dict(),
            "registration": self.registration.metadata.model_dump(mode="json", by_alias=True),
            "definitions": [definition.model_dump(mode="json") for definition in self.definitions],
        }


def _check_declared_digest(pack: FaultPack, path: str, computed: str, expected: str) -> list[str]:
    """Compare the pack's own digest claim against the bytes actually on disk.

    Both digests are printed in full. A truncated digest in a refusal is not
    enough to let an operator confirm which of two packs they were handed.
    """
    problems: list[str] = []
    if pack.declared_digest and pack.declared_digest != computed:
        problems.append(
            f"pack digest mismatch: {path} declares {pack.declared_digest} "
            f"but its content digests to {computed} "
            "(sha256 over the canonical pack document, excluding declared_digest); "
            "the file was modified after it was signed"
        )
    if expected and expected != computed:
        problems.append(
            f"pack digest does not match the expected {expected}: {path} digests to {computed}"
        )
    return problems


def _check_no_shadowing(
    pack: FaultPack, reserved: frozenset[str], builtin_providers: frozenset[str]
) -> list[str]:
    """A pack may add fault ids; it may never redeclare, shadow, or impersonate."""
    problems: list[str] = []
    provider_id = pack.manifest.provider_id
    if provider_id in builtin_providers:
        problems.append(
            f"pack provider id {provider_id!r} is already a built-in mayhem provider; "
            "choose an id that does not shadow a built-in provider"
        )
    for fault in pack.faults:
        if fault.id in reserved:
            problems.append(
                f"pack fault {fault.id!r} is already a mayhem catalog fault; "
                "a pack must not redeclare or shadow a built-in fault id"
            )
    return problems


def _check_catalog_joinable(pack: FaultPack) -> list[str]:
    """Every pack fault must be expressible in the existing catalog contract.

    A pack fault is surfaced as a ``catalog_only`` ``FaultDefinition`` so it uses
    the same machinery as every other refused fault. That machinery derives its
    category from the id prefix, so an id mayhem cannot classify cannot be
    surfaced at all — refuse it here rather than dropping it silently.
    """
    problems: list[str] = []
    for fault in pack.faults:
        try:
            FaultCategory.from_fault_id(fault.id)
        except SchemaValidationError as exc:
            problems.append(f"pack fault {fault.id!r} cannot join the fault catalog: {exc}")
        try:
            RiskLevel(fault.risk)
        except ValueError:
            problems.append(
                f"pack fault {fault.id!r} declares unknown risk {fault.risk!r} "
                f"(expected one of {[level.value for level in RiskLevel]})"
            )
    return problems


def _check_fault_contract(pack: FaultPack) -> list[str]:
    """A pack fault must be expressible as a ``FaultDeclaration``.

    The provider contract says a *mutating* fault must be reversible, and a
    *read-only* fault may not require action permissions. Those two rules do
    not bend to a pack, so a pack that lands between them is refused with the
    fix spelled out rather than quietly downgraded to read-only.
    """
    problems: list[str] = []
    for fault in pack.faults:
        action = set(fault.permissions) & _ACTION_PERMISSIONS
        if action and ProviderPermission.TARGET_MUTATE not in set(fault.permissions):
            names = sorted(permission.value for permission in action)
            problems.append(
                f"pack fault {fault.id!r} requests action permissions "
                f"({', '.join(names)}) without target:mutate; a pack fault that acts on "
                "anything must declare target:mutate so the grant is explicit"
            )
        if fault.reversible is False and ProviderPermission.TARGET_MUTATE in set(fault.permissions):
            problems.append(
                f"pack fault {fault.id!r} is irreversible and declares target:mutate, but a "
                "mutating provider fault must be reversible; publish it as a reversible "
                "fault with a compensation contract, or drop the fault"
            )
    return problems


def _check_registration_shape(pack: FaultPack) -> list[str]:
    """Provider id and version must satisfy the provider metadata contract."""
    problems: list[str] = []
    manifest = pack.manifest
    if not _PROVIDER_ID.fullmatch(manifest.provider_id):
        problems.append(
            f"provider id {manifest.provider_id!r} is not a lowercase dotted identifier "
            "of 2-64 characters"
        )
    if not _SEMVER.fullmatch(manifest.version):
        problems.append(
            f"provider version {manifest.version!r} is not semantic versioning (major.minor.patch)"
        )
    if not manifest.provider_id:
        problems.append("pack names no provider id")
    return problems


def _requested_permissions(pack: FaultPack) -> frozenset[ProviderPermission]:
    """Manifest permissions unioned with every fault's own permissions."""
    return frozenset(pack.manifest.permissions) | frozenset(
        permission for fault in pack.faults for permission in fault.permissions
    )


# ── the declaration gates, re-checkable without re-validating ─────────────────
#
# The rules below are *also* enforced by the models in ``domain.provider``. They
# are restated here as loader checks for one specific reason, and it is worth
# being precise about it: ``ProviderMetadata.model_copy`` does not re-validate,
# this module calls ``model_copy`` itself, and whether pydantic re-runs a nested
# model's validators when a ``ProviderRegistration`` is built around an existing
# instance is behaviour the loader should not be *only* line of defence against —
# it is exactly the kind of undocumented detail that changes between releases.
#
# So the loader does not assume the object in front of it was validated by the
# code path that is running: it reads the declaration's own derived views
# (:attr:`~mayhem.domain.provider.ProviderMetadata.capability_ids`,
# ``target_locator_ids``, ``declared_fault_ids``, ``required_permissions``) and
# compares them. Where the two disagree, the loader refuses — and the test that
# proves these gates fire builds the disagreement with
# ``ProviderRegistration.model_construct``, which is the honest way to reach the
# state pydantic's revalidation currently prevents.


class _Problem(NamedTuple):
    """One refusal: the code a consumer routes on, and the message it prints.

    A code per *problem kind* rather than one bucket for the whole declaration
    gate, so a consumer can distinguish "this provider over-claims" from "this
    provider's defaults contradict its own grammar" without parsing prose.
    """

    code: str
    message: str


def _check_wire_fields(document: Mapping[str, Any]) -> list[str]:
    """Wire keys this core does not implement, named by provider.

    ``PROVIDER_DECLARATION_WIRE_FIELDS`` and ``PROVIDER_FAULT_WIRE_FIELDS`` are
    hand-written frozen contracts. Pydantic's ``extra="forbid"`` would refuse an
    unknown key anyway, but it refuses with a dump of the whole document, which
    does not tell an SDK author *which* field is from a newer core. Naming it is
    the difference between "invalid provider catalog" and "this Mayhem does not
    implement ``sandboxProfiles``; upgrade mayhem or downgrade your SDK".

    Only the top level of a declaration and of each fault declaration are
    checked. Nested objects (``compatibility``, ``evidenceSchema``, a fault's
    ``parameterGrammar``) are pydantic's business; this is the two hand-written
    lists the contract actually froze. Anything structurally unexpected is left
    to :class:`ProviderCatalog`, which is the authority on shape.
    """
    problems: list[str] = []
    if not isinstance(document, dict):
        return problems
    providers = document.get("providers")
    if not isinstance(providers, list):
        return problems
    for index, entry in enumerate(providers):
        if not isinstance(entry, dict):
            continue
        metadata = entry.get("metadata")
        if not isinstance(metadata, dict):
            continue
        provider_id = metadata.get("providerId", f"<providers[{index}]>")
        for key in sorted(set(metadata) - PROVIDER_DECLARATION_WIRE_FIELDS):
            problems.append(
                f"provider {provider_id!r} declares wire field {key!r}, which "
                f"{PROVIDER_DECLARATION_SCHEMA_VERSION} does not implement; "
                "a field added by a newer core is not readable here"
            )
        faults = metadata.get("faultDeclarations")
        if not isinstance(faults, list):
            continue
        for position, fault in enumerate(faults):
            if not isinstance(fault, dict):
                continue
            for key in sorted(set(fault) - PROVIDER_FAULT_WIRE_FIELDS):
                problems.append(
                    f"provider {provider_id!r} fault #{position} declares wire field "
                    f"{key!r}, which {PROVIDER_DECLARATION_SCHEMA_VERSION} does not implement"
                )
    return problems


def _check_declared_permission_union(metadata: ProviderMetadata) -> list[_Problem]:
    """No capability, locator or fault may ask for an undeclared permission.

    The model enforces this on construction. Re-read here through
    :attr:`~mayhem.domain.provider.ProviderMetadata.required_permissions` — the
    union over every part — because that property is what an operator is shown
    before approving an install, and a union that is wider than the declared set
    is a request nobody approved.
    """
    undeclared = sorted(
        permission.value for permission in metadata.required_permissions - metadata.permissions
    )
    if not undeclared:
        return []
    return [
        _Problem(
            "provider_permission_undeclared",
            f"provider {metadata.provider_id!r} requires permissions its own declaration "
            f"does not list: {', '.join(undeclared)}",
        )
    ]


def _check_declared_graph(metadata: ProviderMetadata) -> list[_Problem]:
    """Every declared fault hangs off a declared capability and locator.

    Same rule as the model validator, restated against the declaration's derived
    views so the gate refuses an object it did not build. The refusal names the
    fault and the id it asked for, because "a fault references an undeclared
    capability" without saying which is a search, not a diagnosis.
    """
    capability_ids = metadata.capability_ids
    locator_ids = metadata.target_locator_ids
    problems: list[_Problem] = []
    for fault in metadata.fault_declarations:
        if fault.capability not in capability_ids:
            problems.append(
                _Problem(
                    "provider_capability_undeclared",
                    f"provider {metadata.provider_id!r} fault {fault.id!r} names capability "
                    f"{fault.capability!r}, which it does not declare",
                )
            )
        for locator_id in fault.target_locator_ids:
            if locator_id not in locator_ids:
                problems.append(
                    _Problem(
                        "provider_capability_undeclared",
                        f"provider {metadata.provider_id!r} fault {fault.id!r} names target "
                        f"locator {locator_id!r}, which it does not declare",
                    )
                )
    return problems


def _resolved_parameter_defaults(fault: FaultDeclaration) -> dict[str, str] | None:
    """Every grammar entry's shipped value, or ``None`` if the caller must supply one.

    A ``required`` entry with neither a shipped value nor a default is not a
    load-time problem — the fault is callable, the caller supplies the argument
    at execution time — so the fault is skipped rather than refused. A value
    grammar check that fired on a perfectly callable declaration would be a false
    refusal, and a false refusal is how a gate stops being read.
    """
    values: dict[str, str] = {}
    for entry in fault.parameter_grammar:
        if entry.name in fault.parameters:
            values[entry.name] = fault.parameters[entry.name]
        elif entry.default is not None:
            values[entry.name] = entry.default
        elif entry.required:
            return None
    return values


def _check_parameter_defaults(metadata: ProviderMetadata) -> list[_Problem]:
    """A fault's own parameter defaults must satisfy its declared grammar.

    The grammar is the contract an SDK emits and a core checks calls against;
    a declaration whose *defaults* violate its own grammar is a fault that
    cannot be applied with the values it shipped with. Checked here with the
    domain's pure :func:`~mayhem.domain.provider.fault_parameter_problems`, so
    the value grammar stays in one place, and deliberately only over the
    ``parameters`` the declaration carries — a fault with no grammar is a v1
    artifact and is checked against nothing.
    """
    problems: list[_Problem] = []
    for fault in metadata.fault_declarations:
        if not fault.parameters or not fault.parameter_grammar:
            continue
        defaults = _resolved_parameter_defaults(fault)
        if defaults is None:
            continue
        for problem in fault_parameter_problems(fault, defaults):
            problems.append(
                _Problem(
                    "provider_parameter_default_invalid",
                    f"provider {metadata.provider_id!r} fault {fault.id!r} declares parameter "
                    f"values its own grammar does not admit: {problem}",
                )
            )
    return problems


def _check_evidence_coverage(metadata: ProviderMetadata) -> list[_Problem]:
    """A mutating fault must resolve an evidence schema through its mapping.

    :meth:`~mayhem.domain.provider.ProviderMetadata.evidence_for` is the only way
    to resolve a mapping, and it returns ``None`` for a fault the declaration
    says nothing about. That silence is fine for a read-only fault. It is not
    fine for one that changes a target: a mutation with no declared evidence
    schema is a mutation whose result nobody can seal, and refusing it at load
    is cheaper than discovering it after the fact.
    """
    return [
        _Problem(
            "provider_evidence_missing",
            f"provider {metadata.provider_id!r} fault {fault.id!r} mutates targets but "
            "declares no evidence mapping, so its outcome cannot be recorded",
        )
        for fault in metadata.fault_declarations
        if fault.mutation is ProviderMutation.MUTATING and metadata.evidence_for(fault.id) is None
    ]


def _check_no_provider_shadowing(
    metadata: ProviderMetadata,
    reserved_fault_ids: frozenset[str],
    builtin_providers: frozenset[str],
) -> list[_Problem]:
    """A third-party provider may add ids; it may never shadow mayhem's own.

    The same rule ``_check_no_shadowing`` applies to a fault pack, applied to
    the declaration a *catalog* carries. Without it a catalog could register
    ``docker`` and either fail late on ``provider_already_registered`` or — with
    ``replace=True`` — take over a built-in id, so the refusal has to name the
    collision rather than surface as a duplicate registration.
    """
    problems: list[_Problem] = []
    if metadata.provider_id in builtin_providers:
        problems.append(
            _Problem(
                "provider_id_shadows_builtin",
                f"provider id {metadata.provider_id!r} is already a built-in mayhem provider; "
                "choose an id that does not shadow a built-in provider",
            )
        )
    shadows = sorted(metadata.declared_fault_ids & reserved_fault_ids)
    if shadows:
        problems.append(
            _Problem(
                "provider_fault_id_shadows_builtin",
                f"provider {metadata.provider_id!r} declares fault ids mayhem already owns: "
                f"{', '.join(shadows)}; a provider must not redeclare or shadow a catalog fault",
            )
        )
    return problems


def _declared_strings(runtime: object, method: str) -> frozenset[str] | None:
    """The strings *method* advertises, or ``None`` when the runtime stays quiet.

    ``None`` means "this runtime does not declare that", which is a legitimate
    answer for an in-process object that has no such method: the protocols in
    :mod:`mayhem.providers.protocols` are structural, and a runtime that
    implements none of the optional accessors is checked on the declaration
    alone. What is refused is a runtime that advertises *something* outside what
    it declared — silence is not a claim.
    """
    accessor = getattr(runtime, method, None)
    if not callable(accessor):
        return None
    advertised = accessor()
    if not isinstance(advertised, (list, tuple, set, frozenset)):
        return None
    return frozenset(value for value in advertised if isinstance(value, str))


def _check_behavior(metadata: ProviderMetadata, runtime: object) -> list[str]:
    """What the loaded runtime advertises must be inside what it declared.

    Three optional accessors are read, each from
    :mod:`mayhem.providers.protocols`: ``capabilities()`` (part of
    :class:`~mayhem.providers.protocols.ProviderRuntime`), ``fault_ids()``, and
    ``permissions()``. A runtime that implements none of them is not refused —
    it cannot over-claim about a set it never published.

    Run *before* the runtime is handed to the registry, so a mismatch is a
    refusal rather than a revocation: nothing to take back afterwards, and no
    window in which a mismatched runtime was reachable.
    """
    problems: list[str] = []

    advertised_capabilities = _declared_strings(runtime, "capabilities")
    if advertised_capabilities is not None:
        undeclared = sorted(advertised_capabilities - metadata.capability_ids)
        if undeclared:
            problems.append(
                f"provider {metadata.provider_id!r} advertises capabilities it does not "
                f"declare: {', '.join(undeclared)}"
            )

    advertised_faults = _declared_strings(runtime, "fault_ids")
    if advertised_faults is not None:
        undeclared_faults = sorted(advertised_faults - metadata.declared_fault_ids)
        if undeclared_faults:
            problems.append(
                f"provider {metadata.provider_id!r} advertises faults it does not declare: "
                f"{', '.join(undeclared_faults)}"
            )

    requested: set[ProviderPermission] = set()
    for value in sorted(_declared_strings(runtime, "permissions") or ()):
        try:
            requested.add(ProviderPermission(value))
        except ValueError:
            problems.append(
                f"provider {metadata.provider_id!r} requests unknown permission {value!r}"
            )
    undeclared_permissions = sorted(requested - metadata.permissions)
    if undeclared_permissions:
        problems.append(
            f"provider {metadata.provider_id!r} requests permissions it does not declare: "
            f"{', '.join(permission.value for permission in undeclared_permissions)}"
        )
    return problems


def _category_defaults(category: FaultCategory) -> tuple[FailureDomain, VerificationMethod]:
    """A category's failure domain and verification method, from the live catalog.

    Borrowed from the built-in entries for the same category rather than
    restated, so a pack fault is classified exactly the way a built-in fault of
    its category is and the two cannot drift apart.
    """
    for definition in CATALOG:
        if (
            definition.category is category
            and definition.failure_domain is not None
            and definition.verification_method is not None
        ):
            return (definition.failure_domain, definition.verification_method)
    raise PackValidationError(
        f"mayhem has no catalog entry for fault category {category.value!r}, "
        "so a pack fault of that category cannot be described"
    )


def _pack_refusal_reason(pack: FaultPack, fault: PackFault) -> str:
    """Why this pack fault is catalog-only, in the catalog's own vocabulary."""
    signer = pack.signer or "<no signer — pack is unsigned>"
    return (
        f"catalog.pack_fault_not_executable: {fault.id!r} is contributed by fault pack "
        f"{pack.manifest.provider_id!r} (signer claims {signer!r}, digest "
        f"{pack.pack_digest()[:12]}), whose signature mayhem cannot verify because the "
        "pack format declares no key or trust store; mayhem 1.0 surfaces pack faults in "
        "the catalog for inspection and refuses to plan or execute them"
    )


def pack_definition(pack: FaultPack, fault: PackFault) -> FaultDefinition:
    """Re-express one pack fault in the existing ``catalog_only`` machinery.

    Deliberately not a parallel mechanism: this is an ordinary
    :class:`FaultDefinition` with ``catalog_only=True`` and a populated
    ``refusal_reason``, so ``validate_catalog`` and the planner's catalog-only
    handling apply to it unchanged.
    """
    category = FaultCategory.from_fault_id(fault.id)
    failure_domain, verification_method = _category_defaults(category)
    return FaultDefinition(
        id=fault.id,
        category=category,
        risk=RiskLevel(fault.risk),
        reversible=fault.reversible,
        applicable_node_kinds=frozenset({NodeKind.SERVICE}),
        max_duration_s=300.0,
        observable_effect=(
            fault.observable_effect
            or "effect declared by fault pack "
            f"{pack.manifest.provider_id!r}, not verified by mayhem"
        ),
        compensation_evidence=(fault.compensation,),
        failure_domain=failure_domain,
        target_kind=TargetKind.SERVICE,
        target_kinds=frozenset({TargetKind.SERVICE}),
        engine_lanes=frozenset({EngineLane.MULTI_ENGINE}),
        verification_method=verification_method,
        reversibility=(
            Reversibility.REVERSIBLE if fault.reversible else Reversibility.IRREVERSIBLE
        ),
        maturity=MaturityLevel.EXPERIMENTAL,
        catalog_only=True,
        refusal_reason=_pack_refusal_reason(pack, fault),
    )


def pack_definitions(pack: FaultPack) -> tuple[FaultDefinition, ...]:
    """Every pack fault as a catalog-only definition, checked by ``validate_catalog``."""
    definitions = tuple(pack_definition(pack, fault) for fault in pack.faults)
    if definitions:
        validate_catalog(definitions)
    return definitions


def _fault_declaration(pack: FaultPack, fault: PackFault) -> FaultDeclaration:
    """One pack fault as a provider fault declaration."""
    provider_id = pack.manifest.provider_id
    mutating = ProviderPermission.TARGET_MUTATE in set(fault.permissions)
    return FaultDeclaration(
        id=fault.id,
        capability=f"{provider_id}.pack",
        summary=(
            fault.observable_effect or f"fault {fault.id!r} contributed by pack {provider_id!r}"
        )[:500],
        target_locator_ids=(f"{provider_id}.target",),
        requiredPermissions=frozenset(fault.permissions),
        mutation=ProviderMutation.MUTATING if mutating else ProviderMutation.READ_ONLY,
        reversible=fault.reversible,
    )


def _pack_metadata(pack: FaultPack) -> ProviderMetadata:
    """Pack faults expressed as provider metadata for the provider registry."""
    provider_id = pack.manifest.provider_id
    # The provider contract requires every target locator to hold target:read,
    # so a pack that addresses a target always declares it. This is a floor on
    # the *metadata* only: what the pack actually asked for is still gated
    # against the caller's grant in ``validate_pack``.
    permissions = _requested_permissions(pack) | {ProviderPermission.TARGET_READ}
    return ProviderMetadata(
        apiVersion=PROVIDER_API_VERSION,
        providerId=provider_id,
        name=pack.manifest.provider_id,
        version=pack.manifest.version,
        description=(
            f"Fault pack {pack.manifest.provider_id!r} "
            f"({len(pack.faults)} catalog-only fault(s)); "
            "its signature is unverified and mayhem does not execute pack faults."
        )[:1000],
        permissions=permissions,
        capabilities=(
            CapabilityDescriptor(
                id=f"{provider_id}.pack",
                summary="Faults contributed by a third-party fault pack.",
                requiredPermissions=permissions & _ACTION_PERMISSIONS,
                mutates_targets=ProviderPermission.TARGET_MUTATE in permissions,
                compensable=ProviderPermission.TARGET_MUTATE in permissions,
            ),
        ),
        faultDeclarations=tuple(_fault_declaration(pack, fault) for fault in pack.faults),
        targetLocators=(
            TargetLocator(
                id=f"{provider_id}.target",
                kind="pack_target",
                requiredPermissions=frozenset({ProviderPermission.TARGET_READ}),
            ),
        ),
        evidenceSchema=EvidenceSchema(name=f"{provider_id}-pack-evidence", version="1.0"),
        source=ProviderSource.CATALOG,
        homepage=pack.manifest.homepage or None,
    )


def pack_registration(pack: FaultPack) -> ProviderRegistration:
    """Build the provider registration a loaded pack contributes.

    The implementation reference is deliberately an ``entry_point`` for the
    pack's own id: a pack supplies no importable code, so this registration
    declares *metadata only*. Nothing in mayhem installs such an entry point,
    which is exactly why the pack faults it contributes are catalog-only.
    """
    problems = _check_registration_shape(pack)
    if problems:
        raise PackValidationError(
            f"pack {pack.manifest.provider_id!r} refused: " + "; ".join(problems)
        )
    try:
        metadata = _pack_metadata(pack)
    except (SchemaValidationError, ValueError) as exc:
        raise PackValidationError(
            f"pack {pack.manifest.provider_id!r} refused: it cannot be expressed as a "
            f"mayhem provider registration: {exc}"
        ) from exc
    return ProviderRegistration(
        metadata=metadata,
        implementation=ImplementationReference(
            kind=ImplementationKind.ENTRY_POINT,
            target=pack.manifest.provider_id,
            factory=True,
        ),
    )


class PackLoader:
    """Opt-in fault-pack loading behind explicit permission grants (task 18).

    Nothing loads unless the caller opts in: ``--allow-development-only`` for an
    unsigned pack, and a named permission grant for anything beyond the default
    read-only posture. Every refusal is deterministic and says what to change.
    """

    def __init__(
        self,
        *,
        grants: dict[str, ProviderPermissionSet] | None = None,
        allow_development_only: bool = False,
        activity_ledger: ProviderActivityLedger | None = None,
        principal: str = DEFAULT_PROVIDER_PRINCIPAL,
    ) -> None:
        self._grants = dict(grants or {})
        self._allow_development_only = allow_development_only
        # Phase 4: a pack grant is the same privileged act as a provider grant,
        # so it goes through the same recorded path. Optional, like every ledger
        # in this module — a pack loader with nowhere to write writes no record,
        # and says nothing that implies it did.
        self._ledger = activity_ledger
        self._principal = principal

    def permissions_for(self, provider_id: str) -> ProviderPermissionSet:
        return self._grants.get(provider_id) or ProviderPermissionSet.default(provider_id)

    def grant(self, provider_id: str, permissions: ProviderPermissionSet) -> None:
        """Record what a provider may load, replacing any earlier grant.

        Both states are recorded when a ledger was supplied, for the reason
        :meth:`~mayhem.providers.loader.ProviderLoader.grant_permissions` gives:
        an incident review asks what the pack could reach *before* the grant, not
        only what it can reach now.
        """
        previous = self._grants.get(provider_id)
        self._grants[provider_id] = permissions
        if self._ledger is not None:
            self._ledger.record_permission_change(
                provider_id,
                previous=previous.granted if previous is not None else frozenset(),
                granted=permissions.granted,
                reason="fault pack permission grant",
                actor=self._principal,
            )

    @staticmethod
    def _require_mutation_grant(pack: FaultPack, permissions: ProviderPermissionSet) -> None:
        if not pack.faults or permissions.mutating:
            return
        for fault in pack.faults:
            permissions.require(
                ProviderPermission.TARGET_MUTATE,
                reason=(
                    f"pack fault {fault.id!r} mutates a target; "
                    "grant target:mutate explicitly to load it"
                ),
            )

    def inspect(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate without loading; never raises for a merely invalid pack."""
        try:
            pack = load_pack(payload)
        except PackValidationError as exc:
            return {"loadable": False, "reason": str(exc)}
        permissions = self.permissions_for(pack.manifest.provider_id)
        try:
            self._require_mutation_grant(pack, permissions)
        except SandboxRefusal as exc:
            return {"loadable": False, "reason": str(exc)}
        try:
            return validate_pack(
                pack,
                granted_permissions=permissions.granted,
                allow_development_only=self._allow_development_only,
            )
        except PackValidationError as exc:
            return {"loadable": False, "reason": str(exc)}

    def load(self, payload: dict[str, Any]) -> tuple[FaultPack, dict[str, Any]]:
        """Validate and return the pack, or raise ``PackValidationError``."""
        pack = load_pack(payload)
        permissions = self.permissions_for(pack.manifest.provider_id)
        # The pack must not exceed its own grant, and a mutating pack needs an
        # explicit target:mutate grant rather than the default posture.
        self._require_mutation_grant(pack, permissions)
        report = validate_pack(
            pack,
            granted_permissions=permissions.granted,
            allow_development_only=self._allow_development_only,
        )
        return pack, report

    # -- reading a pack off disk ------------------------------------------------

    def assurance_for(self, pack: FaultPack, *, digest_verified: bool) -> PackAssurance:
        """The trust statement for a pack, independent of any registration."""
        return PackAssurance.for_pack(pack, digest_verified=digest_verified)

    def load_file(
        self,
        path: str | Path,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
        require_grant: bool = True,
    ) -> LoadedPack:
        """Read a pack from disk and take it all the way to a registration.

        The gates, in order, and every one of them refuses:

        1. the file must be readable, UTF-8, and a JSON object;
        2. the document must parse against the pack schema;
        3. ``declared_digest`` must equal the digest of the bytes on disk, and
           must equal ``expected_digest`` when the caller pinned one;
        4. the pack must be schema-compatible, and unsigned or
           ``development_only`` packs are refused unless
           ``allow_development_only`` was set on this loader;
        5. the provider id and version must satisfy the provider contract;
        6. no fault id may be, or shadow, a fault mayhem already owns;
        7. every fault must be classifiable, risk-level'd, and expressible as a
           provider fault declaration;
        8. with ``require_grant``, the pack must not exceed the permissions
           granted to its provider.

        ``reserved_fault_ids`` defaults to the live catalog; pass an explicit
        set to check against something else (a second registry, a test fixture).

        ``require_grant=False`` answers "is this pack *sound*?" without also
        answering "am I *allowed* to use it?". Those are different questions
        and a read-only inspection should not require a grant to ask the first
        one — the permission verdict is reported either way, as
        ``report["permissions"]`` against the pack's own request.
        """
        resolved = str(path)
        document, _file_digest = read_pack_document(path)
        pack = load_pack(document)

        reserved = builtin_fault_ids() if reserved_fault_ids is None else reserved_fault_ids
        builtin_providers = frozenset(create_builtin_registry().ids())
        computed = pack.pack_digest()
        permissions = self.permissions_for(pack.manifest.provider_id)

        problems: list[str] = [
            *_check_declared_digest(pack, resolved, computed, expected_digest),
            *_check_registration_shape(pack),
            *_check_no_shadowing(pack, reserved, builtin_providers),
            *_check_catalog_joinable(pack),
            *_check_fault_contract(pack),
        ]
        if problems:
            raise PackValidationError(
                f"pack {pack.manifest.provider_id!r} refused: " + "; ".join(problems)
            )

        if require_grant:
            # _require_mutation_grant raises SandboxRefusal, which names the
            # permission and provider; convert it so a file-level refusal is
            # one exception type with one message shape.
            try:
                self._require_mutation_grant(pack, permissions)
            except SandboxRefusal as exc:
                raise PackValidationError(
                    f"pack {pack.manifest.provider_id!r} refused: {exc.reason}"
                ) from exc

        # The permission gate needs a grant set to compare against. A real load
        # already passed ``_require_mutation_grant`` above, so reuse the
        # loader's own grants; a read-only inspection grants the pack exactly
        # what it declared, so the gate checks the pack against itself and
        # cannot raise a spurious refusal. Nothing executes on this path, so
        # the widened grant is never exercised.
        granted = permissions.granted if require_grant else _requested_permissions(pack)
        report = validate_pack(
            pack,
            granted_permissions=granted,
            allow_development_only=self._allow_development_only,
        )
        digest_verified = bool(pack.declared_digest) and pack.declared_digest == computed
        assurance = self.assurance_for(pack, digest_verified=digest_verified)
        return LoadedPack(
            pack=pack,
            registration=pack_registration(pack),
            definitions=pack_definitions(pack),
            assurance=assurance,
            report=report,
            path=resolved,
        )

    def inspect_file(
        self,
        path: str | Path,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
        require_grant: bool = True,
    ) -> dict[str, Any]:
        """Validate a pack file without loading it; never raises.

        The refusal is reported under ``loadable: False`` with its reason, so a
        caller rendering a verdict never has to catch anything to stay alive.
        """
        try:
            loaded = self.load_file(
                path,
                expected_digest=expected_digest,
                reserved_fault_ids=reserved_fault_ids,
                require_grant=require_grant,
            )
        except (PackValidationError, SandboxRefusal) as exc:
            return {"loadable": False, "reason": str(exc), "path": str(path)}
        return {"loadable": True, **loaded.to_dict()}

    def validate_file(
        self,
        path: str | Path,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
    ) -> LoadedPack:
        """Answer "is this pack *sound*?" without answering "may I use it?".

        This is the read-only verdict: it applies every structural, digest,
        shadowing, and safety check, and skips only the permission grant.
        Asking whether a file is trustworthy must not itself require a grant.
        The permission verdict is still reported, as
        ``report["permissions"]`` against the pack's own request.
        """
        return self.load_file(
            path,
            expected_digest=expected_digest,
            reserved_fault_ids=reserved_fault_ids,
            require_grant=False,
        )

    def register(
        self,
        loaded: LoadedPack,
        registry: ProviderRegistry,
        *,
        reserved_fault_ids: frozenset[str] | None = None,
    ) -> ProviderRegistration:
        """Put a loaded pack into a provider registry the engine can see.

        The declared fault ids are checked against the ids the pack actually
        defines in both directions, so a registration that names a fault the
        pack does not contain — or omits one it does — is refused instead of
        being registered as a half-truth.
        """
        declarations = loaded.registration.metadata.fault_declarations
        declared = {declaration.id for declaration in declarations}
        defined = {fault.id for fault in loaded.pack.faults}
        if declared != defined:
            details: list[str] = []
            if undefined := sorted(declared - defined):
                details.append(f"declares faults it does not define: {', '.join(undefined)}")
            if undeclared := sorted(defined - declared):
                details.append(f"defines faults it does not declare: {', '.join(undeclared)}")
            raise PackValidationError(
                f"pack {loaded.pack.manifest.provider_id!r} refused: " + "; ".join(details)
            )

        reserved = builtin_fault_ids() if reserved_fault_ids is None else reserved_fault_ids
        shadows = sorted(d.id for d in loaded.definitions if d.id in reserved)
        if shadows:
            raise PackValidationError(
                f"pack {loaded.pack.manifest.provider_id!r} refused: "
                f"these fault ids are already mayhem catalog faults: {', '.join(shadows)}"
            )

        runtime = loaded.runtime()

        def factory() -> PackRuntime:
            return runtime

        registry.register(loaded.registration, factory)
        return loaded.registration

    def load_into(
        self,
        path: str | Path,
        registry: ProviderRegistry,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
    ) -> LoadedPack:
        """``load_file`` plus :meth:`register`, the whole path in one call."""
        loaded = self.load_file(
            path, expected_digest=expected_digest, reserved_fault_ids=reserved_fault_ids
        )
        self.register(loaded, registry, reserved_fault_ids=reserved_fault_ids)
        return loaded


class ProviderLoader:
    """Read, gate, and register third-party providers.

    The *default* posture is default-deny on every axis that can be default-deny,
    and each of them is named here because they are decisions a caller may
    otherwise have to reverse-engineer:

    * ``allowed_permissions`` defaults to the domain's empty set: a declaration
      that asks for a permission loads only when the caller supplied that
      permission explicitly.
    * ``require_sandbox_enforcement`` defaults to
      :data:`DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT` (``True``): a profile that
      needs a mechanism this build does not apply is **refused**, and the
      admission it would have made is sealed either way. The full reasoning, and
      what the decision costs, are at that constant.
    * ``running_version`` defaults to :func:`core_version`. ``running_engine``
      defaults to ``None``, which leaves the engine axis **unchecked**, not
      passed — and a declaration that actually declares an engine constraint
      carries ``engine_verdict="unverified"`` in its compatibility report, so
      "we did not look" cannot be rendered as "we looked and it was fine".
      :func:`detect_engine_lane` is how a caller obtains a real lane.
    * ``store`` defaults to ``None``, which means provider activity is **observed
      but not sealed**. Every inspection then carries
      ``evidence["sealed"] = False`` and :data:`UNSEALED_ACTIVITY_NOTICE`; the
      ledger is opt-in because a loader cannot invent a database, and it is
      *loud* about the absence rather than silent about it.
    """

    def __init__(
        self,
        *,
        registry: ProviderRegistry | None = None,
        allowed_permissions: frozenset[ProviderPermission] = frozenset(),
        import_module_fn: Callable[[str], Any] | None = None,
        entry_points_fn: Callable[..., Iterable[Any]] | None = None,
        running_version: str | None = None,
        running_engine: str | EngineLane | None = None,
        require_sandbox_enforcement: bool = DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT,
        store: Store | None = None,
        activity_ledger: ProviderActivityLedger | None = None,
        principal: str = DEFAULT_PROVIDER_PRINCIPAL,
        lane_id: str = PROVIDER_ACTIVITY_CHAIN_ID,
        audit_stream_id: str = DEFAULT_STREAM_ID,
    ) -> None:
        self.registry = registry if registry is not None else create_builtin_registry()
        self.allowed_permissions = frozenset(allowed_permissions)
        self._import_module = import_module_fn if import_module_fn is not None else import_module
        self._entry_points = entry_points_fn if entry_points_fn is not None else entry_points
        self.running_version = running_version if running_version else core_version()
        # Normalised to the bare lane name so the value in a report is the same
        # string a declaration's ``compatibility.engines`` holds, whether the
        # caller passed an ``EngineLane`` member or its value.
        self.running_engine = str(running_engine) if running_engine else None
        self.require_sandbox_enforcement = require_sandbox_enforcement
        self._profiles: dict[str, SandboxProfile] = {}
        self._declarations: dict[str, ProviderMetadata] = {}
        self._builtin_providers: frozenset[str] | None = None
        self._observed: list[ProviderActivity] = []
        # The loader owns the declarations dict and hands the *same* object to
        # the ledger, so an activity recorded by anything the loader hands a
        # sandbox enforcer to resolves the provider's declared evidence schema
        # without knowing anything about the provider beyond its id.
        self.ledger = (
            activity_ledger
            if activity_ledger is not None
            else (
                ProviderActivityLedger(
                    store,
                    lane_id=lane_id,
                    principal=principal,
                    stream_id=audit_stream_id,
                    declarations=self._declarations,
                )
                if store is not None
                else None
            )
        )

    # -- what this loader checked, and what it did not --------------------------

    def compatibility_report(self, metadata: ProviderMetadata | None = None) -> dict[str, Any]:
        """The compatibility axes this loader checked on this run.

        Three axes, and the engine axis is only among them when the caller
        supplied ``running_engine``. Reported rather than implied so an operator
        reading a load report cannot mistake an unchecked axis for a passed one.

        With *metadata*, the report also carries that declaration's own engine
        verdict, which is the distinction Phase 4 exists to make reachable:

        ``"engine_verdict"``
            ``"not_declared"`` — the declaration states no engine constraint, so
            there is nothing to check and the axis is *inapplicable* rather than
            unchecked. ``"unverified"`` — it declares one and this loader has no
            lane to check it against. ``"matched"``/``"mismatched"`` — a lane was
            supplied and the axis was decided.

        Without *metadata* the loader-level report is the Phase 2 shape, so a
        caller asking "what did this loader check?" gets an answer that is about
        the loader rather than about a declaration that may not exist.
        """
        lane = self.running_engine
        checked = ["api_major", "release_window"]
        unchecked = ["engine"] if lane is None else []
        report: dict[str, Any] = {
            "running_version": self.running_version,
            "running_engine": lane,
            "checked_axes": list(checked),
            "unchecked_axes": list(unchecked),
        }
        if metadata is None:
            return report
        declared = tuple(metadata.compatibility.engines)
        if not declared:
            # Nothing to check is not the same as not checked: the axis is
            # *inapplicable* here, so it appears in neither list. Putting it in
            # ``unchecked_axes`` would train a reader to ignore that list.
            report["unchecked_axes"] = []
            report["inapplicable_axes"] = ["engine"]
            report["declared_engines"] = []
            report["engine_verdict"] = "not_declared"
            return report
        report["declared_engines"] = list(declared)
        if lane is None:
            report["engine_verdict"] = "unverified"
            return report
        report["checked_axes"] = [*checked, "engine"]
        report["unchecked_axes"] = []
        report["inapplicable_axes"] = []
        report["engine_verdict"] = "matched" if lane in declared else "mismatched"
        return report

    def detected_engine(self) -> EngineLane | None:
        """The engine lane this loader's own registry can name, or ``None``.

        A convenience over :func:`detect_engine_lane` so the caller does not have
        to pass the same registry twice:

        .. code-block:: python

            loader = ProviderLoader(registry=narrow)
            loader.running_engine = loader.detected_engine()

        ``None`` means unchecked, and :meth:`compatibility_report` will say so
        for every declaration that declares an engine.
        """
        return detect_engine_lane(self.registry)

    # -- the provider activity this loader produced ---------------------------

    def activities(self) -> tuple[ProviderActivity, ...]:
        """Every provider activity this loader made, oldest first.

        Returned whether or not a ledger exists, because "what did this loader
        decide?" is answerable in memory either way; what differs is whether it
        survived in the sealed chain, which :meth:`evidence_summary` says.
        """
        return tuple(self._observed)

    def evidence_summary(self, provider_id: str | None = None) -> dict[str, Any]:
        """What was sealed, and — when nothing was — why.

        ``sealed`` is the field to read. ``False`` is not an absence a caller has
        to infer: it arrives with :data:`UNSEALED_ACTIVITY_NOTICE` and an empty
        chain id, so a report can be rendered from this without ever implying
        that an unrecorded decision was a recorded one.

        *provider_id* narrows the activity list to one provider, which is what
        every inspection wants. Without it the list is the loader's whole
        history, and a fifty-provider catalog would render fifty copies of all
        fifty providers' activities — quadratic, and wrong: an inspection is
        about its provider.
        """
        observed: Sequence[ProviderActivity] = self._observed
        if provider_id is not None:
            observed = tuple(
                activity for activity in observed if activity.provider_id == provider_id
            )
        return {
            "sealed": self.ledger is not None,
            "chain_run_id": self.ledger.lane_id if self.ledger is not None else "",
            "audit_stream_id": (
                self.ledger.audit_stream.stream_id if self.ledger is not None else ""
            ),
            "activity_count": len(observed),
            "activities": [activity.to_dict() for activity in observed],
            "notice": "" if self.ledger is not None else UNSEALED_ACTIVITY_NOTICE,
        }

    def sealed_events(self) -> tuple[AttestedEvent, ...]:
        """The provider activity chain as stored, or empty when nothing was."""
        return self.ledger.chain() if self.ledger is not None else ()

    def _activity(
        self,
        metadata: ProviderMetadata,
        kind: ProviderActivityKind,
        *,
        outcome: str,
        action_outcome: ActionOutcome,
        target_id: str,
        operation_id: str,
        fault_id: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> ProviderEvidenceRecord | None:
        """Record one activity: always observed, sealed when a ledger exists.

        Returning the evidence record *or* ``None`` is deliberate. ``None`` means
        "observed and not sealed", which is the same answer
        :meth:`evidence_summary` gives, so a caller cannot mistake an unsealed
        record for a sealed one by forgetting to check.

        ``fault_id`` is not decoration: it is the key the ledger resolves the
        provider's declared evidence schema through, so an activity about a
        declared fault lands in *that fault's* mapping rather than in the
        provider's blanket schema.
        """
        activity = ProviderActivity(
            provider_id=metadata.provider_id,
            kind=kind,
            outcome=outcome,
            action_outcome=action_outcome,
            target_id=target_id,
            operation_id=operation_id,
            recorded_at=utc_now(),
            fault_id=fault_id,
            details=dict(details or {}),
        )
        self._observed.append(activity)
        if self.ledger is None:
            return None
        return self.ledger.record_provider_activity(activity)

    def record_action(
        self,
        provider_id: str,
        *,
        target_id: str,
        action_outcome: ActionOutcome,
        fault_id: str = "",
        operation_id: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> ProviderEvidenceRecord:
        """Record a provider-initiated action in the sealed chain.

        The Phase 4 contract point: a provider action participates in Mayhem's
        safety and evidence pipeline *exactly like a native action*. Concretely
        that means it produces the same
        :class:`~mayhem.domain.provider.ProviderEvidenceRecord` shape, carries an
        :class:`~mayhem.domain.evidence.ActionOutcome` from the same closed
        vocabulary an :class:`~mayhem.domain.evidence.EvidenceEnvelope` uses for a
        native step, and lands in the same attested chain and under the same
        verifier.

        ``fault_id`` is resolved through the provider's **own** declared
        :class:`~mayhem.domain.provider.EvidenceMapping`, so the record carries
        the schema the provider published rather than one mayhem invented.

        Raises:
            ProviderNotFoundError: If *provider_id* never passed this loader's
                gates. Evidence for a provider Mayhem did not admit is evidence
                about nothing, and the check is at the only place the declaration
                is known.
        """
        metadata = self._declarations.get(provider_id)
        if metadata is None:
            raise ProviderNotFoundError(
                "provider_not_found",
                f"provider {provider_id!r} was never admitted by this loader, so its "
                "declared evidence mapping cannot be resolved and its action cannot be recorded",
            )
        declared = metadata.evidence_for(fault_id) if fault_id else None
        schema = declared or metadata.evidence_schema
        record = self._activity(
            metadata,
            ProviderActivityKind.ACTION,
            outcome=action_outcome.value,
            action_outcome=action_outcome,
            target_id=target_id,
            operation_id=operation_id or f"provider.action:{provider_id}:{fault_id or target_id}",
            fault_id=fault_id,
            details={
                "fault_id": fault_id,
                "evidence_mapping": "declared" if declared is not None else "provider_schema",
                "declared_evidence_schema": schema.name,
                "declared_evidence_version": schema.version,
                **dict(details or {}),
            },
        )
        if record is None:
            # Observed, not recorded. Returning a record nobody persisted would be
            # the one lie this API must not tell, so it raises instead.
            raise ProviderError(
                "provider_evidence_not_sealed",
                f"provider {provider_id!r} action "
                f"{fault_id or '(unmapped fault)'} was observed but not recorded: this loader "
                "was constructed without a store, so there is no attestation chain to write "
                f"it to. {UNSEALED_ACTIVITY_NOTICE}",
            )
        return record

    def grant_permissions(
        self,
        provider_id: str,
        permissions: Iterable[ProviderPermission],
        *,
        reason: str = "",
        actor: str = "",
    ) -> frozenset[ProviderPermission]:
        """Widen (or narrow) the declaration gate, and record that it happened.

        The gate is **loader-wide**, not per provider: it is the set every
        declaration is compared against. It is named for the provider the caller
        is acting for, and that id must be one this loader admitted, so an audit
        entry cannot be written against a provider that never existed.

        Two things this deliberately does *not* change:

        * the registry's own ``allowed_permissions``, which is fixed when the
          registry is built. Widening this gate cannot widen what an
          already-registered runtime may do — a permission a provider holds at
          runtime is a separate, earlier decision, and only the engine path may
          make it.
        * a profile that was already selected. A widened grant admits a provider
          that asks for more; it does not retro-fit the sandbox profile of one
          that was loaded under the old grant.

        ``self.allowed_permissions`` is public and therefore directly
        assignable, and an assignment writes no audit entry. That is the honest
        limit of an in-process attribute: the *recorded* way to change the grant
        is this method, and the loader states in its report which activities it
        sealed.
        """
        if provider_id not in self._declarations:
            raise ProviderNotFoundError(
                "provider_not_found",
                f"provider {provider_id!r} was never admitted by this loader; a permission "
                "change cannot be recorded against a provider that does not exist here",
            )
        previous = self.allowed_permissions
        updated = frozenset(permissions)
        self.allowed_permissions = updated
        if self.ledger is not None:
            self.ledger.record_permission_change(
                provider_id,
                previous=previous,
                granted=updated,
                reason=reason,
                actor=actor,
            )
        return updated

    def sandbox_profile(self, provider_id: str) -> SandboxProfile:
        """The profile chosen for an already-loaded *provider_id*."""
        try:
            return self._profiles[provider_id]
        except KeyError as exc:
            raise ProviderNotFoundError(
                "provider_not_found",
                f"provider {provider_id!r} has no sandbox profile on this loader",
            ) from exc

    def declaration_for(self, provider_id: str) -> ProviderMetadata:
        """The declaration this loader admitted for *provider_id*."""
        try:
            return self._declarations[provider_id]
        except KeyError as exc:
            raise ProviderNotFoundError(
                "provider_not_found",
                f"provider {provider_id!r} was never admitted by this loader",
            ) from exc

    def sandbox_enforcer(
        self,
        provider_id: str,
        *,
        require_enforced: bool = False,
        read_roots: Iterable[str] = (),
        writable_roots: Iterable[str] = (),
        egress_allowlist: Iterable[str] = (),
    ) -> SandboxEnforcer:
        """An enforcer over the stored profile, with the operator's grants attached.

        The seam an execution path uses: the profile came from the declaration,
        the roots and destinations came from whoever approved the install, and
        every denial the enforcer makes is recorded as evidence *and* handed to
        this loader's ledger when one exists, so the decision reaches the sealed
        chain rather than only the process that made it.
        """
        return SandboxEnforcer(
            self.sandbox_profile(provider_id),
            require_enforced=require_enforced or self.require_sandbox_enforcement,
            read_roots=read_roots,
            writable_roots=writable_roots,
            egress_allowlist=egress_allowlist,
            sink=self.ledger,
        )

    def _builtin_provider_ids(self) -> frozenset[str]:
        """mayhem's own provider ids, read live and cached per loader.

        Live rather than imported as a constant so a built-in added in a later
        release is shadow-checked without editing this module, and cached per
        instance so a catalog of fifty providers does not build fifty built-in
        registries. Built from the authoritative factory rather than from
        ``self.registry``, because the registry may hold third-party providers
        that are not reserved.
        """
        if self._builtin_providers is None:
            self._builtin_providers = frozenset(create_builtin_registry().ids())
        return self._builtin_providers

    def _admit(self, registration: ProviderRegistration) -> SandboxProfile:
        """Every declaration gate, then the sandbox profile it earns.

        The order is fixed so a refusal is deterministic and so a caller can read
        one line of the module docstring and know what happened first:
        compatibility bounds (api major, release window, engine), the declared
        permission set against the grant, the declaration graph, the fault
        parameter defaults, evidence coverage, id shadowing, then the sandbox.

        The order is *also* the recording order: the load is observed before the
        first gate runs, so a refusal is sealed as well as raised, and each gate
        records its own refusal rather than a generic "load failed". Recording
        never changes which gate fires or what it raises — the try/except pairs
        below re-raise the object they caught, untouched.
        """
        metadata = registration.metadata
        provider_id = metadata.provider_id
        self._activity(
            metadata,
            ProviderActivityKind.LOAD,
            outcome="gate_entered",
            action_outcome=ActionOutcome.APPLIED,
            target_id=provider_id,
            operation_id=f"provider.load:{provider_id}",
            details={
                "source": metadata.source.value,
                "declared_version": metadata.version,
                "declared_permissions": sorted(p.value for p in metadata.permissions),
                "fault_ids": sorted(metadata.declared_fault_ids),
                "require_sandbox_enforcement": self.require_sandbox_enforcement,
            },
        )
        try:
            ensure_compatibility_bounds(
                metadata,
                running_version=self.running_version,
                running_engine=self.running_engine,
            )
        except ProviderCompatibilityError as exc:
            self._activity(
                metadata,
                ProviderActivityKind.LOAD,
                outcome="refused",
                action_outcome=ActionOutcome.REFUSED,
                target_id=provider_id,
                operation_id=f"provider.load:{provider_id}",
                details={"gate": "compatibility_bounds", "code": exc.code, "reason": str(exc)},
            )
            raise
        try:
            ensure_declared_permissions(metadata, self.allowed_permissions)
        except ProviderPermissionError as exc:
            self._activity(
                metadata,
                ProviderActivityKind.PERMISSION_DENIED,
                outcome="denied",
                action_outcome=ActionOutcome.REFUSED,
                target_id=provider_id,
                operation_id=f"provider.permission:{provider_id}",
                details={
                    "gate": "declared_permissions",
                    "code": exc.code,
                    "requested": sorted(permission.value for permission in exc.permissions),
                    "granted": sorted(permission.value for permission in self.allowed_permissions),
                },
            )
            raise
        problems: list[_Problem] = [
            *_check_declared_permission_union(metadata),
            *_check_declared_graph(metadata),
            *_check_parameter_defaults(metadata),
            *_check_evidence_coverage(metadata),
            *_check_no_provider_shadowing(
                metadata, builtin_fault_ids(), self._builtin_provider_ids()
            ),
        ]
        if problems:
            # Every problem is reported, not just the first: a declaration that
            # is wrong in three ways should not need three load attempts. The
            # code is the first problem's, in gate order, so it is stable.
            self._activity(
                metadata,
                ProviderActivityKind.LOAD,
                outcome="refused",
                action_outcome=ActionOutcome.REFUSED,
                target_id=provider_id,
                operation_id=f"provider.load:{provider_id}",
                details={
                    "gate": "declaration_graph",
                    "codes": [problem.code for problem in problems],
                    "reasons": [problem.message for problem in problems],
                },
            )
            raise ProviderLoadError(
                problems[0].code, "; ".join(problem.message for problem in problems)
            )
        profile = select_profile(metadata)
        # Deliberately before the profile is stored: a provider refused here has
        # no profile, so a later sandbox_enforcer() call cannot hand out a policy
        # for a provider that never loaded. The enforcer records the admission
        # itself — refused or admitted, with the unapplied mechanisms named — so
        # the verdict is in the chain and not only in the exception.
        SandboxEnforcer(
            profile,
            require_enforced=self.require_sandbox_enforcement,
            sink=self.ledger,
        ).admit()
        self._activity(
            metadata,
            ProviderActivityKind.ADMISSION,
            outcome="profile_selected",
            action_outcome=ActionOutcome.APPLIED,
            target_id=profile.profile_id,
            operation_id=f"provider.profile:{provider_id}",
            details={
                "tier": profile.tier,
                "requested_permissions": sorted(
                    permission.value for permission in profile.requested_permissions
                ),
                "admits_enforcement": profile.admits_enforcement,
                "unapplied_mechanisms": [
                    item.mechanism.value for item in profile.unapplied_mechanisms
                ],
                "engine_verdict": self.compatibility_report(metadata)["engine_verdict"],
                "notice": profile.notice,
            },
        )
        self._profiles[provider_id] = profile
        self._declarations[provider_id] = metadata
        if self.ledger is not None:
            self.ledger.declare(metadata)
        return profile

    def inspect_catalog(self, catalog_path: str | Path) -> ProviderLoadReport:
        catalog = self._read_catalog(catalog_path)
        providers = tuple(
            ProviderInspection(
                provider_id=registration.metadata.provider_id,
                status="ready",
                source=ProviderSource.CATALOG.value,
                metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                sandbox=select_profile(registration.metadata).to_dict(),
                compatibility=self.compatibility_report(registration.metadata),
                evidence=self.evidence_summary(registration.metadata.provider_id),
            )
            for registration in catalog.providers
        )
        return ProviderLoadReport(providers=providers)

    def load_catalog(self, catalog_path: str | Path) -> ProviderLoadReport:
        catalog = self._read_catalog(catalog_path)
        providers: list[ProviderInspection] = []
        loaded: list[str] = []
        failures: list[ProviderLoadFailure] = []
        for registration in catalog.providers:
            provider_id = registration.metadata.provider_id
            profile = self._admit(registration)
            try:
                runtime = self._load_registration_runtime(registration)
                self._register_runtime(registration, runtime, profile)
            except Exception as exc:
                failure = self._failure(provider_id, exc)
                failures.append(failure)
                providers.append(
                    ProviderInspection(
                        provider_id=provider_id,
                        status="failed",
                        source=ProviderSource.CATALOG.value,
                        metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                        error=failure,
                        sandbox=profile.to_dict(),
                        compatibility=self.compatibility_report(registration.metadata),
                        evidence=self.evidence_summary(provider_id),
                    )
                )
                continue
            loaded.append(provider_id)
            providers.append(
                ProviderInspection(
                    provider_id=provider_id,
                    status="loaded",
                    source=ProviderSource.CATALOG.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                    sandbox=profile.to_dict(),
                    compatibility=self.compatibility_report(registration.metadata),
                    evidence=self.evidence_summary(provider_id),
                )
            )
        return ProviderLoadReport(
            providers=tuple(providers),
            loaded=tuple(loaded),
            failures=tuple(failures),
        )

    def inspect_entry_points(self, provider_ids: Iterable[str] = ()) -> ProviderLoadReport:
        selected = set(provider_ids)
        registrations: list[ProviderRegistration] = []
        for entry_point in self._metadata_entry_points():
            if selected and entry_point.name not in selected:
                continue
            registrations.append(self._registration_from_metadata_entry_point(entry_point))
        return ProviderLoadReport(
            providers=tuple(
                ProviderInspection(
                    provider_id=registration.metadata.provider_id,
                    status="ready",
                    source=ProviderSource.ENTRY_POINT.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                    sandbox=select_profile(registration.metadata).to_dict(),
                    compatibility=self.compatibility_report(registration.metadata),
                    evidence=self.evidence_summary(registration.metadata.provider_id),
                )
                for registration in registrations
            )
        )

    def load_entry_points(self, provider_ids: Iterable[str] = ()) -> ProviderLoadReport:
        registrations = tuple(
            self._registration_from_metadata_entry_point(entry_point)
            for entry_point in self._metadata_entry_points()
            if not provider_ids or entry_point.name in set(provider_ids)
        )
        if not registrations:
            return ProviderLoadReport()
        implementations = {
            entry_point.name: entry_point
            for entry_point in self._entry_points(group=IMPLEMENTATION_ENTRY_POINT_GROUP)
        }
        providers: list[ProviderInspection] = []
        loaded: list[str] = []
        failures: list[ProviderLoadFailure] = []
        for registration in registrations:
            provider_id = registration.metadata.provider_id
            profile = self._admit(registration)
            try:
                implementation = implementations.get(provider_id)
                if implementation is None:
                    raise ProviderLoadError(
                        "provider_implementation_missing",
                        f"entry point {provider_id!r} has no "
                        f"{IMPLEMENTATION_ENTRY_POINT_GROUP!r} registration",
                    )
                runtime = self._materialize(implementation.load(), registration.implementation)
                self._register_runtime(registration, runtime, profile)
            except Exception as exc:
                failure = self._failure(provider_id, exc)
                failures.append(failure)
                providers.append(
                    ProviderInspection(
                        provider_id=provider_id,
                        status="failed",
                        source=ProviderSource.ENTRY_POINT.value,
                        metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                        error=failure,
                        sandbox=profile.to_dict(),
                        compatibility=self.compatibility_report(registration.metadata),
                        evidence=self.evidence_summary(provider_id),
                    )
                )
                continue
            loaded.append(provider_id)
            providers.append(
                ProviderInspection(
                    provider_id=provider_id,
                    status="loaded",
                    source=ProviderSource.ENTRY_POINT.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                    sandbox=profile.to_dict(),
                    compatibility=self.compatibility_report(registration.metadata),
                    evidence=self.evidence_summary(provider_id),
                )
            )
        return ProviderLoadReport(
            providers=tuple(providers),
            loaded=tuple(loaded),
            failures=tuple(failures),
        )

    def load_registration(
        self,
        registration: ProviderRegistration,
        runtime: object,
    ) -> ProviderInspection:
        """Run every gate on one in-memory registration and register its runtime.

        The third door into this loader, and the one an **SDK-built** declaration
        needs: :meth:`load_catalog` wants a file and :meth:`load_entry_points`
        wants installed entry-point metadata, so before this existed the only way
        to load a declaration that code had just constructed was to write it to
        disk and read it back — which also meant a declaration an SDK had just
        validated was being validated twice, by two different readers.

        It is deliberately *the same code path*, not a shortcut around it:
        :meth:`_admit` then :meth:`_register_runtime`, in that order, so an
        SDK-built provider is refused by exactly the gates a catalog-loaded one
        is refused by, and refused for exactly the same named reasons. A
        registration that loads here and would not have loaded from a catalog is
        a bug in the gates, and this method makes that bug observable instead of
        something a caller has to arrange a temporary file to discover.

        ``runtime`` is the provider's own object, already constructed by its
        language's loader. It is checked by :meth:`_register_runtime` *before* it
        reaches the registry, so a runtime that advertises more than it declared
        is refused while it is still a local variable.

        Raises:
            ProviderLoadError: From any gate, including a runtime whose behaviour
                disagrees with its declaration.
        """
        profile = self._admit(registration)
        runtime_object = self._materialize(runtime, registration.implementation)
        self._register_runtime(registration, runtime_object, profile)
        provider_id = registration.metadata.provider_id
        return ProviderInspection(
            provider_id=provider_id,
            status="loaded",
            source=registration.metadata.source.value,
            metadata=registration.metadata.model_dump(mode="json", by_alias=True),
            sandbox=profile.to_dict(),
            compatibility=self.compatibility_report(registration.metadata),
            evidence=self.evidence_summary(provider_id),
        )

    def _register_runtime(
        self,
        registration: ProviderRegistration,
        runtime: object,
        profile: SandboxProfile,
    ) -> None:
        """Check what the runtime advertises, *then* put it in the registry.

        Order is the enforcement. A runtime that claims a capability, a fault or
        a permission it never declared is refused while it is still a local
        variable, so it is never registered and therefore never has to be
        revoked: there is no window in which a mismatched runtime was reachable
        by anything holding the registry.
        """
        metadata = registration.metadata
        problems = _check_behavior(metadata, runtime)
        if problems:
            self._activity(
                metadata,
                ProviderActivityKind.LOAD,
                outcome="refused",
                action_outcome=ActionOutcome.REFUSED,
                target_id=metadata.provider_id,
                operation_id=f"provider.behavior:{metadata.provider_id}",
                details={
                    "gate": "runtime_behaviour",
                    "code": "provider_behavior_mismatch",
                    "reasons": problems,
                    "registered": False,
                },
            )
            raise ProviderLoadError("provider_behavior_mismatch", "; ".join(problems))
        self.registry.register(registration, _factory_for(runtime))
        # Recorded after the registry accepted it: an entry that says a provider
        # was registered and a registry that never took it would be a lie in the
        # direction that matters most.
        self._activity(
            metadata,
            ProviderActivityKind.LOAD,
            outcome="loaded",
            action_outcome=ActionOutcome.APPLIED,
            target_id=metadata.provider_id,
            operation_id=f"provider.load:{metadata.provider_id}",
            details={
                "registered": True,
                "sandbox_profile": profile.profile_id,
                "registry_ids": sorted(self.registry.ids()),
            },
        )
        if self.ledger is not None:
            self.ledger.record_registration(
                metadata.provider_id,
                source=metadata.source.value,
                profile_id=profile.profile_id,
                permissions=metadata.permissions,
                fault_ids=sorted(metadata.declared_fault_ids),
                declared_version=metadata.version,
            )

    def _read_catalog(self, catalog_path: str | Path) -> ProviderCatalog:
        path = Path(catalog_path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"cannot read provider catalog {path}: {exc}"
            raise ProviderLoadError("catalog_invalid", message) from exc
        unknown_fields = _check_wire_fields(document)
        if unknown_fields:
            raise ProviderLoadError("provider_wire_field_unknown", "; ".join(unknown_fields))
        try:
            return ProviderCatalog.model_validate(document)
        except ValidationError as exc:
            message = f"invalid provider catalog {path}: {exc}"
            raise ProviderLoadError("catalog_invalid", message) from exc

    def _metadata_entry_points(self) -> tuple[Any, ...]:
        return tuple(self._entry_points(group=METADATA_ENTRY_POINT_GROUP))

    def _registration_from_metadata_entry_point(self, entry_point: Any) -> ProviderRegistration:
        try:
            value = entry_point.load()
            metadata = (
                value
                if isinstance(value, ProviderMetadata)
                else ProviderMetadata.model_validate(value)
            ).model_copy(update={"source": ProviderSource.ENTRY_POINT})
        except (ValidationError, ValueError, TypeError, AttributeError, ImportError) as exc:
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} has invalid metadata: {exc}",
            ) from exc
        if metadata.provider_id != entry_point.name:
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} declares provider {metadata.provider_id!r}",
            )
        try:
            return ProviderRegistration(
                metadata=metadata,
                implementation=ImplementationReference(
                    kind=ImplementationKind.ENTRY_POINT,
                    target=entry_point.name,
                    factory=False,
                ),
            )
        except ValidationError as exc:
            # ``ProviderRegistration`` re-runs the declaration's own validators on
            # the nested model, so an entry point that hands over an edited
            # declaration (``model_copy`` does not validate) is refused here
            # rather than at a gate. Converted so a malformed entry point is one
            # refusal type with one message shape, exactly like the catalog path.
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} has invalid metadata: {exc}",
            ) from exc

    def _load_registration_runtime(self, registration: ProviderRegistration) -> object:
        implementation = registration.implementation
        if implementation.kind is ImplementationKind.IMPORT:
            module_name, attribute = implementation.target.split(":", 1)
            value = getattr(self._import_module(module_name), attribute)
            return self._materialize(value, implementation)
        entry_point = next(
            (
                candidate
                for candidate in self._entry_points(group=IMPLEMENTATION_ENTRY_POINT_GROUP)
                if candidate.name == implementation.target
            ),
            None,
        )
        if entry_point is None:
            raise ProviderLoadError(
                "provider_implementation_missing",
                f"entry point {implementation.target!r} is not installed",
            )
        return self._materialize(entry_point.load(), implementation)

    @staticmethod
    def _materialize(value: object, implementation: Any) -> object:
        if not implementation.factory:
            return value
        if not callable(value):
            raise ProviderLoadError(
                "provider_factory_invalid",
                f"implementation {implementation.target!r} is not callable",
            )
        return value()

    @staticmethod
    def _failure(provider_id: str, exc: Exception) -> ProviderLoadFailure:
        if isinstance(exc, ProviderError):
            return ProviderLoadFailure(provider_id, exc.code, str(exc))
        return ProviderLoadFailure(
            provider_id,
            "provider_load_failed",
            f"{type(exc).__name__}: {exc}",
        )
