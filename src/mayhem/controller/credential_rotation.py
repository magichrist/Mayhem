"""Policy-level credential rotation (plan 19, Phase 3 surface).

The gap this closes, named in the Phase 2 ledger
------------------------------------------------

Phase 2's known limitation: *"`rotate_before` and `rotation_grace` live on the
credential rather than in one policy object, so two agents can carry different
discipline."* That is real. A credential is a fact about one agent; rotation
*discipline* is a fact about the deployment, and a deployment-wide property that
lives on each of a hundred records is a hundred chances to disagree. This module
introduces the policy object, and the service below applies it.

What rotation actually does, and what it does not
-------------------------------------------------

:class:`CredentialRotationService.rotate` mints a successor credential through
:mod:`mayhem.infra.agent_identity_store`, which delegates to the domain registry's
own rule, so "the new credential is strictly newer, the old one is retained as
superseded, and a revoked identity refuses to rotate" has exactly one
implementation. Nothing here re-derives it.

The honest part is what rotation does **not** do, and it is the part that matters:

* **It does not provision key material.** A new credential has a new
  ``credential_id``, and the command verifier binds ``signing_key_id`` to the
  *current* credential — so immediately after a rotation, the agent's old key is
  refused (:data:`~mayhem.domain.agent_identity.CredentialRefusal` /
  ``key_binding``) and its new one does not yet verify anything, because no key
  exists for it. The agent is, for a moment, unable to authenticate, and **that is
  the correct behaviour**: a rotation whose overlap let the old key keep working
  would not have rotated anything. :attr:`RotationOutcome.key_provisioned` says
  which state the agent is in, and it is ``False`` unless a
  :class:`KeyProvisionerPort` was bound. There is no flag that makes it report
  ``True`` without one.
* **It does not push anything to a live peer.** ADR-0003: agents never listen, the
  controller dials out. Revocation propagation remains a *read* the store performs
  on every authorization (Phase 2), not a broadcast.
* **It does not schedule itself.** :meth:`CredentialRotationService.rotate_due`
  is a sweep a scheduler calls. No timer is installed here, because a timer
  installed in a library is a timer nobody can see.

What a policy may and may not say
---------------------------------

:class:`RotationPolicy` is data with three numbers and one derived rule. There is
deliberately no ``enabled`` flag on the policy: an operator who wants rotation
turned off stops calling :meth:`rotate_due`, which is visible, rather than
configuring a policy that does nothing — which is not.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.agent_identity import Revocation, RevocationReason
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from mayhem.domain.agent_identity import AgentCredential, AgentIdentity, RotationWindow
    from mayhem.infra.agent_identity_store import AgentIdentityRepository

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"

#: Default credential lifetime, matching Phase 1's
#: :data:`~mayhem.domain.agent_identity.DEFAULT_CREDENTIAL_TTL_S`. Spelled as a
#: local ``Final`` rather than imported as a *default argument* so the value is
#: visible in the policy's own signature.
DEFAULT_POLICY_TTL_S: Final[float] = 900.0

#: Default lead time before expiry at which rotation is due.
DEFAULT_POLICY_LEAD_S: Final[float] = 300.0


class RotationAction(StrEnum):
    """What a sweep or an operator did to one agent."""

    ROTATED = "rotated"
    REVOKED = "revoked"
    SKIPPED = "skipped"
    FAILED = "failed"


class KeyProvisionerPort(Protocol):
    """Where a rotated agent's signing key comes from.

    A port because key custody is plan 29's business, not this module's. A
    provisioner returns the ``signing_key_id`` it made available; returning
    ``None`` means "no key", and the agent then cannot authenticate — which is a
    fail-closed state, not an error to be swallowed.
    """

    def provision(self, *, agent_id: str, credential_id: str) -> str | None: ...


class RotationPolicy(BaseModel):
    """One deployment-wide rotation discipline.

    Attributes:
        policy_id: Stable id of the policy.
        credential_ttl_s: How long each minted credential is valid.
        rotate_before_s: How long before expiry a credential becomes due for
            rotation.
        rotation_grace_s: How long past due a rotation may be late before it is
            *overdue*. A grace period is a reporting threshold, not a licence to
            keep using an expired credential:
            :meth:`~mayhem.domain.agent_identity.AgentCredential.is_valid_at` decides
            usability, and it never consults grace.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(pattern=_ID)
    credential_ttl_s: Annotated[float, Field(gt=0)] = DEFAULT_POLICY_TTL_S
    rotate_before_s: Annotated[float, Field(ge=0)] = DEFAULT_POLICY_LEAD_S
    rotation_grace_s: Annotated[float, Field(ge=0)] = 0.0

    @model_validator(mode="after")
    def _check_invariants(self) -> RotationPolicy:
        if self.rotate_before_s >= self.credential_ttl_s:
            msg = (
                f"policy {self.policy_id!r} would make every credential due "
                f"({self.rotate_before_s:g}s before a {self.credential_ttl_s:g}s lifetime) "
                "the moment it is issued, so it can never have a credential that is not "
                "already overdue; rotate_before must be shorter than the lifetime"
            )
            raise InvariantViolationError("rotation.policy_degenerate", msg)
        return self

    def due_at(self, expires_at: datetime, issued_at: datetime) -> datetime:
        """When a credential with this window becomes due for rotation."""
        return expires_at - timedelta(seconds=self.rotate_before_s)

    def overdue_at(self, expires_at: datetime) -> datetime:
        """When a rotation stops being merely late."""
        return expires_at + timedelta(seconds=self.rotation_grace_s)

    def describe(self) -> str:
        return (
            f"rotation policy {self.policy_id!r}: ttl {self.credential_ttl_s:g}s, due "
            f"{self.rotate_before_s:g}s before expiry, overdue "
            f"{self.rotation_grace_s:g}s after"
        )


class RotationVerdict(BaseModel):
    """Whether one agent's credential is due, and why. Read-only.

    Attributes:
        agent_id: Whose credential.
        credential_id: Which credential.
        generation: Its generation counter.
        issued_at / expires_at: The window, from the credential.
        due_at / overdue_at: When this *policy* says rotation is due and overdue.
        due / overdue: The two answers, derived.
        reason: A one-line account. Required, so a ``due=False`` row still says
            why.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    credential_id: str
    generation: Annotated[int, Field(ge=1)]
    issued_at: datetime
    expires_at: datetime
    due_at: datetime
    overdue_at: datetime
    due: bool
    overdue: bool
    reason: str = Field(min_length=1)

    def describe(self) -> str:
        mark = "OVERDUE" if self.overdue else ("due" if self.due else "not due")
        return (
            f"{self.agent_id}/{self.credential_id}: {mark} at "
            f"{self.due_at.isoformat()} — {self.reason}"
        )


class RotationOutcome(BaseModel):
    """What happened to one agent, in one sweep or one operator action.

    ``key_provisioned`` is the field to read first. It is ``False`` unless a
    :class:`KeyProvisionerPort` was bound and returned a key, and it is what tells
    an operator that the agent now holds a credential it cannot yet authenticate
    with — a fail-closed window, not a silent success.

    Attributes:
        agent_id: Whose credential.
        action: What was done.
        from_credential / to_credential: The generation transition, ``""`` when
            none happened.
        generation: The generation after the action, when known.
        key_provisioned: Whether signing key material was made available.
        detail: The account. Required on every path, including a skip.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    action: RotationAction
    from_credential: str = ""
    to_credential: str = ""
    generation: int = 0
    key_provisioned: bool = False
    detail: str = Field(min_length=1)

    @property
    def rotated(self) -> bool:
        return self.action is RotationAction.ROTATED

    @property
    def failed(self) -> bool:
        return self.action is RotationAction.FAILED

    def describe(self) -> str:
        # The key note is a statement about *rotation*: a rotated agent is briefly
        # unable to authenticate until custody issues a key. It is deliberately
        # absent for a revocation or a failure, where appending it would say
        # something false -- a revoked agent's problem is the revocation, and no
        # provisioner fixes that.
        key_note = (
            "; signing key provisioned"
            if self.key_provisioned
            else "; NO signing key provisioned — this agent cannot authenticate until "
            "a provisioner issues one"
            if self.rotated
            else ""
        )
        return (
            f"{self.agent_id}: {self.action.value}"
            + (
                f" {self.from_credential} → {self.to_credential} (generation {self.generation})"
                if self.to_credential
                else ""
            )
            + key_note
            + f" — {self.detail}"
        )


class CredentialRotationService:
    """Apply a :class:`RotationPolicy` to the enrolled identities.

    Args:
        identities: The authoritative identity store.
        policy: The deployment's discipline.
        provisioner: Optional. Bound only when a deployment has key custody.
        clock: Injected, so a sweep is reproducible.

    Holds no state: every verdict is recomputed from the store, so a second
    service over the same store is a second operator and it immediately agrees
    with the first.
    """

    def __init__(
        self,
        *,
        identities: AgentIdentityRepository,
        policy: RotationPolicy,
        provisioner: KeyProvisionerPort | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._identities = identities
        self._policy = policy
        self._provisioner = provisioner
        self._clock = clock

    @property
    def policy(self) -> RotationPolicy:
        return self._policy

    @property
    def provisions_keys(self) -> bool:
        """Whether key custody is bound. Assertable rather than discovered."""
        return self._provisioner is not None

    # -- survey ---------------------------------------------------------------
    def verdict_for(
        self, identity: AgentIdentity, *, at: datetime | None = None
    ) -> RotationVerdict:
        """Whether ``identity``'s credential is due under this policy."""
        moment = self._clock() if at is None else at
        credential = identity.credential
        due_at = self._policy.due_at(credential.expires_at, credential.issued_at)
        overdue_at = self._policy.overdue_at(credential.expires_at)
        revoked = identity.revoked
        due = moment >= due_at or revoked
        overdue = moment >= overdue_at
        if revoked:
            reason = "identity is revoked; it can never rotate and must be re-enrolled"
        elif overdue:
            reason = (
                f"rotation was due at {due_at.isoformat()} and the credential expires at "
                f"{credential.expires_at.isoformat()}"
            )
        elif due:
            reason = f"rotation is due at {due_at.isoformat()}"
        else:
            reason = (
                f"credential is current until {credential.expires_at.isoformat()}; rotation "
                f"becomes due at {due_at.isoformat()}"
            )
        return RotationVerdict(
            agent_id=identity.agent_id,
            credential_id=credential.credential_id,
            generation=credential.generation,
            issued_at=credential.issued_at,
            expires_at=credential.expires_at,
            due_at=due_at,
            overdue_at=overdue_at,
            due=due,
            overdue=overdue,
            reason=reason,
        )

    def survey(self, *, at: datetime | None = None) -> tuple[RotationVerdict, ...]:
        """Every enrolled agent's verdict, ordered by agent id."""
        moment = self._clock() if at is None else at
        return tuple(
            self.verdict_for(identity, at=moment)
            for identity in sorted(
                self._identities.list_agents(), key=lambda i: i.agent_id
            )
        )

    def due_agents(self, *, at: datetime | None = None) -> tuple[str, ...]:
        """Just the agent ids whose rotation is due."""
        return tuple(v.agent_id for v in self.survey(at=at) if v.due)

    # -- operations -----------------------------------------------------------
    def rotate(
        self,
        agent_id: str,
        *,
        credential_id: str | None = None,
        at: datetime | None = None,
    ) -> RotationOutcome:
        """Rotate one agent's credential, and provision a key if custody is bound.

        Raises:
            SecurityStateError: If the agent is not enrolled.
            InvariantViolationError: If the identity is revoked or the ttl is not
                positive — surfaced from the domain, never worked around.
        """
        moment = self._clock() if at is None else at
        identity = self._identities.load(agent_id)
        if identity is None:
            msg = (
                f"cannot rotate a credential for unenrolled agent {agent_id!r}; "
                "enrol it first"
            )
            raise DomainError(msg)
        successor_id = credential_id or f"{agent_id}-c{identity.credential.generation + 1}"
        rotated = self._identities.rotate_credential(
            agent_id,
            credential_id=successor_id,
            ttl_s=self._policy.credential_ttl_s,
            now=moment,
        )
        key_provisioned, provision_note = self._provision(rotated.agent_id, successor_id)
        return RotationOutcome(
            agent_id=agent_id,
            action=RotationAction.ROTATED,
            from_credential=identity.credential.credential_id,
            to_credential=rotated.credential.credential_id,
            generation=rotated.credential.generation,
            key_provisioned=key_provisioned,
            detail=(
                f"policy {self._policy.policy_id!r} issued {rotated.credential.credential_id} "
                f"valid until {rotated.credential.expires_at.isoformat()}; the previous "
                f"credential is retained as superseded and its key is refused from now on. "
                f"{provision_note}"
            ),
        )

    def rotate_due(
        self,
        *,
        at: datetime | None = None,
        limit: int | None = None,
    ) -> tuple[RotationOutcome, ...]:
        """Rotate every due agent, one at a time.

        One agent's failure does not stop the sweep: a revoked identity raising
        must not prevent the other ninety-nine credentials from rotating. Failures
        are returned as :attr:`RotationAction.FAILED` outcomes, so the caller sees
        the whole picture rather than the first exception.
        """
        moment = self._clock() if at is None else at
        due = self.due_agents(at=moment)
        if limit is not None:
            due = due[: max(0, limit)]
        outcomes: list[RotationOutcome] = []
        for agent_id in due:
            try:
                outcomes.append(self.rotate(agent_id, at=moment))
            except (DomainError, InvariantViolationError) as exc:
                outcomes.append(
                    RotationOutcome(
                        agent_id=agent_id,
                        action=RotationAction.FAILED,
                        detail=f"rotation refused: {exc}",
                    )
                )
        return tuple(outcomes)

    def revoke(
        self,
        agent_id: str,
        *,
        reason: RevocationReason,
        revoked_by: str,
        note: str = "",
        at: datetime | None = None,
    ) -> RotationOutcome:
        """Revoke an agent outright, through the append-only revocation ledger.

        Raises:
            DomainError: If the agent is not enrolled.
        """
        moment = self._clock() if at is None else at
        identity = self._identities.load(agent_id)
        if identity is None:
            msg = f"cannot revoke unenrolled agent {agent_id!r}"
            raise DomainError(msg)
        revocation = Revocation(
            reason=reason,
            revoked_at=moment,
            revoked_by=revoked_by,
            note=note,
        )
        # ``revoke_agent`` appends the identity-scoped revocation row *and* updates
        # the identity in one transaction. Calling ``record_revocation`` first would
        # insert a second, credential-scoped row for the same event -- turning "this
        # agent is pulled" into "this key is burned" as well, which is a strictly
        # larger outage invented by a bookkeeping slip.
        self._identities.revoke_agent(agent_id, revocation)
        return RotationOutcome(
            agent_id=agent_id,
            action=RotationAction.REVOKED,
            from_credential=identity.credential.credential_id,
            to_credential="",
            generation=identity.credential.generation,
            key_provisioned=False,
            detail=(
                f"revoked ({reason.value}) by {revoked_by} at {moment.isoformat()}; the "
                "revocation is in the append-only ledger, so a command verified against "
                "this identity is refused even if the identity row lags the ledger"
            ),
        )

    # -- internals ------------------------------------------------------------
    def _provision(self, agent_id: str, credential_id: str) -> tuple[bool, str]:
        """Ask custody for a key, or report honestly that there is none."""
        if self._provisioner is None:
            return (
                False,
                "No key provisioner is bound, so no signing key was issued for the new "
                "credential. The agent cannot authenticate until one is: the command "
                "verifier refuses an unknown signing key, so this fails closed rather "
                "than leaving the previous key usable.",
            )
        key_id = self._provisioner.provision(agent_id=agent_id, credential_id=credential_id)
        if not key_id:
            return (
                False,
                f"The bound provisioner returned no key for credential {credential_id!r}; "
                "the agent cannot authenticate until one is issued.",
            )
        return (True, f"Signing key {key_id!r} provisioned by the bound key custodian.")


def credential_window(credential: AgentCredential) -> RotationWindow:
    """The credential's own rotation window, from Phase 1's model.

    Exposed so a caller can compare the *credential's* window against the
    *policy's* schedule and see where they disagree — which is the defect this
    module's policy object was introduced to remove.
    """
    return credential.rotation_window()


def sweep_summary(outcomes: Sequence[RotationOutcome]) -> dict[str, object]:
    """Counts for a sweep. A summary, deliberately not a verdict.

    ``rotated`` counts rotations; ``without_key`` counts rotations that left the
    agent unable to authenticate. A summary that reported only the first would
    make a sweep that broke every agent look identical to a healthy one.
    """
    return {
        "agents": len(outcomes),
        "rotated": sum(1 for o in outcomes if o.rotated),
        "revoked": sum(1 for o in outcomes if o.action is RotationAction.REVOKED),
        "failed": sum(1 for o in outcomes if o.failed),
        "skipped": sum(1 for o in outcomes if o.action is RotationAction.SKIPPED),
        "without_key": sum(1 for o in outcomes if o.rotated and not o.key_provisioned),
    }
