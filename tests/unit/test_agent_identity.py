"""Tests for agent identity, credentials, revocation, and fencing (plan 19 Phase 1).

The phase's acceptance is a *type* property ("a stale token authorizing an
action is unrepresentable"), so most of this file is negative controls: they show
that the shapes which must be impossible are impossible, and that the predicates
which decide the shapes agree with the constructors that refuse them.

Three properties are pinned here and each is deliberately over-tested:

1. **A stale or revoked credential is unusable** — the refusal is a property of
   :class:`~mayhem.domain.agent_identity.CredentialGrant`, which re-runs the
   refusal predicates on its own identity in its own validator, so even direct
   construction cannot mint a grant for a revoked agent.
2. **Revocation propagates** — a registry revocation advances the registry
   version, which makes an existing grant detectably stale.
3. **A fence that does not outrank cannot authorise** — and, separately, the
   plan-19 non-duplication ruling: this module reuses
   :class:`mayhem.domain.fabric.FencingToken` and adds predicates, not a second
   fence type.

Everything is a value here, so nothing is mocked: no clock reads (callers pass
``now``), no crypto, no IO. The store tests use an in-memory migrated SQLite
store, which is the only IO in this file and is what plan 19 Phase 1 actually
added.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mayhem.domain.agent_identity import (
    CERTIFICATE_TRUST_UNVERIFIED,
    DEFAULT_CREDENTIAL_TTL_S,
    REFUSAL_ORDER,
    AgentCredential,
    AgentIdentity,
    AgentIdentityRegistry,
    CertificateRef,
    CredentialGrant,
    CredentialRefusal,
    CredentialRefusedError,
    FenceNotAuthorised,
    PinReason,
    Revocation,
    RevocationReason,
    RotationState,
    TrustAnchorRef,
    assert_fence_authorises,
    authorize_credential,
    check_certificate_pinning,
    fence_chain_is_monotonic,
    fence_permits_dispatch,
    fence_scope_matches,
    fence_transfers_ownership,
    order_refusals,
    require_still_usable,
)
from mayhem.domain.errors import InvariantViolationError, SchemaValidationError
from mayhem.domain.fabric import FencingToken
from mayhem.domain.identity import (
    ANY_ENVIRONMENT,
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
)
from mayhem.infra.agent_identity_store import (
    REVOCATION_SCOPE_CREDENTIAL,
    REVOCATION_SCOPE_IDENTITY,
    AgentIdentityRepository,
    SecurityStateError,
)
from mayhem.infra.store import Store

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
AGENT = "ag-1"
CONTROLLER = "ctl-a"
OTHER_CONTROLLER = "ctl-b"
CREDENTIAL = "cr-1"
FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64
CA_FINGERPRINT = "c" * 64


# --------------------------------------------------------------------------- #
# Builders                                                                     #
# --------------------------------------------------------------------------- #


def credential(
    *,
    credential_id: str = CREDENTIAL,
    agent_id: str = AGENT,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    rotate_before: float = 300.0,
    rotation_grace: float = 0.0,
    rotation_state: RotationState = RotationState.CURRENT,
    generation: int = 1,
    serial: str = "",
) -> AgentCredential:
    """A live, in-window credential issued 60s before NOW.

    Explicit keywords rather than a ``**overrides`` splat: every override a test
    wants is spelled out, so the set of ways a credential can be shaped is a
    closed list a reader can see.
    """
    return AgentCredential(
        credential_id=credential_id,
        agent_id=agent_id,
        issued_at=NOW - timedelta(seconds=60) if issued_at is None else issued_at,
        expires_at=(
            NOW + timedelta(seconds=DEFAULT_CREDENTIAL_TTL_S) if expires_at is None else expires_at
        ),
        rotate_before=rotate_before,
        rotation_grace=rotation_grace,
        rotation_state=rotation_state,
        generation=generation,
        serial=serial,
    )


def identity(
    *,
    agent_id: str = AGENT,
    controller_id: str = CONTROLLER,
    principal: Principal | None = None,
    scope: EnvironmentScope | None = None,
    cert: AgentCredential | None = None,
    certificate: CertificateRef | None = None,
    trust_anchors: tuple[TrustAnchorRef, ...] = (),
) -> AgentIdentity:
    """An enrolled agent whose principal holds ``EXECUTE`` in its stated scope."""
    return AgentIdentity(
        agent_id=agent_id,
        controller_id=controller_id,
        principal=(
            Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD)
            if principal is None
            else principal
        ),
        scope=EnvironmentScope(environment="staging") if scope is None else scope,
        credential=credential() if cert is None else cert,
        certificate=certificate,
        trust_anchors=trust_anchors,
    )


def execute_grant(scope: EnvironmentScope | None = None) -> RoleGrant:
    return RoleGrant(
        role=Role.EXECUTE,
        scope=EnvironmentScope(environment="staging"),
        principal=Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD),
    )


def revocation(reason: RevocationReason = RevocationReason.COMPROMISED) -> Revocation:
    return Revocation(reason=reason, revoked_at=NOW, revoked_by=CONTROLLER, note="host reimaged")


def fence(*, run_id: str = "r-1", step_id: str = "s-1", epoch: int = 1) -> FencingToken:
    return FencingToken(
        run_id=run_id,
        step_id=step_id,
        holder=CONTROLLER,
        epoch=epoch,
        issued_at=NOW,
    )


def chain(*epochs: int) -> tuple[FencingToken, ...]:
    """A handover chain at the given epochs, each via ``next_fence``."""
    tokens: list[FencingToken] = []
    current = FencingToken.issue(run_id="r-1", step_id="s-1", holder=CONTROLLER, now=NOW)
    tokens.append(current)
    for index, epoch in enumerate(epochs):
        current = current.next_fence(holder=f"ctl-{index}", now=NOW + timedelta(seconds=epoch))
        tokens.append(current)
    return tuple(tokens)


# --------------------------------------------------------------------------- #
# Credential window: the validity matrix                                         #
# --------------------------------------------------------------------------- #


def test_live_credential_is_usable() -> None:
    assert identity().is_usable_at(now=NOW)
    assert authorize_credential(identity(), now=NOW).agent_id == AGENT


def test_expired_credential_is_refused() -> None:
    """NEGATIVE CONTROL: the boundary is at-and-after, matching ``Approval``."""
    live = credential()
    past = live.rotation_window().expires_at

    assert live.refusals_at(past) == (CredentialRefusal.EXPIRED,)
    assert CredentialRefusal.EXPIRED not in live.refusals_at(past - timedelta(microseconds=1))
    with pytest.raises(CredentialRefusedError) as excinfo:
        authorize_credential(identity(cert=live), now=past)
    assert excinfo.value.reasons == (CredentialRefusal.EXPIRED,)
    assert excinfo.value.code == "agent_credential_refused"
    assert excinfo.value.agent_id == AGENT


def test_credential_issued_in_the_future_is_refused() -> None:
    future = credential(
        issued_at=NOW + timedelta(seconds=30),
        expires_at=NOW + timedelta(seconds=930),
    )
    assert future.refusals_at(NOW) == (CredentialRefusal.NOT_YET_VALID,)
    assert future.is_valid_at(NOW + timedelta(seconds=30))


def test_a_zero_length_window_is_unrepresentable() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        credential(issued_at=NOW, expires_at=NOW)
    assert excinfo.value.rule == "credential.window"


def test_an_eternal_credential_has_no_spelling() -> None:
    """``expires_at`` is required: there is no "no expiry" construction."""
    with pytest.raises(ValidationError):
        AgentCredential(credential_id=CREDENTIAL, agent_id=AGENT, issued_at=NOW)


def test_naive_datetimes_are_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        credential(issued_at=datetime(2026, 3, 1, 11, 59))  # noqa: DTZ001 — deliberately naive
    assert excinfo.value.rule == "credential.time_aware"


# --------------------------------------------------------------------------- #
# Rotation windows                                                              #
# --------------------------------------------------------------------------- #


def test_rotation_window_is_derived_not_stored() -> None:
    window = credential().rotation_window()
    due = NOW + timedelta(seconds=DEFAULT_CREDENTIAL_TTL_S) - timedelta(seconds=300)
    assert window.due_at == due
    assert window.grace_until == due  # zero grace by default
    assert window.is_open(due - timedelta(seconds=1))
    assert window.is_due(due)
    # Zero grace makes the due instant and the overdue instant the same one: an
    # operator who configures no slack gets no slack.
    assert window.is_overdue(due)


def test_rotation_overdue_is_a_refusal_with_zero_grace() -> None:
    live = credential()
    due = live.rotation_window().due_at
    assert live.refusals_at(due + timedelta(seconds=1)) == (CredentialRefusal.ROTATION_OVERDUE,)
    with pytest.raises(CredentialRefusedError):
        authorize_credential(identity(cert=live), now=due + timedelta(seconds=1))


def test_configured_grace_keeps_an_overdue_credential_usable() -> None:
    live = credential(rotation_grace=120.0)
    due = live.rotation_window().due_at
    window = live.rotation_window()
    assert window.grace_until == due + timedelta(seconds=120)
    assert not window.is_overdue(due + timedelta(seconds=60))
    assert window.is_overdue(window.grace_until)
    assert identity(cert=live).is_usable_at(now=due + timedelta(seconds=60))
    assert not identity(cert=live).is_usable_at(now=window.grace_until)


def test_grace_never_outlives_the_credential() -> None:
    live = credential(rotation_grace=99999.0)
    window = live.rotation_window()
    assert window.grace_until > window.expires_at
    # Past expiry the credential is expired whatever the grace says.
    assert CredentialRefusal.EXPIRED in live.refusals_at(window.expires_at)
    assert live.refusals_at(window.expires_at) == (CredentialRefusal.EXPIRED,)


def test_negative_rotation_grace_is_refused() -> None:
    """Refused by the shared ``Duration`` type, before any module-level rule runs."""
    with pytest.raises(SchemaValidationError):
        credential(rotation_grace=-1.0)


def test_rotation_mints_a_strictly_newer_credential() -> None:
    live = credential()
    successor = live.successor(credential_id="cr-2", ttl_s=900.0, now=NOW)
    assert successor.generation == live.generation + 1
    assert successor.issued_at == NOW
    assert successor.is_valid_at(NOW)


def test_rotation_keeps_the_predecessor_as_superseded_evidence() -> None:
    advanced = identity().with_credential(
        credential().successor(credential_id="cr-2", ttl_s=900.0, now=NOW)
    )
    assert advanced.version == identity().version + 1
    retired = advanced.credential_history[0]
    assert retired.credential_id == CREDENTIAL
    assert retired.rotation_state is RotationState.SUPERSEDED
    assert retired.superseded_by == "cr-2"
    assert advanced.usable_credentials_at(now=NOW) == ("cr-2",)


def test_a_superseded_credential_is_refused() -> None:
    retired = credential().supersede(successor_id="cr-2", at=NOW)
    assert retired.refusals_at(NOW) == (CredentialRefusal.SUPERSEDED,)


def test_supersession_needs_provenance() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        credential(rotation_state=RotationState.SUPERSEDED)
    assert excinfo.value.rule == "credential.superseded_needs_provenance"


def test_a_revoked_credential_cannot_be_rotated() -> None:
    """Rotation must not resurrect a key somebody already burned."""
    revoked = credential().revoke(revocation())
    with pytest.raises(InvariantViolationError) as excinfo:
        revoked.supersede(successor_id="cr-2", at=NOW)
    assert excinfo.value.rule == "credential.cannot_rotate_revoked"


def test_successor_needs_a_positive_ttl() -> None:
    with pytest.raises(InvariantViolationError):
        credential().successor(credential_id="cr-2", ttl_s=0.0)


# --------------------------------------------------------------------------- #
# Revocation                                                                    #
# --------------------------------------------------------------------------- #


def test_credential_revocation_is_refused() -> None:
    registry = AgentIdentityRegistry(identities=(identity(),))
    revoked = registry.revoke_credential(AGENT, revocation())
    with pytest.raises(CredentialRefusedError) as excinfo:
        revoked.authorize(AGENT, now=NOW)
    assert excinfo.value.reasons == (CredentialRefusal.CREDENTIAL_REVOKED,)


def test_identity_revocation_is_refused() -> None:
    registry = AgentIdentityRegistry(identities=(identity(),))
    revoked = registry.revoke_agent(AGENT, revocation(RevocationReason.DECOMMISSIONED))
    assert AGENT in revoked.revoked_agent_ids()
    with pytest.raises(CredentialRefusedError) as excinfo:
        revoked.authorize(AGENT, now=NOW)
    assert excinfo.value.reasons == (CredentialRefusal.IDENTITY_REVOKED,)


def test_a_revoked_credential_stays_revoked() -> None:
    first = credential().revoke(revocation())
    second = first.revoke(revocation(RevocationReason.OPERATOR_REQUEST))
    assert second is first, "the first revocation's actor must not be overwritten"


def test_revocation_needs_a_named_actor() -> None:
    with pytest.raises(ValidationError):
        Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="")


def test_revocation_rejects_an_untrimmed_actor() -> None:
    """Blank is not a name: whitespace cannot stand in for an actor."""
    with pytest.raises(InvariantViolationError) as excinfo:
        Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="   ")
    assert excinfo.value.rule == "revocation.revoker_trimmed"


def test_repeated_identity_revocation_is_idempotent() -> None:
    once = identity().revoke(revocation())
    assert once.revoke(revocation()) is once


def test_rotating_a_revoked_identity_is_refused() -> None:
    registry = AgentIdentityRegistry(identities=(identity().revoke(revocation()),))
    with pytest.raises(InvariantViolationError) as excinfo:
        registry.rotate_credential(AGENT, credential_id="cr-2", ttl_s=900.0, now=NOW)
    assert excinfo.value.rule == "registry.cannot_rotate_revoked_agent"


def test_revoking_an_unenrolled_agent_is_refused() -> None:
    registry = AgentIdentityRegistry()
    with pytest.raises(InvariantViolationError) as excinfo:
        registry.revoke_agent(AGENT, revocation())
    assert excinfo.value.rule == "registry.agent_not_enrolled"


def test_unenrolled_agent_is_default_deny() -> None:
    with pytest.raises(CredentialRefusedError) as excinfo:
        AgentIdentityRegistry().authorize(AGENT, now=NOW)
    assert excinfo.value.reasons == ()
    assert "enrol" in excinfo.value.remediation


# --------------------------------------------------------------------------- #
# Revocation propagation                                                        #
# --------------------------------------------------------------------------- #


def test_revocation_advances_the_registry_version() -> None:
    """Propagation is *detectable*: the grant names the version it cleared."""
    live = AgentIdentityRegistry(identities=(identity(),))
    grant = live.authorize(AGENT, now=NOW)
    assert live.grant_is_current(grant)

    revoked = live.revoke_credential(AGENT, revocation())
    assert revoked.version > live.version
    assert not revoked.grant_is_current(grant)


def test_a_registry_cannot_be_rewound() -> None:
    """Frozen: a revocation returns a new registry, the old one is untouched."""
    live = AgentIdentityRegistry(identities=(identity(),))
    revoked = live.revoke_agent(AGENT, revocation())
    assert live.identities[0].revoked is False
    assert revoked.identities[0].revoked is True


def test_a_grant_goes_stale_with_time() -> None:
    """The use-time re-check: what a pure layer can honestly do without a wire."""
    grant = AgentIdentityRegistry(identities=(identity(),)).authorize(AGENT, now=NOW)
    assert require_still_usable(grant, now=NOW) is grant
    with pytest.raises(CredentialRefusedError) as excinfo:
        require_still_usable(grant, now=NOW + timedelta(seconds=10_000))
    assert excinfo.value.reasons == (CredentialRefusal.EXPIRED,)


def test_revocation_after_authorisation_is_caught_by_the_registry() -> None:
    """A grant carries the identity it cleared, so the registry is the oracle.

    This is the honest limit of a pure layer: it cannot revoke an object a caller
    already holds. What it does instead is make the staleness *visible* — the
    grant names the registry version it cleared against, and a fresh
    authorisation through the advanced registry is refused outright.
    """
    live = AgentIdentityRegistry(identities=(identity(),))
    grant = live.authorize(AGENT, now=NOW)
    revoked = live.revoke_agent(AGENT, revocation(RevocationReason.DECOMMISSIONED))

    assert revoked.grant_is_current(grant) is False
    with pytest.raises(CredentialRefusedError) as excinfo:
        revoked.authorize(AGENT, now=NOW)
    assert excinfo.value.reasons == (CredentialRefusal.IDENTITY_REVOKED,)


def test_grant_construction_is_refused_for_a_revoked_identity() -> None:
    """The type-level property: no construction path mints a grant here."""
    revoked = identity().revoke(revocation())
    with pytest.raises(InvariantViolationError) as excinfo:
        CredentialGrant(
            identity=revoked,
            identity_digest=revoked.identity_digest(),
            authorised_at=NOW,
            identity_version=revoked.version,
        )
    assert "credential_grant.refused_identity" in str(excinfo.value)


def test_grant_construction_is_refused_for_an_expired_identity() -> None:
    stale = identity(cert=credential(expires_at=NOW - timedelta(seconds=1)))
    with pytest.raises(InvariantViolationError) as excinfo:
        CredentialGrant(
            identity=stale,
            identity_digest=stale.identity_digest(),
            authorised_at=NOW,
            identity_version=stale.version,
        )
    assert "expired" in str(excinfo.value)


def test_grant_refuses_an_identity_it_does_not_match() -> None:
    live = identity()
    other = identity()
    with pytest.raises(InvariantViolationError) as excinfo:
        CredentialGrant(
            identity=other,
            identity_digest=live.identity_digest(),
            authorised_at=NOW,
            identity_version=other.version,
        )
    assert "credential_grant.identity_digest_mismatch" in str(excinfo.value)


def test_identity_digest_covers_the_window() -> None:
    """A re-stamped lifetime must not keep the digest an audit trail recorded."""
    live = identity()
    longer = identity(cert=credential(expires_at=live.credential.expires_at + timedelta(hours=1)))
    assert live.identity_digest() != longer.identity_digest()


# --------------------------------------------------------------------------- #
# Controller binding and scope                                                  #
# --------------------------------------------------------------------------- #


def test_another_controllers_agent_is_refused() -> None:
    with pytest.raises(CredentialRefusedError) as excinfo:
        authorize_credential(identity(), now=NOW, controller_id=OTHER_CONTROLLER)
    assert excinfo.value.reasons == (CredentialRefusal.CONTROLLER_MISMATCH,)


def test_the_issuing_controller_is_accepted() -> None:
    assert authorize_credential(identity(), now=NOW, controller_id=CONTROLLER).agent_id == AGENT


def test_identity_and_credential_must_name_the_same_agent() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        identity(cert=credential(agent_id="ag-other"))
    assert excinfo.value.rule == "agent_identity.credential_agent_mismatch"


def test_agent_authority_comes_from_the_shared_role_grant_rules() -> None:
    agent = identity()
    grant = execute_grant()
    assert agent.holds_role([grant], scope=EnvironmentScope(environment="staging"), now=NOW)
    assert not agent.holds_role([grant], scope=EnvironmentScope(environment="production"), now=NOW)
    assert not agent.holds_role([], scope=EnvironmentScope(environment="staging"), now=NOW)


def test_a_wildcard_grant_reaches_every_environment() -> None:
    """The agent's own scope never widens a grant — only a wildcard grant does."""
    wildcard = RoleGrant(
        role=Role.EXECUTE,
        scope=EnvironmentScope.any(),
        principal=Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD),
    )
    agent = identity()
    assert agent.holds_role([wildcard], scope=EnvironmentScope(environment="prod"), now=NOW)
    assert not agent.holds_role(
        [execute_grant()], scope=EnvironmentScope(environment="prod"), now=NOW
    )


def test_wildcard_scope_is_reachable_from_the_shared_vocabulary() -> None:
    agent = identity(scope=EnvironmentScope.any())
    assert agent.scope.environment == ANY_ENVIRONMENT
    assert agent.scope.is_wildcard


# --------------------------------------------------------------------------- #
# Refusal enumeration                                                           #
# --------------------------------------------------------------------------- #


def test_refusals_are_enumerated_not_short_circuited() -> None:
    """An operator needs the whole list, in a canonical order, from one log line."""
    registry = AgentIdentityRegistry(identities=(identity(),))
    dead = registry.revoke_agent(AGENT, revocation()).revoke_credential(
        AGENT, revocation(RevocationReason.DECOMMISSIONED)
    )
    stale = dead.get(AGENT)
    assert stale is not None
    # Due at +600s, expires at +900s: +700s is past due and still inside the
    # window, so the overdue trigger and the expiry trigger do not overlap.
    overdue = stale.refusals_at(now=NOW + timedelta(seconds=700), controller_id=OTHER_CONTROLLER)
    assert CredentialRefusal.ROTATION_OVERDUE in overdue
    assert CredentialRefusal.CREDENTIAL_REVOKED in overdue
    assert CredentialRefusal.IDENTITY_REVOKED in overdue
    assert CredentialRefusal.CONTROLLER_MISMATCH in overdue
    assert CredentialRefusal.EXPIRED not in overdue

    lapsed = stale.refusals_at(now=NOW + timedelta(seconds=10_000))
    assert lapsed == (
        CredentialRefusal.EXPIRED,
        CredentialRefusal.CREDENTIAL_REVOKED,
        CredentialRefusal.IDENTITY_REVOKED,
    )


def test_refusal_order_is_canonical() -> None:
    """Two runs over the same inputs must produce the same log line."""
    assert tuple(CredentialRefusal) == REFUSAL_ORDER
    assert order_refusals(reversed(REFUSAL_ORDER)) == REFUSAL_ORDER
    assert order_refusals([CredentialRefusal.EXPIRED, CredentialRefusal.EXPIRED]) == (
        CredentialRefusal.EXPIRED,
    )


def test_is_revoked_ignores_the_clock() -> None:
    """A revocation has no window — one that expires is not a revocation."""
    revoked = identity().revoke(revocation())
    assert revoked.is_revoked()
    assert revoked.is_revoked(NOW + timedelta(days=365))


def test_credential_refused_error_carries_its_contract() -> None:
    error = CredentialRefusedError(AGENT, (CredentialRefusal.EXPIRED,))
    assert isinstance(error, InvariantViolationError)
    assert error.code == "agent_credential_refused"
    assert "rotate" in error.remediation


# --------------------------------------------------------------------------- #
# Certificate references: data, never a verification claim                      #
# --------------------------------------------------------------------------- #


def certificate(
    *,
    issuer: str = "ca-mesh-1",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    trust_state: str | None = None,
) -> CertificateRef:
    fields: dict[str, object] = {
        "subject": "ag-1",
        "issuer": issuer,
        "serial": "0f1e2d",
        "sha256_fingerprint": FINGERPRINT,
        "not_before": NOW - timedelta(days=1) if not_before is None else not_before,
        "not_after": NOW + timedelta(days=30) if not_after is None else not_after,
    }
    if trust_state is not None:
        fields["trust_state"] = trust_state
    return CertificateRef.model_validate(fields)


def anchor(fingerprint: str = FINGERPRINT, *, subject: str = "ca-mesh-1") -> TrustAnchorRef:
    return TrustAnchorRef(ca_id="ca-1", subject=subject, sha256_fingerprint=fingerprint)


def test_certificate_cannot_claim_to_be_verified() -> None:
    """NEGATIVE CONTROL: Phase 1 has no verifier, so the type forbids the claim."""
    with pytest.raises(InvariantViolationError) as excinfo:
        certificate(trust_state="verified")
    assert excinfo.value.rule == "certificate.trust_state_unsupported"
    assert certificate().chain_verified is False
    assert certificate().trust_state == CERTIFICATE_TRUST_UNVERIFIED


def test_certificate_window_must_be_ordered() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        certificate(not_before=NOW, not_after=NOW)
    assert excinfo.value.rule == "certificate.window"


def test_certificate_covers_only_its_stated_window() -> None:
    """Two recorded timestamps compared — not a validity decision."""
    cert = certificate()
    assert cert.covers(NOW)
    assert not cert.covers(NOW + timedelta(days=31))
    assert cert.chain_verified is False, "comparing windows is not chain verification"


def test_pinning_fails_closed_with_no_anchors() -> None:
    """An agent that pinned nothing must not read as an agent that pinned right."""
    verdict = check_certificate_pinning(certificate(), ())
    assert verdict.reason is PinReason.NO_ANCHORS
    assert verdict.pinned is False
    assert "no_anchors" in verdict.describe()


def test_pinning_compares_fingerprints() -> None:
    matched = check_certificate_pinning(certificate(), (anchor(),))
    assert matched.pinned is True
    assert matched.reason is PinReason.PINNED

    mismatched = check_certificate_pinning(certificate(), (anchor(OTHER_FINGERPRINT),))
    assert mismatched.pinned is False
    assert mismatched.reason is PinReason.FINGERPRINT_MISMATCH


def test_pinning_rejects_a_matching_fingerprint_from_the_wrong_issuer() -> None:
    verdict = check_certificate_pinning(certificate(issuer="rogue-ca"), (anchor(),))
    assert verdict.reason is PinReason.ISSUER_MISMATCH
    assert verdict.pinned is False


def test_a_missing_certificate_cannot_be_pinned() -> None:
    verdict = check_certificate_pinning(None, (anchor(),))
    assert verdict.pinned is False
    assert verdict.reason is PinReason.FINGERPRINT_MISMATCH


def test_identity_pin_verdict_is_the_shared_check() -> None:
    agent = identity(certificate=certificate(), trust_anchors=(anchor(CA_FINGERPRINT),))
    assert agent.pin_verdict().pinned is False
    assert agent.pin_verdict().reason is PinReason.FINGERPRINT_MISMATCH


# --------------------------------------------------------------------------- #
# Fencing — over fabric.FencingToken, with no second fence type                 #
# --------------------------------------------------------------------------- #


def test_this_module_reuses_the_fabric_fence_rather_than_redefining_it() -> None:
    """The non-duplication ruling, asserted.

    Every fence these tests build is a :class:`mayhem.domain.fabric.FencingToken`
    and is accepted by plan-19 predicates unchanged. If a second fence type ever
    appears, this stops holding and the duplication has to be argued for.
    """
    from mayhem.domain import agent_identity as module_under_test

    tokens = [fence(), *chain(1)]
    assert all(isinstance(token, FencingToken) for token in tokens)
    assert not hasattr(module_under_test, "FencingToken"), (
        "plan 19 must not define its own fence type; two orderings over one scope "
        "is the split-brain the fence exists to prevent"
    )
    assert fence_transfers_ownership(tokens[2], tokens[1])
    assert fence_permits_dispatch(tokens[2], tokens[1])


def test_ownership_transfer_requires_a_strictly_newer_fence() -> None:
    """NEGATIVE CONTROL: a non-outranking token cannot authorise a transfer."""
    first, second, third = chain(1, 2)
    assert fence_transfers_ownership(second, first)
    assert fence_transfers_ownership(third, second)
    assert not fence_transfers_ownership(second, second), "an equal epoch is not a transfer"
    assert not fence_transfers_ownership(first, second), "a deposed epoch must never transfer"
    assert not fence_transfers_ownership(first, third)


def test_dispatch_permits_a_retry_but_not_a_deposed_owner() -> None:
    first, second = chain(1)
    assert fence_permits_dispatch(second, second), "same fence, same owner continuing"
    assert not fence_permits_dispatch(first, second)


def test_scope_rules_are_enforced_first() -> None:
    other_run = fence(run_id="r-2", epoch=9)
    other_step = fence(step_id="s-2", epoch=9)
    current = fence(epoch=3)
    for foreign in (other_run, other_step):
        assert not fence_scope_matches(foreign, current)
        assert not fence_permits_dispatch(foreign, current)
        with pytest.raises(FenceNotAuthorised) as excinfo:
            assert_fence_authorises(foreign, current)
        assert excinfo.value.code == "agent_fence_not_authorised"
        assert "different step" in str(excinfo.value)


def test_a_deposed_fence_cannot_authorise_a_dispatch() -> None:
    _, second = chain(1)
    first = second.model_copy(update={"epoch": 1})
    with pytest.raises(FenceNotAuthorised) as excinfo:
        assert_fence_authorises(first, second)
    assert "deposed" in str(excinfo.value)
    assert "next_fence()" in excinfo.value.remediation


def test_assert_passes_for_a_newer_fence() -> None:
    first, second, third = chain(1, 2)
    assert_fence_authorises(second, first)
    assert_fence_authorises(third, second, require_transfer=True)


def test_fence_chain_monotonicity() -> None:
    first, second, third = chain(1, 2)
    assert fence_chain_is_monotonic([first, second, third])
    assert fence_chain_is_monotonic([])
    assert fence_chain_is_monotonic([first])
    assert not fence_chain_is_monotonic([first, first]), "a repeat is not a handover"
    assert not fence_chain_is_monotonic([first, second, first]), "epochs must not go backwards"
    assert not fence_chain_is_monotonic([first, fence(run_id="r-2")])


def test_fence_is_authorised_against_a_fabric_command() -> None:
    """The predicates compose with the envelope plan 03 already defines."""
    from mayhem.domain.fabric import CommandBodyRef, FabricCommand, FabricCommandType

    _, served, newer = chain(1, 2)
    command = FabricCommand(
        protocol="mayhem/1",
        command_id="fc-1",
        run_id="r-1",
        step_id="s-1",
        agent_id=AGENT,
        plan_digest="a" * 64,
        nonce="d" * 32,
        idempotency_key="ik-1",
        fencing_token=newer,
        command=CommandBodyRef(
            command_type=FabricCommandType.INJECT, body_digest="c" * 64, body_ref="body-1"
        ),
        issued_at=NOW,
        signing_key_id="key-1",
        signature="sig" * 8,
    )
    assert command.guards(served)
    assert_fence_authorises(command.fencing_token, served)


# --------------------------------------------------------------------------- #
# Store round-trip (the only IO in this file)                                   #
# --------------------------------------------------------------------------- #


@pytest.fixture
def store() -> Store:
    opened = Store.open_migrated(":memory:")
    yield opened
    opened.close()


def test_identity_survives_a_store_round_trip(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    enrolled = identity()
    repo.save(enrolled)
    loaded = repo.load(AGENT)
    assert loaded is not None
    assert loaded == enrolled
    assert loaded.identity_digest() == enrolled.identity_digest()
    assert [found.agent_id for found in repo.list_agents()] == [AGENT]


def test_store_authorises_from_persisted_state(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    grant = repo.usable_credential(AGENT, now=NOW, controller_id=CONTROLLER)
    assert grant.agent_id == AGENT


def test_store_refuses_an_expired_persisted_credential(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(identity(cert=credential(expires_at=NOW + timedelta(seconds=30))))
    with pytest.raises(CredentialRefusedError) as excinfo:
        repo.usable_credential(AGENT, now=NOW + timedelta(seconds=60))
    assert excinfo.value.reasons == (CredentialRefusal.EXPIRED,)


def test_store_revocation_survives_and_still_refuses(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    repo.revoke_credential(AGENT, revocation())
    with pytest.raises(CredentialRefusedError):
        repo.usable_credential(AGENT, now=NOW)
    assert len(repo.revocations(AGENT, scope=REVOCATION_SCOPE_CREDENTIAL)) == 1
    assert repo.revocations(AGENT, scope=REVOCATION_SCOPE_IDENTITY) == ()


def test_a_ledger_only_identity_revocation_still_refuses(store: Store) -> None:
    """The propagation crash window: the row landed, the identity write did not."""
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    repo.record_revocation(AGENT, CREDENTIAL, revocation(), scope=REVOCATION_SCOPE_IDENTITY)
    with pytest.raises(CredentialRefusedError) as excinfo:
        repo.usable_credential(AGENT, now=NOW)
    assert CredentialRefusal.IDENTITY_REVOKED in excinfo.value.reasons


def test_credential_scope_is_not_promoted_to_identity_scope(store: Store) -> None:
    """Burning one key must not take the whole agent down."""
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    repo.revoke_credential(AGENT, revocation())
    with pytest.raises(CredentialRefusedError) as excinfo:
        repo.usable_credential(AGENT, now=NOW)
    assert excinfo.value.reasons == (CredentialRefusal.CREDENTIAL_REVOKED,)


def test_store_rotation_persists_the_superseded_history(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    advanced = repo.rotate_credential(AGENT, credential_id="cr-2", ttl_s=900.0, now=NOW)
    assert advanced.credential.credential_id == "cr-2"
    reloaded = repo.load(AGENT)
    assert reloaded is not None
    assert [held.credential_id for held in reloaded.credential_history] == [CREDENTIAL, "cr-2"]
    assert reloaded.superseded_credentials[0].rotation_state is RotationState.SUPERSEDED


def test_store_expiry_sweep_is_index_backed(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(
        identity(
            agent_id="ag-soon",
            cert=credential(agent_id="ag-soon", expires_at=NOW + timedelta(seconds=60)),
        )
    )
    repo.save(
        identity(
            agent_id="ag-later",
            cert=credential(agent_id="ag-later", expires_at=NOW + timedelta(seconds=9000)),
        )
    )
    soon = repo.expiring_before(NOW + timedelta(minutes=5))
    assert [found.agent_id for found in soon] == ["ag-soon"]


def test_store_refuses_to_revoke_an_unenrolled_agent(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    with pytest.raises(SecurityStateError):
        repo.revoke_credential(AGENT, revocation())


def test_store_refuses_an_unknown_revocation_scope(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    with pytest.raises(SecurityStateError):
        repo.record_revocation(AGENT, CREDENTIAL, revocation(), scope="everything")


def test_store_refuses_an_unenrolled_agent_at_authorisation(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    with pytest.raises(CredentialRefusedError) as excinfo:
        repo.usable_credential(AGENT, now=NOW)
    assert excinfo.value.reasons == ()


def test_registry_rebuild_never_looks_older_than_a_grant(store: Store) -> None:
    repo = AgentIdentityRepository(store)
    repo.save(identity())
    repo.rotate_credential(AGENT, credential_id="cr-2", ttl_s=900.0, now=NOW)
    grant = repo.registry().authorize(AGENT, now=NOW)
    rebuilt = repo.registry()
    assert rebuilt.grant_is_current(grant)
    assert repo.registry().by_controller(CONTROLLER)[0].agent_id == AGENT
    assert repo.registry().by_controller(OTHER_CONTROLLER) == ()
